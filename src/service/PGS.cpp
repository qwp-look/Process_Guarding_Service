#include "Process_Guard/PGS.h"

#include <ws2tcpip.h>
#include <wtsapi32.h>
#include <userenv.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cwctype>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#endif


namespace
{
// File-local helpers: only the few that are NOT in ProcessGuard::util live here
// (numeric/bool parsing and the WTS session-token helper). Encoding, hashing,
// path/process and string helpers now come from Process_Guard/PGUtil.h.

constexpr const char *kRestartIndexToken = "${PGS_RESTART_INDEX}";
constexpr int kStateFileVersion = 2;

bool parseUnsignedLongLong(const std::string &value, std::uint64_t &out)
{
    const std::string text = ProcessGuard::util::trim(value);
    if (text.empty())
    {
        return false;
    }
    try
    {
        const unsigned long long parsed = std::stoull(text);
        out = static_cast<std::uint64_t>(parsed);
        return true;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

bool parseDwordValue(const std::string &value, DWORD &out)
{
    std::uint64_t parsed = 0;
    if (!parseUnsignedLongLong(value, parsed) || parsed > 0xFFFFFFFFull)
    {
        return false;
    }
    out = static_cast<DWORD>(parsed);
    return true;
}

bool parseBoolFlag(const std::string &value, bool &out)
{
    const std::string text = ProcessGuard::util::trim(value);
    if (text == "1")
    {
        out = true;
        return true;
    }
    if (text == "0")
    {
        out = false;
        return true;
    }
    return false;
}

bool queryUserTokenForSession(DWORD sessionId, HANDLE &userToken)
{
    userToken = nullptr;
    if (sessionId == 0xFFFFFFFF)
    {
        return false;
    }
    return WTSQueryUserToken(sessionId, &userToken) == TRUE;
}
} // namespace

namespace ProcessGuard
{

using namespace util; // pull in base64/utf8/hash/path helpers from PGUtil.h
    // Alias the utf8 path-normalizer to the historical call-site name.
    inline std::string normalizePathForCompare(const std::string &p) { return util::normalizePathForCompareUtf8(p); }

PGS::PGS() = default;

PGS::~PGS()
{
    stop();
}

bool PGS::initialize(const std::string &logFilePath, const std::string &authTokenHash)
{
    if (m_initialized)
    {
        return true;
    }

    Logger::initialize(logFilePath);

    WSADATA wsaData{};
    const int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0)
    {
        Logger::error("PGS: WSAStartup failed, error=" + std::to_string(result));
        return false;
    }

    // Ensure the data root (logs + state) is created with a restrictive DACL
    // (SYSTEM + Administrators only) so the persisted token hash and guard
    // archive are not world-readable under ProgramData.
    {
        std::filesystem::path statePath = std::filesystem::path(defaultStateFilePath(logFilePath));
        std::filesystem::path stateDir = statePath.parent_path();
        std::filesystem::path root = stateDir.parent_path();
        if (!root.empty())
        {
            util::secureCreateDirectory(root.string());
        }
        if (!stateDir.empty())
        {
            util::secureCreateDirectory(stateDir.string());
        }
        std::filesystem::path logRoot = std::filesystem::path(logFilePath).parent_path();
        if (!logRoot.empty() && logRoot.filename() == "logs")
        {
            util::secureCreateDirectory(logRoot.string());
        }
    }

    m_stateFilePath = defaultStateFilePath(logFilePath);
    if (!loadPersistedState())
    {
        Logger::warning("PGS: failed to load persisted state, continuing with empty archive");
    }

    m_requireAuth = true;
    if (!authTokenHash.empty())
    {
        // Host supplied an explicit (already-hashed) token hash. Trust it as-is.
        m_authTokenHash = toLowerAscii(trim(authTokenHash));
        Logger::warning("PGS: auth enabled (token hash provided by host)");
    }
    else
    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        if (m_authTokenHash.empty())
        {
            // No persisted token and no host-supplied one: generate a strong
            // random token, persist its SHA-256 hash, and write the plaintext
            // bootstrap token to a restricted file so the operator can read it
            // (once) and configure clients. We never accept an empty token.
            const std::string generated = util::randomBytesHex(32);
            m_authTokenHash = toLowerAscii(sha256Hex(generated));
            const std::string stateDir = std::filesystem::path(m_stateFilePath).parent_path().string();
            if (writeInitialTokenFile(stateDir, generated))
            {
                Logger::warning("PGS: auth enabled (random token generated; bootstrap token written to "
                                + (stateDir.empty() ? std::string("pgs_initial_token.txt")
                                                    : stateDir + "\\pgs_initial_token.txt") + ")");
            }
            else
            {
                Logger::warning("PGS: auth enabled (random token generated; FAILED to write bootstrap token file)");
            }
        }
        else
        {
            Logger::warning("PGS: auth enabled (token hash restored from persisted state)");
        }
    }

    // Load plugin modules from <exe>\modules before marking the service
    // initialised. A missing/empty directory is fine (loaded=0); failures of
    // individual DLLs are logged inside ModuleManager and do not abort init.
    m_modulesDir = moduleDirectoryOfSelf();
    {
        // PPL module loading is opt-in: it pulls in the Sirius kernel driver
        // (an ARK-class driver exposing far more than PPL). Only load modules
        // when the operator explicitly enables PPL via PGS_ENABLE_PPL=1.
        if (m_pplEnabled)
        {
            const int loaded = m_modules.loadFromDirectory(m_modulesDir);
            if (loaded > 0)
            {
                Logger::warning("PGS: loaded " + std::to_string(loaded) + " module(s) from " + m_modulesDir);
            }
            else
            {
                Logger::warning("PGS: no modules loaded from " + m_modulesDir);
            }
        }
        else
        {
            Logger::warning("PGS: module loading disabled (PPL opt-in off; set PGS_ENABLE_PPL=1 to enable)");
        }
    }
    m_initialized = true;
    Logger::warning("PGS: initialized");
    return true;
}

bool PGS::start()
{
    if (!m_initialized)
    {
        Logger::error("PGS: start called before initialize");
        return false;
    }

    if (m_running.exchange(true))
    {
        Logger::warning("PGS: already running");
        return false;
    }

    if (!createListenSocket())
    {
        m_running = false;
        return false;
    }

    if (!restorePersistedGuards())
    {
        Logger::warning("PGS: one or more persisted guards failed to restore");
    }
    persistState();

    m_clientWorkers.clear();
    m_clientWorkers.reserve(kClientWorkerCount);
    for (std::size_t i = 0; i < kClientWorkerCount; ++i)
    {
        m_clientWorkers.emplace_back(&PGS::clientWorkerLoop, this);
    }
    m_listenerThread = std::thread(&PGS::listenerLoop, this);
    m_monitorThread = std::thread(&PGS::monitorLoop, this);

    Logger::warning("PGS: started");
    return true;
}

void PGS::stop()
{
    if (!m_running.exchange(false))
    {
        return;
    }

    closeListenSocket();
    m_clientQueueCv.notify_all();

    if (m_listenerThread.joinable())
    {
        m_listenerThread.join();
    }
    if (m_monitorThread.joinable())
    {
        m_monitorThread.join();
    }
    for (auto &worker : m_clientWorkers)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }
    m_clientWorkers.clear();

    cleanupGuards();
    WSACleanup();
    m_initialized = false;

    Logger::warning("PGS: stopped");
    Logger::shutdown();
}

bool PGS::isRunning() const
{
    return m_running.load();
}

std::string PGS::defaultStateFilePath(const std::string &logFilePath)
{
    // The archive lives next to the host's data root rather than inside the
    // executable directory so that an installed service can survive upgrades
    // and working-directory changes. When the log root already ends in "logs",
    // we intentionally place state beside it under a sibling "state" folder.
    std::filesystem::path logPath = logFilePath.empty() ? std::filesystem::path("pgs_service.log")
                                                        : std::filesystem::path(logFilePath);
    std::filesystem::path root = logPath.parent_path();
    if (!root.empty() && root.filename() == "logs")
    {
        root = root.parent_path();
    }
    if (root.empty())
    {
        root = std::filesystem::current_path();
    }
    return (root / "state" / "pgs_guard_state.db").string();
}

bool PGS::loadPersistedState()
{
    // State-file format is intentionally line-oriented and append-safe to keep
    // recovery independent from third-party storage libraries. Each line is a
    // complete record so field additions can be versioned explicitly.
    std::lock_guard<std::mutex> lock(m_guardsMutex);
    m_persistedGuards.clear();

    // Parse into a local buffer first and only commit to m_persistedGuards on
    // full success. A malformed line mid-file must not leave a half-populated
    // archive (and a stale m_nextGuardId) behind for restorePersistedGuards().
    std::unordered_map<std::uint64_t, PersistedGuardState> parsedGuards;

    if (m_stateFilePath.empty())
    {
        return true;
    }

    std::ifstream in(m_stateFilePath, std::ios::in | std::ios::binary);
    if (!in.is_open())
    {
        m_nextGuardId = 1ull;
        return true;
    }

    int version = 0;
    std::uint64_t nextGuardId = 1;
    std::string persistedAuthHash;
    std::string line;
    while (std::getline(in, line))
    {
        const std::string trimmed = trim(line);
        if (trimmed.empty())
        {
            continue;
        }

        const std::vector<std::string> fields = splitByChar(trimmed, '\t');
        if (fields.empty())
        {
            continue;
        }

        if (fields[0] == "VERSION")
        {
            if (fields.size() < 2)
            {
                return false;
            }
            try
            {
                version = std::stoi(fields[1]);
            }
            catch (const std::exception &)
            {
                return false;
            }
            continue;
        }

        if (fields[0] == "NEXT_GUARD_ID")
        {
            if (fields.size() < 2 || !parseUnsignedLongLong(fields[1], nextGuardId))
            {
                return false;
            }
            continue;
        }

        if (fields[0] == "AUTH_TOKEN_HASH")
        {
            if (fields.size() < 2)
            {
                return false;
            }
            persistedAuthHash = toLowerAscii(trim(fields[1]));
            continue;
        }

        if (fields[0] == "GUARD")
        {
            if (fields.size() < 10)
            {
                return false;
            }

            PersistedGuardState persisted;
            if (!parseUnsignedLongLong(fields[1], persisted.guardId) ||
                !parseDwordValue(fields[2], persisted.lastKnownPid) ||
                !parseDwordValue(fields[3], persisted.sessionId))
            {
                return false;
            }

            if (!parseMaxRestarts(fields[4], persisted.maxRestarts))
            {
                return false;
            }

            persisted.path = base64Decode(fields[5]);
            persisted.restartArgs = base64Decode(fields[6]);
            persisted.fileHash = (fields[7] == "-") ? std::string() : trim(fields[7]);
            if (!parseBoolFlag(fields[8], persisted.intentional) ||
                !parseBoolFlag(fields[9], persisted.hashVerified))
            {
                return false;
            }

            if (persisted.path.empty() || persisted.guardId == 0)
            {
                return false;
            }

            parsedGuards[persisted.guardId] = persisted;
            if (persisted.guardId >= nextGuardId)
            {
                nextGuardId = persisted.guardId + 1;
            }
        }
    }

    if (version != kStateFileVersion)
    {
        // Migration: v1 stored a non-cryptographic FNV-1a token hash. We do not
        // trust it under SHA-256 auth, so drop only the auth hash (forcing a
        // fresh random token to be generated in initialize()) while KEEPING the
        // guard records so SCM-restart recovery still works. The file is then
        // rewritten at v2 by the next persistState().
        if (version == 1)
        {
            Logger::warning("PGS: migrating state file v1 -> v2 (guard records kept, auth token reset)");
            persistedAuthHash.clear();
        }
        else
        {
            Logger::warning("PGS: unsupported state file version, ignoring persisted archive");
            m_persistedGuards.clear();
            m_nextGuardId = 1ull;
            return false;
        }
    }

    m_persistedGuards = std::move(parsedGuards);
    m_nextGuardId = std::max<std::uint64_t>(1ull, nextGuardId);
    {
        std::lock_guard<std::mutex> authLock(m_authMutex);
        // Only accept a persisted auth hash at v2. An empty hash here makes
        // initialize() generate a fresh random token.
        m_authTokenHash = persistedAuthHash;
    }

    Logger::warning("PGS: loaded persisted archive entries=" + std::to_string(m_persistedGuards.size()) +
                    ", state-file=" + m_stateFilePath);
    return true;
}

void PGS::persistState()
{
    // Persist a snapshot, never a live structure. We first copy the archive
    // under lock, then write outside the lock, then atomically replace the
    // old file. That keeps the runtime hot path short and avoids half-written
    // files when the service is interrupted mid-write.
    std::string authHash;
    {
        std::lock_guard<std::mutex> authLock(m_authMutex);
        authHash = m_authTokenHash;
    }

    std::uint64_t nextGuardId = 1;
    std::vector<PersistedGuardState> snapshot;
    {
        std::lock_guard<std::mutex> guardsLock(m_guardsMutex);
        nextGuardId = m_nextGuardId.load();
        snapshot.reserve(m_persistedGuards.size());
        for (const auto &entry : m_persistedGuards)
        {
            snapshot.push_back(entry.second);
        }
    }

    std::sort(snapshot.begin(), snapshot.end(), [](const PersistedGuardState &a, const PersistedGuardState &b) {
        return a.guardId < b.guardId;
    });

    if (m_stateFilePath.empty())
    {
        return;
    }

    const std::filesystem::path statePath(m_stateFilePath);
    const std::filesystem::path tempPath = statePath.parent_path() / (statePath.filename().string() + ".tmp");
    std::error_code ec;
    if (!statePath.parent_path().empty())
    {
        std::filesystem::create_directories(statePath.parent_path(), ec);
    }

    std::ofstream out(tempPath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        Logger::error("PGS: failed to open temp state file for write: " + tempPath.string());
        return;
    }

    out << "VERSION\t" << kStateFileVersion << "\n";
    out << "NEXT_GUARD_ID\t" << std::max<std::uint64_t>(1ull, nextGuardId) << "\n";
    out << "AUTH_TOKEN_HASH\t" << authHash << "\n";
    for (const auto &guard : snapshot)
    {
        out << "GUARD\t"
            << guard.guardId << "\t"
            << guard.lastKnownPid << "\t"
            << guard.sessionId << "\t"
            << maxRestartsLabel(guard.maxRestarts) << "\t"
            << base64Encode(guard.path) << "\t"
            << base64Encode(guard.restartArgs) << "\t"
            << (guard.fileHash.empty() ? "-" : guard.fileHash) << "\t"
            << (guard.intentional ? "1" : "0") << "\t"
            << (guard.hashVerified ? "1" : "0") << "\n";
    }
    out.flush();
    out.close();

    if (!MoveFileExW(utf8ToWide(tempPath.string()).c_str(),
                     utf8ToWide(statePath.string()).c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        Logger::error("PGS: failed to replace persisted state file, error=" + std::to_string(GetLastError()));
        DeleteFileW(utf8ToWide(tempPath.string()).c_str());
        return;
    }
}

bool PGS::tryAttachPersistedGuard(const PersistedGuardState &persisted, GuardInfo &outGuard)
{
    // Best-case recovery path: the guarded process outlived the service crash.
    // In that case we should not restart it. Instead, verify pid -> image path
    // still matches the archived executable and then rebuild the runtime HANDLE.
    outGuard = GuardInfo{};
    if (persisted.lastKnownPid == 0)
    {
        return false;
    }

    std::string actualPath;
    if (!queryProcessPath(persisted.lastKnownPid, actualPath))
    {
        return false;
    }

    const std::string expectedPath = normalizePathForCompare(persisted.path);
    const std::string actualNormalized = normalizePathForCompare(actualPath);
    if (expectedPath.empty() || actualNormalized.empty() || expectedPath != actualNormalized)
    {
        return false;
    }

    HANDLE processHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, persisted.lastKnownPid);
    if (!processHandle)
    {
        return false;
    }

    DWORD sessionId = 0xFFFFFFFF;
    ProcessIdToSessionId(persisted.lastKnownPid, &sessionId);
    outGuard = GuardInfo{
        persisted.lastKnownPid,
        sessionId,
        actualPath,
        persisted.maxRestarts,
        persisted.restartArgs,
        persisted.fileHash,
        processHandle,
        persisted.intentional,
        persisted.hashVerified,
        persisted.guardId};
    return true;
}

bool PGS::restorePersistedGuards()
{
    // Restore desired-state before the listener/monitor threads start so the
    // service comes up with a coherent guard table instead of briefly exposing
    // an empty world and then mutating under concurrent client traffic.
    //
    // Recovery policy:
    // - if archived pid is still alive and path still matches, reattach
    // - if the guard had already been marked intentional, drop it from archive
    // - otherwise treat the archive as desired-state and relaunch it
    std::vector<PersistedGuardState> snapshot;
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        snapshot.reserve(m_persistedGuards.size());
        for (const auto &entry : m_persistedGuards)
        {
            snapshot.push_back(entry.second);
        }
    }

    bool allRestored = true;
    bool changed = false;
    for (const auto &persisted : snapshot)
    {
        GuardInfo restored;
        if (tryAttachPersistedGuard(persisted, restored))
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            m_guards[restored.pid] = restored;
            m_policyByGuardId[restored.guardId] = RestartPolicyState{persisted.maxRestarts, 0};
            auto it = m_persistedGuards.find(restored.guardId);
            if (it != m_persistedGuards.end())
            {
                it->second.lastKnownPid = restored.pid;
                it->second.sessionId = restored.sessionId;
                it->second.path = restored.path;
            }
            Logger::warning("PGS: restored persisted live guard pid=" + std::to_string(restored.pid) +
                            ", guard-id=" + std::to_string(restored.guardId));
            changed = true;
            continue;
        }

        if (persisted.intentional)
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            m_persistedGuards.erase(persisted.guardId);
            Logger::warning("PGS: dropped persisted intentional guard guard-id=" + std::to_string(persisted.guardId));
            changed = true;
            continue;
        }

        GuardInfo desired{
            0,
            persisted.sessionId,
            persisted.path,
            persisted.maxRestarts,
            persisted.restartArgs,
            persisted.fileHash,
            nullptr,
            false,
            persisted.hashVerified,
            persisted.guardId};

        GuardInfo restarted;
        if (restartGuard(desired, 0, restarted))
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            m_guards[restarted.pid] = restarted;
            m_policyByGuardId[restarted.guardId] = RestartPolicyState{persisted.maxRestarts, 0};
            auto &stored = m_persistedGuards[restarted.guardId];
            stored.guardId = restarted.guardId;
            stored.lastKnownPid = restarted.pid;
            stored.sessionId = restarted.sessionId;
            stored.path = restarted.path;
            stored.maxRestarts = restarted.maxRestarts;
            stored.restartArgs = restarted.restartArgs;
            stored.fileHash = restarted.fileHash;
            stored.intentional = false;
            stored.hashVerified = restarted.hashVerified;
            Logger::warning("PGS: restored persisted missing guard by restart pid=" + std::to_string(restarted.pid) +
                            ", guard-id=" + std::to_string(restarted.guardId));
            changed = true;
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto it = m_persistedGuards.find(persisted.guardId);
            if (it != m_persistedGuards.end())
            {
                it->second.lastKnownPid = 0;
            }
        }
        Logger::error("PGS: failed to restore persisted guard guard-id=" + std::to_string(persisted.guardId) +
                      ", path=" + persisted.path);
        allRestored = false;
        changed = true;
    }

    if (changed)
    {
        persistState();
    }
    return allRestored;
}

void PGS::listenerLoop()
{
    // The listener thread only accepts sockets and enqueues them. Any slow
    // recv/send work is delegated to workers so the accept loop stays responsive
    // even when a client stalls mid-request.
    while (m_running.load())
    {
        sockaddr_in clientAddr{};
        int addrLen = sizeof(clientAddr);
        const SOCKET clientSocket = accept(m_listenSocket, reinterpret_cast<sockaddr *>(&clientAddr), &addrLen);
        if (clientSocket == INVALID_SOCKET)
        {
            if (m_running.load())
            {
                Logger::warning("PGS: accept failed, error=" + std::to_string(WSAGetLastError()));
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(m_clientQueueMutex);
            m_clientQueue.push(clientSocket);
        }
        m_clientQueueCv.notify_one();
    }
}

void PGS::clientWorkerLoop()
{
    // Workers pull accepted sockets from the shared queue and perform the full
    // protocol exchange. A small fixed pool is sufficient because requests are
    // short management commands rather than long-lived streams.
    for (;;)
    {
        SOCKET clientSocket = INVALID_SOCKET;
        {
            std::unique_lock<std::mutex> lock(m_clientQueueMutex);
            m_clientQueueCv.wait(lock, [this]() {
                return !m_running.load() || !m_clientQueue.empty();
            });

            if (m_clientQueue.empty())
            {
                if (!m_running.load())
                {
                    return;
                }
                continue;
            }

            clientSocket = m_clientQueue.front();
            m_clientQueue.pop();
        }

        handleClient(clientSocket);
    }
}

void PGS::handleClient(SOCKET clientSocket)
{
    if (clientSocket == INVALID_SOCKET)
    {
        return;
    }

    const DWORD timeoutMs = kSocketTimeoutMs;
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char *>(&timeoutMs), sizeof(timeoutMs));
    setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char *>(&timeoutMs), sizeof(timeoutMs));

    std::string response = "ERR recv failed";
    std::string request;
    const RecvResult recvState = recvMessage(clientSocket, request);
    if (recvState == RecvResult::Ok)
    {
        // Authentication, command parsing, and dispatch are intentionally kept
        // inside processMessage() so the transport layer stays simple here.
        response = processMessage(request);
    }
    else if (recvState == RecvResult::TooLarge)
    {
        response = "ERR message too large";
    }
    else if (recvState == RecvResult::Closed && !request.empty())
    {
        // Peer closed after sending a partial (newline-less) line: still try
        // to process what we have, mirroring the previous lenient behavior.
        response = processMessage(request);
    }

    if (response.empty())
    {
        response = "ERR empty response";
    }
    response.push_back('\n');
    if (!sendAll(clientSocket, response))
    {
        Logger::warning("PGS: send failed, error=" + std::to_string(WSAGetLastError()));
    }
    closesocket(clientSocket);
}

void PGS::monitorLoop()
{
    // monitorLoop owns the "watch / decide / restart / cleanup" cycle:
    // 1. scan the live guard map for dead handles
    // 2. remove dead entries from the active map
    // 3. outside the lock, decide whether each guard should restart
    // 4. either relaunch and reattach it, or permanently retire its policy
    //
    // Doing restart work outside m_guardsMutex avoids turning expensive Win32
    // process creation calls into a global stop-the-world pause for list/get/
    // register requests.
    while (m_running.load())
    {
        std::vector<GuardInfo> deadGuards;

        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            for (auto it = m_guards.begin(); it != m_guards.end();)
            {
                if (isGuardAlive(it->second))
                {
                    ++it;
                    continue;
                }

                deadGuards.push_back(it->second);
                it = m_guards.erase(it);
            }
        }

        // Process restart decisions outside the main guard map lock.
        //
        // This keeps the lock hold time short and avoids blocking register/list
        // requests while we are creating processes or waiting on system APIs.
        for (const auto &guard : deadGuards)
        {
            if (guard.intentional)
            {
                if (guard.handle)
                {
                    CloseHandle(guard.handle);
                }
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    m_policyByGuardId.erase(guard.guardId);
                    m_persistedGuards.erase(guard.guardId);
                }
                persistState();
                Logger::warning("PGS: guard exited intentionally, pid=" + std::to_string(guard.pid));
                continue;
            }

            bool shouldRestart = true;
            int currentRestarts = 0;
            int maxRestarts = guard.maxRestarts;
            {
                std::lock_guard<std::mutex> lock(m_guardsMutex);
                auto &policy = m_policyByGuardId[guard.guardId];
                if (policy.maxRestarts != guard.maxRestarts)
                {
                    policy.maxRestarts = guard.maxRestarts;
                }
                if (policy.maxRestarts >= 0 && policy.restartCount >= policy.maxRestarts)
                {
                    shouldRestart = false;
                }
                else
                {
                    ++policy.restartCount;
                }
                currentRestarts = policy.restartCount;
                maxRestarts = policy.maxRestarts;
            }

            if (!shouldRestart)
            {
                Logger::warning("PGS: guard restart limit reached, path=" + guard.path +
                                ", max=" + maxRestartsLabel(maxRestarts));
                if (guard.handle)
                {
                    CloseHandle(guard.handle);
                }
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    m_policyByGuardId.erase(guard.guardId);
                    auto persisted = m_persistedGuards.find(guard.guardId);
                    if (persisted != m_persistedGuards.end())
                    {
                        persisted->second.lastKnownPid = 0;
                    }
                }
                persistState();
                continue;
            }

            Logger::warning("PGS: guard died unexpectedly, pid=" + std::to_string(guard.pid));
            Logger::warning("PGS: restart count " + std::to_string(currentRestarts) + "/" +
                            maxRestartsLabel(maxRestarts) +
                            ", path=" + guard.path);

            GuardInfo newGuard;
            if (restartGuard(guard, currentRestarts, newGuard))
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    auto existingNew = m_guards.find(newGuard.pid);
                    if (existingNew != m_guards.end() && existingNew->second.handle)
                    {
                        CloseHandle(existingNew->second.handle);
                    }
                    m_guards[newGuard.pid] = newGuard;
                    auto &persisted = m_persistedGuards[newGuard.guardId];
                    persisted.guardId = newGuard.guardId;
                    persisted.lastKnownPid = newGuard.pid;
                    persisted.sessionId = newGuard.sessionId;
                    persisted.path = newGuard.path;
                    persisted.maxRestarts = newGuard.maxRestarts;
                    persisted.restartArgs = newGuard.restartArgs;
                    persisted.fileHash = newGuard.fileHash;
                    persisted.intentional = false;
                    persisted.hashVerified = newGuard.hashVerified;
                }
                persistState();
                // Note (TOCTOU): by this point the dead guard was already
                // erased from m_guards, so a concurrent "unregister <oldPid>"
                // would have returned "pid not found". The guard is re-added
                // under its new pid per the restart policy. To permanently stop
                // a guard that keeps dying, use "intentional" or unregister the
                // new pid after it restarts.
                Logger::warning("PGS: auto-attached restarted guard pid=" + std::to_string(newGuard.pid));
            }
            else
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    m_policyByGuardId.erase(guard.guardId);
                    auto persisted = m_persistedGuards.find(guard.guardId);
                    if (persisted != m_persistedGuards.end())
                    {
                        persisted->second.lastKnownPid = 0;
                    }
                }
                persistState();
                Logger::error("PGS: restart failed permanently, guard removed pid=" + std::to_string(guard.pid));
            }
            if (guard.handle)
            {
                CloseHandle(guard.handle);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(kMonitorIntervalMs));
    }
}

bool PGS::isGuardAlive(const GuardInfo &info) const
{
    if (!info.handle)
    {
        return false;
    }
    return WaitForSingleObject(info.handle, 0) == WAIT_TIMEOUT;
}

bool PGS::restartGuard(const GuardInfo &info, int restartIndex, GuardInfo &newGuard)
{
    // TOCTOU defense: if a file hash was recorded at registration time,
    // recompute it now and refuse to relaunch if the image on disk has
    // changed. Without this, a binary swapped between crash and restart
    // would be launched while still carrying the stale hashVerified badge.
    if (!info.fileHash.empty())
    {
        std::string currentHash;
        if (!computeFileHash(info.path, currentHash))
        {
            Logger::error("PGS: restart refused, failed to recompute file hash for path=" + info.path);
            return false;
        }
        if (!constantTimeEquals(toLowerAscii(currentHash), toLowerAscii(info.fileHash)))
        {
            Logger::error("PGS: restart refused, file hash mismatch (image changed since registration) path=" + info.path);
            return false;
        }
    }
    // Restart tries to preserve user experience first. We prefer re-launching
    // inside the original session so GUI apps come back on the right desktop.
    // If that fails, we still fall back to a normal CreateProcessW restart so
    // service-side recovery remains possible for console/background workers.
    if (restartGuardInSession(info, restartIndex, newGuard))
    {
        return true;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    const std::wstring exeW = utf8ToWide(info.path);
    if (exeW.empty())
    {
        Logger::error("PGS: restart failed, utf8ToWide path conversion failed for path=" + info.path);
        return false;
    }
    std::wstring commandLine = quoteArgW(exeW);
    if (!info.restartArgs.empty())
    {
        const std::string argsUtf8 = replaceAll(info.restartArgs, kRestartIndexToken, std::to_string(restartIndex));
        const std::wstring argsW = utf8ToWide(argsUtf8);
        if (!argsW.empty())
        {
            commandLine.push_back(L' ');
            commandLine += argsW;
        }
    }
    std::vector<wchar_t> writableCmd(commandLine.begin(), commandLine.end());
    writableCmd.push_back(L'\0');

    const std::wstring workDirW = utf8ToWide(parentDirectory(info.path));
    const BOOL ok = CreateProcessW(
        nullptr,
        writableCmd.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_CONSOLE,
        nullptr,
        workDirW.empty() ? nullptr : workDirW.c_str(),
        &si,
        &pi);

    if (!ok)
    {
        Logger::error("PGS: restart failed for path=" + info.path + ", error=" + std::to_string(GetLastError()));
        return false;
    }

    DWORD targetSession = 0xFFFFFFFF;
    ProcessIdToSessionId(pi.dwProcessId, &targetSession);
    newGuard = GuardInfo{
        pi.dwProcessId,
        targetSession,
        info.path,
        info.maxRestarts,
        info.restartArgs,
        info.fileHash,
        pi.hProcess,
        false,
        info.hashVerified,
        info.guardId};

    Logger::warning("PGS: restart launched in fallback session, pid=" + std::to_string(pi.dwProcessId) +
                    ", session=" + std::to_string(targetSession));
    CloseHandle(pi.hThread);
    return true;
}

bool PGS::restartGuardInSession(const GuardInfo &info, int restartIndex, GuardInfo &newGuard)
{
    // Session-aware restart path:
    // - obtain a user token for the original session when possible
    // - duplicate it into a primary token
    // - build a fresh user environment block
    // - CreateProcessAsUserW on the interactive desktop
    //
    // This is heavier than the fallback path, but it is the only way to bring
    // UI processes back into the intended user session from a service context.
    HANDLE userToken = nullptr;
    DWORD targetSessionId = info.sessionId;
    if (!queryUserTokenForSession(targetSessionId, userToken))
    {
        const DWORD activeSession = WTSGetActiveConsoleSessionId();
        if (!queryUserTokenForSession(activeSession, userToken))
        {
            return false;
        }
        targetSessionId = activeSession;
    }

    HANDLE primaryToken = nullptr;
    const BOOL dupOk = DuplicateTokenEx(
        userToken,
        TOKEN_ALL_ACCESS,
        nullptr,
        SecurityImpersonation,
        TokenPrimary,
        &primaryToken);
    CloseHandle(userToken);
    if (!dupOk)
    {
        return false;
    }

    SetTokenInformation(primaryToken, TokenSessionId, &targetSessionId, sizeof(targetSessionId));

    LPVOID envBlock = nullptr;
    CreateEnvironmentBlock(&envBlock, primaryToken, FALSE);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<wchar_t *>(L"winsta0\\default");

    PROCESS_INFORMATION pi{};
    const std::wstring exeW = utf8ToWide(info.path);
    if (exeW.empty())
    {
        if (envBlock)
        {
            DestroyEnvironmentBlock(envBlock);
        }
        CloseHandle(primaryToken);
        return false;
    }
    std::wstring commandLine = quoteArgW(exeW);
    if (!info.restartArgs.empty())
    {
        const std::string argsUtf8 = replaceAll(info.restartArgs, kRestartIndexToken, std::to_string(restartIndex));
        const std::wstring argsW = utf8ToWide(argsUtf8);
        if (!argsW.empty())
        {
            commandLine.push_back(L' ');
            commandLine += argsW;
        }
    }
    std::vector<wchar_t> writableCmd(commandLine.begin(), commandLine.end());
    writableCmd.push_back(L'\0');

    const std::wstring workDirW = utf8ToWide(parentDirectory(info.path));
    const BOOL ok = CreateProcessAsUserW(
        primaryToken,
        nullptr,
        writableCmd.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        envBlock,
        workDirW.empty() ? nullptr : workDirW.c_str(),
        &si,
        &pi);

    if (envBlock)
    {
        DestroyEnvironmentBlock(envBlock);
    }
    CloseHandle(primaryToken);

    if (!ok)
    {
        return false;
    }

    newGuard = GuardInfo{
        pi.dwProcessId,
        targetSessionId,
        info.path,
        info.maxRestarts,
        info.restartArgs,
        info.fileHash,
        pi.hProcess,
        false,
        info.hashVerified,
        info.guardId};

    Logger::warning("PGS: restart launched in user session, pid=" + std::to_string(pi.dwProcessId) +
                    ", session=" + std::to_string(targetSessionId));
    CloseHandle(pi.hThread);
    return true;
}

bool PGS::parsePid(const std::string &value, DWORD &outPid)
{
    return util::parsePid(value, outPid);
}

bool PGS::parseMaxRestarts(const std::string &value, int &outMaxRestarts)
{
    return util::parseMaxRestarts(value, outMaxRestarts);
}

std::string PGS::maxRestartsLabel(int maxRestarts)
{
    return util::maxRestartsLabel(maxRestarts);
}

std::vector<std::string> PGS::splitByChar(const std::string &value, char delimiter)
{
    return util::split(value, delimiter);
}

std::string PGS::base64Encode(const std::string &input)
{
    return util::base64Encode(input);
}

bool PGS::computeFileHash(const std::string &path, std::string &outHash)
{
    // File integrity hash is SHA-256 (via CNG). The previous FNV-1a hash was
    // non-cryptographic and trivially collidable; SHA-256 is still fast enough
    // for the rare register/verify path.
    return util::sha256FileHex(path, outHash);
}

bool PGS::queryProcessPath(DWORD pid, std::string &outPath)
{
    return util::queryProcessPath(pid, outPath);
}

PGS::RecvResult PGS::recvMessage(SOCKET socket, std::string &payload)
{
    payload.clear();
    bool sawData = false;
    char buffer[kBufferSize];

    for (;;)
    {
        const int received = recv(socket, buffer, static_cast<int>(sizeof(buffer)), 0);
        if (received == 0)
        {
            return sawData ? RecvResult::Closed : RecvResult::Error;
        }
        if (received < 0)
        {
            return RecvResult::Error;
        }

        sawData = true;
        payload.append(buffer, static_cast<std::size_t>(received));

        // Management protocol messages are line oriented. We stop at the first
        // newline and reject messages that grow beyond a conservative upper
        // bound to avoid memory abuse and accidental truncation bugs.
        if (payload.size() > kMaxMessageSize)
        {
            return RecvResult::TooLarge;
        }

        const std::size_t newlinePos = payload.find('\n');
        if (newlinePos != std::string::npos)
        {
            payload.resize(newlinePos);
            return RecvResult::Ok;
        }
    }
}

bool PGS::sendAll(SOCKET socket, const std::string &payload)
{
    std::size_t totalSent = 0;
    while (totalSent < payload.size())
    {
        // Winsock send() is allowed to perform partial writes even on blocking
        // sockets, so loop until the whole response is flushed or the peer dies.
        const int sent = send(socket,
                              payload.data() + totalSent,
                              static_cast<int>(payload.size() - totalSent),
                              0);
        if (sent <= 0)
        {
            return false;
        }
        totalSent += static_cast<std::size_t>(sent);
    }
    return true;
}

std::string PGS::parentDirectory(const std::string &path)
{
    const auto pos = path.find_last_of("\\/");
    if (pos == std::string::npos)
    {
        return std::string();
    }
    return path.substr(0, pos);
}

bool PGS::createListenSocket()
{
    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET)
    {
        Logger::error("PGS: socket failed, error=" + std::to_string(WSAGetLastError()));
        return false;
    }

    constexpr BOOL reuse = TRUE;
    setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&reuse), sizeof(reuse));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(kServerPort);
    inet_pton(AF_INET, kServerIp, &serverAddr.sin_addr);

    if (bind(m_listenSocket, reinterpret_cast<sockaddr *>(&serverAddr), sizeof(serverAddr)) == SOCKET_ERROR)
    {
        Logger::error("PGS: bind failed, error=" + std::to_string(WSAGetLastError()));
        closeListenSocket();
        return false;
    }

    if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        Logger::error("PGS: listen failed, error=" + std::to_string(WSAGetLastError()));
        closeListenSocket();
        return false;
    }

    return true;
}

void PGS::closeListenSocket()
{
    if (m_listenSocket == INVALID_SOCKET)
    {
        return;
    }

    shutdown(m_listenSocket, SD_BOTH);
    closesocket(m_listenSocket);
    m_listenSocket = INVALID_SOCKET;
}

void PGS::cleanupGuards()
{
    std::lock_guard<std::mutex> lock(m_guardsMutex);
    for (auto &entry : m_guards)
    {
        if (entry.second.handle)
        {
            CloseHandle(entry.second.handle);
        }
    }
    m_guards.clear();
    m_policyByGuardId.clear();
}

// Resolve the "modules" directory beside the running pgs_service.exe. Used
// as the plugin scan root. Falls back to a relative "modules" if the exe
// path cannot be determined (should not happen in practice).
std::string PGS::moduleDirectoryOfSelf()
{
    // Resolve the directory of the running executable (pgs_service.exe) and
    // append a "modules" subdirectory. Modules live beside the service binary
    // so the plugin set travels with the installation.
    wchar_t exePath[MAX_PATH] = {0};
    DWORD len = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    if (len == 0 || len >= MAX_PATH)
    {
        return "modules";
    }
    std::wstring wpath(exePath);
    std::size_t slash = wpath.find_last_of(L"\\/");
    std::wstring wdir = (slash == std::wstring::npos) ? std::wstring(L".") : wpath.substr(0, slash);
    wdir += L"\\modules";

    int n = WideCharToMultiByte(CP_UTF8, 0, wdir.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(n > 0 ? n - 1 : 0, '\0');
    if (n > 0)
        WideCharToMultiByte(CP_UTF8, 0, wdir.c_str(), -1, out.data(), n, nullptr, nullptr);
    return out;
}

bool PGS::isPathInsideModulesDir(const std::string &candidateUtf8) const
{
    if (m_modulesDir.empty() || candidateUtf8.empty())
    {
        return false;
    }
    const std::string candidateNorm = normalizePathForCompareUtf8(candidateUtf8);
    const std::string modulesNorm = normalizePathForCompareUtf8(m_modulesDir);
    if (candidateNorm.empty() || modulesNorm.empty())
    {
        return false;
    }
    // Require the candidate to be strictly under the modules directory.
    // Both sides are already lowercased, backslashed, absolute.
    if (candidateNorm == modulesNorm)
    {
        return false; // the directory itself is not a DLL
    }
    const std::string prefix = modulesNorm + "\\";
    if (candidateNorm.rfind(prefix, 0) != 0)
    {
        return false;
    }
    // Must be an existing .dll file.
    const DWORD attr = GetFileAttributesW(utf8ToWide(candidateUtf8).c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        return false;
    }
    return true;
}

bool PGS::writeInitialTokenFile(const std::string &stateDir, const std::string &token) const
{
    std::filesystem::path filePath = stateDir.empty() ? std::filesystem::path("pgs_initial_token.txt")
                                                      : std::filesystem::path(stateDir) / "pgs_initial_token.txt";
    // Ensure the directory exists with a restrictive ACL before writing.
    if (!stateDir.empty())
    {
        util::secureCreateDirectory(stateDir);
    }
    std::ofstream out(filePath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        return false;
    }
    out << token;
    out.flush();
    out.close();

    // Apply the same restrictive DACL to the file (SYSTEM + Administrators).
    const std::wstring wpath = utf8ToWide(filePath.string());
    PSECURITY_DESCRIPTOR psd = nullptr;
    ULONG sdSize = 0;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &psd, &sdSize) &&
        psd)
    {
        BOOL daclPresent = FALSE;
        BOOL daclDefaulted = FALSE;
        PACL dacl = nullptr;
        GetSecurityDescriptorDacl(psd, &daclPresent, &dacl, &daclDefaulted);
        SetNamedSecurityInfoW(const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                              DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                              nullptr, nullptr, dacl, nullptr);
        LocalFree(psd);
    }
    return true;
}

// "module" sub-protocol dispatcher. Wire format (after auth envelope):
//   module list
//   module load <base64-path>
//   module unload <name>
//   module call <name> <kv-request>   (response forwarded verbatim)
} // namespace ProcessGuard
