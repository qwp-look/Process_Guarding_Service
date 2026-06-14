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
// File-local helpers in this translation unit intentionally stay small and
// dependency-free. They normalize input, translate encodings, and wrap a few
// Windows-specific primitives so the PGS member functions can focus on guard
// lifecycle rather than string plumbing.
const std::string kBase64Chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

constexpr int kDefaultMaxRestarts = 3;
constexpr const char *kRestartIndexToken = "${PGS_RESTART_INDEX}";
constexpr int kStateFileVersion = 1;
constexpr std::uint64_t kFnvOffset = 1469598103934665603ull;
constexpr std::uint64_t kFnvPrime = 1099511628211ull;

std::string trim(std::string value)
{
    const auto isNotSpace = [](unsigned char c) { return !std::isspace(c); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), isNotSpace));
    value.erase(std::find_if(value.rbegin(), value.rend(), isNotSpace).base(), value.end());
    return value;
}

std::string toLowerAscii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string wideToUtf8(const std::wstring &input)
{
    if (input.empty())
    {
        return std::string();
    }
    const int needed = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
    {
        return std::string();
    }
    std::string out(static_cast<std::size_t>(needed), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, input.c_str(), -1, &out[0], needed, nullptr, nullptr) <= 0)
    {
        return std::string();
    }
    if (!out.empty() && out.back() == '\0')
    {
        out.pop_back();
    }
    return out;
}

std::string base64Decode(const std::string &input)
{
    std::string output;
    int val = 0;
    int valb = -8;
    for (unsigned char c : input)
    {
        if (c == '=')
        {
            break;
        }
        const auto index = kBase64Chars.find(c);
        if (index == std::string::npos)
        {
            break;
        }
        val = (val << 6) + static_cast<int>(index);
        valb += 6;
        if (valb >= 0)
        {
            output.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return output;
}

std::string replaceAll(std::string text, const std::string &from, const std::string &to)
{
    if (from.empty())
    {
        return text;
    }
    std::size_t startPos = 0;
    while ((startPos = text.find(from, startPos)) != std::string::npos)
    {
        text.replace(startPos, from.length(), to);
        startPos += to.length();
    }
    return text;
}

std::string hashToken(const std::string &token)
{
    std::uint64_t hash = kFnvOffset;
    for (unsigned char c : token)
    {
        hash ^= c;
        hash *= kFnvPrime;
    }
    std::ostringstream oss;
    oss << std::hex << std::nouppercase << std::setw(16) << std::setfill('0') << hash;
    return oss.str();
}

bool parseUnsignedLongLong(const std::string &value, std::uint64_t &out)
{
    const std::string text = trim(value);
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
    const std::string text = trim(value);
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

std::wstring utf8ToWide(const std::string &input)
{
    if (input.empty())
    {
        return std::wstring();
    }
    const int needed = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
    if (needed <= 0)
    {
        return std::wstring();
    }
    std::wstring out(static_cast<std::size_t>(needed), L'\0');
    if (MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, &out[0], needed) <= 0)
    {
        return std::wstring();
    }
    if (!out.empty() && out.back() == L'\0')
    {
        out.pop_back();
    }
    return out;
}

std::string normalizePathForCompare(const std::string &pathUtf8)
{
    const std::wstring pathW = utf8ToWide(pathUtf8);
    if (pathW.empty())
    {
        return std::string();
    }

    std::vector<wchar_t> fullPathBuf(32768, L'\0');
    const DWORD fullLen = GetFullPathNameW(pathW.c_str(), static_cast<DWORD>(fullPathBuf.size()), fullPathBuf.data(), nullptr);
    if (fullLen == 0 || fullLen >= fullPathBuf.size())
    {
        return std::string();
    }

    std::wstring normalized(fullPathBuf.data(), fullLen);
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(towlower(ch));
    });
    return wideToUtf8(normalized);
}

std::wstring quoteArgW(const std::wstring &arg)
{
    if (arg.empty())
    {
        return L"\"\"";
    }

    bool needQuotes = false;
    for (wchar_t ch : arg)
    {
        if (ch == L' ' || ch == L'\t' || ch == L'"')
        {
            needQuotes = true;
            break;
        }
    }
    if (!needQuotes)
    {
        return arg;
    }

    std::wstring out = L"\"";
    int backslashes = 0;
    for (wchar_t ch : arg)
    {
        if (ch == L'\\')
        {
            ++backslashes;
            continue;
        }
        if (ch == L'"')
        {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
            backslashes = 0;
            continue;
        }
        if (backslashes > 0)
        {
            out.append(backslashes, L'\\');
            backslashes = 0;
        }
        out.push_back(ch);
    }
    if (backslashes > 0)
    {
        out.append(backslashes * 2, L'\\');
    }
    out.push_back(L'"');
    return out;
}
} // namespace

namespace ProcessGuard
{

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

    m_stateFilePath = defaultStateFilePath(logFilePath);
    if (!loadPersistedState())
    {
        Logger::warning("PGS: failed to load persisted state, continuing with empty archive");
    }

    m_requireAuth = true;
    if (!authTokenHash.empty())
    {
        m_authTokenHash = toLowerAscii(trim(authTokenHash));
        Logger::warning("PGS: auth enabled (token hash provided by host)");
    }
    else
    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        if (m_authTokenHash.empty())
        {
            m_authTokenHash = hashToken(std::string());
            Logger::warning("PGS: auth enabled (empty token hash fallback)");
        }
        else
        {
            Logger::warning("PGS: auth enabled (token hash restored from persisted state)");
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

            m_persistedGuards[persisted.guardId] = persisted;
            if (persisted.guardId >= nextGuardId)
            {
                nextGuardId = persisted.guardId + 1;
            }
        }
    }

    if (version != kStateFileVersion)
    {
        Logger::warning("PGS: unsupported state file version, ignoring persisted archive");
        m_persistedGuards.clear();
        m_nextGuardId = 1ull;
        return false;
    }

    m_nextGuardId = std::max<std::uint64_t>(1ull, nextGuardId);
    {
        std::lock_guard<std::mutex> authLock(m_authMutex);
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
    if (recvMessage(clientSocket, request))
    {
        // Authentication, command parsing, and dispatch are intentionally kept
        // inside processMessage() so the transport layer stays simple here.
        response = processMessage(request);
    }
    else if (request.size() >= kMaxMessageSize)
    {
        response = "ERR message too large";
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

std::string PGS::processMessage(const std::string &message)
{
    // Protocol framing is line-oriented text:
    // - optional auth envelope: "token <token> <command>"
    // - command body:          "<verb> <args>"
    //
    // The dispatcher is intentionally explicit instead of clever so each
    // management command has a narrow validation path and returns predictable
    // error messages for CLI / GUI callers.
    std::string normalized;
    if (!stripAuthEnvelope(message, normalized))
    {
        return m_requireAuth ? "ERR auth failed or token missing" : "ERR empty command";
    }

    const auto spacePos = normalized.find(' ');
    const std::string command = (spacePos == std::string::npos) ? normalized : normalized.substr(0, spacePos);
    const std::string args = (spacePos == std::string::npos) ? std::string() : trim(normalized.substr(spacePos + 1));

    if (command == "register")
    {
        const std::vector<std::string> fields = splitByChar(args, '|');
        if (fields.size() < 2)
        {
            return "ERR invalid register payload";
        }

        DWORD pid = 0;
        if (!parsePid(trim(fields[0]), pid))
        {
            return "ERR invalid pid in register";
        }

        int maxRestarts = kDefaultMaxRestarts;
        if (fields.size() >= 3 && !parseMaxRestarts(trim(fields[2]), maxRestarts))
        {
            return "ERR invalid max-restarts";
        }

        const std::string restartArgs = (fields.size() >= 4) ? trim(fields[3]) : std::string();
        const std::string declaredHash = (fields.size() >= 5) ? trim(fields[4]) : std::string();
        return handleRegister(pid, trim(fields[1]), maxRestarts, restartArgs, declaredHash);
    }

    if (command == "intentional")
    {
        DWORD pid = 0;
        if (!parsePid(args, pid))
        {
            return "ERR invalid pid for intentional";
        }
        return handleIntentionalExit(pid);
    }

    if (command == "unregister")
    {
        DWORD pid = 0;
        if (!parsePid(args, pid))
        {
            return "ERR invalid pid for unregister";
        }
        return handleUnregister(pid);
    }

    if (command == "set-policy")
    {
        const std::vector<std::string> fields = splitByChar(args, '|');
        if (fields.size() < 2)
        {
            return "ERR invalid set-policy payload";
        }
        DWORD pid = 0;
        if (!parsePid(trim(fields[0]), pid))
        {
            return "ERR invalid pid in set-policy";
        }
        int maxRestarts = -1;
        if (!parseMaxRestarts(trim(fields[1]), maxRestarts))
        {
            return "ERR invalid max-restarts in set-policy";
        }
        const std::string restartArgs = (fields.size() >= 3) ? trim(fields[2]) : std::string();
        return handleSetPolicy(pid, maxRestarts, restartArgs);
    }

    if (command == "set-token")
    {
        const std::vector<std::string> fields = splitByChar(args, '|');
        if (fields.size() < 2)
        {
            return "ERR invalid set-token payload";
        }
        return handleSetToken(trim(fields[0]), trim(fields[1]));
    }

    if (command == "list")
    {
        return handleList();
    }

    if (command == "get")
    {
        DWORD pid = 0;
        if (!parsePid(args, pid))
        {
            return "ERR invalid pid for get";
        }
        return handleGet(pid);
    }

    if (command == "ping")
    {
        return "OK pong";
    }

    if (command == "stats")
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        return "OK guards=" + std::to_string(m_guards.size());
    }

    return "ERR unknown command";
}

std::string PGS::handleRegister(
    DWORD pid,
    const std::string &encodedPath,
    int maxRestarts,
    const std::string &restartArgs,
    const std::string &declaredHash)
{
    // Registration is the trust boundary between clients and the service. The
    // service re-derives everything important that it can:
    // - decode the requested path
    // - query the real image path from pid
    // - verify the two paths match
    // - optionally compute and validate the file hash
    // - open its own synchronization handle
    //
    // That way the guard record stored in memory reflects the actual process
    // being watched, not merely what the client claimed.
    const std::string requestedPath = base64Decode(encodedPath);
    if (requestedPath.empty())
    {
        Logger::warning("PGS: empty decoded path for pid=" + std::to_string(pid));
        return "ERR empty decoded path";
    }

    // Never trust the client supplied path as the source of truth.
    //
    // The CLI may provide a path for convenience, but the service must verify
    // that the pid actually points at the same image. Otherwise a caller could
    // ask PGS to monitor pid=A while later restarting executable=B.
    std::string actualPath;
    if (!queryProcessPath(pid, actualPath))
    {
        Logger::warning("PGS: failed to query image path for pid=" + std::to_string(pid));
        return "ERR failed to query process image path";
    }

    const std::string requestedNormalized = normalizePathForCompare(requestedPath);
    const std::string actualNormalized = normalizePathForCompare(actualPath);
    if (requestedNormalized.empty() || actualNormalized.empty() || requestedNormalized != actualNormalized)
    {
        Logger::warning("PGS: register rejected, path mismatch for pid=" + std::to_string(pid) +
                        ", requested=" + requestedPath + ", actual=" + actualPath);
        return "ERR pid/path mismatch";
    }

    std::string actualHash;
    const bool hasActualHash = computeFileHash(actualPath, actualHash);
    bool hashVerified = false;
    if (!declaredHash.empty())
    {
        if (!hasActualHash)
        {
            return "ERR failed to compute file hash";
        }
        hashVerified = (toLowerAscii(actualHash) == toLowerAscii(declaredHash));
        if (!hashVerified)
        {
            Logger::warning("PGS: register rejected, hash mismatch for path=" + actualPath);
            return "ERR hash mismatch";
        }
    }

    HANDLE processHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!processHandle)
    {
        Logger::warning("PGS: OpenProcess failed for pid=" + std::to_string(pid) + ", error=" + std::to_string(GetLastError()));
        return "ERR OpenProcess failed";
    }

    DWORD sessionId = 0xFFFFFFFF;
    ProcessIdToSessionId(pid, &sessionId);

    const std::string storedHash = declaredHash.empty() ? actualHash : declaredHash;
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto existing = m_guards.find(pid);

        // Preserve guard identity across re-registers of the same live pid.
        // This matters when policy is updated or when a client re-submits the
        // same guard with refreshed metadata.
        const std::uint64_t guardId = (existing != m_guards.end()) ? existing->second.guardId : m_nextGuardId++;
        GuardInfo updated{
            pid,
            sessionId,
            actualPath,
            maxRestarts,
            restartArgs,
            storedHash,
            processHandle,
            false,
            hashVerified,
            guardId};

        if (existing != m_guards.end())
        {
            if (existing->second.handle)
            {
                CloseHandle(existing->second.handle);
            }
            existing->second = updated;
        }
        else
        {
            m_guards.emplace(pid, std::move(updated));
        }

        auto policyIt = m_policyByGuardId.find(guardId);
        if (policyIt == m_policyByGuardId.end())
        {
            m_policyByGuardId.emplace(guardId, RestartPolicyState{maxRestarts, 0});
        }
        else
        {
            policyIt->second.maxRestarts = maxRestarts;
        }

        auto &persisted = m_persistedGuards[guardId];
        persisted.guardId = guardId;
        persisted.lastKnownPid = pid;
        persisted.sessionId = sessionId;
        persisted.path = actualPath;
        persisted.maxRestarts = maxRestarts;
        persisted.restartArgs = restartArgs;
        persisted.fileHash = storedHash;
        persisted.intentional = false;
        persisted.hashVerified = hashVerified;
    }

    persistState();

    Logger::warning("PGS: registered guard pid=" + std::to_string(pid) +
                    ", path=" + actualPath +
                    ", max-restarts=" + maxRestartsLabel(maxRestarts) +
                    ", hash=" + (storedHash.empty() ? std::string("<none>") : storedHash));

    return "OK registered pid=" + std::to_string(pid);
}

std::string PGS::handleIntentionalExit(DWORD pid)
{
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        const auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            Logger::warning("PGS: intentional exit for unknown pid=" + std::to_string(pid));
            return "ERR pid not found";
        }

        it->second.intentional = true;
        auto persisted = m_persistedGuards.find(it->second.guardId);
        if (persisted != m_persistedGuards.end())
        {
            persisted->second.intentional = true;
        }
    }

    persistState();
    Logger::warning("PGS: marked intentional exit for pid=" + std::to_string(pid));
    return "OK intentional marked pid=" + std::to_string(pid);
}

std::string PGS::handleUnregister(DWORD pid)
{
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            return "ERR pid not found";
        }

        const std::uint64_t guardId = it->second.guardId;
        if (it->second.handle)
        {
            CloseHandle(it->second.handle);
        }
        m_guards.erase(it);
        m_policyByGuardId.erase(guardId);
        m_persistedGuards.erase(guardId);
    }

    persistState();
    Logger::warning("PGS: unregistered pid=" + std::to_string(pid));
    return "OK unregistered pid=" + std::to_string(pid);
}

std::string PGS::handleSetPolicy(DWORD pid, int maxRestarts, const std::string &restartArgs)
{
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            return "ERR pid not found";
        }

        it->second.maxRestarts = maxRestarts;
        it->second.restartArgs = restartArgs;
        auto &policy = m_policyByGuardId[it->second.guardId];
        policy.maxRestarts = maxRestarts;
        auto persisted = m_persistedGuards.find(it->second.guardId);
        if (persisted != m_persistedGuards.end())
        {
            persisted->second.maxRestarts = maxRestarts;
            persisted->second.restartArgs = restartArgs;
        }
    }

    persistState();
    Logger::warning("PGS: updated policy pid=" + std::to_string(pid) +
                    ", max=" + maxRestartsLabel(maxRestarts));
    return "OK policy updated pid=" + std::to_string(pid);
}

std::string PGS::handleSetToken(const std::string &encodedOldToken, const std::string &encodedNewToken)
{
    const std::string oldToken = base64Decode(encodedOldToken);
    const std::string newToken = base64Decode(encodedNewToken);
    const std::string oldHash = hashToken(oldToken);
    const std::string newHash = hashToken(newToken);

    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        if (oldHash != m_authTokenHash)
        {
            return "ERR old token mismatch";
        }

        m_authTokenHash = toLowerAscii(newHash);
    }

    persistState();
    Logger::warning("PGS: auth token updated in-memory and persisted");
    return "OK token updated";
}

std::string PGS::handleList()
{
    std::lock_guard<std::mutex> lock(m_guardsMutex);
    std::ostringstream oss;
    oss << "OK count=" << m_guards.size();
    for (const auto &entry : m_guards)
    {
        const auto policyIt = m_policyByGuardId.find(entry.second.guardId);
        const int restartCount = (policyIt == m_policyByGuardId.end()) ? 0 : policyIt->second.restartCount;
        oss << "\n" << makeGuardSummaryLine(entry.second, restartCount);
    }
    return oss.str();
}

std::string PGS::handleGet(DWORD pid)
{
    std::lock_guard<std::mutex> lock(m_guardsMutex);
    const auto it = m_guards.find(pid);
    if (it == m_guards.end())
    {
        return "ERR pid not found";
    }
    const auto policyIt = m_policyByGuardId.find(it->second.guardId);
    const int restartCount = (policyIt == m_policyByGuardId.end()) ? 0 : policyIt->second.restartCount;
    return "OK\n" + makeGuardSummaryLine(it->second, restartCount);
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
    const std::string text = trim(value);
    if (text.empty())
    {
        return false;
    }
    for (char c : text)
    {
        if (c < '0' || c > '9')
        {
            return false;
        }
    }
    try
    {
        outPid = static_cast<DWORD>(std::stoul(text));
        return outPid != 0;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

bool PGS::parseMaxRestarts(const std::string &value, int &outMaxRestarts)
{
    const std::string text = trim(value);
    if (text == "no")
    {
        outMaxRestarts = -1;
        return true;
    }
    if (text.empty())
    {
        return false;
    }
    try
    {
        const int parsed = std::stoi(text);
        if (parsed < 0)
        {
            return false;
        }
        outMaxRestarts = parsed;
        return true;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

std::string PGS::maxRestartsLabel(int maxRestarts)
{
    if (maxRestarts < 0)
    {
        return "no";
    }
    return std::to_string(maxRestarts);
}

std::vector<std::string> PGS::splitByChar(const std::string &value, char delimiter)
{
    std::vector<std::string> parts;
    std::string current;
    for (char ch : value)
    {
        if (ch == delimiter)
        {
            parts.push_back(current);
            current.clear();
        }
        else
        {
            current.push_back(ch);
        }
    }
    parts.push_back(current);
    return parts;
}

std::string PGS::base64Encode(const std::string &input)
{
    std::string output;
    int val = 0;
    int valb = -6;
    for (unsigned char c : input)
    {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0)
        {
            output.push_back(kBase64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6)
    {
        output.push_back(kBase64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (output.size() % 4 != 0)
    {
        output.push_back('=');
    }
    return output;
}

bool PGS::computeFileHash(const std::string &path, std::string &outHash)
{
    const std::wstring pathW = utf8ToWide(path);
    if (pathW.empty())
    {
        return false;
    }

    HANDLE file = CreateFileW(pathW.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    std::uint64_t hash = kFnvOffset;
    char buffer[8192];
    DWORD readBytes = 0;
    while (ReadFile(file, buffer, static_cast<DWORD>(sizeof(buffer)), &readBytes, nullptr) && readBytes > 0)
    {
        for (DWORD i = 0; i < readBytes; ++i)
        {
            const unsigned char byte = static_cast<unsigned char>(buffer[i]);
            hash ^= byte;
            hash *= kFnvPrime;
        }
    }
    CloseHandle(file);

    std::ostringstream oss;
    oss << std::hex << std::nouppercase << std::setw(16) << std::setfill('0') << hash;
    outHash = oss.str();
    return true;
}

bool PGS::queryProcessPath(DWORD pid, std::string &outPath)
{
    // QueryFullProcessImageNameW gives the service its own source of truth for
    // the image path, which is later used for register validation and restarts.
    outPath.clear();
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!processHandle)
    {
        return false;
    }

    std::vector<wchar_t> buffer(32768, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    const BOOL ok = QueryFullProcessImageNameW(processHandle, 0, buffer.data(), &size);
    CloseHandle(processHandle);
    if (!ok || size == 0)
    {
        return false;
    }

    outPath = wideToUtf8(std::wstring(buffer.data(), buffer.data() + size));
    return !outPath.empty();
}

bool PGS::recvMessage(SOCKET socket, std::string &payload)
{
    payload.clear();
    bool sawData = false;
    char buffer[kBufferSize];

    for (;;)
    {
        const int received = recv(socket, buffer, static_cast<int>(sizeof(buffer)), 0);
        if (received == 0)
        {
            return sawData;
        }
        if (received < 0)
        {
            return false;
        }

        sawData = true;
        payload.append(buffer, static_cast<std::size_t>(received));

        // Management protocol messages are line oriented. We stop at the first
        // newline and reject messages that grow beyond a conservative upper
        // bound to avoid memory abuse and accidental truncation bugs.
        if (payload.size() > kMaxMessageSize)
        {
            return false;
        }

        const std::size_t newlinePos = payload.find('\n');
        if (newlinePos != std::string::npos)
        {
            payload.resize(newlinePos);
            return true;
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

std::string PGS::makeGuardSummaryLine(const GuardInfo &guard, int restartCount)
{
    const bool alive = (guard.handle && WaitForSingleObject(guard.handle, 0) == WAIT_TIMEOUT);
    std::ostringstream oss;
    oss << "PID=" << guard.pid
        << ";SESSION=" << guard.sessionId
        << ";ALIVE=" << (alive ? "1" : "0")
        << ";INTENTIONAL=" << (guard.intentional ? "1" : "0")
        << ";MAX_RESTARTS=" << maxRestartsLabel(guard.maxRestarts)
        << ";RESTART_COUNT=" << restartCount
        << ";HASH_VERIFIED=" << (guard.hashVerified ? "1" : "0")
        << ";HASH=" << (guard.fileHash.empty() ? "-" : guard.fileHash)
        << ";PATH_B64=" << base64Encode(guard.path)
        << ";RESTART_ARGS_B64=" << base64Encode(guard.restartArgs);
    return oss.str();
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

bool PGS::stripAuthEnvelope(const std::string &message, std::string &commandLine) const
{
    // Authentication is deliberately simple: the client sends the clear-text
    // token on the local management socket, while the service only stores and
    // compares a hash in memory. The command line that leaves this function is
    // always the auth-free payload understood by processMessage().
    commandLine = trim(message);
    if (commandLine.empty())
    {
        return false;
    }
    if (!m_requireAuth)
    {
        return true;
    }

    if (commandLine.rfind("token ", 0) != 0)
    {
        return false;
    }

    const std::size_t tokenStart = 6;
    const std::size_t tokenEnd = commandLine.find(' ', tokenStart);
    if (tokenEnd == std::string::npos)
    {
        return false;
    }

    const std::string token = commandLine.substr(tokenStart, tokenEnd - tokenStart);
    const std::string inputHash = hashToken(token);
    std::lock_guard<std::mutex> lock(m_authMutex);
    if (inputHash != m_authTokenHash)
    {
        return false;
    }

    commandLine = trim(commandLine.substr(tokenEnd + 1));
    return !commandLine.empty();
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

} // namespace ProcessGuard
