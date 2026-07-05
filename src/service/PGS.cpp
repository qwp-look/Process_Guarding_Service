#include "Process_Guard/PGS.h"

#include <ws2tcpip.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <shellapi.h>
#include <objbase.h>
#include <initguid.h>
#include <shobjidl.h>

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
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#endif


namespace
{
// File-local helpers: only the few that are NOT in ProcessGuard::util live here
// (numeric/bool parsing and the WTS session-token helper). Encoding, hashing,
// path/process and string helpers now come from Process_Guard/PGUtil.h.

constexpr const char *kRestartIndexToken = "${PGS_RESTART_INDEX}";
constexpr int kStateFileVersion = 3;     // v3: advanced guard policy + WindowsApps
constexpr int kLegacyStateFileVersion = 2;
// Per-guard Job Object naming. The "Global\" kernel namespace requires
// SeCreateGlobalPrivilege (held by LocalSystem / Administrators), which is why
// the default service account must stay LocalSystem for full-cascade to work.
constexpr const char *kJobNamePrefix = "Global\\PGS-Job-";
constexpr const char *kModulesAllowlistFile = "modules.allow";

// Enable a named privilege on the current process token (best-effort: ok if the
// privilege is absent, only fail if it cannot be enabled when present). Returns
// true if the privilege is enabled afterwards.
#ifndef SE_TCB_NAME_W
#define SE_TCB_NAME_W L"SeTcbPrivilege"
#endif
bool enableProcessPrivilege(LPCWSTR privName)
{
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok) || !tok)
    {
        return false;
    }
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, privName, &luid))
    {
        CloseHandle(tok);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    const DWORD err = GetLastError();
    CloseHandle(tok);
    return ok && err == ERROR_SUCCESS;
}

// Obtain the user token for a WTS session. WTSQueryUserToken requires the
// SE_TCB_NAME privilege, which LocalSystem holds natively but an elevated
// admin process holds disabled-by-default. We therefore enable SE_TCB on the
// current token (no-op when already enabled) and retry once on first failure.
bool queryUserTokenForSession(DWORD sessionId, HANDLE &userToken)
{
    userToken = nullptr;
    if (sessionId == 0xFFFFFFFF)
    {
        return false;
    }
    if (WTSQueryUserToken(sessionId, &userToken))
    {
        return true;
    }
    // Retry after enabling SE_TCB_NAME (covers elevated-admin `run` mode; the
    // privilege exists in the token but starts disabled).
    enableProcessPrivilege(SE_TCB_NAME_W);
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
    // v3: gate the allowlist. m_modulesPermissive was restored from the archive
    // above (MODULES_PERMISSIVE) or left false; push it to the registry so the
    // permissive escape hatch applies during this loadFromDirectory() scan.
    m_modules.setPermissive(m_modulesPermissive);
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

    // v3: single IOCP shared by all per-guard Job Objects. Created BEFORE
    // restorePersistedGuards() so re-attached/restarted guards can bind their
    // job completion port to it at job-creation time.
    m_ioPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0);
    if (!m_ioPort)
    {
        Logger::warning("PGS: IOCP creation failed, will fall back to polling only, error=" + std::to_string(GetLastError()));
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
    std::uint16_t archivedServerPort = 0;
    bool archivedModulesPermissive = false;
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

        if (fields[0] == "SERVER_PORT")
        {
            if (fields.size() >= 2)
            {
                DWORD sp = 0;
                if (parseDwordValue(fields[1], sp) && sp > 0)
                {
                    archivedServerPort = static_cast<std::uint16_t>(sp);
                }
            }
            continue;
        }

        if (fields[0] == "MODULES_PERMISSIVE")
        {
            if (fields.size() >= 2)
            {
                bool b = false;
                if (parseBoolFlag(fields[1], b))
                {
                    archivedModulesPermissive = b;
                }
            }
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

            // v3 advanced guard-policy fields (trailing the v2 base). Older
            // archives that stop at field[9] get the legacy defaults here.
            {
                DWORD dv = 0;
                if (fields.size() > 12 && parseDwordValue(fields[12], dv))
                {
                    persisted.restartWindowSec = static_cast<int>(dv);
                }
                if (fields.size() > 13 && parseDwordValue(fields[13], dv))
                {
                    persisted.restartDelayMs = static_cast<int>(dv);
                }
                if (fields.size() > 15 && parseDwordValue(fields[15], dv))
                {
                    persisted.hangTimeoutMs = static_cast<int>(dv);
                }
            }
            if (fields.size() > 10)
            {
                const std::string aks = trim(fields[10]);
                if (aks == "1" || aks == "winapp" || aks == "uwp" || aks == "store")
                {
                    persisted.appKind = AppKind::WinApp;
                }
            }
            if (fields.size() > 11 && fields[11] != "-")
            {
                persisted.aumid = base64Decode(fields[11]);
            }
            if (fields.size() > 14)
            {
                const std::string bv = trim(fields[14]);
                persisted.backoff = (bv == "1" || bv == "true" || bv == "yes");
            }
            if (fields.size() > 16)
            {
                const std::string bv = trim(fields[16]);
                persisted.killOnExit = (bv == "1" || bv == "true" || bv == "yes");
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
        // Migration: the v3 archive only ADDS trailing fields over v2, so v1 and
        // v2 are forward-compatible. v1's FNV-1a token hash is not trusted under
        // SHA-256 auth, so we drop only the auth hash (initialize() will mint a
        // fresh random token) while KEEPING guard records for SCM-restart
        // recovery. v2 already has the SHA-256 hash; its guards parsed with the
        // advanced-policy defaults above. The next persistState() rewrites at v3.
        if (version == 1)
        {
            Logger::warning("PGS: migrating state file v1 -> v3 (guard records kept, auth token reset)");
            persistedAuthHash.clear();
        }
        else if (version == kLegacyStateFileVersion)
        {
            Logger::warning("PGS: migrating state file v2 -> v3 (guard records kept, advanced policy defaulted)");
        }
        else
        {
            Logger::warning("PGS: unsupported state file version " + std::to_string(version) + ", ignoring persisted archive");
            m_persistedGuards.clear();
            m_nextGuardId = 1ull;
            return false;
        }
    }

    m_persistedGuards = std::move(parsedGuards);
    m_nextGuardId = std::max<std::uint64_t>(1ull, nextGuardId);
    {
        std::lock_guard<std::mutex> authLock(m_authMutex);
        // Accept a persisted auth hash at v2/v3. An empty hash here makes
        // initialize() generate a fresh random token.
        m_authTokenHash = persistedAuthHash;
    }

    // v3: restore the archived listen port only when the host has not
    // explicitly overridden it (here: m_serverPort still at the default). The
    // module-permissive flag gates the ModuleManager allowlist (see E).
    if (m_serverPort == kServerPort && archivedServerPort != 0)
    {
        m_serverPort = archivedServerPort;
    }
    m_modulesPermissive = archivedModulesPermissive;

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
    out << "SERVER_PORT\t" << m_serverPort << "\n";
    out << "MODULES_PERMISSIVE\t" << (m_modulesPermissive ? "1" : "0") << "\n";
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
            << (guard.hashVerified ? "1" : "0") << "\t"
            << (guard.appKind == AppKind::WinApp ? "winapp" : "win32") << "\t"
            << (guard.aumid.empty() ? "-" : base64Encode(guard.aumid)) << "\t"
            << guard.restartWindowSec << "\t"
            << guard.restartDelayMs << "\t"
            << (guard.backoff ? "1" : "0") << "\t"
            << guard.hangTimeoutMs << "\t"
            << (guard.killOnExit ? "1" : "0") << "\n";
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
        persisted.guardId,
        persisted.appKind,
        persisted.aumid,
        persisted.restartWindowSec,
        persisted.restartDelayMs,
        persisted.backoff,
        persisted.hangTimeoutMs,
        persisted.killOnExit,
        nullptr};
    // v3: reopen (or create) the survivor's per-guard Job so monitoring of the
    // whole process family resumes after a service crash.
    assignGuardToJob(outGuard);
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
            m_policyByGuardId[restored.guardId] = RestartPolicyState{persisted.maxRestarts, 0, {}};
            auto it = m_persistedGuards.find(restored.guardId);
            if (it != m_persistedGuards.end())
            {
                it->second.lastKnownPid = restored.pid;
                it->second.sessionId = restored.sessionId;
                it->second.path = restored.path;
                it->second.appKind = restored.appKind;
                it->second.aumid = restored.aumid;
                it->second.restartWindowSec = restored.restartWindowSec;
                it->second.restartDelayMs = restored.restartDelayMs;
                it->second.backoff = restored.backoff;
                it->second.hangTimeoutMs = restored.hangTimeoutMs;
                it->second.killOnExit = restored.killOnExit;
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
            persisted.guardId,
            persisted.appKind,
            persisted.aumid,
            persisted.restartWindowSec,
            persisted.restartDelayMs,
            persisted.backoff,
            persisted.hangTimeoutMs,
            persisted.killOnExit,
            nullptr};

        GuardInfo restarted;
        if (restartGuard(desired, 0, restarted))
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            m_guards[restarted.pid] = restarted;
            // v3: assign the freshly restarted process to its per-guard Job.
            assignGuardToJob(m_guards[restarted.pid]);
            m_policyByGuardId[restarted.guardId] = RestartPolicyState{persisted.maxRestarts, 0, {}};
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
            stored.appKind = restarted.appKind;
            stored.aumid = restarted.aumid;
            stored.restartWindowSec = restarted.restartWindowSec;
            stored.restartDelayMs = restarted.restartDelayMs;
            stored.backoff = restarted.backoff;
            stored.hangTimeoutMs = restarted.hangTimeoutMs;
            stored.killOnExit = restarted.killOnExit;
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
    // 1. fire deferred (backoff/delay) restarts whose delay has elapsed
    // 2. drain the shared IOCP so process/family exits wake us within ~50ms
    //    (IOCP is the fast wake path; the handle poll below is the backstop)
    // 3. scan the live guard map for dead handles (+ optional GUI hang probe)
    // 4. for newly-dead guards, decide restart under sliding-window policy
    // 5. either relaunch+reattach (and reassign its per-guard Job) or retire
    //
    // All restart/create work runs outside m_guardsMutex so a slow CreateProcess
    // cannot block list/get/register requests.
    struct PendingRestart
    {
        GuardInfo guard;
        int restartIndex;
        std::chrono::steady_clock::time_point readyAt;
    };
    std::vector<PendingRestart> pending;

    while (m_running.load())
    {
        const auto now = std::chrono::steady_clock::now();

        // Fire deferred restarts whose backoff/delay has elapsed.
        for (auto pit = pending.begin(); pit != pending.end();)
        {
            if (pit->readyAt > now)
            {
                ++pit;
                continue;
            }
            GuardInfo restarted;
            if (restartGuard(pit->guard, pit->restartIndex, restarted))
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    auto existingNew = m_guards.find(restarted.pid);
                    if (existingNew != m_guards.end() && existingNew->second.handle)
                    {
                        CloseHandle(existingNew->second.handle);
                    }
                    m_guards[restarted.pid] = restarted;
                    assignGuardToJob(m_guards[restarted.pid]);
                    auto &persisted = m_persistedGuards[restarted.guardId];
                    persisted.guardId = restarted.guardId;
                    persisted.lastKnownPid = restarted.pid;
                    persisted.sessionId = restarted.sessionId;
                    persisted.path = restarted.path;
                    persisted.maxRestarts = restarted.maxRestarts;
                    persisted.restartArgs = restarted.restartArgs;
                    persisted.fileHash = restarted.fileHash;
                    persisted.intentional = false;
                    persisted.hashVerified = restarted.hashVerified;
                    persisted.appKind = restarted.appKind;
                    persisted.aumid = restarted.aumid;
                    persisted.restartWindowSec = restarted.restartWindowSec;
                    persisted.restartDelayMs = restarted.restartDelayMs;
                    persisted.backoff = restarted.backoff;
                    persisted.hangTimeoutMs = restarted.hangTimeoutMs;
                    persisted.killOnExit = restarted.killOnExit;
                }
                persistState();
                Logger::warning("PGS: auto-attached restarted guard pid=" + std::to_string(restarted.pid));
            }
            else
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    m_policyByGuardId.erase(pit->guard.guardId);
                    auto persisted = m_persistedGuards.find(pit->guard.guardId);
                    if (persisted != m_persistedGuards.end())
                    {
                        persisted->second.lastKnownPid = 0;
                    }
                }
                persistState();
                Logger::error("PGS: restart failed permanently, guard removed path=" + pit->guard.path);
            }
            if (pit->guard.handle)
            {
                CloseHandle(pit->guard.handle);
            }
            pit = pending.erase(pit);
        }

        // IOCP fast wake: consume one completion (50ms cap) so a fresh exit
        // notification short-circuits the wait; the poll below is still the
        // authoritative liveness source.
        if (m_ioPort)
        {
            DWORD code = 0;
            ULONG_PTR key = 0;
            LPOVERLAPPED ov = nullptr;
            GetQueuedCompletionStatus(m_ioPort, &code, &key, &ov, 50);
            (void)code;
            (void)key;
            (void)ov;
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        std::vector<GuardInfo> deadGuards;
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            for (auto it = m_guards.begin(); it != m_guards.end();)
            {
                if (isGuardAlive(it->second))
                {
                    if (it->second.hangTimeoutMs > 0 && isGuardHung(it->second))
                    {
                        Logger::warning("PGS: guard hung (unresponsive GUI), pid=" +
                                        std::to_string(it->second.pid) +
                                        ", hang-timeout=" + std::to_string(it->second.hangTimeoutMs) + "ms");
                        terminateGuardFamily(it->second.guardId);
                        deadGuards.push_back(it->second);
                        it = m_guards.erase(it);
                        continue;
                    }
                    ++it;
                    continue;
                }

                deadGuards.push_back(it->second);
                it = m_guards.erase(it);
            }
        }

        // Process restart decisions outside the main guard map lock so creating
        // processes / waiting on system APIs cannot block register/list/get.
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
                closeGuardJob(guard.guardId);
                persistState();
                Logger::warning("PGS: guard exited intentionally, pid=" + std::to_string(guard.pid));
                continue;
            }

            bool shouldRestart = true;
            int currentRestarts = 0;
            int maxRestarts = guard.maxRestarts;
            const int windowSec = guard.restartWindowSec;
            const bool windowed = (windowSec > 0);
            {
                std::lock_guard<std::mutex> lock(m_guardsMutex);
                auto &policy = m_policyByGuardId[guard.guardId];
                if (policy.maxRestarts != guard.maxRestarts)
                {
                    policy.maxRestarts = guard.maxRestarts;
                }
                if (windowed)
                {
                    const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    policy.recentRestartMs = util::pruneRestartWindow(policy.recentRestartMs, nowMs, windowSec);
                    currentRestarts = static_cast<int>(policy.recentRestartMs.size());
                }
                else
                {
                    currentRestarts = policy.restartCount;
                }
                maxRestarts = policy.maxRestarts;
                shouldRestart = !(policy.maxRestarts >= 0 && currentRestarts >= policy.maxRestarts);
            }

            if (!shouldRestart)
            {
                Logger::warning("PGS: guard restart limit reached, path=" + guard.path +
                                ", max=" + maxRestartsLabel(maxRestarts) +
                                (windowed ? " (sliding window)" : ""));
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
                closeGuardJob(guard.guardId);
                persistState();
                continue;
            }

            // Terminate the whole family (orphan/child processes) before
            // relaunching so a crash-looping parent cannot leave ghosts behind.
            terminateGuardFamily(guard.guardId);

            const int restartIndex = currentRestarts + 1;
            int delayMs = guard.restartDelayMs;
            if (guard.backoff)
            {
                delayMs = util::computeBackoffDelay(guard.restartDelayMs, restartIndex);
            }

            // Record the restart now; if relaunch fails below, policy is retired
            // and the recorded timestamp/count is effectively discarded.
            {
                std::lock_guard<std::mutex> lock(m_guardsMutex);
                auto &policy = m_policyByGuardId[guard.guardId];
                if (windowed)
                {
                    const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    policy.recentRestartMs.push_back(nowMs);
                    policy.recentRestartMs = util::pruneRestartWindow(policy.recentRestartMs, nowMs, windowSec);
                }
                else
                {
                    ++policy.restartCount;
                }
                currentRestarts = windowed ? static_cast<int>(policy.recentRestartMs.size()) : policy.restartCount;
            }

            Logger::warning("PGS: guard died unexpectedly, pid=" + std::to_string(guard.pid) +
                            (guard.appKind == AppKind::WinApp ? " (winapp)" : ""));
            Logger::warning("PGS: restart count " + std::to_string(currentRestarts) + "/" +
                            maxRestartsLabel(maxRestarts) +
                            ", path=" + guard.path +
                            ", app-kind=" + (guard.appKind == AppKind::WinApp ? "winapp" : "win32") +
                            (delayMs > 0 ? ", delay=" + std::to_string(delayMs) + "ms" : ""));

            if (delayMs > 0)
            {
                // Defer the relaunch so backoff/delay cannot stall monitoring of
                // other guards. The dead pid handle is kept in the pending copy
                // and closed when the deferred relaunch fires.
                const auto readyAt = std::chrono::steady_clock::now() + std::chrono::milliseconds(delayMs);
                pending.push_back({guard, restartIndex, readyAt});
                continue;
            }

            GuardInfo newGuard;
            if (restartGuard(guard, restartIndex, newGuard))
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    auto existingNew = m_guards.find(newGuard.pid);
                    if (existingNew != m_guards.end() && existingNew->second.handle)
                    {
                        CloseHandle(existingNew->second.handle);
                    }
                    m_guards[newGuard.pid] = newGuard;
                    assignGuardToJob(m_guards[newGuard.pid]);
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
                    persisted.appKind = newGuard.appKind;
                    persisted.aumid = newGuard.aumid;
                    persisted.restartWindowSec = newGuard.restartWindowSec;
                    persisted.restartDelayMs = newGuard.restartDelayMs;
                    persisted.backoff = newGuard.backoff;
                    persisted.hangTimeoutMs = newGuard.hangTimeoutMs;
                    persisted.killOnExit = newGuard.killOnExit;
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
    // v3: WindowsApps (UWP/Store) cannot be (re)launched with CreateProcessW*
    // — they must be activated through their AUMID. Route the whole restart to
    // restartAppGuard (it impersonates the user session and shell-activates the
    // app, returning the new pid/handle).
    if (info.appKind == AppKind::WinApp && !info.aumid.empty())
    {
        return restartAppGuard(info, restartIndex, newGuard);
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
        info.guardId,
        info.appKind,
        info.aumid,
        info.restartWindowSec,
        info.restartDelayMs,
        info.backoff,
        info.hangTimeoutMs,
        info.killOnExit,
        nullptr};

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
        info.guardId,
        info.appKind,
        info.aumid,
        info.restartWindowSec,
        info.restartDelayMs,
        info.backoff,
        info.hangTimeoutMs,
        info.killOnExit,
        nullptr};

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
    serverAddr.sin_port = htons(m_serverPort);
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
    // v3: release all per-guard Job Objects and the shared IOCP.
    {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        for (auto &kv : m_jobs)
        {
            if (kv.second)
            {
                CloseHandle(kv.second);
            }
        }
        m_jobs.clear();
    }
    if (m_ioPort)
    {
        CloseHandle(m_ioPort);
        m_ioPort = nullptr;
    }
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
// ---- v3 Job Object / cascade / WindowsApps helpers ---------------------------

bool PGS::createGuardJob(std::uint64_t guardId, bool killOnExit, HANDLE &outJob)
{
    // A named job Global\PGS-Job-<guardId> groups one guarded process and all
    // of its descendants. Breakaway is NOT enabled, so child/grandchild
    // processes stay in the job and TerminateJobObject can clear the whole
    // family on restart. The "Global\" namespace needs SeCreateGlobalPrivilege
    // (LocalSystem/Administrators), which is why cascade requires LocalSystem.
    outJob = nullptr;
    const std::wstring name = utf8ToWide(std::string(kJobNamePrefix) + std::to_string(guardId));
    HANDLE job = CreateJobObjectW(nullptr, name.c_str());
    if (!job)
    {
        Logger::warning("PGS: CreateJobObjectW failed guard-id=" + std::to_string(guardId) +
                        ", error=" + std::to_string(GetLastError()));
        return false;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli{};
    eli.BasicLimitInformation.LimitFlags = killOnExit ? JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE : 0;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &eli, sizeof(eli)))
    {
        Logger::warning("PGS: SetInformationJobObject(limit) failed guard-id=" + std::to_string(guardId) +
                        ", error=" + std::to_string(GetLastError()));
    }
    if (m_ioPort)
    {
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT acp{};
        acp.CompletionPort = m_ioPort;
        acp.CompletionKey = reinterpret_cast<PVOID>(static_cast<uintptr_t>(guardId));
        if (!SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &acp, sizeof(acp)))
        {
            Logger::warning("PGS: job completion-port bind failed guard-id=" + std::to_string(guardId) +
                            ", error=" + std::to_string(GetLastError()));
        }
    }
    outJob = job;
    return true;
}

bool PGS::attachGuardJob(std::uint64_t guardId, HANDLE &outJob)
{
    // Reopen a survivor job (the process still running after a PGS crash) so we
    // resume observing it. Returns false if the named job is gone (e.g. the
    // process was never in a job, or the kernel object was already released).
    outJob = nullptr;
    const std::wstring name = utf8ToWide(std::string(kJobNamePrefix) + std::to_string(guardId));
    HANDLE job = OpenJobObjectW(JOB_OBJECT_ALL_ACCESS, FALSE, name.c_str());
    if (!job)
    {
        return false;
    }
    outJob = job;
    return true;
}

bool PGS::assignGuardToJob(GuardInfo &guard)
{
    // Reuse an existing job for this guardId, else reopen a survivor job, else
    // create a fresh one; then assign the live process into it. On any failure
    // we leave guard.jobHandle null - poll-based exit detection still works, we
    // just lose cascade observe/terminate for this guard.
    if (!guard.handle || guard.guardId == 0)
    {
        return false;
    }
    HANDLE job = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        auto it = m_jobs.find(guard.guardId);
        if (it != m_jobs.end())
        {
            job = it->second;
        }
    }
    if (!job)
    {
        HANDLE reopened = nullptr;
        if (attachGuardJob(guard.guardId, reopened) && reopened)
        {
            job = reopened;
        }
        else
        {
            if (reopened)
            {
                CloseHandle(reopened);
                reopened = nullptr;
            }
            if (!createGuardJob(guard.guardId, guard.killOnExit, job))
            {
                return false;
            }
        }
        {
            std::lock_guard<std::mutex> lock(m_jobMutex);
            m_jobs[guard.guardId] = job;
        }
    }
    if (!AssignProcessToJobObject(job, guard.handle))
    {
        // Common cause: the process is already in an incompatible job, or a
        // permission shortfall. Guarding continues via polling.
        Logger::warning("PGS: AssignProcessToJobObject failed guard-id=" + std::to_string(guard.guardId) +
                        ", pid=" + std::to_string(guard.pid) +
                        ", error=" + std::to_string(GetLastError()));
        return false;
    }
    guard.jobHandle = job;
    return true;
}

void PGS::terminateGuardFamily(std::uint64_t guardId)
{
    // Kill every process in this guard's job (the guarded process plus all
    // descendant/orphan processes still attached) so a relaunch starts clean.
    std::lock_guard<std::mutex> lock(m_jobMutex);
    const auto it = m_jobs.find(guardId);
    if (it == m_jobs.end() || !it->second)
    {
        return;
    }
    if (!TerminateJobObject(it->second, 1))
    {
        Logger::warning("PGS: TerminateJobObject failed guard-id=" + std::to_string(guardId) +
                        ", error=" + std::to_string(GetLastError()));
    }
}

void PGS::closeGuardJob(std::uint64_t guardId)
{
    std::lock_guard<std::mutex> lock(m_jobMutex);
    const auto it = m_jobs.find(guardId);
    if (it != m_jobs.end())
    {
        if (it->second)
        {
            CloseHandle(it->second);
        }
        m_jobs.erase(it);
    }
}

bool PGS::isGuardHung(const GuardInfo &info) const
{
    // Probe each visible top-level window owned by the guard's pid with
    // SendMessageTimeout(WM_NULL); any timeout >= hangTimeoutMs flags the
    // guard as hung. Non-GUI guards have no such window and report false, so
    // this never false-triggers on background workers. Reliable mainly when
    // PGS runs in the interactive session (a Session 0 service can see
    // cross-session ACCESS_DENIED instead of a clean timeout).
    if (info.hangTimeoutMs <= 0 || !info.handle)
    {
        return false;
    }
    struct Ctx
    {
        DWORD pid;
        DWORD timeoutMs;
        bool hung;
    };
    Ctx ctx{info.pid, static_cast<DWORD>(info.hangTimeoutMs), false};
    auto enumProc = [](HWND hwnd, LPARAM lp) -> BOOL
    {
        auto *c = reinterpret_cast<Ctx *>(lp);
        DWORD wpid = 0;
        GetWindowThreadProcessId(hwnd, &wpid);
        if (wpid != c->pid)
        {
            return TRUE;
        }
        if (!IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != nullptr)
        {
            return TRUE;
        }
        DWORD_PTR res = 0;
        const LRESULT r = SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, SMTO_ABORTIFHUNG | SMTO_BLOCK, c->timeoutMs, &res);
        if (r == 0)
        {
            const DWORD err = GetLastError();
            if (err == ERROR_TIMEOUT || err == ERROR_ACCESS_DENIED)
            {
                c->hung = true;
                return FALSE; // stop enumerating; we have our answer
            }
        }
        return TRUE;
    };
    EnumWindows(enumProc, reinterpret_cast<LPARAM>(&ctx));
    return ctx.hung;
}

bool PGS::restartAppGuard(const GuardInfo &info, int restartIndex, GuardInfo &newGuard)
{
    // Activate a WindowsApps (UWP/Store) guard via its AUMID. The primary path is
    // IApplicationActivationManager::ActivateApplication (the documented Start-menu
    // activation entry), which returns the real packaged app pid so we can keep a
    // handle for liveness watching. We impersonate the original user token so a
    // Session 0 service lands the app in the interactive session. ShellExecuteExW
    // with "shell:AppsFolder\<AUMID>" is the fallback when COM activation is
    // unavailable; the broker there rarely yields a usable hProcess.
    if (info.aumid.empty())
    {
        Logger::error("PGS: winapp restart refused, missing AUMID, path=" + info.path);
        return false;
    }

    HANDLE userToken = nullptr;
    DWORD targetSessionId = info.sessionId;
    // When PGS itself runs inside the target session (console `run` mode under an
    // interactive admin), it already holds that session's user token and we can
    // clone it directly -- no SE_TCB_NAME required (that privilege is granted
    // only to LocalSystem, which an elevated admin token does NOT carry, so
    // WTSQueryUserToken would always fail here). WTSQueryUserToken remains the
    // path for the Session-0 service case below.
    DWORD mySession = 0xFFFFFFFF;
    ProcessIdToSessionId(GetCurrentProcessId(), &mySession);
    if (mySession != 0xFFFFFFFF && mySession == targetSessionId)
    {
        OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &userToken);
    }
    if (!userToken && !queryUserTokenForSession(targetSessionId, userToken))
    {
        const DWORD activeSession = WTSGetActiveConsoleSessionId();
        if (mySession != 0xFFFFFFFF && mySession == activeSession)
        {
            OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &userToken);
        }
        if (!userToken && !queryUserTokenForSession(activeSession, userToken))
        {
            Logger::error("PGS: winapp restart failed, no user token for any session, aumid=" + info.aumid);
            return false;
        }
        targetSessionId = activeSession;
    }
    HANDLE primaryToken = nullptr;
    if (!DuplicateTokenEx(userToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenImpersonation, &primaryToken))
    {
        CloseHandle(userToken);
        Logger::error("PGS: winapp restart failed, DuplicateTokenEx error=" + std::to_string(GetLastError()));
        return false;
    }
    CloseHandle(userToken);
    // Impersonation-token form: ActivateApplication runs under the thread token;
    // we do NOT set TokenSessionId (that is a primary-token concern for
    // CreateProcessAsUser, which this winapp path never uses).

    std::string argsUtf8 = info.restartArgs;
    if (!argsUtf8.empty())
    {
        argsUtf8 = replaceAll(argsUtf8, kRestartIndexToken, std::to_string(restartIndex));
    }
    const std::wstring aumidW = utf8ToWide(info.aumid);
    const std::wstring argsW = utf8ToWide(argsUtf8);

    bool ok = false;
    DWORD activatedPid = 0;
    HANDLE procHandle = nullptr;

    if (!SetThreadToken(nullptr, primaryToken))
    {
        CloseHandle(primaryToken);
        Logger::error("PGS: winapp restart failed, SetThreadToken error=" + std::to_string(GetLastError()));
        return false;
    }

    HRESULT comInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool comInited = (SUCCEEDED(comInit) || comInit == RPC_E_CHANGED_MODE);
    if (comInited)
    {
        IApplicationActivationManager *act = nullptr;
        HRESULT hr = CoCreateInstance(CLSID_ApplicationActivationManager, nullptr,
                                      CLSCTX_LOCAL_SERVER | CLSCTX_NO_FAILURE_LOG,
                                      IID_PPV_ARGS(&act));
        if (SUCCEEDED(hr) && act)
        {
            hr = act->ActivateApplication(aumidW.c_str(),
                                          (argsW.empty() ? L"" : argsW.c_str()),
                                          AO_NONE, &activatedPid);
            if (SUCCEEDED(hr) && activatedPid != 0)
            {
                procHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                          FALSE, activatedPid);
                ok = (procHandle != nullptr);
                if (!ok)
                {
                    Logger::warning("PGS: winapp ActivateApplication ok pid=" + std::to_string(activatedPid) +
                                    " but OpenProcess failed error=" + std::to_string(GetLastError()) +
                                    ", aumid=" + info.aumid);
                    activatedPid = 0;
                }
            }
            else
            {
                Logger::warning("PGS: ActivateApplication hr=0x" +
                                std::to_string(static_cast<unsigned long>(hr)) +
                                " pid=" + std::to_string(activatedPid) +
                                ", aumid=" + info.aumid);
            }
            act->Release();
        }
        else
        {
            Logger::warning("PGS: CoCreateInstance(ApplicationActivationManager) hr=0x" +
                            std::to_string(static_cast<unsigned long>(hr)) +
                            ", falling back to ShellExecute, aumid=" + info.aumid);
        }
        if (comInit == S_OK || comInit == S_FALSE)
        {
            CoUninitialize();
        }
    }

    // Fallback: ShellExecuteExW("shell:AppsFolder\<AUMID>"). Broker often does
    // not hand back hProcess, so this is best-effort.
    if (!ok)
    {
        std::wstring file = L"shell:AppsFolder\\" + aumidW;
        std::vector<wchar_t> paramsBuf(argsW.begin(), argsW.end());
        paramsBuf.push_back(L'\0');
        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
        sei.lpFile = file.c_str();
        sei.lpParameters = (argsW.empty() ? nullptr : paramsBuf.data());
        sei.nShow = SW_SHOWNORMAL;
        ok = (ShellExecuteExW(&sei) == TRUE);
        if (ok)
        {
            procHandle = sei.hProcess;
            activatedPid = procHandle ? GetProcessId(procHandle) : 0;
        }
    }

    SetThreadToken(nullptr, nullptr);
    CloseHandle(primaryToken);

    if (!ok || !procHandle || activatedPid == 0)
    {
        Logger::error("PGS: winapp restart failed, aumid=" + info.aumid +
                      ", error=" + std::to_string(GetLastError()));
        if (procHandle)
        {
            CloseHandle(procHandle);
        }
        return false;
    }

    DWORD sessionId = 0xFFFFFFFF;
    ProcessIdToSessionId(activatedPid, &sessionId);
    newGuard = GuardInfo{
        activatedPid,
        sessionId,
        info.path,
        info.maxRestarts,
        info.restartArgs,
        info.fileHash,
        procHandle,
        false,
        info.hashVerified,
        info.guardId,
        AppKind::WinApp,
        info.aumid,
        info.restartWindowSec,
        info.restartDelayMs,
        info.backoff,
        info.hangTimeoutMs,
        info.killOnExit,
        nullptr};
    Logger::warning("PGS: winapp restart activated pid=" + std::to_string(activatedPid) +
                    ", aumid=" + info.aumid);
    return true;
}

int PGS::recordRestartAndEffectiveCount(std::uint64_t /*guardId*/, RestartPolicyState &policy, int windowSec)
{
    const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (windowSec > 0)
    {
        policy.recentRestartMs = util::pruneRestartWindow(policy.recentRestartMs, nowMs, windowSec);
        policy.recentRestartMs.push_back(nowMs);
        return static_cast<int>(policy.recentRestartMs.size());
    }
    ++policy.restartCount;
    return policy.restartCount;
}
} // namespace ProcessGuard
