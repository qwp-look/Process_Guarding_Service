#include "Process_Guard/PGS.h"

#include <ws2tcpip.h>
#include <winhttp.h>
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
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#endif

#include "PGSInternal.h"
namespace ProcessGuard
{

using namespace pgs_internal;

using namespace util; // pull in base64/utf8/hash/path helpers from PGUtil.h

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
    // (SYSTEM + Administrators + current runtime identity) so persisted secrets
    // are not world-readable while console/dev runs can still write their files.
    {
        std::filesystem::path statePath = std::filesystem::path(defaultStateFilePath(logFilePath));
        std::filesystem::path stateDir = statePath.parent_path();
        std::filesystem::path root = stateDir.parent_path();
        if (!root.empty())
        {
            if (!util::secureCreateDirectory(root.string()))
            {
                Logger::warning("PGS: failed to secure data root directory: " + root.string());
            }
        }
        if (!stateDir.empty())
        {
            if (!util::secureCreateDirectory(stateDir.string()))
            {
                Logger::warning("PGS: failed to secure state directory: " + stateDir.string());
            }
        }
        std::filesystem::path logRoot = std::filesystem::path(logFilePath).parent_path();
        if (!logRoot.empty() && logRoot.filename() == "logs")
        {
            if (!util::secureCreateDirectory(logRoot.string()))
            {
                Logger::warning("PGS: failed to secure log directory: " + logRoot.string());
            }
        }
    }

    m_stateFilePath = defaultStateFilePath(logFilePath);
    m_dataDirCache = std::filesystem::path(m_stateFilePath).parent_path().string();
    if (m_dataDirCache.empty())
    {
        m_dataDirCache = ".";
    }
    if (!loadPersistedState())
    {
        Logger::warning("PGS: failed to load persisted state, continuing with empty archive");
    }
    {
        std::lock_guard<std::mutex> lock(m_artifactMutex);
        loadArtifactPolicyLocked();
    }

    m_requireAuth = true;
    const std::string explicitAuthHash = toLowerAscii(trim(authTokenHash));
    if (!explicitAuthHash.empty())
    {
        // Host supplied an explicit (already-hashed) token hash. Accept only
        // SHA-256 hex so an embedding cannot accidentally disable auth with
        // whitespace or a malformed persisted value.
        if (!isSha256Hex(explicitAuthHash))
        {
            Logger::error("PGS: invalid auth token hash supplied by host");
            WSACleanup();
            return false;
        }
        m_authTokenHash = explicitAuthHash;
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
                Logger::error("PGS: refusing to start because bootstrap token file could not be written with a protected ACL");
                m_authTokenHash.clear();
                WSACleanup();
                return false;
            }
        }
        else
        {
            Logger::warning("PGS: auth enabled (token hash restored from persisted state)");
        }
    }

    // Prepare <exe>\modules before marking the service initialised. Module
    // loading is a general opt-in via --enable-modules.
    //
    // P0-03 fail-closed: startup only *audits* the modules tree. It must NOT
    // auto-repair ACLs (that would hide an insecure install). Explicit repair
    // is `pgs_bless doctor repair-modules-acl` only.
    m_modulesDir = moduleDirectoryOfSelf();
    const bool wantModules = m_modulesEnabled || m_modulesPermissive.load();
    if (!m_modulesDir.empty())
    {
        // Create the directory if missing so doctor/load paths have a root, but
        // do not mutate owner/DACL here.
        std::error_code ec;
        std::filesystem::create_directories(m_modulesDir, ec);
    }

    util::ModulesAclAuditResult modulesAclAudit{};
    bool modulesAclOk = false;
    if (wantModules && !m_modulesDir.empty())
    {
        modulesAclAudit = util::auditModulesAcl(m_modulesDir);
        modulesAclOk = modulesAclAudit.ok;
        if (!modulesAclAudit.ok)
        {
            const std::string firstBad = modulesAclAudit.badPaths.empty()
                ? m_modulesDir
                : modulesAclAudit.badPaths.front();
            const std::string detail = "module.acl-insecure;reason=" + modulesAclAudit.reason +
                ";bad_count=" + std::to_string(modulesAclAudit.badPaths.size()) +
                ";path=" + firstBad;
            if (m_modulesPermissive.load())
            {
                Logger::warning("PGS: " + detail + " (permissive mode: continuing with warning; run doctor repair-modules-acl)");
            }
            else
            {
                Logger::error("PGS: " + detail + " (refusing module load; run doctor repair-modules-acl)");
            }
        }
    }
    else if (wantModules && m_modulesDir.empty())
    {
        Logger::error("PGS: module.acl-insecure;reason=modules-root-empty (refusing module load)");
    }

    // v3: gate the allowlist. m_modulesPermissive was restored from the archive
    // above (MODULES_PERMISSIVE) or left false; push it to the registry so the
    // permissive escape hatch applies during this loadFromDirectory() scan.
    // ABI v2: hand modules a services struct so stateful modules (scheduler)
    // can call back into PGS. Built before loadFromDirectory() so every
    // module's PG_Init receives it.
    {
        PGS_ServicesV3 svc{};
        svc.size = static_cast<unsigned int>(sizeof(PGS_ServicesV3));
        svc.context = this;
        svc.call = &PGS::callThunk;
        svc.now_ms = &PGS::nowMsThunk;
        svc.call_json = &PGS::callJsonThunk;
        svc.emit_event = &PGS::emitEventThunk;
        svc.get_data_dir = &PGS::getDataDirThunk;
        svc.log = &PGS::logThunk;
    m_modules.setServices(svc);
    }
    m_modules.setPermissive(m_modulesPermissive.load());
    m_modules.setEnabledModules(std::vector<std::string>{"*"});
    {
        const bool permissive = m_modulesPermissive.load();
        // Production: require clean ACL audit. Permissive: allow load with warning.
        const bool mayLoad = modulesAclOk || permissive;
        if ((m_modulesEnabled || permissive) && mayLoad && !m_modulesDir.empty())
        {
            if (!modulesAclOk && permissive)
            {
                Logger::warning("PGS: loading modules under permissive mode despite ACL audit failure");
            }
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
        else if (m_modulesEnabled || permissive)
        {
            Logger::error("PGS: module loading refused because modules directory ACL audit failed (module.acl-insecure)");
        }
        else
        {
            Logger::warning("PGS: module loading disabled (set --enable-modules to enable module loading)");
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
    m_healthThread = std::thread(&PGS::healthLoop, this);
    m_notifyThread = std::thread(&PGS::notifyLoop, this);

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
    m_healthCv.notify_all();
    m_notifyCv.notify_all();

    if (m_listenerThread.joinable())
    {
        m_listenerThread.join();
    }
    if (m_monitorThread.joinable())
    {
        m_monitorThread.join();
    }
    if (m_healthThread.joinable())
    {
        m_healthThread.join();
    }
    if (m_notifyThread.joinable())
    {
        m_notifyThread.join();
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


std::string PGS::parentDirectory(const std::string &path)
{
    const auto pos = path.find_last_of("\\/");
    if (pos == std::string::npos)
    {
        return std::string();
    }
    return path.substr(0, pos);
}


// Resolve the "modules" directory beside the running pgs_service.exe. Used
// as the plugin scan root. Falls back to a relative "modules" if the exe
// path cannot be determined (should not happen in practice).
// ABI v2 callbacks exposed to modules via PGS_Services.
int PGS::callThunk(void *context, const char *request, char *response, size_t responseSize)
{
    PGS *self = static_cast<PGS *>(context);
    if (!self || !response || responseSize == 0)
    {
        return 1;
    }
    // Module callbacks run in-process after the module itself has passed the
    // allowlist/signature gate, so they do not know or carry the operator token.
    // Keep external TCP auth in processMessage() and route trusted callbacks to
    // the authenticated command dispatcher directly.
    std::string resp = self->dispatchCommandLine(request ? request : "");
    size_t n = resp.size();
    if (n >= responseSize)
    {
        n = responseSize - 1;
    }
    memcpy(response, resp.c_str(), n);
    response[n] = '\0';
    // processMessage always returns an "OK ..."/"ERR ..." string; the rc here
    // signals transport success, not command success (mirrors PGSClient).
    return 0;
}


int PGS::callJsonThunk(void *context, const char *requestJson, char *responseJson, size_t responseSize)
{
    PGS *self = static_cast<PGS *>(context);
    if (!self || !responseJson || responseSize == 0)
    {
        return 1;
    }
    const std::string request = requestJson ? requestJson : "";
    const std::string method = jsonStringValue(request, "method");
    const std::string response = (method.rfind("pgs.", 0) == 0)
        ? self->handleCoreJsonRpc(request)
        : self->handleModuleCommand(std::string("invoke-json ") + request);
    size_t n = response.size();
    if (n >= responseSize)
    {
        n = responseSize - 1;
    }
    memcpy(responseJson, response.c_str(), n);
    responseJson[n] = '\0';
    return 0;
}


int PGS::emitEventThunk(void *context, const char *eventJson)
{
    PGS *self = static_cast<PGS *>(context);
    if (!self)
    {
        return 1;
    }
    const std::string json = eventJson ? eventJson : "";
    const std::string requestedType = jsonStringValue(json, "type");
    const bool safeType = !requestedType.empty() && requestedType.size() <= 96 &&
        std::all_of(requestedType.begin(), requestedType.end(), [](unsigned char ch) {
            return std::isalnum(ch) || ch == '.' || ch == '_' || ch == '-';
        });
    self->recordEvent(safeType ? requestedType : std::string("module.event"),
                      std::string("json_b64=") + util::base64Encode(json));
    return 0;
}

const char *PGS::getDataDirThunk(void *context)
{
    PGS *self = static_cast<PGS *>(context);
    if (!self)
    {
        return "";
    }
    return self->m_dataDirCache.c_str();
}


void PGS::logThunk(void * /*context*/, int level, const char *message)
{
    const std::string text = std::string("PGS module: ") + (message ? message : "");
    if (level >= 3)
    {
        Logger::error(text);
    }
    else
    {
        Logger::warning(text);
    }
}


long long PGS::nowMsThunk(void * /*context*/)
{
    // Epoch milliseconds from GetSystemTimeAsFileTime (1601-based 100ns ticks).
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return static_cast<long long>((u.QuadPart - 116444736000000000ULL) / 10000ULL);
}


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
    const DWORD attr = GetFileAttributesW(utf8ToWide(candidateUtf8).c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        return false;
    }
    const std::string candidateFinal = finalPathForCompareUtf8(candidateUtf8, false);
    const std::string modulesFinal = finalPathForCompareUtf8(m_modulesDir, true);
    if (candidateFinal.empty() || modulesFinal.empty())
    {
        return false;
    }
    if (candidateFinal.size() <= 4 ||
        candidateFinal.compare(candidateFinal.size() - 4, 4, ".dll") != 0)
    {
        return false;
    }
    // Require the fully-resolved file path to be strictly under the fully-
    // resolved modules directory, so junctions/symlinks cannot escape it.
    if (candidateFinal == modulesFinal)
    {
        return false;
    }
    const std::string prefix = modulesFinal + "\\";
    return candidateFinal.rfind(prefix, 0) == 0;
}


bool PGS::writeInitialTokenFile(const std::string &stateDir, const std::string &token) const
{
    std::filesystem::path filePath = stateDir.empty() ? std::filesystem::path("pgs_initial_token.txt")
                                                      : std::filesystem::path(stateDir) / "pgs_initial_token.txt";
    // Ensure the directory exists with a restrictive ACL before writing.
    if (!stateDir.empty())
    {
        if (!util::secureCreateDirectory(stateDir))
        {
            Logger::error("PGS: failed to secure bootstrap token directory ACL: " + stateDir);
            return false;
        }
    }
    std::ofstream out(filePath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        Logger::warning("PGS: failed to open bootstrap token file for write: " + filePath.string());
        return false;
    }
    out << token;
    out.flush();
    if (!out.good())
    {
        Logger::error("PGS: failed to write bootstrap token file: " + filePath.string());
        out.close();
        DeleteFileW(filePath.wstring().c_str());
        return false;
    }
    out.close();

    // Token file uses a stricter boundary than the state directory: OWNER=BA and
    // SY+BA-only protected DACL (no interactive/runtime user ACE). Matches doctor
    // repair via secureBootstrapTokenAcl so first-write and repair stay aligned.
    if (!util::secureBootstrapTokenAcl(filePath.string()))
    {
        Logger::error("PGS: failed to secure bootstrap token file ACL: " + filePath.string());
        DeleteFileW(filePath.wstring().c_str());
        return false;
    }
    return true;
}

} // namespace ProcessGuard
