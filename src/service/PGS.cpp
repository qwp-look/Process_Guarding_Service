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


namespace
{
// File-local helpers: only the few that are NOT in ProcessGuard::util live here
// (numeric/bool parsing and the WTS session-token helper). Encoding, hashing,
// path/process and string helpers now come from Process_Guard/PGUtil.h.

constexpr const char *kRestartIndexToken = "${PGS_RESTART_INDEX}";
constexpr int kStateFileVersion = 5;     // v5: durable quarantine failure reason codes
constexpr int kPreviousStateFileVersion = 4; // v4: durable quarantine/failure state
constexpr int kAdvancedStateFileVersion = 3; // v3: advanced guard policy + WindowsApps
constexpr int kLegacyStateFileVersion = 2;
constexpr int kDefaultHealthIntervalMs = 30000;
constexpr int kMinHealthIntervalMs = 1000;
constexpr int kMaxHealthIntervalMs = 3600000;
constexpr int kDefaultHealthTimeoutMs = 2000;
constexpr int kMinHealthTimeoutMs = 100;
constexpr int kMaxHealthTimeoutMs = 30000;
constexpr int kDefaultHealthFailures = 3;
// Per-guard Job Object naming. The "Global\" kernel namespace requires
// SeCreateGlobalPrivilege (held by LocalSystem / Administrators), which is why
// the default service account must stay LocalSystem for full-cascade to work.
constexpr const char *kJobNamePrefix = "Global\\PGS-Job-";
constexpr const char *kModulesAllowlistFile = "modules.allow";

bool setRestartFailure(std::string &code, std::string &message,
                       const std::string &failureCode, const std::string &failureMessage)
{
    code = failureCode;
    message = failureMessage;
    return false;
}

bool isSha256Hex(const std::string &value)
{
    if (value.size() != 64)
    {
        return false;
    }
    for (unsigned char ch : value)
    {
        if (!std::isxdigit(ch))
        {
            return false;
        }
    }
    return true;
}

std::string sanitizeGroupName(std::string name)
{
    name = ProcessGuard::util::toLowerAscii(ProcessGuard::util::trim(name));
    if (name.size() > 64)
    {
        return std::string();
    }
    for (char ch : name)
    {
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
                        ch == '_' || ch == '-' || ch == '.';
        if (!ok)
        {
            return std::string();
        }
    }
    return name;
}

std::vector<std::string> splitCsvTrimmed(const std::string &value)
{
    std::vector<std::string> out;
    std::string current;
    for (char ch : value)
    {
        if (ch == ',')
        {
            const std::string item = sanitizeGroupName(current);
            if (!item.empty())
            {
                out.push_back(item);
            }
            current.clear();
        }
        else
        {
            current.push_back(ch);
        }
    }
    const std::string item = sanitizeGroupName(current);
    if (!item.empty())
    {
        out.push_back(item);
    }
    return out;
}

std::string joinCsv(const std::vector<std::string> &values)
{
    std::ostringstream oss;
    for (std::size_t i = 0; i < values.size(); ++i)
    {
        if (i != 0)
        {
            oss << ',';
        }
        oss << values[i];
    }
    return oss.str();
}

bool parseInt64Field(const std::string &value, std::int64_t &out)
{
    const std::string text = ProcessGuard::util::trim(value);
    if (text.empty())
    {
        return false;
    }
    try
    {
        out = std::stoll(text);
        return true;
    }
    catch (const std::exception &)
    {
        return false;
    }
}

bool parseIntField(const std::string &value, int &out)
{
    std::int64_t parsed = 0;
    if (!parseInt64Field(value, parsed) || parsed < std::numeric_limits<int>::min() ||
        parsed > std::numeric_limits<int>::max())
    {
        return false;
    }
    out = static_cast<int>(parsed);
    return true;
}

bool looksLikeJsonObjectOrArray(const std::string &text)
{
    const std::string t = ProcessGuard::util::trim(text);
    return !t.empty() && ((t.front() == '{' && t.back() == '}') || (t.front() == '[' && t.back() == ']'));
}

std::string jsonStringValue(const std::string &text, const std::string &key)
{
    const std::string needle = "\"" + key + "\"";
    std::size_t pos = text.find(needle);
    if (pos == std::string::npos)
    {
        return std::string();
    }
    pos = text.find(':', pos + needle.size());
    if (pos == std::string::npos)
    {
        return std::string();
    }
    ++pos;
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])))
    {
        ++pos;
    }
    if (pos >= text.size() || text[pos] != '"')
    {
        return std::string();
    }
    ++pos;
    std::string out;
    bool escaped = false;
    for (; pos < text.size(); ++pos)
    {
        const char ch = text[pos];
        if (escaped)
        {
            switch (ch)
            {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            default: out.push_back(ch); break;
            }
            escaped = false;
            continue;
        }
        if (ch == '\\')
        {
            escaped = true;
            continue;
        }
        if (ch == '"')
        {
            break;
        }
        out.push_back(ch);
    }
    return out;
}

std::string jsonScalarValue(const std::string &text, const std::string &key)
{
    const std::string quoted = jsonStringValue(text, key);
    if (!quoted.empty())
    {
        return quoted;
    }
    const std::string needle = "\"" + key + "\"";
    std::size_t pos = text.find(needle);
    if (pos == std::string::npos)
    {
        return std::string();
    }
    pos = text.find(':', pos + needle.size());
    if (pos == std::string::npos)
    {
        return std::string();
    }
    ++pos;
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])))
    {
        ++pos;
    }
    const std::size_t start = pos;
    while (pos < text.size())
    {
        const char ch = text[pos];
        if (ch == ',' || ch == '}' || std::isspace(static_cast<unsigned char>(ch)))
        {
            break;
        }
        ++pos;
    }
    return ProcessGuard::util::trim(text.substr(start, pos - start));
}

bool jsonIntValue(const std::string &text, const std::string &key, int &out)
{
    const std::string value = jsonScalarValue(text, key);
    if (value.empty())
    {
        return false;
    }
    return parseIntField(value, out);
}

bool jsonBoolValue(const std::string &text, const std::string &key, bool defaultValue)
{
    const std::string value = ProcessGuard::util::toLowerAscii(ProcessGuard::util::trim(jsonScalarValue(text, key)));
    if (value.empty())
    {
        return defaultValue;
    }
    return value == "1" || value == "true" || value == "yes" || value == "on";
}

struct HealthCheckConfig
{
    bool enabled = true;
    std::string type;
    std::string action = "event";
    int intervalMs = kDefaultHealthIntervalMs;
    int timeoutMs = kDefaultHealthTimeoutMs;
    int failures = kDefaultHealthFailures;
    std::string host;
    int port = 0;
    std::string url;
    int expectedStatus = 0;
    int minStatus = 200;
    int maxStatus = 399;
};

int clampHealthInt(int value, int minValue, int maxValue)
{
    return std::max(minValue, std::min(maxValue, value));
}

bool parseHealthCheckConfig(const std::string &json, HealthCheckConfig &out, std::string &err)
{
    out = HealthCheckConfig{};
    if (!looksLikeJsonObjectOrArray(json))
    {
        err = "health-check config must be a JSON object";
        return false;
    }
    out.enabled = jsonBoolValue(json, "enabled", true);
    if (!out.enabled)
    {
        out.type = "disabled";
        return true;
    }
    out.type = ProcessGuard::util::toLowerAscii(ProcessGuard::util::trim(jsonStringValue(json, "type")));
    if (out.type.empty())
    {
        out.type = ProcessGuard::util::toLowerAscii(ProcessGuard::util::trim(jsonStringValue(json, "probe")));
    }
    if (out.type != "process" && out.type != "tcp" && out.type != "http")
    {
        err = "health-check type must be process, tcp, or http";
        return false;
    }
    int value = 0;
    if (jsonIntValue(json, "interval_ms", value))
    {
        out.intervalMs = clampHealthInt(value, kMinHealthIntervalMs, kMaxHealthIntervalMs);
    }
    else if (jsonIntValue(json, "interval_sec", value) || jsonIntValue(json, "interval_seconds", value))
    {
        const long long scaled = static_cast<long long>(value) * 1000ll;
        out.intervalMs = static_cast<int>(std::max<long long>(kMinHealthIntervalMs, std::min<long long>(kMaxHealthIntervalMs, scaled)));
    }
    if (jsonIntValue(json, "timeout_ms", value))
    {
        out.timeoutMs = clampHealthInt(value, kMinHealthTimeoutMs, kMaxHealthTimeoutMs);
    }
    if (jsonIntValue(json, "failures", value) || jsonIntValue(json, "failure_threshold", value))
    {
        out.failures = clampHealthInt(value, 1, 100);
    }
    out.action = ProcessGuard::util::toLowerAscii(ProcessGuard::util::trim(jsonStringValue(json, "action")));
    if (out.action.empty())
    {
        out.action = "event";
    }
    if (out.action == "alert" || out.action == "notify")
    {
        out.action = "event";
    }
    if (out.action == "ignore")
    {
        out.action = "none";
    }
    if (out.action != "event" && out.action != "none" && out.action != "restart" && out.action != "quarantine")
    {
        err = "health-check action must be event, restart, quarantine, or none";
        return false;
    }
    if (out.type == "tcp")
    {
        out.host = ProcessGuard::util::trim(jsonStringValue(json, "host"));
        if (out.host.empty())
        {
            out.host = ProcessGuard::util::trim(jsonStringValue(json, "address"));
        }
        if (out.host.empty() || !jsonIntValue(json, "port", out.port) || out.port <= 0 || out.port > 65535)
        {
            err = "tcp health-check requires host and 1-65535 port";
            return false;
        }
    }
    if (out.type == "http")
    {
        out.url = ProcessGuard::util::trim(jsonStringValue(json, "url"));
        if (out.url.empty())
        {
            err = "http health-check requires url";
            return false;
        }
        if (jsonIntValue(json, "expected_status", value) || jsonIntValue(json, "status", value))
        {
            out.expectedStatus = value;
        }
        if (jsonIntValue(json, "min_status", value))
        {
            out.minStatus = clampHealthInt(value, 100, 599);
        }
        if (jsonIntValue(json, "max_status", value))
        {
            out.maxStatus = clampHealthInt(value, 100, 599);
        }
        if (out.expectedStatus > 0 && (out.expectedStatus < 100 || out.expectedStatus > 599))
        {
            err = "http expected_status must be 100-599";
            return false;
        }
        if (out.minStatus > out.maxStatus)
        {
            err = "http min_status must be <= max_status";
            return false;
        }
    }
    return true;
}

struct HealthTask
{
    DWORD pid = 0;
    std::uint64_t guardId = 0;
    HANDLE processHandle = nullptr;
    std::string path;
    std::string configJson;
    HealthCheckConfig config;
};

bool duplicateProcessHandle(HANDLE source, HANDLE &out)
{
    out = nullptr;
    if (!source)
    {
        return false;
    }
    return DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &out, 0, FALSE, DUPLICATE_SAME_ACCESS) == TRUE;
}

bool probeProcessHealth(const HealthTask &task, std::string &message)
{
    if (!task.processHandle)
    {
        message = "process handle unavailable";
        return false;
    }
    const DWORD wait = WaitForSingleObject(task.processHandle, 0);
    if (wait == WAIT_TIMEOUT)
    {
        message = "process alive";
        return true;
    }
    DWORD exitCode = 0;
    GetExitCodeProcess(task.processHandle, &exitCode);
    message = "process exited code=" + std::to_string(exitCode);
    return false;
}

bool probeTcpHealth(const HealthCheckConfig &cfg, std::string &message)
{
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo *result = nullptr;
    const std::string portText = std::to_string(cfg.port);
    const int gai = getaddrinfo(cfg.host.c_str(), portText.c_str(), &hints, &result);
    if (gai != 0 || !result)
    {
        message = "tcp resolve failed host=" + cfg.host;
        return false;
    }
    bool ok = false;
    int lastErr = 0;
    for (addrinfo *ai = result; ai && !ok; ai = ai->ai_next)
    {
        SOCKET s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET)
        {
            lastErr = WSAGetLastError();
            continue;
        }
        u_long nonBlocking = 1;
        ioctlsocket(s, FIONBIO, &nonBlocking);
        const int c = connect(s, ai->ai_addr, static_cast<int>(ai->ai_addrlen));
        if (c == 0)
        {
            ok = true;
        }
        else
        {
            lastErr = WSAGetLastError();
            if (lastErr == WSAEWOULDBLOCK || lastErr == WSAEINPROGRESS || lastErr == WSAEINVAL)
            {
                fd_set writeSet;
                FD_ZERO(&writeSet);
                FD_SET(s, &writeSet);
                fd_set errorSet;
                FD_ZERO(&errorSet);
                FD_SET(s, &errorSet);
                timeval tv{};
                tv.tv_sec = cfg.timeoutMs / 1000;
                tv.tv_usec = (cfg.timeoutMs % 1000) * 1000;
                const int sel = select(0, nullptr, &writeSet, &errorSet, &tv);
                if (sel > 0 && FD_ISSET(s, &writeSet))
                {
                    int soError = 0;
                    int soLen = sizeof(soError);
                    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char *>(&soError), &soLen);
                    if (soError == 0)
                    {
                        ok = true;
                    }
                    else
                    {
                        lastErr = soError;
                    }
                }
                else if (sel == 0)
                {
                    lastErr = WSAETIMEDOUT;
                }
            }
        }
        closesocket(s);
    }
    freeaddrinfo(result);
    if (ok)
    {
        message = "tcp connected " + cfg.host + ":" + std::to_string(cfg.port);
        return true;
    }
    message = "tcp connect failed host=" + cfg.host + ":" + std::to_string(cfg.port) + " error=" + std::to_string(lastErr);
    return false;
}

bool probeHttpHealth(const HealthCheckConfig &cfg, std::string &message)
{
    const std::wstring urlW = ProcessGuard::util::utf8ToWide(cfg.url);
    if (urlW.empty())
    {
        message = "http url conversion failed";
        return false;
    }
    URL_COMPONENTS components{};
    components.dwStructSize = sizeof(components);
    components.dwSchemeLength = static_cast<DWORD>(-1);
    components.dwHostNameLength = static_cast<DWORD>(-1);
    components.dwUrlPathLength = static_cast<DWORD>(-1);
    components.dwExtraInfoLength = static_cast<DWORD>(-1);
    if (!WinHttpCrackUrl(urlW.c_str(), 0, 0, &components))
    {
        message = "http url parse failed error=" + std::to_string(GetLastError());
        return false;
    }
    if (components.nScheme != INTERNET_SCHEME_HTTP && components.nScheme != INTERNET_SCHEME_HTTPS)
    {
        message = "http scheme must be http or https";
        return false;
    }
    const std::wstring host(components.lpszHostName, components.dwHostNameLength);
    std::wstring target(components.lpszUrlPath, components.dwUrlPathLength);
    if (target.empty())
    {
        target = L"/";
    }
    if (components.dwExtraInfoLength > 0)
    {
        target.append(components.lpszExtraInfo, components.dwExtraInfoLength);
    }
    HINTERNET session = WinHttpOpen(L"PGSHealth/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
    {
        message = "http open failed error=" + std::to_string(GetLastError());
        return false;
    }
    WinHttpSetTimeouts(session, cfg.timeoutMs, cfg.timeoutMs, cfg.timeoutMs, cfg.timeoutMs);
    HINTERNET connect = WinHttpConnect(session, host.c_str(), components.nPort, 0);
    if (!connect)
    {
        const DWORD err = GetLastError();
        WinHttpCloseHandle(session);
        message = "http connect failed error=" + std::to_string(err);
        return false;
    }
    const DWORD flags = (components.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(connect, L"GET", target.c_str(), nullptr,
                                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!request)
    {
        const DWORD err = GetLastError();
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        message = "http request open failed error=" + std::to_string(err);
        return false;
    }
    bool ok = false;
    DWORD status = 0;
    if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
        WinHttpReceiveResponse(request, nullptr))
    {
        DWORD len = sizeof(status);
        if (WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &status, &len, WINHTTP_NO_HEADER_INDEX))
        {
            ok = cfg.expectedStatus > 0 ? (static_cast<int>(status) == cfg.expectedStatus)
                                        : (static_cast<int>(status) >= cfg.minStatus && static_cast<int>(status) <= cfg.maxStatus);
        }
    }
    const DWORD err = ok ? 0 : GetLastError();
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    if (ok)
    {
        message = "http status=" + std::to_string(status);
        return true;
    }
    message = status > 0 ? ("http unexpected status=" + std::to_string(status))
                         : ("http request failed error=" + std::to_string(err));
    return false;
}

bool runHealthProbe(const HealthTask &task, const HealthCheckConfig &cfg, std::string &message)
{
    if (!cfg.enabled)
    {
        message = "health-check disabled";
        return true;
    }
    if (cfg.type == "process")
    {
        return probeProcessHealth(task, message);
    }
    if (cfg.type == "tcp")
    {
        return probeTcpHealth(cfg, message);
    }
    if (cfg.type == "http")
    {
        return probeHttpHealth(cfg, message);
    }
    message = "unknown health-check type";
    return false;
}

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

std::string finalPathForCompareUtf8(const std::string &pathUtf8, bool directory)
{
    const std::wstring pathW = ProcessGuard::util::utf8ToWide(pathUtf8);
    if (pathW.empty())
    {
        return std::string();
    }

    const DWORD flags = directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;
    HANDLE h = CreateFileW(pathW.c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, flags, nullptr);
    if (h == INVALID_HANDLE_VALUE)
    {
        return std::string();
    }

    std::vector<wchar_t> buffer(32768, L'\0');
    const DWORD len = GetFinalPathNameByHandleW(
        h, buffer.data(), static_cast<DWORD>(buffer.size()),
        FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    CloseHandle(h);
    if (len == 0 || len >= buffer.size())
    {
        return std::string();
    }

    std::wstring normalized(buffer.data(), len);
    if (normalized.rfind(L"\\\\?\\UNC\\", 0) == 0)
    {
        normalized = L"\\\\" + normalized.substr(8);
    }
    else if (normalized.rfind(L"\\\\?\\", 0) == 0)
    {
        normalized = normalized.substr(4);
    }
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(towlower(ch));
    });
    return ProcessGuard::util::wideToUtf8(normalized);
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

std::int64_t PGS::currentEpochMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool PGS::validateHealthCheckConfig(const std::string &configJson, std::string &error)
{
    HealthCheckConfig parsed;
    return parseHealthCheckConfig(configJson, parsed, error);
}

void PGS::resetHealthRuntimeState(GuardInfo &guard)
{
    guard.healthStatus = guard.healthCheckJson.empty() ? "disabled" : "pending";
    guard.healthLastMessage.clear();
    guard.healthLastCheckMs = 0;
    guard.healthLastOkMs = 0;
    guard.healthLastFailureMs = 0;
    guard.healthNextCheckMs = guard.healthCheckJson.empty() ? 0 : currentEpochMs();
    guard.healthFailureCount = 0;
}

GuardInfo PGS::desiredGuardFromPersisted(const PersistedGuardState &persisted)
{
    GuardInfo guard{};
    guard.pid = persisted.lastKnownPid;
    guard.sessionId = persisted.sessionId;
    guard.path = persisted.path;
    guard.maxRestarts = persisted.maxRestarts;
    guard.restartArgs = persisted.restartArgs;
    guard.fileHash = persisted.fileHash;
    guard.intentional = persisted.intentional;
    guard.hashVerified = persisted.hashVerified;
    guard.guardId = persisted.guardId;
    guard.appKind = persisted.appKind;
    guard.aumid = persisted.aumid;
    guard.restartWindowSec = persisted.restartWindowSec;
    guard.restartDelayMs = persisted.restartDelayMs;
    guard.backoff = persisted.backoff;
    guard.hangTimeoutMs = persisted.hangTimeoutMs;
    guard.killOnExit = persisted.killOnExit;
    guard.healthCheckJson = persisted.healthCheckJson;
    resetHealthRuntimeState(guard);
    guard.groupName = persisted.groupName;
    guard.paused = persisted.paused;
    guard.createdAtMs = persisted.createdAtMs;
    guard.lastStartMs = persisted.lastStartMs;
    guard.lastExitMs = persisted.lastExitMs;
    guard.lastExitCode = persisted.lastExitCode;
    guard.cumulativeRunMs = persisted.cumulativeRunMs;
    guard.restartIntervalSumMs = persisted.restartIntervalSumMs;
    guard.restartIntervalCount = persisted.restartIntervalCount;
    guard.crashLoop = persisted.crashLoop;
    guard.restartHookJson = persisted.restartHookJson;
    guard.quarantined = persisted.quarantined;
    guard.lastFailureCode = persisted.lastFailureCode;
    guard.lastFailure = persisted.lastFailure;
    guard.nextRetryMs = persisted.nextRetryMs;
    guard.failureCount = persisted.failureCount;
    return guard;
}

void PGS::copyGuardToPersisted(const GuardInfo &guard, PersistedGuardState &persisted)
{
    persisted.guardId = guard.guardId;
    persisted.lastKnownPid = guard.pid;
    persisted.sessionId = guard.sessionId;
    persisted.path = guard.path;
    persisted.maxRestarts = guard.maxRestarts;
    persisted.restartArgs = guard.restartArgs;
    persisted.fileHash = guard.fileHash;
    persisted.intentional = guard.intentional;
    persisted.hashVerified = guard.hashVerified;
    persisted.appKind = guard.appKind;
    persisted.aumid = guard.aumid;
    persisted.restartWindowSec = guard.restartWindowSec;
    persisted.restartDelayMs = guard.restartDelayMs;
    persisted.backoff = guard.backoff;
    persisted.hangTimeoutMs = guard.hangTimeoutMs;
    persisted.killOnExit = guard.killOnExit;
    persisted.healthCheckJson = guard.healthCheckJson;
    persisted.groupName = guard.groupName;
    persisted.paused = guard.paused;
    persisted.createdAtMs = guard.createdAtMs;
    persisted.lastStartMs = guard.lastStartMs;
    persisted.lastExitMs = guard.lastExitMs;
    persisted.lastExitCode = guard.lastExitCode;
    persisted.cumulativeRunMs = guard.cumulativeRunMs;
    persisted.restartIntervalSumMs = guard.restartIntervalSumMs;
    persisted.restartIntervalCount = guard.restartIntervalCount;
    persisted.crashLoop = guard.crashLoop;
    persisted.restartHookJson = guard.restartHookJson;
    persisted.quarantined = guard.quarantined;
    persisted.lastFailureCode = guard.lastFailureCode;
    persisted.lastFailure = guard.lastFailure;
    persisted.nextRetryMs = guard.nextRetryMs;
    persisted.failureCount = guard.failureCount;
}

void PGS::inheritRestartProfile(GuardInfo &newGuard, const GuardInfo &oldGuard)
{
    const std::int64_t nowMs = currentEpochMs();
    newGuard.healthCheckJson = oldGuard.healthCheckJson;
    resetHealthRuntimeState(newGuard);
    newGuard.groupName = oldGuard.groupName;
    newGuard.paused = oldGuard.paused;
    newGuard.createdAtMs = oldGuard.createdAtMs > 0 ? oldGuard.createdAtMs : nowMs;
    newGuard.lastStartMs = nowMs;
    newGuard.lastExitMs = oldGuard.lastExitMs;
    newGuard.lastExitCode = oldGuard.lastExitCode;
    newGuard.cumulativeRunMs = oldGuard.cumulativeRunMs;
    newGuard.restartHookJson = oldGuard.restartHookJson;
    clearFailureState(newGuard);
    if (oldGuard.lastStartMs > 0)
    {
        newGuard.restartIntervalSumMs = oldGuard.restartIntervalSumMs + std::max<std::int64_t>(0, nowMs - oldGuard.lastStartMs);
        newGuard.restartIntervalCount = oldGuard.restartIntervalCount + 1;
    }
    else
    {
        newGuard.restartIntervalSumMs = oldGuard.restartIntervalSumMs;
        newGuard.restartIntervalCount = oldGuard.restartIntervalCount;
    }
    const std::int64_t avgMs = newGuard.restartIntervalCount > 0
        ? (newGuard.restartIntervalSumMs / newGuard.restartIntervalCount)
        : 0;
    newGuard.crashLoop = (newGuard.restartIntervalCount >= 3 && avgMs > 0 && avgMs < 60000);
}

void PGS::markGuardExitForProfile(GuardInfo &guard, DWORD exitCode, std::int64_t exitMs)
{
    guard.lastExitMs = exitMs;
    guard.lastExitCode = static_cast<int>(exitCode);
    if (guard.lastStartMs > 0 && exitMs > guard.lastStartMs)
    {
        guard.cumulativeRunMs += exitMs - guard.lastStartMs;
    }
}

std::int64_t PGS::effectiveCumulativeRunMs(const GuardInfo &guard, std::int64_t nowMs)
{
    std::int64_t total = guard.cumulativeRunMs;
    if (guard.handle && guard.lastStartMs > 0 && nowMs > guard.lastStartMs &&
        WaitForSingleObject(guard.handle, 0) == WAIT_TIMEOUT)
    {
        total += nowMs - guard.lastStartMs;
    }
    return total;
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
    std::unordered_map<std::uint64_t, RestartPolicyState> parsedPolicy;
    std::unordered_map<std::string, GuardGroupState> parsedGroups;
    std::uint64_t groupCount = 0;
    std::uint64_t parsedGroupLines = 0;

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

        if (fields[0] == "RESTART_COUNT")
        {
            std::uint64_t guardId = 0;
            std::uint64_t count = 0;
            if (fields.size() >= 3 &&
                parseUnsignedLongLong(fields[1], guardId) &&
                parseUnsignedLongLong(fields[2], count) &&
                guardId != 0)
            {
                auto &policy = parsedPolicy[guardId];
                policy.restartCount = static_cast<int>(std::min<std::uint64_t>(
                    count, static_cast<std::uint64_t>(std::numeric_limits<int>::max())));
            }
            continue;
        }

        if (fields[0] == "RESTART")
        {
            std::uint64_t guardId = 0;
            std::uint64_t epochMs = 0;
            if (fields.size() >= 3 &&
                parseUnsignedLongLong(fields[1], guardId) &&
                parseUnsignedLongLong(fields[2], epochMs) &&
                guardId != 0)
            {
                parsedPolicy[guardId].recentRestartMs.push_back(static_cast<std::int64_t>(epochMs));
            }
            continue;
        }

        if (fields[0] == "GROUP_COUNT")
        {
            if (fields.size() >= 2)
            {
                parseUnsignedLongLong(fields[1], groupCount);
            }
            continue;
        }

        if (fields[0] == "GROUP")
        {
            if (fields.size() < 3)
            {
                return false;
            }
            GuardGroupState group;
            group.name = sanitizeGroupName(base64Decode(fields[1]));
            if (group.name.empty())
            {
                return false;
            }
            if (!parseBoolFlag(fields[2], group.paused))
            {
                return false;
            }
            if (fields.size() > 3)
            {
                parseIntField(fields[3], group.startupOrder);
            }
            if (fields.size() > 4 && fields[4] != "-")
            {
                group.dependencies = splitCsvTrimmed(base64Decode(fields[4]));
            }
            parsedGroups[group.name] = group;
            ++parsedGroupLines;
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
            if (fields.size() > 17 && fields[17] != "-")
            {
                persisted.healthCheckJson = base64Decode(fields[17]);
                if (!persisted.healthCheckJson.empty() && !looksLikeJsonObjectOrArray(persisted.healthCheckJson))
                {
                    persisted.healthCheckJson.clear();
                }
            }
            if (fields.size() > 18 && fields[18] != "-")
            {
                persisted.groupName = sanitizeGroupName(base64Decode(fields[18]));
            }
            if (fields.size() > 19)
            {
                bool b = false;
                if (parseBoolFlag(fields[19], b))
                {
                    persisted.paused = b;
                }
            }
            if (fields.size() > 20) parseInt64Field(fields[20], persisted.createdAtMs);
            if (fields.size() > 21) parseInt64Field(fields[21], persisted.lastStartMs);
            if (fields.size() > 22) parseInt64Field(fields[22], persisted.lastExitMs);
            if (fields.size() > 23) parseIntField(fields[23], persisted.lastExitCode);
            if (fields.size() > 24) parseInt64Field(fields[24], persisted.cumulativeRunMs);
            if (fields.size() > 25) parseInt64Field(fields[25], persisted.restartIntervalSumMs);
            if (fields.size() > 26) parseIntField(fields[26], persisted.restartIntervalCount);
            if (fields.size() > 27)
            {
                bool b = false;
                if (parseBoolFlag(fields[27], b))
                {
                    persisted.crashLoop = b;
                }
            }
            if (fields.size() > 28 && fields[28] != "-")
            {
                persisted.restartHookJson = base64Decode(fields[28]);
                if (!persisted.restartHookJson.empty() && !looksLikeJsonObjectOrArray(persisted.restartHookJson))
                {
                    persisted.restartHookJson.clear();
                }
            }
            if (fields.size() > 29)
            {
                bool b = false;
                if (parseBoolFlag(fields[29], b))
                {
                    persisted.quarantined = b;
                }
            }
            if (fields.size() > 30 && fields[30] != "-")
            {
                persisted.lastFailure = base64Decode(fields[30]);
            }
            if (fields.size() > 31) parseInt64Field(fields[31], persisted.nextRetryMs);
            if (fields.size() > 32) parseIntField(fields[32], persisted.failureCount);
            if (persisted.failureCount < 0) persisted.failureCount = 0;
            if (fields.size() > 33 && fields[33] != "-")
            {
                persisted.lastFailureCode = trim(fields[33]);
            }
            if (persisted.createdAtMs <= 0)
            {
                persisted.createdAtMs = currentEpochMs();
            }
            if (persisted.lastStartMs <= 0 && persisted.lastKnownPid != 0)
            {
                persisted.lastStartMs = persisted.createdAtMs;
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
        else if (version == kLegacyStateFileVersion || version == kAdvancedStateFileVersion || version == kPreviousStateFileVersion)
        {
            Logger::warning("PGS: migrating state file v" + std::to_string(version) + " -> v5 (guard records kept)");
        }
        else
        {
            Logger::warning("PGS: unsupported state file version " + std::to_string(version) + ", ignoring persisted archive");
            m_persistedGuards.clear();
            m_nextGuardId = 1ull;
            return false;
        }
    }
    if (!persistedAuthHash.empty() && !isSha256Hex(persistedAuthHash))
    {
        Logger::warning("PGS: persisted auth hash is invalid, generating a fresh token");
        persistedAuthHash.clear();
    }

    const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    m_policyByGuardId.clear();
    for (const auto &entry : parsedGuards)
    {
        RestartPolicyState policy = RestartPolicyState{entry.second.maxRestarts, 0, {}};
        auto pit = parsedPolicy.find(entry.first);
        if (pit != parsedPolicy.end())
        {
            policy = pit->second;
            policy.maxRestarts = entry.second.maxRestarts;
        }
        if (entry.second.restartWindowSec > 0)
        {
            policy.recentRestartMs = util::pruneRestartWindow(
                policy.recentRestartMs, nowMs, entry.second.restartWindowSec);
            policy.restartCount = static_cast<int>(policy.recentRestartMs.size());
        }
        else
        {
            policy.recentRestartMs.clear();
        }
        m_policyByGuardId[entry.first] = std::move(policy);
    }

    m_persistedGuards = std::move(parsedGuards);
    m_guardGroups = std::move(parsedGroups);
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
    if (!m_serverPortUserSet && m_serverPort == kServerPort && archivedServerPort != 0)
    {
        m_serverPort = archivedServerPort;
    }
    if (!m_modulesPermissiveUserSet.load())
    {
        m_modulesPermissive.store(archivedModulesPermissive);
    }

    Logger::warning("PGS: loaded persisted archive entries=" + std::to_string(m_persistedGuards.size()) +
                    ", state-file=" + m_stateFilePath);
    if (groupCount != 0 && groupCount != parsedGroupLines)
    {
        Logger::warning("PGS: persisted group count mismatch, parsed=" + std::to_string(parsedGroupLines) +
                        ", declared=" + std::to_string(groupCount));
    }
    return true;
}

void PGS::persistState()
{
    // Persist a snapshot, never a live structure. We first copy the archive
    // under lock, then write outside the lock, then atomically replace the
    // old file. That keeps the runtime hot path short and avoids half-written
    // files when the service is interrupted mid-write.
    std::lock_guard<std::mutex> persistLock(m_persistMutex);
    std::string authHash;
    {
        std::lock_guard<std::mutex> authLock(m_authMutex);
        authHash = m_authTokenHash;
    }

    std::uint64_t nextGuardId = 1;
    std::vector<PersistedGuardState> snapshot;
    std::unordered_map<std::uint64_t, RestartPolicyState> policySnapshot;
    std::vector<GuardGroupState> groupSnapshot;
    {
        std::lock_guard<std::mutex> guardsLock(m_guardsMutex);
        nextGuardId = m_nextGuardId.load();
        snapshot.reserve(m_persistedGuards.size());
        for (const auto &entry : m_persistedGuards)
        {
            snapshot.push_back(entry.second);
        }
        policySnapshot = m_policyByGuardId;
        groupSnapshot.reserve(m_guardGroups.size());
        for (const auto &entry : m_guardGroups)
        {
            groupSnapshot.push_back(entry.second);
        }
    }

    std::sort(snapshot.begin(), snapshot.end(), [](const PersistedGuardState &a, const PersistedGuardState &b) {
        return a.guardId < b.guardId;
    });
    std::sort(groupSnapshot.begin(), groupSnapshot.end(), [](const GuardGroupState &a, const GuardGroupState &b) {
        return a.name < b.name;
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
    out << "MODULES_PERMISSIVE\t" << (m_modulesPermissive.load() ? "1" : "0") << "\n";
    out << "GROUP_COUNT\t" << groupSnapshot.size() << "\n";
    for (const auto &group : groupSnapshot)
    {
        out << "GROUP\t"
            << base64Encode(group.name) << "\t"
            << (group.paused ? "1" : "0") << "\t"
            << group.startupOrder << "\t"
            << (group.dependencies.empty() ? "-" : base64Encode(joinCsv(group.dependencies))) << "\n";
    }
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
            << (guard.killOnExit ? "1" : "0") << "\t"
            << (guard.healthCheckJson.empty() ? "-" : base64Encode(guard.healthCheckJson)) << "\t"
            << (guard.groupName.empty() ? "-" : base64Encode(guard.groupName)) << "\t"
            << (guard.paused ? "1" : "0") << "\t"
            << guard.createdAtMs << "\t"
            << guard.lastStartMs << "\t"
            << guard.lastExitMs << "\t"
            << guard.lastExitCode << "\t"
            << guard.cumulativeRunMs << "\t"
            << guard.restartIntervalSumMs << "\t"
            << guard.restartIntervalCount << "\t"
            << (guard.crashLoop ? "1" : "0") << "\t"
            << (guard.restartHookJson.empty() ? "-" : base64Encode(guard.restartHookJson)) << "\t"
            << (guard.quarantined ? "1" : "0") << "\t"
            << (guard.lastFailure.empty() ? "-" : base64Encode(guard.lastFailure)) << "\t"
            << guard.nextRetryMs << "\t"
            << guard.failureCount << "\t"
            << (guard.lastFailureCode.empty() ? "-" : guard.lastFailureCode) << "\n";
        const auto pit = policySnapshot.find(guard.guardId);
        if (pit != policySnapshot.end())
        {
            if (pit->second.restartCount > 0)
            {
                out << "RESTART_COUNT\t" << guard.guardId << "\t" << pit->second.restartCount << "\n";
            }
            if (guard.restartWindowSec > 0)
            {
                const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                const auto recent = util::pruneRestartWindow(
                    pit->second.recentRestartMs, nowMs, guard.restartWindowSec);
                for (const std::int64_t t : recent)
                {
                    out << "RESTART\t" << guard.guardId << "\t" << t << "\n";
                }
            }
        }
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

    constexpr DWORD kGuardProcessAccess =
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE;
    HANDLE processHandle = OpenProcess(kGuardProcessAccess, FALSE, persisted.lastKnownPid);
    if (!processHandle)
    {
        processHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, persisted.lastKnownPid);
    }
    if (!processHandle)
    {
        return false;
    }

    DWORD sessionId = 0xFFFFFFFF;
    ProcessIdToSessionId(persisted.lastKnownPid, &sessionId);
    outGuard = desiredGuardFromPersisted(persisted);
    outGuard.pid = persisted.lastKnownPid;
    outGuard.sessionId = sessionId;
    outGuard.path = actualPath;
    outGuard.handle = processHandle;
    outGuard.jobHandle = nullptr;
    if (outGuard.createdAtMs <= 0)
    {
        outGuard.createdAtMs = currentEpochMs();
    }
    if (outGuard.lastStartMs <= 0)
    {
        outGuard.lastStartMs = outGuard.createdAtMs;
    }
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
        if (persisted.quarantined)
        {
            Logger::warning("PGS: persisted guard remains quarantined during restore, guard-id=" +
                            std::to_string(persisted.guardId));
            recordEvent("guard.restore-quarantine",
                        "guard_id=" + std::to_string(persisted.guardId) +
                        ";path=" + persisted.path +
                        ";reason_b64=" + base64Encode(persisted.lastFailure));
            continue;
        }
        if (tryAttachPersistedGuard(persisted, restored))
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            m_guards[restored.pid] = restored;
            clearFailureState(m_guards[restored.pid]);
            auto &policy = m_policyByGuardId[restored.guardId];
            policy.maxRestarts = persisted.maxRestarts;
            auto it = m_persistedGuards.find(restored.guardId);
            if (it != m_persistedGuards.end())
            {
                copyGuardToPersisted(restored, it->second);
            }
            Logger::warning("PGS: restored persisted live guard pid=" + std::to_string(restored.pid) +
                            ", guard-id=" + std::to_string(restored.guardId));
            recordEvent("guard.restore-attach",
                        "pid=" + std::to_string(restored.pid) +
                        ";guard_id=" + std::to_string(restored.guardId) +
                        ";path=" + restored.path);
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

        GuardInfo desired = desiredGuardFromPersisted(persisted);
        desired.pid = 0;
        desired.handle = nullptr;
        desired.jobHandle = nullptr;
        desired.intentional = false;

        bool restorePaused = desired.paused;
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            const auto git = desired.groupName.empty() ? m_guardGroups.end() : m_guardGroups.find(desired.groupName);
            restorePaused = restorePaused || (git != m_guardGroups.end() && git->second.paused);
            if (restorePaused)
            {
                auto &stored = m_persistedGuards[desired.guardId];
                stored = persisted;
                stored.lastKnownPid = 0;
                stored.intentional = false;
            }
        }
        if (restorePaused)
        {
            Logger::warning("PGS: persisted missing guard kept paused during restore, guard-id=" +
                            std::to_string(persisted.guardId));
            recordEvent("guard.restore-paused",
                        "guard_id=" + std::to_string(persisted.guardId) +
                        ";path=" + persisted.path);
            changed = true;
            continue;
        }

        bool shouldRestart = true;
        int restartIndex = 1;
        const bool windowed = (persisted.restartWindowSec > 0);
        const bool restartAlreadyRecorded = (persisted.lastKnownPid == 0 && persisted.restartDelayMs > 0);
        int currentRestarts = 0;
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto &policy = m_policyByGuardId[persisted.guardId];
            policy.maxRestarts = persisted.maxRestarts;
            if (windowed)
            {
                const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                policy.recentRestartMs = util::pruneRestartWindow(policy.recentRestartMs, nowMs, persisted.restartWindowSec);
                policy.restartCount = static_cast<int>(policy.recentRestartMs.size());
                currentRestarts = policy.restartCount;
            }
            else
            {
                currentRestarts = policy.restartCount;
            }

            if (restartAlreadyRecorded)
            {
                // A delayed/backoff restart records budget before it enters the
                // pending queue and persists lastKnownPid=0. If PGS is stopped
                // during that delay, restore must complete the already-counted
                // relaunch instead of charging the budget a second time.
                shouldRestart = !(policy.maxRestarts >= 0 && currentRestarts > policy.maxRestarts);
                if (shouldRestart)
                {
                    restartIndex = currentRestarts > 0 ? currentRestarts
                                                       : recordRestartAndEffectiveCount(persisted.guardId, policy, persisted.restartWindowSec);
                }
            }
            else
            {
                shouldRestart = !(policy.maxRestarts >= 0 && currentRestarts >= policy.maxRestarts);
                if (shouldRestart)
                {
                    restartIndex = recordRestartAndEffectiveCount(persisted.guardId, policy, persisted.restartWindowSec);
                }
            }
        }

        if (!shouldRestart)
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto it = m_persistedGuards.find(persisted.guardId);
            if (it != m_persistedGuards.end())
            {
                markGuardQuarantined(it->second, "restart.limit", "restart limit reached during restore", currentEpochMs());
                it->second.lastKnownPid = 0;
            }
            Logger::warning("PGS: persisted guard restart limit reached during restore, guard-id=" +
                            std::to_string(persisted.guardId) +
                            ", max=" + maxRestartsLabel(persisted.maxRestarts) +
                            (windowed ? " (sliding window)" : ""));
            recordEvent("guard.restore-limit",
                        "guard_id=" + std::to_string(persisted.guardId) +
                        ";path=" + persisted.path +
                        ";max=" + maxRestartsLabel(persisted.maxRestarts));
            changed = true;
            continue;
        }

        GuardInfo restarted;
        std::string failureCode;
        std::string failureMessage;
        if (restartGuard(desired, restartIndex, restarted, failureCode, failureMessage))
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            m_guards[restarted.pid] = restarted;
            // v3: assign the freshly restarted process to its per-guard Job.
            assignGuardToJob(m_guards[restarted.pid]);
            auto &policy = m_policyByGuardId[restarted.guardId];
            policy.maxRestarts = persisted.maxRestarts;
            auto &stored = m_persistedGuards[restarted.guardId];
            copyGuardToPersisted(restarted, stored);
            stored.intentional = false;
            Logger::warning("PGS: restored persisted missing guard by restart pid=" + std::to_string(restarted.pid) +
                            ", guard-id=" + std::to_string(restarted.guardId));
            recordEvent("guard.restore-restart",
                        "pid=" + std::to_string(restarted.pid) +
                        ";guard_id=" + std::to_string(restarted.guardId) +
                        ";path=" + restarted.path);
            changed = true;
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto it = m_persistedGuards.find(persisted.guardId);
            if (it != m_persistedGuards.end())
            {
                markGuardQuarantined(it->second, failureCode.empty() ? "restart.restore_failed" : failureCode,
                                     failureMessage.empty() ? "restore restart failed" : failureMessage, currentEpochMs());
                it->second.lastKnownPid = 0;
            }
        }
        Logger::error("PGS: failed to restore persisted guard guard-id=" + std::to_string(persisted.guardId) +
                      ", guard quarantined path=" + persisted.path);
        recordEvent("guard.restore-failed",
                    "guard_id=" + std::to_string(persisted.guardId) +
                    ";path=" + persisted.path);
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
        bool queued = false;
        {
            std::lock_guard<std::mutex> lock(m_clientQueueMutex);
            if (m_clientQueue.size() < kMaxClientQueueSize)
            {
                m_clientQueue.push(clientSocket);
                queued = true;
            }
        }
        if (queued)
        {
            m_clientQueueCv.notify_one();
        }
        else
        {
            Logger::warning("PGS: client queue full, rejecting connection");
            sendAll(clientSocket, "ERR server busy\n");
            closesocket(clientSocket);
        }
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
            std::string failureCode;
            std::string failureMessage;
            if (restartGuard(pit->guard, pit->restartIndex, restarted, failureCode, failureMessage))
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    auto existingNew = m_guards.find(restarted.pid);
                    if (existingNew != m_guards.end() && existingNew->second.handle)
                    {
                        CloseHandle(existingNew->second.handle);
                    }
                    m_guards[restarted.pid] = restarted;
                    clearFailureState(m_guards[restarted.pid]);
                    assignGuardToJob(m_guards[restarted.pid]);
                    auto &persisted = m_persistedGuards[restarted.guardId];
                    copyGuardToPersisted(restarted, persisted);
                    persisted.intentional = false;
                }
                persistState();
                Logger::warning("PGS: auto-attached restarted guard pid=" + std::to_string(restarted.pid));
                recordEvent("guard.restart",
                            "pid=" + std::to_string(restarted.pid) +
                            ";guard_id=" + std::to_string(restarted.guardId) +
                            ";path=" + restarted.path);
            }
            else
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    quarantineGuardLocked(pit->guard, failureCode.empty() ? "restart.deferred_failed" : failureCode,
                                          failureMessage.empty() ? "deferred restart failed" : failureMessage);
                }
                persistState();
                closeGuardJob(pit->guard.guardId, true);
                Logger::error("PGS: restart failed permanently, guard quarantined path=" + pit->guard.path);
                recordEvent("guard.restart-failed",
                            "guard_id=" + std::to_string(pit->guard.guardId) +
                            ";path=" + pit->guard.path);
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
        std::vector<GuardInfo> hangCandidates;
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            for (auto it = m_guards.begin(); it != m_guards.end();)
            {
                if (isGuardAlive(it->second))
                {
                    if (it->second.hangTimeoutMs > 0)
                    {
                        hangCandidates.push_back(it->second);
                    }
                    ++it;
                    continue;
                }

                DWORD exitCode = 0;
                if (it->second.handle)
                {
                    GetExitCodeProcess(it->second.handle, &exitCode);
                }
                markGuardExitForProfile(it->second, exitCode, currentEpochMs());
                deadGuards.push_back(it->second);
                it = m_guards.erase(it);
            }
        }
        for (const GuardInfo &candidate : hangCandidates)
        {
            if (!isGuardHung(candidate))
            {
                continue;
            }

            Logger::warning("PGS: guard hung (unresponsive GUI), pid=" +
                            std::to_string(candidate.pid) +
                            ", hang-timeout=" + std::to_string(candidate.hangTimeoutMs) + "ms");
            recordEvent("guard.hung",
                        "pid=" + std::to_string(candidate.pid) +
                        ";guard_id=" + std::to_string(candidate.guardId) +
                        ";path=" + candidate.path);
            terminateGuardFamily(candidate.guardId);

            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto it = m_guards.find(candidate.pid);
            if (it != m_guards.end() && it->second.guardId == candidate.guardId)
            {
                markGuardExitForProfile(it->second, 1, currentEpochMs());
                deadGuards.push_back(it->second);
                m_guards.erase(it);
            }
        }

        // Process restart decisions outside the main guard map lock so creating
        // processes / waiting on system APIs cannot block register/list/get.
        for (const auto &guard : deadGuards)
        {
            bool guardPaused = guard.paused;
            {
                std::lock_guard<std::mutex> lock(m_guardsMutex);
                const auto git = guard.groupName.empty() ? m_guardGroups.end() : m_guardGroups.find(guard.groupName);
                guardPaused = guardPaused || (git != m_guardGroups.end() && git->second.paused);
            }

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
                recordEvent("guard.intentional-exit",
                            "pid=" + std::to_string(guard.pid) +
                            ";guard_id=" + std::to_string(guard.guardId) +
                            ";path=" + guard.path);
                continue;
            }

            if (guardPaused)
            {
                if (guard.handle)
                {
                    CloseHandle(guard.handle);
                }
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    auto &persisted = m_persistedGuards[guard.guardId];
                    copyGuardToPersisted(guard, persisted);
                    persisted.lastKnownPid = 0;
                    persisted.intentional = false;
                    persisted.paused = guard.paused;
                }
                closeGuardJob(guard.guardId, true);
                persistState();
                Logger::warning("PGS: guard exited while paused, restart suppressed pid=" + std::to_string(guard.pid));
                recordEvent("guard.paused-exit",
                            "pid=" + std::to_string(guard.pid) +
                            ";guard_id=" + std::to_string(guard.guardId) +
                            ";path=" + guard.path);
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
                    quarantineGuardLocked(guard, "restart.limit", "restart limit reached");
                }
                closeGuardJob(guard.guardId, true);
                persistState();
                recordEvent("guard.restart-limit",
                            "pid=" + std::to_string(guard.pid) +
                            ";guard_id=" + std::to_string(guard.guardId) +
                            ";path=" + guard.path +
                            ";max=" + maxRestartsLabel(maxRestarts));
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
                    policy.restartCount = static_cast<int>(policy.recentRestartMs.size());
                }
                else
                {
                    if (policy.restartCount < std::numeric_limits<int>::max())
                    {
                        ++policy.restartCount;
                    }
                }
                currentRestarts = windowed ? static_cast<int>(policy.recentRestartMs.size()) : policy.restartCount;
            }

            Logger::warning("PGS: guard died unexpectedly, pid=" + std::to_string(guard.pid) +
                            (guard.appKind == AppKind::WinApp ? " (winapp)" : ""));
            recordEvent("guard.died",
                        "pid=" + std::to_string(guard.pid) +
                        ";guard_id=" + std::to_string(guard.guardId) +
                        ";path=" + guard.path);
            Logger::warning("PGS: restart count " + std::to_string(currentRestarts) + "/" +
                            maxRestartsLabel(maxRestarts) +
                            ", path=" + guard.path +
                            ", app-kind=" + (guard.appKind == AppKind::WinApp ? "winapp" : "win32") +
                            (delayMs > 0 ? ", delay=" + std::to_string(delayMs) + "ms" : ""));

            if (delayMs > 0)
            {
                // Defer the relaunch so backoff/delay cannot stall monitoring of
                // other guards. Mark the archive as "pending and already
                // counted" before persisting so an SCM/service restart during
                // the delay resumes the same attempt without double-counting it.
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    auto it = m_persistedGuards.find(guard.guardId);
                    if (it != m_persistedGuards.end())
                    {
                        copyGuardToPersisted(guard, it->second);
                        it->second.lastKnownPid = 0;
                        it->second.intentional = false;
                    }
                }
                persistState();
                // The dead pid handle is kept in the pending copy and closed
                // when the deferred relaunch fires.
                const auto readyAt = std::chrono::steady_clock::now() + std::chrono::milliseconds(delayMs);
                pending.push_back({guard, restartIndex, readyAt});
                continue;
            }

            GuardInfo newGuard;
            std::string failureCode;
            std::string failureMessage;
            if (restartGuard(guard, restartIndex, newGuard, failureCode, failureMessage))
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    auto existingNew = m_guards.find(newGuard.pid);
                    if (existingNew != m_guards.end() && existingNew->second.handle)
                    {
                        CloseHandle(existingNew->second.handle);
                    }
                    m_guards[newGuard.pid] = newGuard;
                    clearFailureState(m_guards[newGuard.pid]);
                    assignGuardToJob(m_guards[newGuard.pid]);
                    auto &persisted = m_persistedGuards[newGuard.guardId];
                    copyGuardToPersisted(newGuard, persisted);
                    persisted.intentional = false;
                }
                persistState();
                Logger::warning("PGS: auto-attached restarted guard pid=" + std::to_string(newGuard.pid));
                recordEvent("guard.restart",
                            "pid=" + std::to_string(newGuard.pid) +
                            ";guard_id=" + std::to_string(newGuard.guardId) +
                            ";path=" + newGuard.path);
            }
            else
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    quarantineGuardLocked(guard, failureCode.empty() ? "restart.failed" : failureCode,
                                          failureMessage.empty() ? "restart failed" : failureMessage);
                }
                persistState();
                closeGuardJob(guard.guardId, true);
                Logger::error("PGS: restart failed permanently, guard quarantined pid=" + std::to_string(guard.pid));
                recordEvent("guard.restart-failed",
                            "pid=" + std::to_string(guard.pid) +
                            ";guard_id=" + std::to_string(guard.guardId) +
                            ";path=" + guard.path);
            }
            if (guard.handle)
            {
                CloseHandle(guard.handle);
            }
        }
    }

    for (PendingRestart &restart : pending)
    {
        if (restart.guard.handle)
        {
            CloseHandle(restart.guard.handle);
            restart.guard.handle = nullptr;
        }
    }
}

void PGS::healthLoop()
{
    while (m_running.load())
    {
        std::vector<HealthTask> tasks;
        std::vector<std::pair<std::string, std::string>> events;
        const std::int64_t nowMs = currentEpochMs();
        runArtifactMaintenanceIfDue(nowMs);
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            for (auto &entry : m_guards)
            {
                GuardInfo &guard = entry.second;
                if (guard.healthCheckJson.empty())
                {
                    if (guard.healthStatus != "disabled")
                    {
                        resetHealthRuntimeState(guard);
                    }
                    continue;
                }

                HealthCheckConfig config;
                std::string configError;
                if (!parseHealthCheckConfig(guard.healthCheckJson, config, configError))
                {
                    const bool firstError = guard.healthStatus != "config-error";
                    guard.healthStatus = "config-error";
                    guard.healthLastMessage = configError;
                    guard.healthLastFailureMs = nowMs;
                    guard.healthNextCheckMs = nowMs + kDefaultHealthIntervalMs;
                    if (firstError)
                    {
                        events.emplace_back("guard.health-config-error",
                                            "pid=" + std::to_string(guard.pid) +
                                            ";guard_id=" + std::to_string(guard.guardId) +
                                            ";error_b64=" + base64Encode(configError));
                    }
                    continue;
                }
                if (!config.enabled)
                {
                    if (guard.healthStatus != "disabled")
                    {
                        resetHealthRuntimeState(guard);
                    }
                    continue;
                }

                const auto groupIt = guard.groupName.empty() ? m_guardGroups.end() : m_guardGroups.find(guard.groupName);
                const bool paused = guard.paused || (groupIt != m_guardGroups.end() && groupIt->second.paused);
                if (paused || guard.quarantined || guard.intentional)
                {
                    guard.healthStatus = paused ? "paused" : (guard.quarantined ? "quarantined" : "disabled");
                    guard.healthNextCheckMs = nowMs + config.intervalMs;
                    continue;
                }
                if (guard.healthNextCheckMs > nowMs)
                {
                    continue;
                }

                HANDLE dup = nullptr;
                if (!duplicateProcessHandle(guard.handle, dup))
                {
                    guard.healthStatus = "degraded";
                    guard.healthLastMessage = "process handle unavailable";
                    guard.healthLastFailureMs = nowMs;
                    ++guard.healthFailureCount;
                    guard.healthNextCheckMs = nowMs + config.intervalMs;
                    continue;
                }
                guard.healthStatus = "checking";
                guard.healthLastCheckMs = nowMs;
                guard.healthNextCheckMs = nowMs + config.intervalMs;
                HealthTask task;
                task.pid = guard.pid;
                task.guardId = guard.guardId;
                task.processHandle = dup;
                task.path = guard.path;
                task.configJson = guard.healthCheckJson;
                task.config = config;
                tasks.push_back(std::move(task));
            }
        }

        for (HealthTask &task : tasks)
        {
            std::string message;
            const bool ok = runHealthProbe(task, task.config, message);
            const std::int64_t checkedMs = currentEpochMs();
            bool restartGuardNow = false;
            bool terminateQuarantinedProcess = false;
            bool persistAfterAction = false;
            HANDLE staleGuardHandle = nullptr;
            {
                std::lock_guard<std::mutex> lock(m_guardsMutex);
                auto it = m_guards.find(task.pid);
                if (it == m_guards.end() || it->second.guardId != task.guardId || it->second.healthCheckJson != task.configJson)
                {
                    CloseHandle(task.processHandle);
                    task.processHandle = nullptr;
                    continue;
                }
                GuardInfo &guard = it->second;
                guard.healthLastCheckMs = checkedMs;
                guard.healthNextCheckMs = checkedMs + task.config.intervalMs;
                guard.healthLastMessage = message;
                if (ok)
                {
                    const bool recovered = guard.healthStatus == "unhealthy" || guard.healthStatus == "degraded" || guard.healthFailureCount > 0;
                    guard.healthStatus = "healthy";
                    guard.healthLastOkMs = checkedMs;
                    guard.healthFailureCount = 0;
                    if (recovered)
                    {
                        events.emplace_back("guard.health-ok",
                                            "pid=" + std::to_string(task.pid) +
                                            ";guard_id=" + std::to_string(task.guardId) +
                                            ";type=" + task.config.type +
                                            ";message_b64=" + base64Encode(message));
                    }
                }
                else
                {
                    const int previousFailures = guard.healthFailureCount;
                    guard.healthLastFailureMs = checkedMs;
                    if (guard.healthFailureCount < std::numeric_limits<int>::max())
                    {
                        ++guard.healthFailureCount;
                    }
                    const bool thresholdReached = guard.healthFailureCount >= task.config.failures;
                    guard.healthStatus = thresholdReached ? "unhealthy" : "degraded";
                    if (thresholdReached && previousFailures < task.config.failures)
                    {
                        events.emplace_back("guard.health-unhealthy",
                                            "pid=" + std::to_string(task.pid) +
                                            ";guard_id=" + std::to_string(task.guardId) +
                                            ";type=" + task.config.type +
                                            ";failures=" + std::to_string(guard.healthFailureCount) +
                                            ";message_b64=" + base64Encode(message));
                    }
                    if (thresholdReached && task.config.action == "restart")
                    {
                        guard.healthStatus = "restarting";
                        restartGuardNow = true;
                        events.emplace_back("guard.health-restart",
                                            "pid=" + std::to_string(task.pid) +
                                            ";guard_id=" + std::to_string(task.guardId) +
                                            ";type=" + task.config.type +
                                            ";message_b64=" + base64Encode(message));
                    }
                    else if (thresholdReached && task.config.action == "quarantine")
                    {
                        GuardInfo archived = guard;
                        staleGuardHandle = guard.handle;
                        quarantineGuardLocked(archived, "health.failed", "health-check failed: " + message);
                        terminateQuarantinedProcess = true;
                        persistAfterAction = true;
                    }
                }
            }

            if (restartGuardNow)
            {
                terminateGuardFamily(task.guardId);
                TerminateProcess(task.processHandle, 1);
            }
            if (terminateQuarantinedProcess)
            {
                terminateGuardFamily(task.guardId);
                TerminateProcess(task.processHandle, 1);
                closeGuardJob(task.guardId, true);
                if (staleGuardHandle)
                {
                    CloseHandle(staleGuardHandle);
                }
            }
            if (persistAfterAction)
            {
                persistState();
            }
            if (task.processHandle)
            {
                CloseHandle(task.processHandle);
                task.processHandle = nullptr;
            }
        }

        for (const auto &event : events)
        {
            recordEvent(event.first, event.second);
        }

        std::unique_lock<std::mutex> lock(m_healthMutex);
        m_healthCv.wait_for(lock, std::chrono::milliseconds(500), [this]() {
            return !m_running.load();
        });
    }
}

void PGS::notifyLoop()
{
    while (true)
    {
        std::pair<std::string, std::string> event;
        {
            std::unique_lock<std::mutex> lock(m_notifyMutex);
            m_notifyCv.wait(lock, [this]() {
                return !m_running.load() || !m_notifyQueue.empty();
            });
            if (m_notifyQueue.empty())
            {
                if (!m_running.load())
                {
                    return;
                }
                continue;
            }
            event = std::move(m_notifyQueue.front());
            m_notifyQueue.pop();
        }

        bool notifyLoaded = false;
        for (const auto &module : m_modules.list())
        {
            if (module.name == "notify" && !module.disabled)
            {
                notifyLoaded = true;
                break;
            }
        }
        if (!notifyLoaded)
        {
            continue;
        }

        std::string response;
        std::string err;
        const std::string request = "op=event;type=" + event.first + ";detail_b64=" + base64Encode(event.second);
        const bool called = m_modules.invoke("notify", request, response, err);
        if (!called || response.rfind("OK", 0) != 0)
        {
            recordEvent("notify.delivery-failed",
                        "type=" + event.first +
                        ";error_b64=" + base64Encode(called ? response : err));
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

bool PGS::restartGuard(const GuardInfo &info, int restartIndex, GuardInfo &newGuard, std::string &failureCode, std::string &failureMessage)
{
    failureCode.clear();
    failureMessage.clear();
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
            return setRestartFailure(failureCode, failureMessage, "restart.hash_unreadable", "failed to recompute file hash for path=" + info.path);
        }
        if (!constantTimeEquals(toLowerAscii(currentHash), toLowerAscii(info.fileHash)))
        {
            Logger::error("PGS: restart refused, file hash mismatch (image changed since registration) path=" + info.path);
            return setRestartFailure(failureCode, failureMessage, "restart.hash_mismatch", "file hash mismatch for path=" + info.path);
        }
    }
    // v3: WindowsApps (UWP/Store) cannot be (re)launched with CreateProcessW*
    // — they must be activated through their AUMID. Route the whole restart to
    // restartAppGuard (it impersonates the user session and shell-activates the
    // app, returning the new pid/handle).
    if (info.appKind == AppKind::WinApp && !info.aumid.empty())
    {
        return restartAppGuard(info, restartIndex, newGuard, failureCode, failureMessage);
    }

    // Restart tries to preserve user experience first. We prefer re-launching
    // inside the original session so GUI apps come back on the right desktop.
    // If that fails, we still fall back to a normal CreateProcessW restart so
    // service-side recovery remains possible for console/background workers.
    if (restartGuardInSession(info, restartIndex, newGuard, failureCode, failureMessage))
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
        return setRestartFailure(failureCode, failureMessage, "restart.path_encoding", "path conversion failed for path=" + info.path);
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
        const DWORD err = GetLastError();
        Logger::error("PGS: restart failed for path=" + info.path + ", error=" + std::to_string(err));
        return setRestartFailure(failureCode, failureMessage, "restart.create_process", "CreateProcessW failed for path=" + info.path + ", error=" + std::to_string(err));
    }

    DWORD targetSession = 0xFFFFFFFF;
    ProcessIdToSessionId(pi.dwProcessId, &targetSession);
    newGuard = info;
    newGuard.pid = pi.dwProcessId;
    newGuard.sessionId = targetSession;
    newGuard.handle = pi.hProcess;
    newGuard.intentional = false;
    newGuard.jobHandle = nullptr;
    inheritRestartProfile(newGuard, info);

    Logger::warning("PGS: restart launched in fallback session, pid=" + std::to_string(pi.dwProcessId) +
                    ", session=" + std::to_string(targetSession));
    CloseHandle(pi.hThread);
    return true;
}

bool PGS::restartGuardInSession(const GuardInfo &info, int restartIndex, GuardInfo &newGuard, std::string &failureCode, std::string &failureMessage)
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
            return setRestartFailure(failureCode, failureMessage, "restart.session_token", "failed to query user token for session=" + std::to_string(targetSessionId) + " or active session=" + std::to_string(activeSession));
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
        const DWORD err = GetLastError();
        Logger::warning("PGS: DuplicateTokenEx failed for restart session=" +
                        std::to_string(targetSessionId) +
                        ", error=" + std::to_string(err));
        return setRestartFailure(failureCode, failureMessage, "restart.duplicate_token", "DuplicateTokenEx failed for restart session=" + std::to_string(targetSessionId) + ", error=" + std::to_string(err));
    }

    if (!SetTokenInformation(primaryToken, TokenSessionId, &targetSessionId, sizeof(targetSessionId)))
    {
        const DWORD err = GetLastError();
        Logger::warning("PGS: SetTokenInformation(TokenSessionId) failed for restart session=" +
                        std::to_string(targetSessionId) +
                        ", error=" + std::to_string(err));
        CloseHandle(primaryToken);
        return setRestartFailure(failureCode, failureMessage, "restart.session_token", "SetTokenInformation(TokenSessionId) failed for restart session=" + std::to_string(targetSessionId) + ", error=" + std::to_string(err));
    }

    LPVOID envBlock = nullptr;
    if (!CreateEnvironmentBlock(&envBlock, primaryToken, FALSE))
    {
        const DWORD err = GetLastError();
        Logger::warning("PGS: CreateEnvironmentBlock failed for restart session=" +
                        std::to_string(targetSessionId) +
                        ", error=" + std::to_string(err));
        CloseHandle(primaryToken);
        return setRestartFailure(failureCode, failureMessage, "restart.environment", "CreateEnvironmentBlock failed for restart session=" + std::to_string(targetSessionId) + ", error=" + std::to_string(err));
    }

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
        return setRestartFailure(failureCode, failureMessage, "restart.path_encoding", "path conversion failed for path=" + info.path);
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
    const DWORD createErr = ok ? ERROR_SUCCESS : GetLastError();

    if (envBlock)
    {
        DestroyEnvironmentBlock(envBlock);
    }
    CloseHandle(primaryToken);

    if (!ok)
    {
        Logger::warning("PGS: CreateProcessAsUserW failed for restart path=" + info.path +
                        ", session=" + std::to_string(targetSessionId) +
                        ", error=" + std::to_string(createErr));
        return setRestartFailure(failureCode, failureMessage, "restart.create_process_as_user", "CreateProcessAsUserW failed for restart path=" + info.path + ", session=" + std::to_string(targetSessionId) + ", error=" + std::to_string(createErr));
    }

    newGuard = info;
    newGuard.pid = pi.dwProcessId;
    newGuard.sessionId = targetSessionId;
    newGuard.handle = pi.hProcess;
    newGuard.intentional = false;
    newGuard.jobHandle = nullptr;
    inheritRestartProfile(newGuard, info);

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

    constexpr BOOL exclusive = TRUE;
    if (setsockopt(m_listenSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
                   reinterpret_cast<const char *>(&exclusive), sizeof(exclusive)) == SOCKET_ERROR)
    {
        Logger::error("PGS: SO_EXCLUSIVEADDRUSE failed, error=" + std::to_string(WSAGetLastError()));
        closeListenSocket();
        return false;
    }

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
    if (m_ioPort)
    {
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT acp{};
        acp.CompletionPort = m_ioPort;
        acp.CompletionKey = reinterpret_cast<PVOID>(static_cast<uintptr_t>(guardId));
        if (!SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &acp, sizeof(acp)))
        {
            Logger::warning("PGS: survivor job completion-port rebind failed guard-id=" +
                            std::to_string(guardId) +
                            ", error=" + std::to_string(GetLastError()));
        }
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

void PGS::closeGuardJob(std::uint64_t guardId, bool preserveProcesses)
{
    std::lock_guard<std::mutex> lock(m_jobMutex);
    const auto it = m_jobs.find(guardId);
    if (it != m_jobs.end())
    {
        if (it->second)
        {
            if (preserveProcesses)
            {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli{};
                if (QueryInformationJobObject(it->second, JobObjectExtendedLimitInformation, &eli, sizeof(eli), nullptr))
                {
                    eli.BasicLimitInformation.LimitFlags &= ~JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                    if (!SetInformationJobObject(it->second, JobObjectExtendedLimitInformation, &eli, sizeof(eli)))
                    {
                        Logger::warning("PGS: failed to clear kill-on-job-close guard-id=" +
                                        std::to_string(guardId) +
                                        ", error=" + std::to_string(GetLastError()));
                    }
                }
                else
                {
                    Logger::warning("PGS: failed to query job limits guard-id=" +
                                    std::to_string(guardId) +
                                    ", error=" + std::to_string(GetLastError()));
                }
            }
            CloseHandle(it->second);
        }
        m_jobs.erase(it);
    }
}

bool PGS::setGuardJobKillOnExit(std::uint64_t guardId, bool killOnExit)
{
    std::lock_guard<std::mutex> lock(m_jobMutex);
    const auto it = m_jobs.find(guardId);
    if (it == m_jobs.end() || !it->second)
    {
        return false;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli{};
    if (!QueryInformationJobObject(it->second, JobObjectExtendedLimitInformation, &eli, sizeof(eli), nullptr))
    {
        Logger::warning("PGS: failed to query job limits for policy update guard-id=" +
                        std::to_string(guardId) +
                        ", error=" + std::to_string(GetLastError()));
        return false;
    }

    if (killOnExit)
    {
        eli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }
    else
    {
        eli.BasicLimitInformation.LimitFlags &= ~JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }

    if (!SetInformationJobObject(it->second, JobObjectExtendedLimitInformation, &eli, sizeof(eli)))
    {
        Logger::warning("PGS: failed to update kill-on-exit for job guard-id=" +
                        std::to_string(guardId) +
                        ", error=" + std::to_string(GetLastError()));
        return false;
    }
    return true;
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
            if (err == ERROR_TIMEOUT)
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

bool PGS::restartAppGuard(const GuardInfo &info, int restartIndex, GuardInfo &newGuard, std::string &failureCode, std::string &failureMessage)
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
        return setRestartFailure(failureCode, failureMessage, "winapp.missing_aumid", "WindowsApps restart requires AUMID for path=" + info.path);
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
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &userToken))
        {
            Logger::warning("PGS: winapp restart could not open current process token, error=" +
                            std::to_string(GetLastError()));
        }
    }
    if (!userToken && !queryUserTokenForSession(targetSessionId, userToken))
    {
        const DWORD activeSession = WTSGetActiveConsoleSessionId();
        if (mySession != 0xFFFFFFFF && mySession == activeSession)
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &userToken))
            {
                Logger::warning("PGS: winapp restart could not open active-session process token, error=" +
                                std::to_string(GetLastError()));
            }
        }
    if (!userToken && !queryUserTokenForSession(activeSession, userToken))
        {
            Logger::error("PGS: winapp restart failed, no user token for any session, aumid=" + info.aumid);
            return setRestartFailure(failureCode, failureMessage, "winapp.no_user_token", "no user token for WindowsApps restart, aumid=" + info.aumid);
        }
        targetSessionId = activeSession;
    }
    HANDLE primaryToken = nullptr;
    if (!DuplicateTokenEx(userToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenImpersonation, &primaryToken))
    {
        const DWORD err = GetLastError();
        CloseHandle(userToken);
        Logger::error("PGS: winapp restart failed, DuplicateTokenEx error=" + std::to_string(err));
        return setRestartFailure(failureCode, failureMessage, "winapp.duplicate_token", "DuplicateTokenEx failed for WindowsApps restart, error=" + std::to_string(err));
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
        const DWORD err = GetLastError();
        CloseHandle(primaryToken);
        Logger::error("PGS: winapp restart failed, SetThreadToken error=" + std::to_string(err));
        return setRestartFailure(failureCode, failureMessage, "winapp.set_thread_token", "SetThreadToken failed for WindowsApps restart, error=" + std::to_string(err));
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
        const DWORD err = GetLastError();
        Logger::error("PGS: winapp restart failed, aumid=" + info.aumid +
                      ", error=" + std::to_string(err));
        if (procHandle)
        {
            CloseHandle(procHandle);
        }
        return setRestartFailure(failureCode, failureMessage, "winapp.activate_failed", "WindowsApps activation failed, aumid=" + info.aumid + ", error=" + std::to_string(err));
    }

    DWORD sessionId = 0xFFFFFFFF;
    ProcessIdToSessionId(activatedPid, &sessionId);
    newGuard = info;
    newGuard.pid = activatedPid;
    newGuard.sessionId = sessionId;
    newGuard.handle = procHandle;
    newGuard.intentional = false;
    newGuard.appKind = AppKind::WinApp;
    newGuard.jobHandle = nullptr;
    inheritRestartProfile(newGuard, info);
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
        policy.restartCount = static_cast<int>(policy.recentRestartMs.size());
        return policy.restartCount;
    }
    if (policy.restartCount < std::numeric_limits<int>::max())
    {
        ++policy.restartCount;
    }
    return policy.restartCount;
}
} // namespace ProcessGuard
