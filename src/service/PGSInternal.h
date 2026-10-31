#ifndef PGS_INTERNAL_H
#define PGS_INTERNAL_H

// File-local helpers shared by the pgs_core translation units
// (PGS.cpp, PGSServer.cpp, PGSMonitor.cpp, PGSHealth.cpp, PGSGuardStore.cpp).
// Everything here used to live in the anonymous namespace of PGS.cpp; it was
// promoted to inline definitions in pgs_internal when the core was split.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wtsapi32.h>

#include <cstdint>
#include <string>
#include <vector>

namespace ProcessGuard
{
namespace pgs_internal
{

// File-local helpers: only the few that are NOT in ProcessGuard::util live here
// (numeric/bool parsing and the WTS session-token helper). Encoding, hashing,
// path/process and string helpers now come from Process_Guard/PGUtil.h.

// Alias the utf8 path-normalizer to the historical call-site name.
inline std::string normalizePathForCompare(const std::string &p) { return util::normalizePathForCompareUtf8(p); }

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

inline bool setRestartFailure(std::string &code, std::string &message,
                       const std::string &failureCode, const std::string &failureMessage)
{
    code = failureCode;
    message = failureMessage;
    return false;
}

inline bool isSha256Hex(const std::string &value)
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

inline std::string sanitizeGroupName(std::string name)
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

inline std::vector<std::string> splitCsvTrimmed(const std::string &value)
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

inline std::string joinCsv(const std::vector<std::string> &values)
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

inline bool parseInt64Field(const std::string &value, std::int64_t &out)
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

inline bool parseIntField(const std::string &value, int &out)
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

inline bool looksLikeJsonObjectOrArray(const std::string &text)
{
    const std::string t = ProcessGuard::util::trim(text);
    return !t.empty() && ((t.front() == '{' && t.back() == '}') || (t.front() == '[' && t.back() == ']'));
}

inline std::string jsonStringValue(const std::string &text, const std::string &key)
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

inline std::string jsonScalarValue(const std::string &text, const std::string &key)
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

inline bool jsonIntValue(const std::string &text, const std::string &key, int &out)
{
    const std::string value = jsonScalarValue(text, key);
    if (value.empty())
    {
        return false;
    }
    return parseIntField(value, out);
}

inline bool jsonBoolValue(const std::string &text, const std::string &key, bool defaultValue)
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

inline int clampHealthInt(int value, int minValue, int maxValue)
{
    return std::max(minValue, std::min(maxValue, value));
}

inline bool parseHealthCheckConfig(const std::string &json, HealthCheckConfig &out, std::string &err)
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

inline bool duplicateProcessHandle(HANDLE source, HANDLE &out)
{
    out = nullptr;
    if (!source)
    {
        return false;
    }
    return DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &out, 0, FALSE, DUPLICATE_SAME_ACCESS) == TRUE;
}

inline bool probeProcessHealth(const HealthTask &task, std::string &message)
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

inline bool probeTcpHealth(const HealthCheckConfig &cfg, std::string &message)
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

inline bool probeHttpHealth(const HealthCheckConfig &cfg, std::string &message)
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

inline bool runHealthProbe(const HealthTask &task, const HealthCheckConfig &cfg, std::string &message)
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
inline bool enableProcessPrivilege(LPCWSTR privName)
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
inline bool queryUserTokenForSession(DWORD sessionId, HANDLE &userToken)
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

inline std::string finalPathForCompareUtf8(const std::string &pathUtf8, bool directory)
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

} // namespace pgs_internal
} // namespace ProcessGuard

#endif // PGS_INTERNAL_H
