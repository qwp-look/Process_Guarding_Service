/*
 * pgs_service_guard_module.cpp - local Windows Service Control Manager helper.
 *
 * Provides explicit status/start/stop/ensure operations for Windows services.
 * Mutations require confirm=1. This module does not contact remote services.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

#include <windows.h>
#include <winsvc.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "Process_Guard/PGModule.h"

namespace
{
    PGS_ServicesV3 g_services{};
    bool g_servicesReady = false;
    std::filesystem::path g_policyPath;
    std::mutex g_mutex;

    constexpr std::size_t kMaxAllowServices = 128;

    struct ServicePolicy
    {
        std::vector<std::string> allow;
        bool allowProtected = false;
    };

    const char *const kProtectedServices[] = {
        "bits",
        "cryptsvc",
        "dcomlaunch",
        "eventlog",
        "gpsvc",
        "lanmanserver",
        "lanmanworkstation",
        "lsm",
        "mpssvc",
        "nsi",
        "plugplay",
        "rpcss",
        "samss",
        "schedule",
        "securityhealthservice",
        "sense",
        "termservice",
        "trustedinstaller",
        "w32time",
        "wdnissvc",
        "windefend",
        "winmgmt",
        "wscsvc"
    };

    std::string trim(std::string value)
    {
        const char *ws = " \t\r\n";
        const std::size_t first = value.find_first_not_of(ws);
        if (first == std::string::npos) return std::string();
        const std::size_t last = value.find_last_not_of(ws);
        return value.substr(first, last - first + 1);
    }

    std::string lower(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        return value;
    }

    std::string requestValue(const std::string &request, const std::string &key)
    {
        const std::string needle = key + "=";
        std::size_t pos = request.find(needle);
        if (pos == std::string::npos) return std::string();
        pos += needle.size();
        const std::size_t end = request.find(';', pos);
        return end == std::string::npos ? request.substr(pos) : request.substr(pos, end - pos);
    }

    bool truthy(const std::string &value)
    {
        const std::string v = lower(trim(value));
        return v == "1" || v == "true" || v == "yes" || v == "on" || v == "confirm";
    }

    bool requestHasKey(const std::string &request, const std::string &key)
    {
        return request.find(key + "=") != std::string::npos;
    }

    bool isSafeServiceName(const std::string &name)
    {
        if (name.empty() || name.size() > 256) return false;
        for (unsigned char ch : name)
        {
            if (ch == ';' || ch == '\r' || ch == '\n' || ch == '\0' || ch == '/' || ch == '\\') return false;
            if (ch < 0x20) return false;
        }
        return true;
    }

    std::string canonicalServiceName(const std::string &name)
    {
        return lower(trim(name));
    }

    bool isProtectedServiceName(const std::string &name)
    {
        const std::string key = canonicalServiceName(name);
        for (const char *protectedName : kProtectedServices)
        {
            if (key == protectedName) return true;
        }
        return false;
    }

    std::string base64Encode(const std::string &input)
    {
        static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        int val = 0;
        int valb = -6;
        for (unsigned char c : input)
        {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0)
            {
                out.push_back(alphabet[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6) out.push_back(alphabet[((val << 8) >> (valb + 8)) & 0x3F]);
        while (out.size() % 4) out.push_back('=');
        return out;
    }

    std::string base64Decode(const std::string &input)
    {
        static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<int> table(256, -1);
        for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(chars[static_cast<std::size_t>(i)])] = i;
        std::string out;
        int val = 0;
        int valb = -8;
        for (unsigned char c : input)
        {
            if (c == '=') break;
            if (table[c] < 0) continue;
            val = (val << 6) + table[c];
            valb += 6;
            if (valb >= 0)
            {
                out.push_back(static_cast<char>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }

    std::string jsonEscape(const std::string &value)
    {
        std::ostringstream out;
        for (unsigned char ch : value)
        {
            switch (ch)
            {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20) out << "\\u00" << "0123456789abcdef"[(ch >> 4) & 0x0F] << "0123456789abcdef"[ch & 0x0F];
                else out << static_cast<char>(ch);
                break;
            }
        }
        return out.str();
    }

    std::string wideToUtf8(const std::wstring &input)
    {
        if (input.empty()) return std::string();
        const int len = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
        if (len <= 0) return std::string(input.begin(), input.end());
        std::string out(static_cast<std::size_t>(len), '\0');
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), out.data(), len, nullptr, nullptr);
        return out;
    }

    std::wstring utf8ToWide(const std::string &input)
    {
        if (input.empty()) return std::wstring();
        const int needed = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
        if (needed <= 0) return std::wstring(input.begin(), input.end());
        std::wstring out(static_cast<std::size_t>(needed), L'\0');
        if (MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, &out[0], needed) <= 0) return std::wstring(input.begin(), input.end());
        if (!out.empty() && out.back() == L'\0') out.pop_back();
        return out;
    }

    std::string win32Error(DWORD code)
    {
        char *buffer = nullptr;
        const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
        const DWORD len = FormatMessageA(flags, nullptr, code, 0, reinterpret_cast<LPSTR>(&buffer), 0, nullptr);
        std::string out = len && buffer ? std::string(buffer, len) : ("win32=" + std::to_string(code));
        if (buffer) LocalFree(buffer);
        while (!out.empty() && (out.back() == '\r' || out.back() == '\n' || out.back() == ' ' || out.back() == '\t')) out.pop_back();
        return out;
    }

    std::filesystem::path policyPath()
    {
        return g_policyPath.empty() ? std::filesystem::path(L"service_guard_policy.cfg") : g_policyPath;
    }

    std::string policyPathUtf8()
    {
        return wideToUtf8(policyPath().wstring());
    }

    bool appendUniqueService(std::vector<std::string> &values, const std::string &name)
    {
        const std::string trimmed = trim(name);
        const std::string key = canonicalServiceName(trimmed);
        if (trimmed.empty() || !isSafeServiceName(trimmed)) return false;
        for (const std::string &existing : values)
        {
            if (canonicalServiceName(existing) == key) return true;
        }
        if (values.size() >= kMaxAllowServices) return false;
        values.push_back(trimmed);
        return true;
    }

    bool parseServiceList(const std::string &text, std::vector<std::string> &out, std::string &error)
    {
        out.clear();
        error.clear();
        std::string current;
        auto flush = [&]() -> bool {
            const std::string item = trim(current);
            current.clear();
            if (item.empty()) return true;
            if (!isSafeServiceName(item))
            {
                error = "invalid service name in allow policy";
                return false;
            }
            if (!appendUniqueService(out, item))
            {
                error = "service_guard allow policy limit reached";
                return false;
            }
            return true;
        };
        for (char ch : text)
        {
            if (ch == ',')
            {
                if (!flush()) return false;
            }
            else
            {
                current.push_back(ch);
            }
        }
        return flush();
    }

    std::string joinCsv(const std::vector<std::string> &values)
    {
        std::ostringstream out;
        for (std::size_t i = 0; i < values.size(); ++i)
        {
            if (i != 0) out << ',';
            out << values[i];
        }
        return out.str();
    }

    ServicePolicy loadPolicy()
    {
        ServicePolicy policy;
        std::ifstream in(policyPath(), std::ios::in | std::ios::binary);
        std::string line;
        while (std::getline(in, line))
        {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            const std::size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            const std::string key = lower(trim(line.substr(0, eq)));
            const std::string value = trim(line.substr(eq + 1));
            if (key == "allow_protected")
            {
                policy.allowProtected = truthy(value);
            }
            else if (key == "allow")
            {
                appendUniqueService(policy.allow, value);
            }
        }
        if (policy.allow.empty()) policy.allowProtected = false;
        return policy;
    }

    bool savePolicy(const ServicePolicy &policy)
    {
        const std::filesystem::path path = policyPath();
        std::error_code ec;
        if (!path.parent_path().empty())
        {
            std::filesystem::create_directories(path.parent_path(), ec);
            if (ec) return false;
        }
        std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out << "allow_protected=" << (policy.allowProtected ? "1" : "0") << "\n";
        for (const std::string &name : policy.allow)
        {
            out << "allow=" << name << "\n";
        }
        return true;
    }

    bool policyAllowsMutation(const ServicePolicy &policy, const std::string &name, std::string &reason)
    {
        if (isProtectedServiceName(name) && !policy.allowProtected)
        {
            reason = "protected-service";
            return false;
        }
        if (!policy.allow.empty())
        {
            const std::string key = canonicalServiceName(name);
            const bool listed = std::any_of(policy.allow.begin(), policy.allow.end(), [&](const std::string &allowed) {
                return canonicalServiceName(allowed) == key;
            });
            if (!listed)
            {
                reason = "not-allowlisted";
                return false;
            }
        }
        return true;
    }

    std::string policyFields(const ServicePolicy &policy, bool includePath)
    {
        std::string out = "mutation_policy=confirm_plus_allowlist_plus_protected_deny";
        out += ";allowlist_mode=";
        out += policy.allow.empty() ? "disabled" : "enabled";
        out += ";allow_count=" + std::to_string(policy.allow.size());
        out += ";allow_protected=" + std::string(policy.allowProtected ? "1" : "0");
        out += ";protected_services=" + std::to_string(sizeof(kProtectedServices) / sizeof(kProtectedServices[0]));
        out += ";max_allow_services=" + std::to_string(kMaxAllowServices);
        if (includePath)
        {
            out += ";policy_path_b64=" + base64Encode(policyPathUtf8());
            out += ";allow_b64=" + base64Encode(joinCsv(policy.allow));
        }
        return out;
    }

    PGS_ServicesV3 servicesSnapshot()
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        return g_servicesReady ? g_services : PGS_ServicesV3{};
    }

    void emitAuditEvent(const std::string &type, const std::string &op, const std::string &name,
                        const std::string &result, const std::string &reason)
    {
        PGS_ServicesV3 services = servicesSnapshot();
        if (!services.emit_event) return;
        std::ostringstream event;
        event << "{\"type\":\"" << jsonEscape(type)
              << "\",\"module\":\"service_guard\""
              << ",\"op\":\"" << jsonEscape(op) << "\""
              << ",\"name\":\"" << jsonEscape(name) << "\""
              << ",\"result\":\"" << jsonEscape(result) << "\""
              << ",\"reason\":\"" << jsonEscape(reason) << "\""
              << ",\"caller\":\"authenticated-management-client\"}";
        services.emit_event(services.context, event.str().c_str());
    }

    void emitPolicyEvent(const ServicePolicy &policy, const std::string &result, const std::string &reason)
    {
        PGS_ServicesV3 services = servicesSnapshot();
        if (!services.emit_event) return;
        std::ostringstream event;
        event << "{\"type\":\"service_guard.policy\""
              << ",\"module\":\"service_guard\""
              << ",\"result\":\"" << jsonEscape(result) << "\""
              << ",\"reason\":\"" << jsonEscape(reason) << "\""
              << ",\"allow_count\":" << policy.allow.size()
              << ",\"allow_protected\":" << (policy.allowProtected ? "true" : "false")
              << ",\"caller\":\"authenticated-management-client\"}";
        services.emit_event(services.context, event.str().c_str());
    }

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0) return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
    }

    std::string stateText(DWORD state)
    {
        switch (state)
        {
        case SERVICE_STOPPED: return "stopped";
        case SERVICE_START_PENDING: return "start_pending";
        case SERVICE_STOP_PENDING: return "stop_pending";
        case SERVICE_RUNNING: return "running";
        case SERVICE_CONTINUE_PENDING: return "continue_pending";
        case SERVICE_PAUSE_PENDING: return "pause_pending";
        case SERVICE_PAUSED: return "paused";
        default: return "unknown";
        }
    }

    bool queryService(const std::string &name, SERVICE_STATUS_PROCESS &status, std::string &error, DWORD desiredAccess = SERVICE_QUERY_STATUS)
    {
        if (!isSafeServiceName(name))
        {
            error = "invalid service name";
            return false;
        }
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm)
        {
            error = "OpenSCManager failed: " + win32Error(GetLastError());
            return false;
        }
        SC_HANDLE svc = OpenServiceW(scm, utf8ToWide(name).c_str(), desiredAccess | SERVICE_QUERY_STATUS);
        if (!svc)
        {
            error = "OpenService failed: " + win32Error(GetLastError());
            CloseServiceHandle(scm);
            return false;
        }
        DWORD needed = 0;
        const BOOL ok = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&status), sizeof(status), &needed);
        if (!ok) error = "QueryServiceStatusEx failed: " + win32Error(GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return ok == TRUE;
    }

    std::string queryResponse(const std::string &name)
    {
        SERVICE_STATUS_PROCESS status{};
        std::string error;
        if (!queryService(name, status, error)) return "ERR " + error;
        std::ostringstream out;
        out << "OK name=" << name
            << ";state=" << stateText(status.dwCurrentState)
            << ";pid=" << status.dwProcessId
            << ";win32_exit=" << status.dwWin32ExitCode;
        return out.str();
    }

    std::string mutateService(const std::string &op, const std::string &name, bool confirm)
    {
        if (!isSafeServiceName(name)) return "ERR invalid service name";
        if (!confirm)
        {
            emitAuditEvent("service_guard.mutation-denied", op, name, "denied", "confirm-required");
            return "ERR service mutation requires confirm=1";
        }
        ServicePolicy policy;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            policy = loadPolicy();
        }
        std::string policyReason;
        if (!policyAllowsMutation(policy, name, policyReason))
        {
            emitAuditEvent("service_guard.mutation-denied", op, name, "denied", policyReason);
            return "ERR service mutation denied by policy: " + policyReason;
        }
        emitAuditEvent("service_guard.mutation-attempt", op, name, "attempt", "confirm=1");
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm)
        {
            const std::string error = "OpenSCManager failed: " + win32Error(GetLastError());
            emitAuditEvent("service_guard.mutation-failed", op, name, "failed", error);
            return "ERR " + error;
        }
        const DWORD access = SERVICE_QUERY_STATUS | (op == "start" ? SERVICE_START : SERVICE_STOP);
        SC_HANDLE svc = OpenServiceW(scm, utf8ToWide(name).c_str(), access);
        if (!svc)
        {
            const std::string error = "OpenService failed: " + win32Error(GetLastError());
            emitAuditEvent("service_guard.mutation-failed", op, name, "failed", error);
            const std::string err = "ERR " + error;
            CloseServiceHandle(scm);
            return err;
        }
        BOOL ok = FALSE;
        if (op == "start") ok = StartServiceW(svc, 0, nullptr);
        else
        {
            SERVICE_STATUS status{};
            ok = ControlService(svc, SERVICE_CONTROL_STOP, &status);
        }
        if (!ok)
        {
            const DWORD err = GetLastError();
            if ((op == "start" && err != ERROR_SERVICE_ALREADY_RUNNING) || (op == "stop" && err != ERROR_SERVICE_NOT_ACTIVE))
            {
                const std::string error = op + " failed: " + win32Error(err);
                emitAuditEvent("service_guard.mutation-failed", op, name, "failed", error);
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                return "ERR " + error;
            }
        }
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        const std::string response = queryResponse(name);
        emitAuditEvent(response.rfind("OK", 0) == 0 ? "service_guard.mutation" : "service_guard.mutation-failed",
                       op, name, response.rfind("OK", 0) == 0 ? "succeeded" : "failed",
                       response.rfind("OK", 0) == 0 ? "" : response);
        return response;
    }

    std::string statusResponse()
    {
        ServicePolicy policy;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            policy = loadPolicy();
        }
        return "OK scm=local;mutations_require_confirm=1;" + policyFields(policy, false);
    }

    std::string handlePolicy(const std::string &request)
    {
        const std::string action = lower(trim(requestValue(request, "action").empty() ? "status" : requestValue(request, "action")));
        if (action == "status")
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            return "OK " + policyFields(loadPolicy(), true);
        }
        if (action != "set" && action != "clear")
        {
            return "ERR unknown service_guard policy action";
        }
        if (!truthy(requestValue(request, "confirm")))
        {
            return "ERR service_guard policy update requires confirm=1";
        }

        ServicePolicy policy;
        std::string eventReason;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            policy = loadPolicy();
            if (action == "clear")
            {
                policy = ServicePolicy{};
                eventReason = "cleared";
            }
            else
            {
                const bool hasAllow = requestHasKey(request, "allow_b64") || requestHasKey(request, "allow");
                if (hasAllow)
                {
                    const std::string listText = requestHasKey(request, "allow_b64")
                        ? base64Decode(requestValue(request, "allow_b64"))
                        : requestValue(request, "allow");
                    std::vector<std::string> parsed;
                    std::string parseError;
                    if (!parseServiceList(listText, parsed, parseError))
                    {
                        return "ERR " + parseError;
                    }
                    policy.allow = std::move(parsed);
                }
                if (requestHasKey(request, "allow_protected"))
                {
                    policy.allowProtected = truthy(requestValue(request, "allow_protected"));
                }
                if (policy.allow.empty() && policy.allowProtected)
                {
                    return "ERR allow_protected requires a non-empty service allowlist";
                }
                eventReason = hasAllow ? "allowlist-updated" : "policy-updated";
            }
            if (!savePolicy(policy)) return "ERR failed to persist service_guard policy";
        }
        emitPolicyEvent(policy, "updated", eventReason);
        return "OK " + policyFields(policy, true);
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "service_guard"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=service_guard;version=1.0.0;abi=3;summary=Local Windows service guard helper;capabilities=service.query,service.start,service.stop,service.policy,event.emit";
}

PG_MODULE_API int PG_Init(void *reserved)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_servicesReady = false;
    g_services = PGS_ServicesV3{};
    g_policyPath.clear();
    if (reserved)
    {
        const PGS_ServicesV3 *services = static_cast<const PGS_ServicesV3 *>(reserved);
        if (services->size >= sizeof(PGS_Services))
        {
            if (services->size >= sizeof(PGS_ServicesV3)) g_services = *services;
            else
            {
                const PGS_Services *v2 = static_cast<const PGS_Services *>(reserved);
                g_services.size = v2->size;
                g_services.context = v2->context;
                g_services.call = v2->call;
                g_services.now_ms = v2->now_ms;
            }
            g_servicesReady = (g_services.context != nullptr);
        }
    }
    if (g_servicesReady && g_services.get_data_dir)
    {
        const char *root = g_services.get_data_dir(g_services.context);
        if (root && root[0]) g_policyPath = std::filesystem::path(utf8ToWide(root)) / L"modules" / L"service_guard" / L"service_guard_policy.cfg";
    }
    if (g_policyPath.empty()) g_policyPath = std::filesystem::path(L"service_guard_policy.cfg");
    return 0;
}

PG_MODULE_API void PG_Shutdown(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_services = PGS_ServicesV3{};
    g_servicesReady = false;
    g_policyPath.clear();
}

PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize)
{
    const std::string req = request ? request : "";
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "status" : requestValue(req, "op")));
    if (op == "status")
    {
        setResponse(responseBuf, responseBufSize, statusResponse());
        return 0;
    }
    if (op == "policy")
    {
        const std::string response = handlePolicy(req);
        setResponse(responseBuf, responseBufSize, response);
        return response.rfind("OK", 0) == 0 ? 0 : 1;
    }
    if (op == "protected")
    {
        std::ostringstream out;
        out << "OK count=" << (sizeof(kProtectedServices) / sizeof(kProtectedServices[0]));
        for (const char *name : kProtectedServices)
        {
            out << "\nSERVICE name=" << name;
        }
        setResponse(responseBuf, responseBufSize, out.str());
        return 0;
    }
    const std::string name = trim(requestValue(req, "name"));
    if (op == "query")
    {
        const std::string response = queryResponse(name);
        setResponse(responseBuf, responseBufSize, response);
        return response.rfind("OK", 0) == 0 ? 0 : 1;
    }
    if (op == "start" || op == "stop")
    {
        const std::string response = mutateService(op, name, truthy(requestValue(req, "confirm")));
        setResponse(responseBuf, responseBufSize, response);
        return response.rfind("OK", 0) == 0 ? 0 : 1;
    }
    if (op == "ensure")
    {
        const std::string state = lower(trim(requestValue(req, "state")));
        if (state != "running" && state != "stopped")
        {
            setResponse(responseBuf, responseBufSize, "ERR ensure state must be running or stopped");
            return 1;
        }
        SERVICE_STATUS_PROCESS status{};
        std::string error;
        if (!queryService(name, status, error))
        {
            setResponse(responseBuf, responseBufSize, "ERR " + error);
            return 1;
        }
        if ((state == "running" && status.dwCurrentState == SERVICE_RUNNING) || (state == "stopped" && status.dwCurrentState == SERVICE_STOPPED))
        {
            setResponse(responseBuf, responseBufSize, queryResponse(name));
            return 0;
        }
        const std::string response = mutateService(state == "running" ? "start" : "stop", name, truthy(requestValue(req, "confirm")));
        setResponse(responseBuf, responseBufSize, response);
        return response.rfind("OK", 0) == 0 ? 0 : 1;
    }
    setResponse(responseBuf, responseBufSize, "ERR unknown service_guard op");
    return 1;
}

PG_MODULE_API int PG_InvokeJson(const char *requestJson, char *responseJson, size_t responseJsonSize)
{
    (void)requestJson;
    setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":\"USE_KV\",\"message\":\"service_guard JSON entry is reserved; use module call KV\"}}");
    return 1;
}

} // extern "C"
