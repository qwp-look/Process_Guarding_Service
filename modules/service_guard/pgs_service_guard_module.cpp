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
#include <sstream>
#include <string>

#include "Process_Guard/PGModule.h"

namespace
{
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
        if (!confirm) return "ERR service mutation requires confirm=1";
        if (!isSafeServiceName(name)) return "ERR invalid service name";
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return "ERR OpenSCManager failed: " + win32Error(GetLastError());
        const DWORD access = SERVICE_QUERY_STATUS | (op == "start" ? SERVICE_START : SERVICE_STOP);
        SC_HANDLE svc = OpenServiceW(scm, utf8ToWide(name).c_str(), access);
        if (!svc)
        {
            const std::string err = "ERR OpenService failed: " + win32Error(GetLastError());
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
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                return "ERR " + op + " failed: " + win32Error(err);
            }
        }
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return queryResponse(name);
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
    return "name=service_guard;version=1.0.0;abi=3;summary=Local Windows service guard helper;capabilities=service.query,service.start,service.stop";
}

PG_MODULE_API int PG_Init(void *) { return 0; }
PG_MODULE_API void PG_Shutdown(void) {}

PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize)
{
    const std::string req = request ? request : "";
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "status" : requestValue(req, "op")));
    if (op == "status")
    {
        setResponse(responseBuf, responseBufSize, "OK scm=local;mutations_require_confirm=1");
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
