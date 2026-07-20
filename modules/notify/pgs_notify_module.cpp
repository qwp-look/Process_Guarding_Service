/*
 * pgs_notify_module.cpp - Windows-native PGS notification module (ABI v3).
 *
 * Channels intentionally stay local to Windows: Application Event Log is on by
 * default, while MessageBox popup is explicit opt-in. No chat software,
 * webhook, mail, or remote messenger integration lives here.
 *
 * Request KV examples:
 *   op=status
 *   op=config;eventlog=1;popup=0
 *   op=event;type=guard.quarantine;detail_b64=...
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "Process_Guard/PGModule.h"

namespace
{
    PGS_ServicesV3 g_services{};
    bool g_servicesReady = false;
    std::filesystem::path g_configPath;
    bool g_eventLogEnabled = true;
    bool g_popupEnabled = false;

    std::string trim(std::string value)
    {
        const char *ws = " \t\r\n";
        const std::size_t first = value.find_first_not_of(ws);
        if (first == std::string::npos)
            return std::string();
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
        if (pos == std::string::npos)
            return std::string();
        pos += needle.size();
        const std::size_t end = request.find(';', pos);
        return end == std::string::npos ? request.substr(pos) : request.substr(pos, end - pos);
    }

    bool parseBool(const std::string &value, bool fallback)
    {
        const std::string v = lower(trim(value));
        if (v.empty()) return fallback;
        if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
        if (v == "0" || v == "false" || v == "no" || v == "off") return false;
        return fallback;
    }

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0)
            return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
    }

    std::wstring utf8ToWide(const std::string &input)
    {
        if (input.empty()) return std::wstring();
        const int len = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
        if (len <= 0) return std::wstring(input.begin(), input.end());
        std::wstring out(static_cast<std::size_t>(len - 1), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, out.data(), len);
        return out;
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

    std::string base64Decode(const std::string &input)
    {
        static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::vector<int> table(256, -1);
        for (int i = 0; i < static_cast<int>(alphabet.size()); ++i)
            table[static_cast<unsigned char>(alphabet[static_cast<std::size_t>(i)])] = i;
        std::string out;
        int val = 0;
        int valb = -8;
        for (unsigned char ch : input)
        {
            if (ch == '=') break;
            if (table[ch] == -1) continue;
            val = (val << 6) + table[ch];
            valb += 6;
            if (valb >= 0)
            {
                out.push_back(static_cast<char>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }

    std::string base64Encode(const std::string &input)
    {
        static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        int val = 0;
        int valb = -6;
        for (unsigned char ch : input)
        {
            val = (val << 8) + ch;
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

    void saveConfig()
    {
        if (g_configPath.empty()) return;
        std::error_code ec;
        std::filesystem::create_directories(g_configPath.parent_path(), ec);
        std::ofstream out(g_configPath, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return;
        out << "eventlog=" << (g_eventLogEnabled ? "1" : "0") << "\n";
        out << "popup=" << (g_popupEnabled ? "1" : "0") << "\n";
    }

    void loadConfig()
    {
        g_eventLogEnabled = true;
        g_popupEnabled = false;
        if (g_configPath.empty()) return;
        std::ifstream in(g_configPath, std::ios::in | std::ios::binary);
        std::string line;
        while (std::getline(in, line))
        {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            const std::size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            const std::string key = lower(trim(line.substr(0, eq)));
            const std::string value = trim(line.substr(eq + 1));
            if (key == "eventlog") g_eventLogEnabled = parseBool(value, g_eventLogEnabled);
            if (key == "popup") g_popupEnabled = parseBool(value, g_popupEnabled);
        }
    }

    WORD eventTypeFor(const std::string &type)
    {
        const std::string t = lower(type);
        if (t.find("failed") != std::string::npos ||
            t.find("failure") != std::string::npos ||
            t.find("quarantine") != std::string::npos ||
            t.find("unhealthy") != std::string::npos ||
            t.find("config-error") != std::string::npos)
        {
            return EVENTLOG_ERROR_TYPE;
        }
        if (t.find("restart") != std::string::npos || t.find("hung") != std::string::npos)
        {
            return EVENTLOG_WARNING_TYPE;
        }
        return EVENTLOG_INFORMATION_TYPE;
    }

    bool writeEventLog(const std::string &type, const std::string &detail)
    {
        HANDLE source = RegisterEventSourceW(nullptr, L"ProcessGuardService");
        if (!source) return false;
        const std::wstring line1 = utf8ToWide("PGS event: " + type);
        const std::wstring line2 = utf8ToWide("detail: " + detail);
        LPCWSTR strings[2] = {line1.c_str(), line2.c_str()};
        const BOOL ok = ReportEventW(source, eventTypeFor(type), 0, 1000, nullptr, 2, 0, strings, nullptr);
        DeregisterEventSource(source);
        return ok == TRUE;
    }

    void showPopup(const std::string &type, const std::string &detail)
    {
        const std::wstring title = L"Process Guard Service";
        const std::wstring body = utf8ToWide("PGS event: " + type + "\n" + detail);
        HMODULE user32 = LoadLibraryW(L"user32.dll");
        if (!user32) return;
        using MessageBoxTimeoutWFn = int (WINAPI *)(HWND, LPCWSTR, LPCWSTR, UINT, WORD, DWORD);
        const FARPROC proc = GetProcAddress(user32, "MessageBoxTimeoutW");
        MessageBoxTimeoutWFn timeoutFn = nullptr;
        static_assert(sizeof(timeoutFn) == sizeof(proc), "function pointer size mismatch");
        std::memcpy(&timeoutFn, &proc, sizeof(timeoutFn));
        const UINT flags = MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_SERVICE_NOTIFICATION;
        if (timeoutFn)
            timeoutFn(nullptr, body.c_str(), title.c_str(), flags, 0, 10000);
        else
            MessageBoxW(nullptr, body.c_str(), title.c_str(), flags);
        FreeLibrary(user32);
    }

    std::string statusResponse()
    {
        const std::string path = g_configPath.empty() ? std::string() : wideToUtf8(g_configPath.wstring());
        return "OK eventlog=" + std::string(g_eventLogEnabled ? "1" : "0") +
               ";popup=" + (g_popupEnabled ? "1" : "0") +
               ";config_path_b64=" + base64Encode(path);
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "notify"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=notify;version=1.0.0;abi=3;"
           "summary=Windows-native Event Log and optional local popup notifications;"
           "capabilities=notify.eventlog,notify.popup,event.read";
}

PG_MODULE_API int PG_Init(void *reserved)
{
    g_servicesReady = false;
    g_services = PGS_ServicesV3{};
    g_configPath.clear();
    if (reserved)
    {
        const PGS_ServicesV3 *services = static_cast<const PGS_ServicesV3 *>(reserved);
        if (services->size >= sizeof(PGS_ServicesV3))
        {
            g_services = *services;
            g_servicesReady = true;
            if (g_services.get_data_dir)
            {
                const char *root = g_services.get_data_dir(g_services.context);
                if (root && root[0])
                {
                    g_configPath = std::filesystem::path(utf8ToWide(root)) / L"modules" / L"notify" / L"notify.cfg";
                }
            }
        }
    }
    if (g_configPath.empty())
    {
        g_configPath = std::filesystem::path(L"notify.cfg");
    }
    loadConfig();
    return 0;
}

PG_MODULE_API void PG_Shutdown(void)
{
    saveConfig();
    g_services = PGS_ServicesV3{};
    g_servicesReady = false;
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

    if (op == "config")
    {
        const std::string eventlog = requestValue(req, "eventlog");
        const std::string popup = requestValue(req, "popup");
        if (!eventlog.empty()) g_eventLogEnabled = parseBool(eventlog, g_eventLogEnabled);
        if (!popup.empty()) g_popupEnabled = parseBool(popup, g_popupEnabled);
        saveConfig();
        setResponse(responseBuf, responseBufSize, statusResponse());
        return 0;
    }

    if (op == "event")
    {
        const std::string type = trim(requestValue(req, "type"));
        const std::string detail = base64Decode(requestValue(req, "detail_b64"));
        if (type.empty())
        {
            setResponse(responseBuf, responseBufSize, "ERR notify event requires type");
            return 1;
        }
        bool delivered = false;
        if (g_eventLogEnabled)
        {
            delivered = writeEventLog(type, detail) || delivered;
        }
        if (g_popupEnabled)
        {
            showPopup(type, detail);
            delivered = true;
        }
        setResponse(responseBuf, responseBufSize, delivered ? "OK notified" : "ERR no notification channel delivered");
        return delivered ? 0 : 1;
    }

    setResponse(responseBuf, responseBufSize, "ERR unknown notify op");
    return 1;
}

} // extern "C"
