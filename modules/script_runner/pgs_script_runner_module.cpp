/*
 * pgs_script_runner_module.cpp - restricted local script runner (ABI v3).
 *
 * Default state is disabled. Operators must enable it explicitly, register a
 * script under the service data directory, and pass confirm=1 before running.
 * No remote shell, chat, webhook, or network integration is provided.
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
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "Process_Guard/PGModule.h"

namespace
{
    PGS_ServicesV3 g_services{};
    bool g_servicesReady = false;
    std::mutex g_mutex;

    struct Script
    {
        std::string id;
        std::string path;
        std::string args;
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
        for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(chars[i])] = i;
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

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0) return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
    }

    bool safeId(const std::string &id)
    {
        if (id.empty() || id.size() > 64) return false;
        for (unsigned char ch : id)
        {
            if (!(std::isalnum(ch) || ch == '_' || ch == '-')) return false;
        }
        return true;
    }

    bool safeArgs(const std::string &args)
    {
        if (args.size() > 512) return false;
        for (unsigned char ch : args)
        {
            if (ch == '\r' || ch == '\n' || ch == '\0') return false;
        }
        return true;
    }

    std::string dataDir()
    {
        if (g_servicesReady && g_services.get_data_dir)
        {
            const char *root = g_services.get_data_dir(g_services.context);
            if (root && root[0]) return root;
        }
        return std::string();
    }

    std::filesystem::path moduleRoot()
    {
        return std::filesystem::path(dataDir()) / "modules" / "script_runner";
    }

    std::filesystem::path scriptsPath()
    {
        return moduleRoot() / "scripts.db";
    }

    std::filesystem::path configPath()
    {
        return moduleRoot() / "config.cfg";
    }

    bool enabled()
    {
        std::ifstream in(configPath(), std::ios::in | std::ios::binary);
        std::string body;
        std::getline(in, body, '\0');
        return body.find("enabled=1") != std::string::npos;
    }

    bool setEnabled(bool value)
    {
        std::error_code ec;
        std::filesystem::create_directories(moduleRoot(), ec);
        if (ec) return false;
        std::ofstream out(configPath(), std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out << "enabled=" << (value ? "1" : "0") << "\n";
        return true;
    }

    bool pathInsideRoot(const std::filesystem::path &path, const std::filesystem::path &root)
    {
        std::error_code ec;
        const auto p = std::filesystem::weakly_canonical(path, ec);
        if (ec) return false;
        const auto r = std::filesystem::weakly_canonical(root, ec);
        if (ec) return false;
        const std::wstring ps = p.wstring();
        const std::wstring rs = r.wstring();
        return ps.size() >= rs.size() && _wcsnicmp(ps.c_str(), rs.c_str(), rs.size()) == 0;
    }

    std::vector<Script> loadScripts()
    {
        std::vector<Script> scripts;
        std::ifstream in(scriptsPath(), std::ios::in | std::ios::binary);
        std::string line;
        while (std::getline(in, line))
        {
            Script s;
            s.id = requestValue(line, "id");
            s.path = base64Decode(requestValue(line, "path_b64"));
            s.args = base64Decode(requestValue(line, "args_b64"));
            if (safeId(s.id) && !s.path.empty() && safeArgs(s.args)) scripts.push_back(std::move(s));
        }
        return scripts;
    }

    bool saveScripts(const std::vector<Script> &scripts)
    {
        std::error_code ec;
        std::filesystem::create_directories(moduleRoot(), ec);
        if (ec) return false;
        std::ofstream out(scriptsPath(), std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        for (const Script &s : scripts)
        {
            out << "id=" << s.id << ";path_b64=" << base64Encode(s.path) << ";args_b64=" << base64Encode(s.args) << "\n";
        }
        return true;
    }

    const Script *findScript(const std::vector<Script> &scripts, const std::string &id)
    {
        for (const Script &s : scripts) if (lower(s.id) == lower(id)) return &s;
        return nullptr;
    }

    std::wstring quoteArg(const std::wstring &arg)
    {
        std::wstring out = L"\"";
        unsigned backslashes = 0;
        for (wchar_t ch : arg)
        {
            if (ch == L'\\') { ++backslashes; continue; }
            if (ch == L'\"')
            {
                out.append(backslashes * 2 + 1, L'\\');
                out.push_back(ch);
                backslashes = 0;
                continue;
            }
            out.append(backslashes, L'\\');
            backslashes = 0;
            out.push_back(ch);
        }
        out.append(backslashes * 2, L'\\');
        out.push_back(L'\"');
        return out;
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "script_runner"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=script_runner;version=1.0.0;abi=3;summary=Restricted local script runner;capabilities=script.run";
}

PG_MODULE_API int PG_Init(void *reserved)
{
    g_servicesReady = false;
    g_services = PGS_ServicesV3{};
    if (!reserved) return 0;
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
    return 0;
}

PG_MODULE_API void PG_Shutdown(void)
{
    g_services = PGS_ServicesV3{};
    g_servicesReady = false;
}

PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    const std::string req = request ? request : "";
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "status" : requestValue(req, "op")));
    if (op == "status")
    {
        const std::vector<Script> scripts = loadScripts();
        setResponse(responseBuf, responseBufSize, "OK enabled=" + std::string(enabled() ? "1" : "0") + ";scripts=" + std::to_string(scripts.size()) + ";root_b64=" + base64Encode(moduleRoot().string()));
        return 0;
    }
    if (op == "config")
    {
        const bool value = truthy(requestValue(req, "enabled"));
        if (!setEnabled(value))
        {
            setResponse(responseBuf, responseBufSize, "ERR failed to persist config");
            return 1;
        }
        setResponse(responseBuf, responseBufSize, "OK enabled=" + std::string(value ? "1" : "0"));
        return 0;
    }
    if (op == "add")
    {
        Script s;
        s.id = requestValue(req, "id");
        s.path = base64Decode(requestValue(req, "path_b64"));
        s.args = base64Decode(requestValue(req, "args_b64"));
        if (!safeId(s.id) || s.path.empty() || !safeArgs(s.args))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid script entry");
            return 1;
        }
        const std::filesystem::path root = moduleRoot() / "scripts";
        std::error_code ec;
        std::filesystem::create_directories(root, ec);
        if (ec)
        {
            setResponse(responseBuf, responseBufSize, "ERR failed to create scripts directory");
            return 1;
        }
        if (!pathInsideRoot(std::filesystem::path(s.path), root))
        {
            setResponse(responseBuf, responseBufSize, "ERR script must be under module data scripts directory");
            return 1;
        }
        if (!std::filesystem::is_regular_file(s.path, ec))
        {
            setResponse(responseBuf, responseBufSize, "ERR script file not found");
            return 1;
        }
        std::vector<Script> scripts = loadScripts();
        scripts.erase(std::remove_if(scripts.begin(), scripts.end(), [&](const Script &existing) { return lower(existing.id) == lower(s.id); }), scripts.end());
        scripts.push_back(s);
        if (!saveScripts(scripts))
        {
            setResponse(responseBuf, responseBufSize, "ERR failed to persist scripts");
            return 1;
        }
        setResponse(responseBuf, responseBufSize, "OK id=" + s.id);
        return 0;
    }
    if (op == "list")
    {
        const std::vector<Script> scripts = loadScripts();
        std::ostringstream out;
        out << "OK count=" << scripts.size();
        for (const Script &s : scripts) out << "\nSCRIPT id=" << s.id << ";path_b64=" << base64Encode(s.path);
        setResponse(responseBuf, responseBufSize, out.str());
        return 0;
    }
    if (op == "run")
    {
        if (!enabled())
        {
            setResponse(responseBuf, responseBufSize, "ERR script runner disabled");
            return 1;
        }
        if (!truthy(requestValue(req, "confirm")))
        {
            setResponse(responseBuf, responseBufSize, "ERR run requires confirm=1");
            return 1;
        }
        const std::string id = requestValue(req, "id");
        const std::vector<Script> scripts = loadScripts();
        const Script *s = findScript(scripts, id);
        if (!s)
        {
            setResponse(responseBuf, responseBufSize, "ERR script not found");
            return 1;
        }
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        const std::wstring scriptW = utf8ToWide(s->path);
        std::wstring command = quoteArg(scriptW);
        if (!s->args.empty()) command += L" " + utf8ToWide(s->args);
        const BOOL ok = CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        if (!ok)
        {
            setResponse(responseBuf, responseBufSize, "ERR CreateProcess failed");
            return 1;
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        setResponse(responseBuf, responseBufSize, "OK id=" + id + ";pid=" + std::to_string(pi.dwProcessId));
        return 0;
    }
    setResponse(responseBuf, responseBufSize, "ERR unknown script_runner op");
    return 1;
}

} // extern "C"
