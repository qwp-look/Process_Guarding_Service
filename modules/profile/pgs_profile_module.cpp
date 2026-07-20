/*
 * pgs_profile_module.cpp - PGS guard policy profiles (ABI v2).
 *
 * Stores named restart-policy profiles and applies them through PGS
 * set-policy. Profiles intentionally cover the policy fields that PGS can
 * change after registration today: max restarts and restart args.
 *
 * Request KV examples:
 *   op=set;name=default;max=3;restart_args_b64=...
 *   op=list
 *   op=get;name=default
 *   op=remove;name=default
 *   op=apply;name=default;pid=1234
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <map>
#include <mutex>
#include <sstream>
#include <string>

#include "Process_Guard/PGModule.h"

namespace
{
    HMODULE g_self = nullptr;
    PGS_ServicesV3 g_services{};
    bool g_servicesReady = false;
    std::string g_moduleDir;
    std::string g_dbPath;
    std::mutex g_mutex;

    struct Profile
    {
        std::string name;
        std::string maxRestarts = "3";
        std::string restartArgsB64;
    };

    std::map<std::string, Profile> g_profiles;

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

    bool validName(const std::string &name)
    {
        if (name.empty() || name.size() > 64)
            return false;
        for (unsigned char ch : name)
        {
            if (!(std::isalnum(ch) || ch == '_' || ch == '-' || ch == '.'))
                return false;
        }
        return true;
    }

    bool validMax(const std::string &max)
    {
        if (max == "no")
            return true;
        if (max.empty())
            return false;
        for (char ch : max)
        {
            if (ch < '0' || ch > '9')
                return false;
        }
        try
        {
            return std::stoul(max) <= 2147483647ul;
        }
        catch (...)
        {
            return false;
        }
    }

    bool validPid(const std::string &text)
    {
        if (text.empty())
            return false;
        for (char ch : text)
        {
            if (ch < '0' || ch > '9')
                return false;
        }
        try
        {
            return std::stoul(text) != 0;
        }
        catch (...)
        {
            return false;
        }
    }

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0)
            return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
    }

    std::string moduleDirOf(HMODULE self)
    {
        wchar_t buffer[MAX_PATH] = {0};
        DWORD len = GetModuleFileNameW(self, buffer, MAX_PATH);
        if (len == 0 || len >= MAX_PATH)
            return std::string();
        std::wstring path(buffer, len);
        const std::size_t pos = path.find_last_of(L"\\/");
        if (pos == std::wstring::npos)
            return std::string();
        const std::wstring dir = path.substr(0, pos);
        int bytes = WideCharToMultiByte(CP_UTF8, 0, dir.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string out(bytes > 0 ? bytes - 1 : 0, '\0');
        if (bytes > 0)
            WideCharToMultiByte(CP_UTF8, 0, dir.c_str(), -1, out.data(), bytes, nullptr, nullptr);
        return out;
    }

    std::string joinPath(const std::string &a, const std::string &b)
    {
        if (a.empty())
            return b;
        std::filesystem::path p(a);
        p /= b;
        return p.string();
    }

    bool ensureParentDir(const std::string &path)
    {
        std::error_code ec;
        const std::filesystem::path parent = std::filesystem::path(path).parent_path();
        if (parent.empty())
            return true;
        std::filesystem::create_directories(parent, ec);
        return !ec;
    }

    std::string dataDirFromServices(const PGS_ServicesV3 &services)
    {
        if (services.size >= sizeof(PGS_ServicesV3) && services.get_data_dir)
        {
            const char *dir = services.get_data_dir(services.context);
            if (dir && dir[0])
                return dir;
        }
        return std::string();
    }

    std::string resolveDbPath()
    {
        const std::string dataRoot = dataDirFromServices(g_services);
        if (!dataRoot.empty())
        {
            return joinPath(joinPath(joinPath(dataRoot, "modules"), "profile"), "pgs_profiles.db");
        }
        return g_moduleDir.empty() ? "pgs_profiles.db" : joinPath(g_moduleDir, "pgs_profiles.db");
    }

    void migrateLegacyDbIfNeeded()
    {
        const std::string legacy = g_moduleDir.empty() ? "pgs_profiles.db" : joinPath(g_moduleDir, "pgs_profiles.db");
        if (legacy.empty() || g_dbPath.empty() || legacy == g_dbPath)
            return;
        std::error_code ec;
        if (!std::filesystem::exists(g_dbPath, ec) && std::filesystem::exists(legacy, ec))
        {
            ensureParentDir(g_dbPath);
            std::filesystem::copy_file(legacy, g_dbPath, std::filesystem::copy_options::skip_existing, ec);
        }
    }

    std::string dbPath()
    {
        return g_dbPath.empty() ? resolveDbPath() : g_dbPath;
    }

    bool saveProfiles()
    {
        const std::string path = dbPath();
        if (!ensureParentDir(path))
            return false;
        const std::string tmp = path + ".tmp";
        {
            std::ofstream out(tmp, std::ios::out | std::ios::binary | std::ios::trunc);
            if (!out.is_open())
                return false;
            out << "# PGS profile db v1\n";
            for (const auto &item : g_profiles)
            {
                out << "name=" << item.second.name
                    << ";max=" << item.second.maxRestarts
                    << ";restart_args_b64=" << item.second.restartArgsB64
                    << "\n";
            }
        }
        return MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
    }

    void loadProfiles()
    {
        g_profiles.clear();
        std::ifstream in(dbPath(), std::ios::in | std::ios::binary);
        if (!in.is_open())
            return;
        std::string line;
        while (std::getline(in, line))
        {
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            line = trim(line);
            if (line.empty() || line[0] == '#')
                continue;
            Profile profile;
            profile.name = requestValue(line, "name");
            profile.maxRestarts = requestValue(line, "max");
            profile.restartArgsB64 = requestValue(line, "restart_args_b64");
            if (validName(profile.name) && validMax(profile.maxRestarts))
                g_profiles[lower(profile.name)] = profile;
        }
    }

    bool callPGS(const std::string &command, std::string &response)
    {
        response.clear();
        if (!g_servicesReady || !g_services.call || !g_services.context)
        {
            response = "ERR services unavailable";
            return false;
        }
        char buffer[8192] = {0};
        const int rc = g_services.call(g_services.context, command.c_str(), buffer, sizeof(buffer));
        response.assign(buffer);
        return rc == 0;
    }

    std::string profileLine(const Profile &profile)
    {
        return "NAME=" + profile.name +
               ";MAX_RESTARTS=" + profile.maxRestarts +
               ";RESTART_ARGS_B64=" + profile.restartArgsB64;
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE hInstDLL, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        g_self = hInstDLL;
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "profile"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=profile;version=1.0.0;abi=2;"
           "summary=Named restart policy profiles;"
           "capabilities=profile.set,profile.list,profile.apply,guard.policy";
}

PG_MODULE_API int PG_Init(void *reserved)
{
    g_moduleDir = moduleDirOf(g_self);
    if (reserved)
    {
        const PGS_Services *base = static_cast<const PGS_Services *>(reserved);
        if (base->size >= sizeof(PGS_Services))
        {
            g_services.size = base->size;
            g_services.context = base->context;
            g_services.call = base->call;
            g_services.now_ms = base->now_ms;
            if (base->size >= sizeof(PGS_ServicesV3))
            {
                const PGS_ServicesV3 *v3 = static_cast<const PGS_ServicesV3 *>(reserved);
                g_services.call_json = v3->call_json;
                g_services.emit_event = v3->emit_event;
                g_services.get_data_dir = v3->get_data_dir;
                g_services.log = v3->log;
            }
            g_servicesReady = (g_services.call != nullptr);
        }
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    g_dbPath = resolveDbPath();
    migrateLegacyDbIfNeeded();
    loadProfiles();
    return 0;
}

PG_MODULE_API void PG_Shutdown(void)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    saveProfiles();
    g_profiles.clear();
    g_services = PGS_ServicesV3{};
    g_servicesReady = false;
}

PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize)
{
    const std::string req = request ? request : "";
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "list" : requestValue(req, "op")));

    if (op == "set")
    {
        Profile profile;
        profile.name = trim(requestValue(req, "name"));
        profile.maxRestarts = trim(requestValue(req, "max"));
        if (profile.maxRestarts.empty())
            profile.maxRestarts = "3";
        profile.restartArgsB64 = requestValue(req, "restart_args_b64");
        if (!validName(profile.name))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid profile name");
            return 1;
        }
        if (!validMax(profile.maxRestarts))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid max");
            return 1;
        }
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            g_profiles[lower(profile.name)] = profile;
            if (!saveProfiles())
            {
                setResponse(responseBuf, responseBufSize, "ERR failed to save profiles");
                return 1;
            }
        }
        setResponse(responseBuf, responseBufSize, "OK profile saved name=" + profile.name);
        return 0;
    }

    if (op == "list")
    {
        std::ostringstream out;
        std::lock_guard<std::mutex> lock(g_mutex);
        out << "OK count=" << g_profiles.size();
        for (const auto &item : g_profiles)
            out << "\n" << profileLine(item.second);
        setResponse(responseBuf, responseBufSize, out.str());
        return 0;
    }

    if (op == "get")
    {
        const std::string name = trim(requestValue(req, "name"));
        if (!validName(name))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid profile name");
            return 1;
        }
        std::lock_guard<std::mutex> lock(g_mutex);
        auto it = g_profiles.find(lower(name));
        if (it == g_profiles.end())
        {
            setResponse(responseBuf, responseBufSize, "ERR profile not found");
            return 1;
        }
        setResponse(responseBuf, responseBufSize, "OK\n" + profileLine(it->second));
        return 0;
    }

    if (op == "remove")
    {
        const std::string name = trim(requestValue(req, "name"));
        if (!validName(name))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid profile name");
            return 1;
        }
        std::lock_guard<std::mutex> lock(g_mutex);
        if (g_profiles.erase(lower(name)) == 0)
        {
            setResponse(responseBuf, responseBufSize, "ERR profile not found");
            return 1;
        }
        if (!saveProfiles())
        {
            setResponse(responseBuf, responseBufSize, "ERR failed to save profiles");
            return 1;
        }
        setResponse(responseBuf, responseBufSize, "OK profile removed name=" + name);
        return 0;
    }

    if (op == "apply")
    {
        const std::string name = trim(requestValue(req, "name"));
        const std::string pid = trim(requestValue(req, "pid"));
        if (!validName(name) || !validPid(pid))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid apply arguments");
            return 1;
        }
        Profile profile;
        {
            std::lock_guard<std::mutex> lock(g_mutex);
            auto it = g_profiles.find(lower(name));
            if (it == g_profiles.end())
            {
                setResponse(responseBuf, responseBufSize, "ERR profile not found");
                return 1;
            }
            profile = it->second;
        }
        std::string command = "set-policy " + pid + "|" + profile.maxRestarts;
        if (!profile.restartArgsB64.empty())
            command += "|" + profile.restartArgsB64;
        std::string response;
        const bool ok = callPGS(command, response);
        setResponse(responseBuf, responseBufSize, response.empty() ? "ERR apply failed" : response);
        return ok && response.rfind("OK", 0) == 0 ? 0 : 1;
    }

    setResponse(responseBuf, responseBufSize, "ERR unknown profile op");
    return 1;
}

} // extern "C"
