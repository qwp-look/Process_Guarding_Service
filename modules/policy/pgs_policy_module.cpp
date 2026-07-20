/*
 * pgs_policy_module.cpp - named guard policy templates (ABI v3).
 *
 * Stores restart-policy templates under the service data directory and can apply
 * them to an existing guard through the PGS callback surface.
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

    struct Template
    {
        std::string name;
        std::string maxRestarts;
        std::string restartArgs;
        std::string restartWindow;
        std::string restartDelay;
        std::string backoff;
        std::string hangTimeout;
        std::string killOnExit;
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

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0) return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
    }

    bool safeName(const std::string &name)
    {
        if (name.empty() || name.size() > 64) return false;
        for (unsigned char ch : name)
        {
            if (!(std::isalnum(ch) || ch == '_' || ch == '-')) return false;
        }
        return true;
    }

    bool safeText(const std::string &value)
    {
        if (value.size() > 1024) return false;
        for (unsigned char ch : value)
        {
            if (ch == '\r' || ch == '\n' || ch == '\0') return false;
        }
        return true;
    }

    bool safeUnsignedOrEmpty(const std::string &value)
    {
        if (value.empty()) return true;
        for (char ch : value) if (ch < '0' || ch > '9') return false;
        return true;
    }

    bool safeMax(const std::string &value)
    {
        if (value == "no" || value == "none" || value == "-1") return true;
        return !value.empty() && safeUnsignedOrEmpty(value);
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

    std::string dataDir()
    {
        if (g_servicesReady && g_services.get_data_dir)
        {
            const char *root = g_services.get_data_dir(g_services.context);
            if (root && root[0]) return root;
        }
        return std::string();
    }

    std::filesystem::path templatesPath()
    {
        return std::filesystem::path(dataDir()) / "modules" / "policy" / "templates.db";
    }

    std::vector<Template> loadTemplates()
    {
        std::vector<Template> templates;
        std::ifstream in(templatesPath(), std::ios::in | std::ios::binary);
        std::string line;
        while (std::getline(in, line))
        {
            Template t;
            t.name = requestValue(line, "name");
            t.maxRestarts = requestValue(line, "max");
            t.restartArgs = base64Decode(requestValue(line, "args_b64"));
            t.restartWindow = requestValue(line, "window");
            t.restartDelay = requestValue(line, "delay");
            t.backoff = requestValue(line, "backoff");
            t.hangTimeout = requestValue(line, "hang");
            t.killOnExit = requestValue(line, "kill");
            if (safeName(t.name)) templates.push_back(std::move(t));
        }
        return templates;
    }

    bool saveTemplates(const std::vector<Template> &templates)
    {
        const std::filesystem::path path = templatesPath();
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) return false;
        std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        for (const Template &t : templates)
        {
            out << "name=" << t.name << ";max=" << t.maxRestarts << ";args_b64=" << base64Encode(t.restartArgs)
                << ";window=" << t.restartWindow << ";delay=" << t.restartDelay << ";backoff=" << t.backoff
                << ";hang=" << t.hangTimeout << ";kill=" << t.killOnExit << "\n";
        }
        return true;
    }

    const Template *findTemplate(const std::vector<Template> &templates, const std::string &name)
    {
        for (const Template &t : templates) if (lower(t.name) == lower(name)) return &t;
        return nullptr;
    }

    bool callPGS(const std::string &command, std::string &response)
    {
        response.clear();
        if (!g_servicesReady || !g_services.call || !g_services.context)
        {
            response = "ERR callback unavailable";
            return false;
        }
        std::vector<char> buffer(8192, '\0');
        const int rc = g_services.call(g_services.context, command.c_str(), buffer.data(), buffer.size());
        response.assign(buffer.data());
        return rc == 0 && response.rfind("ERR", 0) != 0;
    }

    bool validateTemplate(const Template &t, std::string &error)
    {
        if (!safeName(t.name)) { error = "invalid name"; return false; }
        if (!safeMax(t.maxRestarts)) { error = "invalid max"; return false; }
        if (!safeText(t.restartArgs)) { error = "invalid restart args"; return false; }
        if (!safeUnsignedOrEmpty(t.restartWindow) || !safeUnsignedOrEmpty(t.restartDelay) || !safeUnsignedOrEmpty(t.hangTimeout)) { error = "invalid numeric field"; return false; }
        if (!t.backoff.empty() && t.backoff != "0" && t.backoff != "1") { error = "invalid backoff"; return false; }
        if (!t.killOnExit.empty() && t.killOnExit != "0" && t.killOnExit != "1") { error = "invalid kill"; return false; }
        return true;
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "policy"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=policy;version=1.0.0;abi=3;summary=Named guard policy templates;capabilities=policy.template,guard.policy";
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
        const std::vector<Template> templates = loadTemplates();
        setResponse(responseBuf, responseBufSize, "OK templates=" + std::to_string(templates.size()));
        return 0;
    }
    if (op == "set")
    {
        Template t;
        t.name = requestValue(req, "name");
        t.maxRestarts = requestValue(req, "max");
        if (t.maxRestarts.empty()) t.maxRestarts = "3";
        t.restartArgs = base64Decode(requestValue(req, "args_b64"));
        t.restartWindow = requestValue(req, "window");
        t.restartDelay = requestValue(req, "delay");
        t.backoff = requestValue(req, "backoff");
        t.hangTimeout = requestValue(req, "hang");
        t.killOnExit = requestValue(req, "kill");
        std::string error;
        if (!validateTemplate(t, error))
        {
            setResponse(responseBuf, responseBufSize, "ERR " + error);
            return 1;
        }
        std::vector<Template> templates = loadTemplates();
        templates.erase(std::remove_if(templates.begin(), templates.end(), [&](const Template &existing) { return lower(existing.name) == lower(t.name); }), templates.end());
        templates.push_back(t);
        if (!saveTemplates(templates))
        {
            setResponse(responseBuf, responseBufSize, "ERR failed to persist templates");
            return 1;
        }
        setResponse(responseBuf, responseBufSize, "OK name=" + t.name);
        return 0;
    }
    if (op == "list")
    {
        const std::vector<Template> templates = loadTemplates();
        std::ostringstream out;
        out << "OK count=" << templates.size();
        for (const Template &t : templates)
        {
            out << "\nTEMPLATE name=" << t.name << ";max=" << t.maxRestarts << ";window=" << t.restartWindow << ";delay=" << t.restartDelay << ";backoff=" << t.backoff << ";hang=" << t.hangTimeout << ";kill=" << t.killOnExit;
        }
        setResponse(responseBuf, responseBufSize, out.str());
        return 0;
    }
    if (op == "remove")
    {
        const std::string name = requestValue(req, "name");
        if (!safeName(name))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid name");
            return 1;
        }
        std::vector<Template> templates = loadTemplates();
        const std::size_t before = templates.size();
        templates.erase(std::remove_if(templates.begin(), templates.end(), [&](const Template &t) { return lower(t.name) == lower(name); }), templates.end());
        if (!saveTemplates(templates))
        {
            setResponse(responseBuf, responseBufSize, "ERR failed to persist templates");
            return 1;
        }
        setResponse(responseBuf, responseBufSize, "OK removed=" + std::to_string(before - templates.size()));
        return 0;
    }
    if (op == "apply")
    {
        const std::string name = requestValue(req, "name");
        const std::string pid = requestValue(req, "pid");
        if (!safeName(name) || pid.empty())
        {
            setResponse(responseBuf, responseBufSize, "ERR apply requires name and pid");
            return 1;
        }
        const std::vector<Template> templates = loadTemplates();
        const Template *t = findTemplate(templates, name);
        if (!t)
        {
            setResponse(responseBuf, responseBufSize, "ERR template not found");
            return 1;
        }
        std::string command = "set-policy " + pid + "|" + t->maxRestarts + "|" + base64Encode(t->restartArgs) + "|" + t->restartWindow + "|" + t->restartDelay + "|" + t->backoff + "|" + t->hangTimeout + "|" + t->killOnExit;
        std::string response;
        if (!callPGS(command, response))
        {
            setResponse(responseBuf, responseBufSize, response.empty() ? "ERR policy callback failed" : response);
            return 1;
        }
        setResponse(responseBuf, responseBufSize, "OK applied=" + name + ";pid=" + pid + ";response_b64=" + base64Encode(response));
        return 0;
    }
    setResponse(responseBuf, responseBufSize, "ERR unknown policy op");
    return 1;
}

} // extern "C"
