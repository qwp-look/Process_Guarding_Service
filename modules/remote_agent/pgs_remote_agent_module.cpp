/*
 * pgs_remote_agent_module.cpp - local node-agent metadata for cluster use.
 *
 * This is not a chat/webhook integration and it does not open a listener. It
 * exposes local agent status/heartbeat metadata so a future cluster agent can
 * build on a stable module surface.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

#include "Process_Guard/PGModule.h"

namespace
{
    PGS_ServicesV3 g_services{};
    bool g_servicesReady = false;

    std::string trim(std::string value)
    {
        const char *ws = " \t\r\n";
        const std::size_t first = value.find_first_not_of(ws);
        if (first == std::string::npos) return std::string();
        const std::size_t last = value.find_last_not_of(ws);
        return value.substr(first, last - first + 1);
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

    std::string lower(std::string value)
    {
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        return value;
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

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0) return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
    }

    std::string hostname()
    {
        char buffer[MAX_COMPUTERNAME_LENGTH + 1] = {0};
        DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
        if (GetComputerNameA(buffer, &size)) return std::string(buffer, size);
        return "unknown";
    }

    long long nowMs()
    {
        if (g_servicesReady && g_services.now_ms) return g_services.now_ms(g_services.context);
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER uli{};
        uli.LowPart = ft.dwLowDateTime;
        uli.HighPart = ft.dwHighDateTime;
        return static_cast<long long>((uli.QuadPart - 116444736000000000ULL) / 10000ULL);
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
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "remote_agent"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=remote_agent;version=1.0.0;abi=3;summary=Local cluster-agent metadata surface;capabilities=remote_agent.status,guard.list,health.stats";
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
    const std::string req = request ? request : "";
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "status" : requestValue(req, "op")));
    if (op == "status" || op == "heartbeat")
    {
        std::string stats;
        callPGS("stats", stats);
        setResponse(responseBuf, responseBufSize,
                    "OK node_b64=" + base64Encode(hostname()) +
                    ";time_ms=" + std::to_string(nowMs()) +
                    ";listener=none;remote_channels=0;stats_b64=" + base64Encode(stats));
        return 0;
    }
    if (op == "guards")
    {
        std::string list;
        if (!callPGS("list", list))
        {
            setResponse(responseBuf, responseBufSize, list.empty() ? "ERR list callback failed" : list);
            return 1;
        }
        setResponse(responseBuf, responseBufSize, "OK list_b64=" + base64Encode(list));
        return 0;
    }
    setResponse(responseBuf, responseBufSize, "ERR unknown remote_agent op");
    return 1;
}

} // extern "C"
