/*
 * pgs_health_module.cpp - PGS health/status module (ABI v2).
 *
 * Provides lightweight service health summaries by calling back into PGS via
 * PGS_Services. It does not own state and does not perform notifications.
 *
 * Request KV examples:
 *   op=summary
 *   op=stats
 *   op=list
 *   op=events;limit=25
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
    PGS_Services g_services{};
    bool g_servicesReady = false;

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

    std::string kvValue(const std::string &kv, const std::string &key)
    {
        const std::string needle = key + "=";
        std::size_t pos = kv.find(needle);
        if (pos == std::string::npos)
            return std::string();
        pos += needle.size();
        const std::size_t semi = kv.find(';', pos);
        const std::size_t space = kv.find(' ', pos);
        std::size_t end = std::string::npos;
        if (semi != std::string::npos && space != std::string::npos)
            end = std::min(semi, space);
        else if (semi != std::string::npos)
            end = semi;
        else
            end = space;
        return end == std::string::npos ? kv.substr(pos) : kv.substr(pos, end - pos);
    }

    bool parseUnsigned(const std::string &text, unsigned long &out)
    {
        const std::string value = trim(text);
        if (value.empty())
            return false;
        for (char ch : value)
        {
            if (ch < '0' || ch > '9')
                return false;
        }
        try
        {
            out = std::stoul(value);
            return true;
        }
        catch (...)
        {
            return false;
        }
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

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0)
            return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
    }

    bool callPGS(const std::string &command, std::string &response)
    {
        response.clear();
        if (!g_servicesReady || !g_services.call || !g_services.context)
        {
            response = "ERR services unavailable";
            return false;
        }
        std::vector<char> buffer(8192, '\0');
        const int rc = g_services.call(g_services.context, command.c_str(), buffer.data(), buffer.size());
        response.assign(buffer.data());
        return rc == 0;
    }

    std::vector<std::string> linesOf(const std::string &text)
    {
        std::vector<std::string> lines;
        std::string current;
        std::istringstream in(text);
        while (std::getline(in, current))
        {
            if (!current.empty() && current.back() == '\r')
                current.pop_back();
            lines.push_back(current);
        }
        return lines;
    }

    std::string makeSummary()
    {
        std::string stats;
        if (!callPGS("stats", stats) || stats.rfind("OK", 0) != 0)
        {
            return "ERR stats unavailable";
        }

        std::string list;
        int dead = 0;
        int intentional = 0;
        if (callPGS("list", list) && list.rfind("OK", 0) == 0)
        {
            const std::vector<std::string> lines = linesOf(list);
            for (std::size_t i = 1; i < lines.size(); ++i)
            {
                const bool alive = kvValue(lines[i], "ALIVE") == "1";
                const bool isIntentional = kvValue(lines[i], "INTENTIONAL") == "1";
                if (isIntentional)
                    ++intentional;
                if (!alive && !isIntentional)
                    ++dead;
            }
        }

        const std::string guards = kvValue(stats, "guards");
        const std::string active = kvValue(stats, "active");
        const std::string totalRestarts = kvValue(stats, "totalRestarts");
        const std::string windowRestarts = kvValue(stats, "restartsInWindow");
        const std::string uptime = kvValue(stats, "uptime");
        const std::string status = (dead == 0) ? "ok" : "degraded";

        std::ostringstream out;
        out << "OK status=" << status
            << ";guards=" << (guards.empty() ? "0" : guards)
            << ";active=" << (active.empty() ? "0" : active)
            << ";dead=" << dead
            << ";intentional=" << intentional
            << ";total_restarts=" << (totalRestarts.empty() ? "0" : totalRestarts)
            << ";restarts_in_window=" << (windowRestarts.empty() ? "0" : windowRestarts)
            << ";uptime_sec=" << (uptime.empty() ? "0" : uptime);
        return out.str();
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "health"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=health;version=1.0.0;abi=2;"
           "summary=Service health summaries from stats/list/events;"
           "capabilities=health.summary,health.stats,guard.list,event.read";
}

PG_MODULE_API int PG_Init(void *reserved)
{
    g_servicesReady = false;
    if (!reserved)
        return 0;
    const PGS_Services *services = static_cast<const PGS_Services *>(reserved);
    if (services->size >= sizeof(PGS_Services) && services->call)
    {
        g_services = *services;
        g_servicesReady = true;
    }
    return 0;
}

PG_MODULE_API void PG_Shutdown(void)
{
    g_services = PGS_Services{};
    g_servicesReady = false;
}

PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize)
{
    const std::string req = request ? request : "";
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "summary" : requestValue(req, "op")));

    if (op == "summary")
    {
        const std::string response = makeSummary();
        setResponse(responseBuf, responseBufSize, response);
        return response.rfind("OK", 0) == 0 ? 0 : 1;
    }

    if (op == "stats" || op == "list")
    {
        std::string response;
        const bool ok = callPGS(op, response);
        setResponse(responseBuf, responseBufSize, response);
        return ok && response.rfind("OK", 0) == 0 ? 0 : 1;
    }

    if (op == "events")
    {
        unsigned long limit = 25;
        const std::string requested = requestValue(req, "limit");
        if (!requested.empty() && (!parseUnsigned(requested, limit) || limit == 0 || limit > 512))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid limit");
            return 1;
        }
        std::string response;
        const bool ok = callPGS("events list " + std::to_string(limit), response);
        setResponse(responseBuf, responseBufSize, response);
        return ok && response.rfind("OK", 0) == 0 ? 0 : 1;
    }

    setResponse(responseBuf, responseBufSize, "ERR unknown health op");
    return 1;
}

} // extern "C"
