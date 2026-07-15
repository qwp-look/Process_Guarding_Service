/*
 * pgs_report_module.cpp - PGS snapshot/report module (ABI v2).
 *
 * Produces compact base64 text snapshots from stats/list/events. This is also
 * the lightweight backup/export surface requested for the non-notify module
 * set; it does not write files by itself.
 *
 * Request KV examples:
 *   op=snapshot;limit=25
 *   op=backup;limit=50
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

    const char kBase64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string base64Encode(const std::string &input)
    {
        std::string out;
        int val = 0;
        int valb = -6;
        for (unsigned char c : input)
        {
            val = (val << 8) + c;
            valb += 8;
            while (valb >= 0)
            {
                out.push_back(kBase64[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6)
            out.push_back(kBase64[((val << 8) >> (valb + 8)) & 0x3F]);
        while (out.size() % 4)
            out.push_back('=');
        return out;
    }

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

    bool parseLimit(const std::string &text, unsigned long &out)
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
            return out > 0 && out <= 512;
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

    std::string makeReport(const std::string &mode, unsigned long limit, bool &truncated)
    {
        std::string stats;
        std::string guards;
        std::string events;
        callPGS("stats", stats);
        callPGS("list", guards);
        callPGS("events list " + std::to_string(limit), events);

        std::ostringstream report;
        report << "PGS " << mode << "\n"
               << "\n[stats]\n" << (stats.empty() ? "ERR unavailable" : stats) << "\n"
               << "\n[guards]\n" << (guards.empty() ? "ERR unavailable" : guards) << "\n"
               << "\n[events]\n" << (events.empty() ? "ERR unavailable" : events) << "\n";

        std::string text = report.str();
        constexpr std::size_t kMaxPlainBytes = 5600;
        truncated = text.size() > kMaxPlainBytes;
        if (truncated)
        {
            text.resize(kMaxPlainBytes);
            text += "\n[truncated]\n";
        }
        return text;
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "report"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=report;version=1.0.0;abi=2;"
           "summary=Base64 service snapshots and backup reports;"
           "capabilities=report.snapshot,report.backup,event.read,guard.list,health.stats";
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
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "snapshot" : requestValue(req, "op")));
    if (op != "snapshot" && op != "backup")
    {
        setResponse(responseBuf, responseBufSize, "ERR unknown report op");
        return 1;
    }

    unsigned long limit = (op == "backup") ? 50 : 25;
    const std::string requestedLimit = requestValue(req, "limit");
    if (!requestedLimit.empty() && !parseLimit(requestedLimit, limit))
    {
        setResponse(responseBuf, responseBufSize, "ERR invalid limit");
        return 1;
    }

    bool truncated = false;
    const std::string report = makeReport(op, limit, truncated);
    const std::string response = "OK mode=" + op +
                                 ";limit=" + std::to_string(limit) +
                                 ";truncated=" + (truncated ? "1" : "0") +
                                 ";REPORT_B64=" + base64Encode(report);
    setResponse(responseBuf, responseBufSize, response);
    return 0;
}

} // extern "C"
