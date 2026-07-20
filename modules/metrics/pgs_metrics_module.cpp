/*
 * pgs_metrics_module.cpp - local PGS metrics module (ABI v3).
 *
 * Exposes compact local service/guard metrics in KV, JSON, or Prometheus text.
 * It only reads PGS status through the module callback surface and does not
 * export data to any remote service.
 *
 * Request KV examples:
 *   op=summary
 *   op=json
 *   op=prometheus
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

    const char kBase64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

    std::string kvValue(const std::string &kv, const std::string &key)
    {
        const std::string needle = key + "=";
        std::size_t pos = kv.find(needle);
        if (pos == std::string::npos) return std::string();
        pos += needle.size();
        const std::size_t semi = kv.find(';', pos);
        const std::size_t tab = kv.find('\t', pos);
        const std::size_t space = kv.find(' ', pos);
        std::size_t end = std::string::npos;
        const std::size_t candidates[] = {semi, tab, space};
        for (std::size_t candidate : candidates)
        {
            if (candidate != std::string::npos && (end == std::string::npos || candidate < end)) end = candidate;
        }
        return end == std::string::npos ? kv.substr(pos) : kv.substr(pos, end - pos);
    }

    std::vector<std::string> splitLines(const std::string &text)
    {
        std::vector<std::string> lines;
        std::string line;
        std::istringstream in(text);
        while (std::getline(in, line))
        {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            lines.push_back(line);
        }
        return lines;
    }

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
        if (valb > -6) out.push_back(kBase64[((val << 8) >> (valb + 8)) & 0x3F]);
        while (out.size() % 4) out.push_back('=');
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

    std::string jsonStringValue(const std::string &text, const std::string &key)
    {
        const std::string needle = "\"" + key + "\"";
        std::size_t pos = text.find(needle);
        if (pos == std::string::npos) return std::string();
        pos = text.find(':', pos + needle.size());
        if (pos == std::string::npos) return std::string();
        ++pos;
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
        if (pos >= text.size() || text[pos] != '"') return std::string();
        ++pos;
        std::string out;
        bool escaped = false;
        for (; pos < text.size(); ++pos)
        {
            const char ch = text[pos];
            if (escaped)
            {
                if (ch == 'n') out.push_back('\n');
                else if (ch == 'r') out.push_back('\r');
                else if (ch == 't') out.push_back('\t');
                else out.push_back(ch);
                escaped = false;
                continue;
            }
            if (ch == '\\') { escaped = true; continue; }
            if (ch == '"') break;
            out.push_back(ch);
        }
        return out;
    }

    std::string jsonId(const std::string &requestJson)
    {
        const std::string id = jsonStringValue(requestJson, "id");
        return id.empty() ? std::string("null") : ("\"" + jsonEscape(id) + "\"");
    }

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0) return;
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

    struct Metrics
    {
        std::string guards = "0";
        std::string active = "0";
        std::string totalRestarts = "0";
        std::string restartsInWindow = "0";
        std::string uptime = "0";
        int quarantined = 0;
        int unhealthy = 0;
        int paused = 0;
        int missing = 0;
        DWORD memoryLoad = 0;
        unsigned long long totalPhysMb = 0;
        unsigned long long availPhysMb = 0;
    };

    Metrics collectMetrics()
    {
        Metrics m;
        std::string stats;
        if (callPGS("stats", stats))
        {
            m.guards = kvValue(stats, "guards").empty() ? "0" : kvValue(stats, "guards");
            m.active = kvValue(stats, "active").empty() ? "0" : kvValue(stats, "active");
            m.totalRestarts = kvValue(stats, "totalRestarts").empty() ? "0" : kvValue(stats, "totalRestarts");
            m.restartsInWindow = kvValue(stats, "restartsInWindow").empty() ? "0" : kvValue(stats, "restartsInWindow");
            m.uptime = kvValue(stats, "uptime").empty() ? "0" : kvValue(stats, "uptime");
        }
        std::string list;
        if (callPGS("list", list))
        {
            const std::vector<std::string> lines = splitLines(list);
            for (std::size_t i = 1; i < lines.size(); ++i)
            {
                const std::string status = lower(kvValue(lines[i], "STATUS"));
                const std::string health = lower(kvValue(lines[i], "HEALTH_STATUS"));
                if (status == "quarantined") ++m.quarantined;
                if (status == "paused") ++m.paused;
                if (status == "missing") ++m.missing;
                if (!health.empty() && health != "disabled" && health != "healthy") ++m.unhealthy;
            }
        }
        MEMORYSTATUSEX mem{};
        mem.dwLength = sizeof(mem);
        if (GlobalMemoryStatusEx(&mem))
        {
            m.memoryLoad = mem.dwMemoryLoad;
            m.totalPhysMb = static_cast<unsigned long long>(mem.ullTotalPhys / (1024ull * 1024ull));
            m.availPhysMb = static_cast<unsigned long long>(mem.ullAvailPhys / (1024ull * 1024ull));
        }
        return m;
    }

    std::string summaryKv(const Metrics &m)
    {
        std::ostringstream out;
        out << "OK guards=" << m.guards
            << ";active=" << m.active
            << ";quarantined=" << m.quarantined
            << ";paused=" << m.paused
            << ";missing=" << m.missing
            << ";unhealthy=" << m.unhealthy
            << ";total_restarts=" << m.totalRestarts
            << ";restarts_in_window=" << m.restartsInWindow
            << ";uptime_sec=" << m.uptime
            << ";memory_load=" << m.memoryLoad
            << ";total_physical_mb=" << m.totalPhysMb
            << ";available_physical_mb=" << m.availPhysMb;
        return out.str();
    }

    std::string metricsJson(const Metrics &m)
    {
        std::ostringstream out;
        out << "{\"guards\":" << m.guards
            << ",\"active\":" << m.active
            << ",\"quarantined\":" << m.quarantined
            << ",\"paused\":" << m.paused
            << ",\"missing\":" << m.missing
            << ",\"unhealthy\":" << m.unhealthy
            << ",\"total_restarts\":" << m.totalRestarts
            << ",\"restarts_in_window\":" << m.restartsInWindow
            << ",\"uptime_sec\":" << m.uptime
            << ",\"memory_load\":" << m.memoryLoad
            << ",\"total_physical_mb\":" << m.totalPhysMb
            << ",\"available_physical_mb\":" << m.availPhysMb << "}";
        return out.str();
    }

    std::string prometheusText(const Metrics &m)
    {
        std::ostringstream out;
        out << "# TYPE pgs_guards gauge\npgs_guards " << m.guards << "\n"
            << "# TYPE pgs_active_guards gauge\npgs_active_guards " << m.active << "\n"
            << "# TYPE pgs_quarantined_guards gauge\npgs_quarantined_guards " << m.quarantined << "\n"
            << "# TYPE pgs_unhealthy_guards gauge\npgs_unhealthy_guards " << m.unhealthy << "\n"
            << "# TYPE pgs_total_restarts counter\npgs_total_restarts " << m.totalRestarts << "\n"
            << "# TYPE pgs_uptime_seconds gauge\npgs_uptime_seconds " << m.uptime << "\n"
            << "# TYPE pgs_system_memory_load_percent gauge\npgs_system_memory_load_percent " << m.memoryLoad << "\n"
            << "# TYPE pgs_system_available_memory_megabytes gauge\npgs_system_available_memory_megabytes " << m.availPhysMb << "\n";
        return out.str();
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "metrics"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=metrics;version=1.0.0;abi=3;"
           "summary=Local PGS guard and host metrics;"
           "capabilities=metrics.summary,metrics.prometheus,health.stats,guard.list";
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
        g_servicesReady = (g_services.call && g_services.context);
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
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "summary" : requestValue(req, "op")));
    const Metrics m = collectMetrics();
    if (op == "summary")
    {
        setResponse(responseBuf, responseBufSize, summaryKv(m));
        return 0;
    }
    if (op == "json")
    {
        setResponse(responseBuf, responseBufSize, "OK json_b64=" + base64Encode(metricsJson(m)));
        return 0;
    }
    if (op == "prometheus")
    {
        setResponse(responseBuf, responseBufSize, "OK prometheus_b64=" + base64Encode(prometheusText(m)));
        return 0;
    }
    setResponse(responseBuf, responseBufSize, "ERR unknown metrics op");
    return 1;
}

PG_MODULE_API int PG_InvokeJson(const char *requestJson, char *responseJson, size_t responseJsonSize)
{
    const std::string req = requestJson ? requestJson : "";
    const std::string method = jsonStringValue(req, "method");
    const Metrics m = collectMetrics();
    const std::string id = jsonId(req);
    std::string result;
    bool ok = true;
    if (method == "metrics.summary") result = metricsJson(m);
    else if (method == "metrics.prometheus") result = "{\"prometheus_b64\":\"" + base64Encode(prometheusText(m)) + "\"}";
    else
    {
        ok = false;
        result = "{\"code\":\"METHOD_NOT_FOUND\",\"message\":\"unknown metrics method\"}";
    }

    if (ok)
        setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":" + result + "}");
    else
        setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":" + result + "}");
    return ok ? 0 : 1;
}

} // extern "C"
