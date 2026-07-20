/*
 * pgs_report_module.cpp - PGS snapshot/report module (ABI v3).
 *
 * Produces compact base64 text snapshots from stats/list/events. When
 * artifact=1 is supplied it stores the report through the host ArtifactStore
 * and records a completed OperationStore entry instead of embedding the report
 * in the short KV response.
 *
 * Request KV examples:
 *   op=snapshot;limit=25
 *   op=backup;limit=50;artifact=1
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

    bool truthy(const std::string &value)
    {
        const std::string v = lower(trim(value));
        return v == "1" || v == "true" || v == "yes" || v == "on";
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

    std::string jsonEscape(const std::string &value)
    {
        std::ostringstream out;
        for (unsigned char ch : value)
        {
            switch (ch)
            {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\b': out << "\\b"; break;
            case '\f': out << "\\f"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (ch < 0x20)
                {
                    out << "\\u";
                    const char hex[] = "0123456789abcdef";
                    out << '0' << '0' << hex[(ch >> 4) & 0x0F] << hex[ch & 0x0F];
                }
                else
                {
                    out << static_cast<char>(ch);
                }
                break;
            }
        }
        return out.str();
    }

    std::string jsonStringValue(const std::string &text, const std::string &key)
    {
        const std::string needle = "\"" + key + "\"";
        std::size_t pos = text.find(needle);
        if (pos == std::string::npos)
            return std::string();
        pos = text.find(':', pos + needle.size());
        if (pos == std::string::npos)
            return std::string();
        ++pos;
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos])))
            ++pos;
        if (pos >= text.size() || text[pos] != '"')
            return std::string();
        ++pos;
        std::string out;
        bool escaped = false;
        for (; pos < text.size(); ++pos)
        {
            const char ch = text[pos];
            if (escaped)
            {
                switch (ch)
                {
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                default: out.push_back(ch); break;
                }
                escaped = false;
                continue;
            }
            if (ch == '\\')
            {
                escaped = true;
                continue;
            }
            if (ch == '"')
                break;
            out.push_back(ch);
        }
        return out;
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

    bool callPGSJson(const std::string &method, const std::string &paramsJson, std::string &response)
    {
        response.clear();
        if (!g_servicesReady || !g_services.call_json || !g_services.context)
        {
            response = "{\"error\":{\"message\":\"JSON services unavailable\"}}";
            return false;
        }
        const std::string request = "{\"jsonrpc\":\"2.0\",\"id\":\"report\",\"method\":\"" +
                                    jsonEscape(method) + "\",\"params\":" + paramsJson + "}";
        std::vector<char> buffer(PG_MODULE_DEFAULT_MAX_JSON_BYTES + 1, '\0');
        const int rc = g_services.call_json(g_services.context, request.c_str(), buffer.data(), buffer.size());
        response.assign(buffer.data());
        return rc == 0 && response.find("\"error\"") == std::string::npos;
    }

    std::string makeReport(const std::string &mode, unsigned long limit, std::size_t maxBytes, bool &truncated)
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
        truncated = text.size() > maxBytes;
        if (truncated)
        {
            text.resize(maxBytes);
            text += "\n[truncated]\n";
        }
        return text;
    }

    bool makeArtifactReport(const std::string &mode, const std::string &report, bool truncated,
                            std::string &operationId, std::string &artifactId, std::string &error)
    {
        std::string response;
        if (!callPGSJson("pgs.operation.create",
                         "{\"method\":\"report." + jsonEscape(mode) +
                             "\",\"status\":\"running\",\"progress\":10,\"message\":\"building report\"}",
                         response))
        {
            error = "operation.create failed: " + response;
            return false;
        }
        operationId = jsonStringValue(response, "operation_id");
        if (operationId.empty())
        {
            error = "operation.create returned no operation_id";
            return false;
        }

        const std::string filename = mode == "backup" ? "pgs-backup.txt" : "pgs-snapshot.txt";
        const std::string putParams = "{\"operation_id\":\"" + jsonEscape(operationId) +
            "\",\"method\":\"report." + jsonEscape(mode) +
            "\",\"filename\":\"" + filename +
            "\",\"content_type\":\"text/plain; charset=utf-8\",\"content_b64\":\"" +
            base64Encode(report) + "\"}";
        if (!callPGSJson("pgs.artifact.put", putParams, response))
        {
            callPGSJson("pgs.operation.fail", "{\"operation_id\":\"" + jsonEscape(operationId) +
                         "\",\"code\":\"ARTIFACT_WRITE_FAILED\",\"message\":\"report artifact write failed\"}", response);
            error = "artifact.put failed: " + response;
            return false;
        }
        artifactId = jsonStringValue(response, "artifact_id");
        if (artifactId.empty())
        {
            error = "artifact.put returned no artifact_id";
            return false;
        }

        const std::string finishParams = "{\"operation_id\":\"" + jsonEscape(operationId) +
            "\",\"message\":\"report stored\",\"artifact_ids\":[\"" + jsonEscape(artifactId) +
            "\"],\"result\":{\"mode\":\"" + jsonEscape(mode) +
            "\",\"artifact_id\":\"" + jsonEscape(artifactId) +
            "\",\"truncated\":" + (truncated ? "true" : "false") + "}}";
        if (!callPGSJson("pgs.operation.finish", finishParams, response))
        {
            error = "operation.finish failed: " + response;
            return false;
        }
        return true;
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "report"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.1.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=report;version=1.1.0;abi=3;"
           "summary=Base64 service snapshots, backups, and artifact-backed reports;"
           "capabilities=report.snapshot,report.backup,event.read,guard.list,health.stats,pgs.operation.create,pgs.operation.update,pgs.operation.finish,pgs.operation.fail,pgs.artifact.put,pgs.artifact.get_meta";
}

PG_MODULE_API int PG_Init(void *reserved)
{
    g_servicesReady = false;
    if (!reserved)
        return 0;
    const PGS_ServicesV3 *services = static_cast<const PGS_ServicesV3 *>(reserved);
    if (services->size >= sizeof(PGS_Services) && services->call)
    {
        if (services->size >= sizeof(PGS_ServicesV3))
        {
            g_services = *services;
        }
        else
        {
            const PGS_Services *v2 = static_cast<const PGS_Services *>(reserved);
            g_services = PGS_ServicesV3{};
            g_services.size = v2->size;
            g_services.context = v2->context;
            g_services.call = v2->call;
            g_services.now_ms = v2->now_ms;
        }
        g_servicesReady = true;
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

    const bool artifactMode = truthy(requestValue(req, "artifact"));
    bool truncated = false;
    const std::string report = makeReport(op, limit, artifactMode ? 24000 : 5600, truncated);
    if (artifactMode)
    {
        std::string operationId;
        std::string artifactId;
        std::string error;
        if (!makeArtifactReport(op, report, truncated, operationId, artifactId, error))
        {
            setResponse(responseBuf, responseBufSize, "ERR " + error);
            return 1;
        }
        const std::string response = "OK mode=" + op +
                                     ";limit=" + std::to_string(limit) +
                                     ";truncated=" + (truncated ? "1" : "0") +
                                     ";operation_id=" + operationId +
                                     ";artifact_id=" + artifactId;
        setResponse(responseBuf, responseBufSize, response);
        return 0;
    }

    const std::string response = "OK mode=" + op +
                                 ";limit=" + std::to_string(limit) +
                                 ";truncated=" + (truncated ? "1" : "0") +
                                 ";REPORT_B64=" + base64Encode(report);
    setResponse(responseBuf, responseBufSize, response);
    return 0;
}

} // extern "C"
