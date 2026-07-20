/*
 * pgs_eventlog_module.cpp - local Windows Event Log reader for PGS (ABI v3).
 *
 * Reads the Application log on the local machine and filters by source when
 * requested. This module is read-only and does not talk to any remote service.
 *
 * Request KV examples:
 *   op=status
 *   op=recent;limit=20;source=ProcessGuardService
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

#include <windows.h>
#include <ctime>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

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

    bool parseLimit(const std::string &value, DWORD &out)
    {
        const std::string text = trim(value);
        if (text.empty()) return false;
        for (char ch : text) if (ch < '0' || ch > '9') return false;
        try
        {
            const unsigned long parsed = std::stoul(text);
            if (parsed == 0 || parsed > 512) return false;
            out = static_cast<DWORD>(parsed);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    bool isSafeKvValue(const std::string &value)
    {
        if (value.size() > 128) return false;
        for (unsigned char ch : value)
        {
            if (ch == ';' || ch == '\r' || ch == '\n' || ch == '\0') return false;
            if (ch < 0x20 && ch != '\t') return false;
        }
        return true;
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

    std::string jsonNumberValue(const std::string &text, const std::string &key)
    {
        const std::string needle = "\"" + key + "\"";
        std::size_t pos = text.find(needle);
        if (pos == std::string::npos) return std::string();
        pos = text.find(':', pos + needle.size());
        if (pos == std::string::npos) return std::string();
        ++pos;
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
        const std::size_t start = pos;
        while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) ++pos;
        return pos > start ? text.substr(start, pos - start) : std::string();
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

    std::string eventTypeString(WORD type)
    {
        switch (type)
        {
        case EVENTLOG_ERROR_TYPE: return "error";
        case EVENTLOG_WARNING_TYPE: return "warning";
        default: return "information";
        }
    }

    std::string formatTime(DWORD seconds)
    {
        std::time_t value = static_cast<std::time_t>(seconds);
        std::tm tm{};
        if (localtime_s(&tm, &value) != 0) return std::to_string(seconds);
        char buffer[64] = {0};
        if (std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", &tm) == 0) return std::to_string(seconds);
        return buffer;
    }

    std::string recentEvents(const std::string &sourceFilter, DWORD limit)
    {
        HANDLE log = OpenEventLogW(nullptr, L"Application");
        if (!log) return "ERR failed to open Application event log";

        DWORD read = 0;
        DWORD needed = 0;
        DWORD flags = EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ;
        std::vector<char> buffer(64 * 1024);
        DWORD count = 0;
        std::vector<std::string> lines;
        while (count < limit)
        {
            if (!ReadEventLogA(log, flags, 0, buffer.data(), static_cast<DWORD>(buffer.size()), &read, &needed) || read == 0)
            {
                break;
            }
            DWORD offset = 0;
            while (offset + sizeof(EVENTLOGRECORD) <= read && count < limit)
            {
                const auto *rec = reinterpret_cast<const EVENTLOGRECORD *>(buffer.data() + offset);
                if (rec->Length == 0 || offset + rec->Length > read)
                {
                    break;
                }
                const char *source = reinterpret_cast<const char *>(buffer.data() + offset + sizeof(EVENTLOGRECORD));
                if (source && *source)
                {
                    const std::string sourceText = source;
                    if (!sourceFilter.empty() && lower(sourceText) != lower(sourceFilter))
                    {
                        offset += rec->Length;
                        continue;
                    }
                    std::ostringstream line;
                    line << "EVENT index=" << count
                         << ";event_id=" << (rec->EventID & 0xFFFF)
                         << ";type=" << eventTypeString(rec->EventType)
                         << ";source_b64=" << base64Encode(sourceText)
                         << ";time=" << formatTime(rec->TimeGenerated)
                         << ";strings=" << rec->NumStrings;
                    lines.push_back(line.str());
                    ++count;
                }
                offset += rec->Length;
            }
        }
        CloseEventLog(log);

        std::ostringstream out;
        out << "OK count=" << count;
        for (const std::string &line : lines)
        {
            out << '\n' << line;
        }
        return out.str();
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "eventlog"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=eventlog;version=1.0.0;abi=3;"
           "summary=Local Windows Event Log reader for PGS;"
           "capabilities=eventlog.read,event.read";
}

PG_MODULE_API int PG_Init(void * /*reserved*/)
{
    return 0;
}

PG_MODULE_API void PG_Shutdown(void)
{
}

PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize)
{
    const std::string req = request ? request : "";
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "status" : requestValue(req, "op")));
    if (op == "status")
    {
        setResponse(responseBuf, responseBufSize, "OK source=Application;name=ProcessGuardService");
        return 0;
    }
    if (op == "recent")
    {
        DWORD limit = 20;
        if (!requestValue(req, "limit").empty() && !parseLimit(requestValue(req, "limit"), limit))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid limit");
            return 1;
        }
        const std::string source = requestValue(req, "source");
        if (!source.empty() && !isSafeKvValue(source))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid source");
            return 1;
        }
        const std::string response = recentEvents(source, limit);
        setResponse(responseBuf, responseBufSize, response);
        return response.rfind("OK", 0) == 0 ? 0 : 1;
    }
    setResponse(responseBuf, responseBufSize, "ERR unknown eventlog op");
    return 1;
}

PG_MODULE_API int PG_InvokeJson(const char *requestJson, char *responseJson, size_t responseJsonSize)
{
    const std::string req = requestJson ? requestJson : "";
    const std::string method = jsonStringValue(req, "method");
    const std::string id = jsonId(req);
    if (method == "eventlog.status")
    {
        setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"source\":\"ProcessGuardService\",\"log\":\"Application\"}}");
        return 0;
    }
    if (method == "eventlog.recent")
    {
        DWORD limit = 20;
        std::string limitText = jsonStringValue(req, "limit");
        if (limitText.empty()) limitText = jsonNumberValue(req, "limit");
        if (!limitText.empty() && !parseLimit(limitText, limit))
        {
            setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":\"INVALID_LIMIT\",\"message\":\"invalid limit\"}}");
            return 1;
        }
        const std::string source = jsonStringValue(req, "source");
        if (!source.empty() && !isSafeKvValue(source))
        {
            setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":\"INVALID_SOURCE\",\"message\":\"invalid source\"}}");
            return 1;
        }
        const std::string response = recentEvents(source, limit);
        if (response.rfind("OK", 0) != 0)
        {
            setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":\"EVENTLOG_FAILED\",\"message\":\"" + jsonEscape(response) + "\"}}");
            return 1;
        }
        setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"events_b64\":\"" + base64Encode(response) + "\"}}");
        return 0;
    }
    setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":\"METHOD_NOT_FOUND\",\"message\":\"unknown eventlog method\"}}");
    return 1;
}

} // extern "C"
