/*
 * pgs_dump_module.cpp - explicit opt-in local minidump collection (ABI v3).
 *
 * This module never sends data remotely. A dump request requires confirm=1 and
 * stores the dump in the service ArtifactStore instead of exposing filesystem
 * paths through the protocol.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

#include <windows.h>
#include <dbghelp.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
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
    constexpr std::size_t kMaxDumpArtifactBytes = 16u * 1024u * 1024u;

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

    bool parseDword(const std::string &text, DWORD &out)
    {
        const std::string value = trim(text);
        if (value.empty()) return false;
        for (char ch : value) if (ch < '0' || ch > '9') return false;
        try
        {
            const unsigned long parsed = std::stoul(value);
            if (parsed == 0 || parsed > 0xFFFFFFFFul) return false;
            out = static_cast<DWORD>(parsed);
            return true;
        }
        catch (...)
        {
            return false;
        }
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

    std::string jsonRawValue(const std::string &text, const std::string &key)
    {
        const std::string needle = "\"" + key + "\"";
        std::size_t pos = text.find(needle);
        if (pos == std::string::npos) return std::string();
        pos = text.find(':', pos + needle.size());
        if (pos == std::string::npos) return std::string();
        ++pos;
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
        const std::size_t start = pos;
        while (pos < text.size() && text[pos] != ',' && text[pos] != '}') ++pos;
        return trim(text.substr(start, pos - start));
    }

    std::string jsonId(const std::string &requestJson)
    {
        const std::string id = jsonStringValue(requestJson, "id");
        return id.empty() ? std::string("null") : ("\"" + jsonEscape(id) + "\"");
    }

    std::string win32Error(DWORD code)
    {
        char *buffer = nullptr;
        const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
        const DWORD len = FormatMessageA(flags, nullptr, code, 0, reinterpret_cast<LPSTR>(&buffer), 0, nullptr);
        std::string out = len && buffer ? std::string(buffer, len) : ("win32=" + std::to_string(code));
        if (buffer) LocalFree(buffer);
        while (!out.empty() && (out.back() == '\r' || out.back() == '\n' || out.back() == ' ' || out.back() == '\t')) out.pop_back();
        return out;
    }

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0) return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
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

    bool readWholeFile(const std::filesystem::path &path, std::string &out)
    {
        std::ifstream in(path, std::ios::in | std::ios::binary);
        if (!in.is_open()) return false;
        std::ostringstream oss;
        oss << in.rdbuf();
        out = oss.str();
        return true;
    }

    bool callPGSJson(const std::string &method, const std::string &paramsJson, std::string &response)
    {
        response.clear();
        if (!g_servicesReady || !g_services.call_json || !g_services.context)
        {
            response = "{\"error\":{\"message\":\"JSON services unavailable\"}}";
            return false;
        }
        const std::string request = "{\"jsonrpc\":\"2.0\",\"id\":\"dump\",\"method\":\"" + jsonEscape(method) + "\",\"params\":" + paramsJson + "}";
        std::vector<char> buffer(PG_MODULE_DEFAULT_MAX_JSON_BYTES + 1, '\0');
        const int rc = g_services.call_json(g_services.context, request.c_str(), buffer.data(), buffer.size());
        response.assign(buffer.data());
        return rc == 0 && response.find("\"error\"") == std::string::npos;
    }

    std::string collectDump(DWORD pid, bool confirm, const std::string &type)
    {
        if (!confirm)
        {
            return "ERR dump collect requires confirm=1";
        }
        const std::string rootText = dataDir();
        if (rootText.empty()) return "ERR service data directory unavailable";

        const std::filesystem::path tmpDir = std::filesystem::path(rootText) / "modules" / "dump" / "tmp";
        std::error_code ec;
        std::filesystem::create_directories(tmpDir, ec);
        if (ec) return "ERR failed to create dump temp directory";
        const std::filesystem::path dumpPath = tmpDir / ("pgs-dump-" + std::to_string(pid) + ".dmp");

        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, pid);
        if (!process)
        {
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        }
        if (!process)
        {
            return "ERR OpenProcess failed: " + win32Error(GetLastError());
        }
        HANDLE file = CreateFileW(dumpPath.wstring().c_str(), GENERIC_WRITE | GENERIC_READ, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            const DWORD err = GetLastError();
            CloseHandle(process);
            return "ERR failed to create dump file: " + win32Error(err);
        }
        MINIDUMP_TYPE dumpType = MiniDumpNormal;
        if (lower(type) == "with-data" || lower(type) == "data")
        {
            dumpType = static_cast<MINIDUMP_TYPE>(MiniDumpWithDataSegs | MiniDumpWithHandleData | MiniDumpWithThreadInfo);
        }
        const BOOL ok = MiniDumpWriteDump(process, pid, file, dumpType, nullptr, nullptr, nullptr);
        const DWORD err = ok ? ERROR_SUCCESS : GetLastError();
        CloseHandle(file);
        CloseHandle(process);
        if (!ok)
        {
            std::filesystem::remove(dumpPath, ec);
            return "ERR MiniDumpWriteDump failed: " + win32Error(err);
        }

        const std::uintmax_t size = std::filesystem::file_size(dumpPath, ec);
        if (ec || size == 0)
        {
            std::filesystem::remove(dumpPath, ec);
            return "ERR dump file is empty";
        }
        if (size > kMaxDumpArtifactBytes)
        {
            std::filesystem::remove(dumpPath, ec);
            return "ERR dump exceeds artifact limit";
        }
        std::string content;
        if (!readWholeFile(dumpPath, content))
        {
            std::filesystem::remove(dumpPath, ec);
            return "ERR failed to read dump file";
        }
        std::filesystem::remove(dumpPath, ec);

        std::string response;
        if (!callPGSJson("pgs.operation.create", "{\"method\":\"dump.collect\",\"status\":\"running\",\"progress\":20,\"message\":\"collecting dump\"}", response))
        {
            return "ERR operation.create failed: " + response;
        }
        const std::string operationId = jsonStringValue(response, "operation_id");
        if (operationId.empty()) return "ERR operation.create returned no operation_id";

        const std::string filename = "pgs-dump-" + std::to_string(pid) + ".dmp";
        const std::string params = "{\"operation_id\":\"" + jsonEscape(operationId) +
            "\",\"method\":\"dump.collect\",\"filename\":\"" + jsonEscape(filename) +
            "\",\"content_type\":\"application/vnd.microsoft.minidump\",\"sensitive\":true,\"sensitivity\":\"high\",\"ttl_ms\":21600000,\"content_b64\":\"" +
            base64Encode(content) + "\"}";
        if (!callPGSJson("pgs.artifact.put", params, response))
        {
            callPGSJson("pgs.operation.fail", "{\"operation_id\":\"" + jsonEscape(operationId) + "\",\"code\":\"ARTIFACT_WRITE_FAILED\",\"message\":\"dump artifact write failed\"}", response);
            return "ERR artifact.put failed: " + response;
        }
        const std::string artifactId = jsonStringValue(response, "artifact_id");
        if (artifactId.empty()) return "ERR artifact.put returned no artifact_id";
        callPGSJson("pgs.operation.finish", "{\"operation_id\":\"" + jsonEscape(operationId) + "\",\"message\":\"dump stored\",\"artifact_ids\":[\"" + jsonEscape(artifactId) + "\"],\"result\":{\"artifact_id\":\"" + jsonEscape(artifactId) + "\",\"pid\":" + std::to_string(pid) + ",\"bytes\":" + std::to_string(size) + "}}", response);
        return "OK pid=" + std::to_string(pid) + ";bytes=" + std::to_string(size) + ";operation_id=" + operationId + ";artifact_id=" + artifactId;
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "dump"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=dump;version=1.0.0;abi=3;summary=Explicit local minidump collection;capabilities=dump.collect,pgs.operation.create,pgs.operation.finish,pgs.operation.fail,pgs.artifact.put";
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
    if (op == "status")
    {
        setResponse(responseBuf, responseBufSize, "OK enabled=1;requires_confirm=1;max_bytes=" + std::to_string(kMaxDumpArtifactBytes));
        return 0;
    }
    if (op == "collect")
    {
        DWORD pid = 0;
        if (!parseDword(requestValue(req, "pid"), pid))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid pid");
            return 1;
        }
        const std::string response = collectDump(pid, truthy(requestValue(req, "confirm")), requestValue(req, "type"));
        setResponse(responseBuf, responseBufSize, response);
        return response.rfind("OK", 0) == 0 ? 0 : 1;
    }
    setResponse(responseBuf, responseBufSize, "ERR unknown dump op");
    return 1;
}

PG_MODULE_API int PG_InvokeJson(const char *requestJson, char *responseJson, size_t responseJsonSize)
{
    const std::string req = requestJson ? requestJson : "";
    const std::string method = jsonStringValue(req, "method");
    const std::string id = jsonId(req);
    if (method == "dump.status")
    {
        setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"enabled\":true,\"requires_confirm\":true,\"max_bytes\":" + std::to_string(kMaxDumpArtifactBytes) + "}}");
        return 0;
    }
    if (method == "dump.collect")
    {
        DWORD pid = 0;
        const std::string pidText = jsonRawValue(req, "pid");
        if (!parseDword(pidText, pid))
        {
            setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":\"INVALID_PID\",\"message\":\"invalid pid\"}}");
            return 1;
        }
        const bool confirm = truthy(jsonRawValue(req, "confirm"));
        const std::string response = collectDump(pid, confirm, jsonStringValue(req, "type"));
        if (response.rfind("OK", 0) != 0)
        {
            setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":\"DUMP_FAILED\",\"message\":\"" + jsonEscape(response) + "\"}}");
            return 1;
        }
        setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"summary_b64\":\"" + base64Encode(response) + "\"}}");
        return 0;
    }
    setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":\"METHOD_NOT_FOUND\",\"message\":\"unknown dump method\"}}");
    return 1;
}

} // extern "C"
