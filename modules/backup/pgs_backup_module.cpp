/*
 * pgs_backup_module.cpp - local PGS state backup module (ABI v3).
 *
 * Creates a compact text snapshot of the PGS service data directory. Bootstrap
 * plaintext tokens, transient artifact payloads, and temporary files are
 * intentionally skipped. Backup output can be stored in the service ArtifactStore.
 *
 * Request KV examples:
 *   op=snapshot;artifact=1
 *   op=snapshot;max_bytes=1048576
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
#include <sstream>
#include <string>
#include <vector>

#include "Process_Guard/PGModule.h"

namespace
{
    PGS_ServicesV3 g_services{};
    bool g_servicesReady = false;

    const char kBase64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    constexpr std::size_t kDefaultMaxBackupBytes = 2u * 1024u * 1024u;
    constexpr std::size_t kHardMaxBackupBytes = 8u * 1024u * 1024u;

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
        return v == "1" || v == "true" || v == "yes" || v == "on";
    }

    bool parseSize(const std::string &text, std::size_t &out)
    {
        const std::string value = trim(text);
        if (value.empty()) return false;
        for (char ch : value) if (ch < '0' || ch > '9') return false;
        try
        {
            const unsigned long long parsed = std::stoull(value);
            if (parsed == 0 || parsed > kHardMaxBackupBytes) return false;
            out = static_cast<std::size_t>(parsed);
            return true;
        }
        catch (...)
        {
            return false;
        }
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

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0) return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
    }

    std::string wideToUtf8(const std::wstring &input)
    {
        if (input.empty()) return std::string();
        const int len = WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
        if (len <= 0) return std::string(input.begin(), input.end());
        std::string out(static_cast<std::size_t>(len), '\0');
        WideCharToMultiByte(CP_UTF8, 0, input.c_str(), static_cast<int>(input.size()), out.data(), len, nullptr, nullptr);
        return out;
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

    std::string dataDir()
    {
        if (g_servicesReady && g_services.get_data_dir)
        {
            const char *root = g_services.get_data_dir(g_services.context);
            if (root && root[0]) return root;
        }
        return std::string();
    }

    bool skipPath(const std::filesystem::path &root, const std::filesystem::path &path)
    {
        std::error_code ec;
        const std::filesystem::path rel = std::filesystem::relative(path, root, ec);
        if (ec) return true;
        for (const auto &part : rel)
        {
            const std::string leaf = lower(wideToUtf8(part.wstring()));
            if (leaf == "artifacts" || leaf == "backups" || leaf == "tmp") return true;
        }
        const std::string file = lower(wideToUtf8(path.filename().wstring()));
        if (file == "pgs_initial_token.txt" || (file.size() >= 4 && file.substr(file.size() - 4) == ".tmp")) return true;
        return false;
    }

    struct BackupResult
    {
        std::string text;
        std::size_t files = 0;
        std::size_t bytes = 0;
        bool truncated = false;
        std::string error;
    };

    BackupResult makeBackup(std::size_t maxBytes)
    {
        BackupResult result;
        const std::string rootText = dataDir();
        if (rootText.empty())
        {
            result.error = "service data directory unavailable";
            return result;
        }
        const std::filesystem::path root(rootText);
        std::error_code ec;
        if (!std::filesystem::is_directory(root, ec))
        {
            result.error = "service data directory missing";
            return result;
        }

        std::ostringstream out;
        out << "PGS backup v1\n";
        out << "data_root_b64=" << base64Encode(rootText) << "\n";
        for (const auto &entry : std::filesystem::recursive_directory_iterator(root, ec))
        {
            if (ec) break;
            if (!entry.is_regular_file(ec) || skipPath(root, entry.path())) continue;
            std::string content;
            if (!readWholeFile(entry.path(), content)) continue;
            const std::filesystem::path rel = std::filesystem::relative(entry.path(), root, ec);
            if (ec) continue;
            const std::string relText = wideToUtf8(rel.wstring());
            const std::string line = "file_b64=" + base64Encode(relText) + ";size=" + std::to_string(content.size()) + ";content_b64=" + base64Encode(content) + "\n";
            if (out.tellp() >= 0 && static_cast<std::size_t>(out.tellp()) + line.size() > maxBytes)
            {
                result.truncated = true;
                break;
            }
            out << line;
            ++result.files;
            result.bytes += content.size();
        }
        result.text = out.str();
        return result;
    }

    bool callPGSJson(const std::string &method, const std::string &paramsJson, std::string &response)
    {
        response.clear();
        if (!g_servicesReady || !g_services.call_json || !g_services.context)
        {
            response = "{\"error\":{\"message\":\"JSON services unavailable\"}}";
            return false;
        }
        const std::string request = "{\"jsonrpc\":\"2.0\",\"id\":\"backup\",\"method\":\"" + jsonEscape(method) + "\",\"params\":" + paramsJson + "}";
        std::vector<char> buffer(PG_MODULE_DEFAULT_MAX_JSON_BYTES + 1, '\0');
        const int rc = g_services.call_json(g_services.context, request.c_str(), buffer.data(), buffer.size());
        response.assign(buffer.data());
        return rc == 0 && response.find("\"error\"") == std::string::npos;
    }

    bool artifactBackup(const BackupResult &backup, std::string &operationId, std::string &artifactId, std::string &error)
    {
        std::string response;
        if (!callPGSJson("pgs.operation.create", "{\"method\":\"backup.snapshot\",\"status\":\"running\",\"progress\":10,\"message\":\"building backup\"}", response))
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
        const std::string putParams = "{\"operation_id\":\"" + jsonEscape(operationId) + "\",\"method\":\"backup.snapshot\",\"filename\":\"pgs-state-backup.txt\",\"content_type\":\"text/plain; charset=utf-8\",\"content_b64\":\"" + base64Encode(backup.text) + "\"}";
        if (!callPGSJson("pgs.artifact.put", putParams, response))
        {
            callPGSJson("pgs.operation.fail", "{\"operation_id\":\"" + jsonEscape(operationId) + "\",\"code\":\"ARTIFACT_WRITE_FAILED\",\"message\":\"backup artifact write failed\"}", response);
            error = "artifact.put failed: " + response;
            return false;
        }
        artifactId = jsonStringValue(response, "artifact_id");
        if (artifactId.empty())
        {
            error = "artifact.put returned no artifact_id";
            return false;
        }
        const std::string finishParams = "{\"operation_id\":\"" + jsonEscape(operationId) + "\",\"message\":\"backup stored\",\"artifact_ids\":[\"" + jsonEscape(artifactId) + "\"],\"result\":{\"artifact_id\":\"" + jsonEscape(artifactId) + "\",\"files\":" + std::to_string(backup.files) + ",\"bytes\":" + std::to_string(backup.bytes) + ",\"truncated\":" + (backup.truncated ? "true" : "false") + "}}";
        if (!callPGSJson("pgs.operation.finish", finishParams, response))
        {
            error = "operation.finish failed: " + response;
            return false;
        }
        return true;
    }

    std::string snapshotResponse(const std::string &request)
    {
        std::size_t maxBytes = kDefaultMaxBackupBytes;
        const std::string maxText = requestValue(request, "max_bytes");
        if (!maxText.empty() && !parseSize(maxText, maxBytes)) return "ERR invalid max_bytes";
        BackupResult backup = makeBackup(maxBytes);
        if (!backup.error.empty()) return "ERR " + backup.error;
        if (truthy(requestValue(request, "artifact")))
        {
            std::string op;
            std::string art;
            std::string error;
            if (!artifactBackup(backup, op, art, error)) return "ERR " + error;
            return "OK files=" + std::to_string(backup.files) + ";bytes=" + std::to_string(backup.bytes) + ";truncated=" + (backup.truncated ? "1" : "0") + ";operation_id=" + op + ";artifact_id=" + art;
        }
        return "OK files=" + std::to_string(backup.files) + ";bytes=" + std::to_string(backup.bytes) + ";truncated=" + (backup.truncated ? "1" : "0") + ";backup_b64=" + base64Encode(backup.text);
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "backup"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=backup;version=1.0.0;abi=3;"
           "summary=Local PGS state backup snapshots;"
           "capabilities=backup.snapshot,pgs.operation.create,pgs.operation.finish,pgs.operation.fail,pgs.artifact.put";
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
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "snapshot" : requestValue(req, "op")));
    if (op == "snapshot")
    {
        const std::string response = snapshotResponse(req);
        setResponse(responseBuf, responseBufSize, response);
        return response.rfind("OK", 0) == 0 ? 0 : 1;
    }
    if (op == "status")
    {
        const std::string root = dataDir();
        setResponse(responseBuf, responseBufSize, root.empty() ? "ERR data directory unavailable" : ("OK data_dir_b64=" + base64Encode(root)));
        return root.empty() ? 1 : 0;
    }
    setResponse(responseBuf, responseBufSize, "ERR unknown backup op");
    return 1;
}

PG_MODULE_API int PG_InvokeJson(const char *requestJson, char *responseJson, size_t responseJsonSize)
{
    const std::string req = requestJson ? requestJson : "";
    const std::string method = jsonStringValue(req, "method");
    const std::string params = req;
    const std::string id = jsonId(req);
    if (method != "backup.snapshot" && method != "backup.status")
    {
        setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":\"METHOD_NOT_FOUND\",\"message\":\"unknown backup method\"}}");
        return 1;
    }
    if (method == "backup.status")
    {
        const std::string root = dataDir();
        setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"data_dir_b64\":\"" + base64Encode(root) + "\"}}");
        return 0;
    }
    std::string kv = "op=snapshot";
    const std::string artifact = lower(trim(jsonRawValue(params, "artifact")));
    if (artifact == "true" || artifact == "1") kv += ";artifact=1";
    const std::string maxBytes = trim(jsonRawValue(params, "max_bytes"));
    if (!maxBytes.empty()) kv += ";max_bytes=" + maxBytes;
    const std::string response = snapshotResponse(kv);
    if (response.rfind("OK", 0) != 0)
    {
        setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"error\":{\"code\":\"BACKUP_FAILED\",\"message\":\"" + jsonEscape(response) + "\"}}");
        return 1;
    }
    setResponse(responseJson, responseJsonSize, "{\"jsonrpc\":\"2.0\",\"id\":" + id + ",\"result\":{\"summary_b64\":\"" + base64Encode(response) + "\"}}");
    return 0;
}

} // extern "C"
