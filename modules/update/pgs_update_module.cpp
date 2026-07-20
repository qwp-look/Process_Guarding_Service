/*
 * pgs_update_module.cpp - local release manifest verifier (ABI v3).
 *
 * This first pass intentionally performs no network access and no installation.
 * It verifies local release-manifest.json file hashes so update workflows can
 * later build on a safe manifest-verification foundation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
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

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0) return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
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

    bool sha256File(const std::filesystem::path &path, std::string &out)
    {
        out.clear();
        std::ifstream in(path, std::ios::in | std::ios::binary);
        if (!in.is_open()) return false;
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
        DWORD objLen = 0, cb = 0;
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cb, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return false;
        }
        std::vector<unsigned char> obj(objLen);
        if (BCryptCreateHash(alg, &hash, obj.data(), objLen, nullptr, 0, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return false;
        }
        char buffer[32768];
        while (in.good())
        {
            in.read(buffer, sizeof(buffer));
            const std::streamsize got = in.gcount();
            if (got > 0 && BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer), static_cast<ULONG>(got), 0) != 0)
            {
                BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg, 0); return false;
            }
        }
        unsigned char digest[32] = {0};
        const bool ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (!ok) return false;
        std::ostringstream oss;
        for (unsigned char b : digest) oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        out = oss.str();
        return true;
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

    std::string jsonArrayText(const std::string &text, const std::string &key)
    {
        const std::string needle = "\"" + key + "\"";
        std::size_t pos = text.find(needle);
        if (pos == std::string::npos) return std::string();
        pos = text.find(':', pos + needle.size());
        if (pos == std::string::npos) return std::string();
        pos = text.find('[', pos);
        if (pos == std::string::npos) return std::string();
        const std::size_t start = pos;
        int depth = 0;
        bool inString = false;
        bool escaped = false;
        for (; pos < text.size(); ++pos)
        {
            const char ch = text[pos];
            if (inString)
            {
                if (escaped) { escaped = false; continue; }
                if (ch == '\\') { escaped = true; continue; }
                if (ch == '"') inString = false;
                continue;
            }
            if (ch == '"') { inString = true; continue; }
            if (ch == '[') ++depth;
            else if (ch == ']')
            {
                --depth;
                if (depth == 0) return text.substr(start, pos - start + 1);
            }
        }
        return std::string();
    }

    bool safeReleaseRelativePath(const std::string &rel)
    {
        if (rel.empty() || rel.size() > 4096) return false;
        if (rel[0] == '/' || rel[0] == '\\') return false;
        if (rel.find(':') != std::string::npos) return false;
        std::filesystem::path path(rel);
        for (const auto &part : path)
        {
            const std::string text = part.string();
            if (text == "..") return false;
        }
        return true;
    }

    std::filesystem::path releaseRootFromManifest(const std::filesystem::path &manifestPath, const std::string &body)
    {
        const std::string root = jsonStringValue(body, "release_root");
        if (!root.empty())
        {
            std::error_code ec;
            const std::filesystem::path path(root);
            if (std::filesystem::exists(path, ec) && std::filesystem::is_directory(path, ec)) return path;
        }
        return manifestPath.parent_path();
    }

    std::string verifyManifest(const std::filesystem::path &manifestPath)
    {
        std::string body;
        if (!readWholeFile(manifestPath, body)) return "ERR manifest not readable";
        const std::filesystem::path releaseRoot = releaseRootFromManifest(manifestPath, body);
        const std::string filesText = jsonArrayText(body, "files");
        if (filesText.empty()) return "ERR manifest files array missing";
        std::size_t pos = 0;
        std::size_t files = 0;
        std::size_t verified = 0;
        std::string firstError;
        while (true)
        {
            const std::size_t pathPos = filesText.find("\"path\"", pos);
            if (pathPos == std::string::npos) break;
            const std::size_t objStart = filesText.rfind('{', pathPos);
            const std::size_t objEnd = filesText.find('}', pathPos);
            if (objStart == std::string::npos || objEnd == std::string::npos) break;
            const std::string obj = filesText.substr(objStart, objEnd - objStart + 1);
            const std::string rel = jsonStringValue(obj, "path");
            const std::string expected = lower(jsonStringValue(obj, "sha256"));
            pos = objEnd + 1;
            if (rel.empty() || expected.empty()) continue;
            ++files;
            if (!safeReleaseRelativePath(rel))
            {
                if (firstError.empty()) firstError = "unsafe path: " + rel;
                continue;
            }
            std::filesystem::path file = releaseRoot / std::filesystem::path(rel);
            std::string actual;
            if (!sha256File(file, actual) || lower(actual) != expected)
            {
                if (firstError.empty()) firstError = "hash mismatch: " + rel;
                continue;
            }
            ++verified;
        }
        if (!firstError.empty()) return "ERR " + firstError + ";verified=" + std::to_string(verified) + ";files=" + std::to_string(files);
        return "OK files=" + std::to_string(files) + ";verified=" + std::to_string(verified) + ";mode=local-manifest";
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "update"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=update;version=1.0.0;abi=3;summary=Local release manifest verifier;capabilities=update.verify";
}

PG_MODULE_API int PG_Init(void *) { return 0; }
PG_MODULE_API void PG_Shutdown(void) {}

PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize)
{
    const std::string req = request ? request : "";
    const std::string op = lower(trim(requestValue(req, "op").empty() ? "status" : requestValue(req, "op")));
    if (op == "status")
    {
        setResponse(responseBuf, responseBufSize, "OK mode=local-manifest;network=disabled;install=disabled");
        return 0;
    }
    if (op == "verify")
    {
        std::string pathText = base64Decode(requestValue(req, "manifest_b64"));
        if (pathText.empty()) pathText = requestValue(req, "manifest");
        if (pathText.empty())
        {
            setResponse(responseBuf, responseBufSize, "ERR verify requires manifest path");
            return 1;
        }
        const std::string response = verifyManifest(std::filesystem::path(pathText));
        setResponse(responseBuf, responseBufSize, response);
        return response.rfind("OK", 0) == 0 ? 0 : 1;
    }
    setResponse(responseBuf, responseBufSize, "ERR unknown update op");
    return 1;
}

} // extern "C"
