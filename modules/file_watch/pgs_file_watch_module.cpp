/*
 * pgs_file_watch_module.cpp - local file change detector for PGS (ABI v3).
 *
 * Stores watch rules under the service data directory. The first pass is a
 * demand-driven detector: operators call check, changed files emit local PGS
 * events that the Windows-native notify module can deliver.
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

    struct Rule
    {
        std::string id;
        std::string path;
        std::string action;
        std::string hash;
        std::uintmax_t size = 0;
        std::int64_t writeTime = 0;
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

    bool parseUnsigned(const std::string &text, std::uintmax_t &out)
    {
        const std::string value = trim(text);
        if (value.empty()) return false;
        for (char ch : value) if (ch < '0' || ch > '9') return false;
        try { out = static_cast<std::uintmax_t>(std::stoull(value)); return true; } catch (...) { return false; }
    }

    bool parseInt64(const std::string &text, std::int64_t &out)
    {
        const std::string value = trim(text);
        if (value.empty()) return false;
        for (char ch : value) if ((ch < '0' || ch > '9') && ch != '-') return false;
        try { out = std::stoll(value); return true; } catch (...) { return false; }
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

    std::string dataDir()
    {
        if (g_servicesReady && g_services.get_data_dir)
        {
            const char *root = g_services.get_data_dir(g_services.context);
            if (root && root[0]) return root;
        }
        return std::string();
    }

    std::filesystem::path rulesPath()
    {
        return std::filesystem::path(dataDir()) / "modules" / "file_watch" / "rules.db";
    }

    bool safeAction(const std::string &action)
    {
        const std::string a = lower(trim(action));
        return a.empty() || a == "event" || a == "none";
    }

    bool safeId(const std::string &id)
    {
        if (id.empty() || id.size() > 64) return false;
        for (unsigned char ch : id)
        {
            if (!(std::isalnum(ch) || ch == '_' || ch == '-')) return false;
        }
        return true;
    }

    std::int64_t fileTimeMs(const std::filesystem::path &path)
    {
        std::error_code ec;
        const auto t = std::filesystem::last_write_time(path, ec);
        if (ec) return 0;
        return static_cast<std::int64_t>(t.time_since_epoch().count());
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

    bool snapshotFile(const std::string &pathText, std::uintmax_t &size, std::int64_t &writeTime, std::string &hash)
    {
        std::filesystem::path path(pathText);
        std::error_code ec;
        if (!std::filesystem::is_regular_file(path, ec)) return false;
        size = std::filesystem::file_size(path, ec);
        if (ec) return false;
        writeTime = fileTimeMs(path);
        return sha256File(path, hash);
    }

    std::vector<Rule> loadRules()
    {
        std::vector<Rule> rules;
        std::ifstream in(rulesPath(), std::ios::in | std::ios::binary);
        std::string line;
        while (std::getline(in, line))
        {
            if (trim(line).empty()) continue;
            Rule r;
            r.id = requestValue(line, "id");
            r.path = base64Decode(requestValue(line, "path_b64"));
            r.action = requestValue(line, "action");
            r.hash = requestValue(line, "sha256");
            parseUnsigned(requestValue(line, "size"), r.size);
            parseInt64(requestValue(line, "write_time"), r.writeTime);
            if (safeId(r.id) && !r.path.empty() && safeAction(r.action)) rules.push_back(std::move(r));
        }
        return rules;
    }

    bool saveRules(const std::vector<Rule> &rules)
    {
        const std::filesystem::path path = rulesPath();
        std::error_code ec;
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) return false;
        std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        for (const Rule &r : rules)
        {
            out << "id=" << r.id << ";path_b64=" << base64Encode(r.path) << ";action=" << (r.action.empty() ? "event" : r.action)
                << ";size=" << r.size << ";write_time=" << r.writeTime << ";sha256=" << r.hash << "\n";
        }
        return true;
    }

    std::string makeId(const std::string &path)
    {
        std::uint32_t h = 2166136261u;
        for (unsigned char ch : path)
        {
            h ^= ch;
            h *= 16777619u;
        }
        std::ostringstream out;
        out << "fw_" << std::hex << h;
        return out.str();
    }

    void emitChangedEvent(const Rule &r)
    {
        if (!g_servicesReady || !g_services.emit_event) return;
        const std::string event = "{\"type\":\"file_watch.changed\",\"id\":\"" + jsonEscape(r.id) + "\",\"path\":\"" + jsonEscape(r.path) + "\"}";
        g_services.emit_event(g_services.context, event.c_str());
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "file_watch"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=file_watch;version=1.0.0;abi=3;summary=Demand-driven local file change watcher;capabilities=file.watch,event.emit";
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
        const std::vector<Rule> rules = loadRules();
        setResponse(responseBuf, responseBufSize, "OK rules=" + std::to_string(rules.size()) + ";mode=demand;actions=event,none");
        return 0;
    }
    if (op == "add")
    {
        Rule r;
        r.path = base64Decode(requestValue(req, "path_b64"));
        if (r.path.empty()) r.path = requestValue(req, "path");
        r.id = requestValue(req, "id");
        if (r.id.empty()) r.id = makeId(r.path);
        r.action = lower(trim(requestValue(req, "action")));
        if (r.action.empty()) r.action = "event";
        if (!safeId(r.id) || r.path.empty() || !safeAction(r.action))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid file_watch rule");
            return 1;
        }
        if (!snapshotFile(r.path, r.size, r.writeTime, r.hash))
        {
            setResponse(responseBuf, responseBufSize, "ERR watched file is not readable");
            return 1;
        }
        std::vector<Rule> rules = loadRules();
        rules.erase(std::remove_if(rules.begin(), rules.end(), [&](const Rule &existing) { return existing.id == r.id; }), rules.end());
        rules.push_back(r);
        if (!saveRules(rules))
        {
            setResponse(responseBuf, responseBufSize, "ERR failed to persist file_watch rules");
            return 1;
        }
        setResponse(responseBuf, responseBufSize, "OK id=" + r.id + ";path_b64=" + base64Encode(r.path) + ";sha256=" + r.hash);
        return 0;
    }
    if (op == "remove")
    {
        const std::string id = requestValue(req, "id");
        if (!safeId(id))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid id");
            return 1;
        }
        std::vector<Rule> rules = loadRules();
        const std::size_t before = rules.size();
        rules.erase(std::remove_if(rules.begin(), rules.end(), [&](const Rule &r) { return r.id == id; }), rules.end());
        if (!saveRules(rules))
        {
            setResponse(responseBuf, responseBufSize, "ERR failed to persist file_watch rules");
            return 1;
        }
        setResponse(responseBuf, responseBufSize, "OK removed=" + std::to_string(before - rules.size()));
        return 0;
    }
    if (op == "list")
    {
        const std::vector<Rule> rules = loadRules();
        std::ostringstream out;
        out << "OK count=" << rules.size();
        for (const Rule &r : rules)
        {
            out << "\nRULE id=" << r.id << ";action=" << r.action << ";path_b64=" << base64Encode(r.path) << ";size=" << r.size << ";sha256=" << r.hash;
        }
        setResponse(responseBuf, responseBufSize, out.str());
        return 0;
    }
    if (op == "check")
    {
        std::vector<Rule> rules = loadRules();
        std::size_t changed = 0;
        for (Rule &r : rules)
        {
            std::uintmax_t size = 0;
            std::int64_t writeTime = 0;
            std::string hash;
            const bool ok = snapshotFile(r.path, size, writeTime, hash);
            if (!ok || size != r.size || writeTime != r.writeTime || hash != r.hash)
            {
                ++changed;
                if (r.action == "event") emitChangedEvent(r);
                if (ok)
                {
                    r.size = size;
                    r.writeTime = writeTime;
                    r.hash = hash;
                }
            }
        }
        saveRules(rules);
        setResponse(responseBuf, responseBufSize, "OK checked=" + std::to_string(rules.size()) + ";changed=" + std::to_string(changed));
        return 0;
    }
    setResponse(responseBuf, responseBufSize, "ERR unknown file_watch op");
    return 1;
}

} // extern "C"
