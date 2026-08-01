/*
 * pgs_script_runner_module.cpp - restricted local script runner (ABI v3).
 *
 * Default state is disabled. Operators must enable it explicitly, register a
 * script under the service data directory, and pass confirm=1 before running.
 * No remote shell, chat, webhook, or network integration is provided.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

#include <windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <cwctype>
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

    struct Script
    {
        std::string id;
        std::string path;
        std::string args;
        std::string sha256;
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

    bool truthy(const std::string &value)
    {
        const std::string v = lower(trim(value));
        return v == "1" || v == "true" || v == "yes" || v == "on" || v == "confirm";
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

    std::wstring utf8ToWide(const std::string &input)
    {
        if (input.empty()) return std::wstring();
        const int needed = MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, nullptr, 0);
        if (needed <= 0) return std::wstring(input.begin(), input.end());
        std::wstring out(static_cast<std::size_t>(needed), L'\0');
        if (MultiByteToWideChar(CP_UTF8, 0, input.c_str(), -1, &out[0], needed) <= 0) return std::wstring(input.begin(), input.end());
        if (!out.empty() && out.back() == L'\0') out.pop_back();
        return out;
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

    void setResponse(char *responseBuf, size_t responseBufSize, const std::string &text)
    {
        if (!responseBuf || responseBufSize == 0) return;
        const std::size_t n = std::min(responseBufSize - 1, text.size());
        std::memcpy(responseBuf, text.data(), n);
        responseBuf[n] = '\0';
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

    bool isSha256Hex(const std::string &value)
    {
        if (value.size() != 64) return false;
        for (unsigned char ch : value)
        {
            if (!std::isxdigit(ch)) return false;
        }
        return true;
    }

    bool safeArgs(const std::string &args)
    {
        if (args.size() > 512) return false;
        for (unsigned char ch : args)
        {
            if (ch == '\r' || ch == '\n' || ch == '\0') return false;
        }
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

    std::filesystem::path moduleRoot()
    {
        return std::filesystem::path(dataDir()) / "modules" / "script_runner";
    }

    std::filesystem::path scriptsPath()
    {
        return moduleRoot() / "scripts.db";
    }

    std::filesystem::path configPath()
    {
        return moduleRoot() / "config.cfg";
    }

    std::filesystem::path allowedScriptsRoot()
    {
        return moduleRoot() / "scripts";
    }

    bool enabled()
    {
        std::ifstream in(configPath(), std::ios::in | std::ios::binary);
        std::string body;
        std::getline(in, body, '\0');
        return body.find("enabled=1") != std::string::npos;
    }

    bool setEnabled(bool value)
    {
        std::error_code ec;
        std::filesystem::create_directories(moduleRoot(), ec);
        if (ec) return false;
        std::ofstream out(configPath(), std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        out << "enabled=" << (value ? "1" : "0") << "\n";
        return true;
    }

    std::wstring normalizeFinalPath(std::wstring value)
    {
        std::replace(value.begin(), value.end(), L'/', L'\\');
        std::transform(value.begin(), value.end(), value.begin(), [](wchar_t ch) {
            return static_cast<wchar_t>(std::towlower(ch));
        });
        while (value.size() > 3 && value.back() == L'\\') value.pop_back();
        return value;
    }

    bool finalPathHasPrefix(const std::wstring &path, const std::wstring &root)
    {
        const std::wstring p = normalizeFinalPath(path);
        const std::wstring r = normalizeFinalPath(root);
        return p == r || (p.size() > r.size() && p.compare(0, r.size(), r) == 0 && p[r.size()] == L'\\');
    }

    bool finalPathFromHandle(HANDLE handle, std::wstring &out)
    {
        out.clear();
        std::vector<wchar_t> buffer(32768, L'\0');
        const DWORD len = GetFinalPathNameByHandleW(handle, buffer.data(), static_cast<DWORD>(buffer.size()), FILE_NAME_NORMALIZED);
        if (len == 0 || len >= buffer.size()) return false;
        out.assign(buffer.data(), len);
        return true;
    }

    bool sha256Handle(HANDLE file, std::string &out)
    {
        out.clear();
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(file, zero, nullptr, FILE_BEGIN)) return false;

        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD objLen = 0;
        DWORD cb = 0;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;
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

        std::vector<unsigned char> buffer(32768);
        bool ok = true;
        for (;;)
        {
            DWORD got = 0;
            if (!ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &got, nullptr))
            {
                ok = false;
                break;
            }
            if (got == 0) break;
            if (BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer.data()), got, 0) != 0)
            {
                ok = false;
                break;
            }
        }

        unsigned char digest[32] = {0};
        if (ok) ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (!ok) return false;
        std::ostringstream oss;
        for (unsigned char b : digest) oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        out = oss.str();
        SetFilePointerEx(file, zero, nullptr, FILE_BEGIN);
        return true;
    }

    std::string sha256String(const std::string &input)
    {
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        DWORD objLen = 0;
        DWORD cb = 0;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return std::string();
        if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cb, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return std::string();
        }
        std::vector<unsigned char> obj(objLen);
        if (BCryptCreateHash(alg, &hash, obj.data(), objLen, nullptr, 0, 0) != 0)
        {
            BCryptCloseAlgorithmProvider(alg, 0);
            return std::string();
        }
        bool ok = BCryptHashData(hash, reinterpret_cast<PUCHAR>(const_cast<char *>(input.data())), static_cast<ULONG>(input.size()), 0) == 0;
        unsigned char digest[32] = {0};
        if (ok) ok = BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0;
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (!ok) return std::string();
        std::ostringstream oss;
        for (unsigned char b : digest) oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
        return oss.str();
    }

    bool validateScriptFile(const std::string &scriptPath, std::string &finalPathUtf8, std::string &sha256, std::string &reason)
    {
        finalPathUtf8.clear();
        sha256.clear();
        reason.clear();

        const std::filesystem::path root = allowedScriptsRoot();
        std::error_code ec;
        std::filesystem::create_directories(root, ec);
        if (ec)
        {
            reason = "failed to create scripts directory";
            return false;
        }

        const std::wstring rootW = root.wstring();
        HANDLE rootHandle = CreateFileW(rootW.c_str(), FILE_READ_ATTRIBUTES,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
        if (rootHandle == INVALID_HANDLE_VALUE)
        {
            reason = "failed to inspect scripts directory: " + win32Error(GetLastError());
            return false;
        }
        std::wstring rootFinal;
        const bool rootOk = finalPathFromHandle(rootHandle, rootFinal);
        CloseHandle(rootHandle);
        if (!rootOk)
        {
            reason = "failed to resolve scripts directory final path";
            return false;
        }

        const std::wstring pathW = utf8ToWide(scriptPath);
        HANDLE file = CreateFileW(pathW.c_str(), GENERIC_READ | FILE_READ_ATTRIBUTES,
                                  FILE_SHARE_READ | FILE_SHARE_DELETE,
                                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            const DWORD err = GetLastError();
            reason = (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND)
                ? "script file not found"
                : ("script file is not readable: " + win32Error(err));
            return false;
        }

        BY_HANDLE_FILE_INFORMATION info{};
        if (!GetFileInformationByHandle(file, &info) || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            CloseHandle(file);
            reason = "script file not found";
            return false;
        }

        std::wstring scriptFinal;
        if (!finalPathFromHandle(file, scriptFinal))
        {
            CloseHandle(file);
            reason = "failed to resolve script final path";
            return false;
        }
        if (!finalPathHasPrefix(scriptFinal, rootFinal))
        {
            CloseHandle(file);
            reason = "script must be under module data scripts directory";
            return false;
        }
        if (!sha256Handle(file, sha256))
        {
            CloseHandle(file);
            reason = "failed to hash script";
            return false;
        }
        CloseHandle(file);
        finalPathUtf8 = wideToUtf8(scriptFinal);
        return true;
    }

    void emitScriptEvent(const std::string &type, const std::string &id,
                         const std::string &result, const std::string &reason,
                         const std::string &sha256, const std::string &args)
    {
        if (!g_servicesReady || !g_services.emit_event) return;
        const std::string argsHash = sha256String(args);
        std::ostringstream event;
        event << "{\"type\":\"" << jsonEscape(type)
              << "\",\"module\":\"script_runner\""
              << ",\"id\":\"" << jsonEscape(id) << "\""
              << ",\"result\":\"" << jsonEscape(result) << "\""
              << ",\"reason\":\"" << jsonEscape(reason) << "\""
              << ",\"sha256\":\"" << jsonEscape(sha256) << "\""
              << ",\"args_sha256\":\"" << jsonEscape(argsHash) << "\""
              << ",\"caller\":\"authenticated-management-client\"}";
        g_services.emit_event(g_services.context, event.str().c_str());
    }

    std::vector<Script> loadScripts()
    {
        std::vector<Script> scripts;
        std::ifstream in(scriptsPath(), std::ios::in | std::ios::binary);
        std::string line;
        while (std::getline(in, line))
        {
            Script s;
            s.id = requestValue(line, "id");
            s.path = base64Decode(requestValue(line, "path_b64"));
            s.args = base64Decode(requestValue(line, "args_b64"));
            s.sha256 = lower(trim(requestValue(line, "sha256")));
            if (!isSha256Hex(s.sha256)) s.sha256.clear();
            if (safeId(s.id) && !s.path.empty() && safeArgs(s.args)) scripts.push_back(std::move(s));
        }
        return scripts;
    }

    bool saveScripts(const std::vector<Script> &scripts)
    {
        std::error_code ec;
        std::filesystem::create_directories(moduleRoot(), ec);
        if (ec) return false;
        std::ofstream out(scriptsPath(), std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open()) return false;
        for (const Script &s : scripts)
        {
            out << "id=" << s.id << ";path_b64=" << base64Encode(s.path) << ";args_b64=" << base64Encode(s.args) << ";sha256=" << s.sha256 << "\n";
        }
        return true;
    }

    const Script *findScript(const std::vector<Script> &scripts, const std::string &id)
    {
        for (const Script &s : scripts) if (lower(s.id) == lower(id)) return &s;
        return nullptr;
    }

    std::wstring quoteArg(const std::wstring &arg)
    {
        std::wstring out = L"\"";
        unsigned backslashes = 0;
        for (wchar_t ch : arg)
        {
            if (ch == L'\\') { ++backslashes; continue; }
            if (ch == L'\"')
            {
                out.append(backslashes * 2 + 1, L'\\');
                out.push_back(ch);
                backslashes = 0;
                continue;
            }
            out.append(backslashes, L'\\');
            backslashes = 0;
            out.push_back(ch);
        }
        out.append(backslashes * 2, L'\\');
        out.push_back(L'\"');
        return out;
    }
} // namespace

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" {

PG_MODULE_API const char *PG_GetName(void) { return "script_runner"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION_JSON; }
PG_MODULE_API const char *PG_GetManifest(void)
{
    return "name=script_runner;version=1.0.0;abi=3;summary=Restricted local script runner;capabilities=script.run,event.emit";
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
        const std::vector<Script> scripts = loadScripts();
        setResponse(responseBuf, responseBufSize, "OK enabled=" + std::string(enabled() ? "1" : "0") +
            ";scripts=" + std::to_string(scripts.size()) +
            ";root_b64=" + base64Encode(wideToUtf8(moduleRoot().wstring())) +
            ";path_policy=final-path-under-data-scripts" +
            ";hash_on_run=1;audit=1");
        return 0;
    }
    if (op == "config")
    {
        const bool value = truthy(requestValue(req, "enabled"));
        if (!setEnabled(value))
        {
            setResponse(responseBuf, responseBufSize, "ERR failed to persist config");
            return 1;
        }
        emitScriptEvent("script_runner.config", "", "updated", value ? "enabled" : "disabled", "", "");
        setResponse(responseBuf, responseBufSize, "OK enabled=" + std::string(value ? "1" : "0"));
        return 0;
    }
    if (op == "add")
    {
        Script s;
        s.id = requestValue(req, "id");
        s.path = base64Decode(requestValue(req, "path_b64"));
        s.args = base64Decode(requestValue(req, "args_b64"));
        if (!safeId(s.id) || s.path.empty() || !safeArgs(s.args))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid script entry");
            return 1;
        }
        std::string finalPath;
        std::string reason;
        if (!validateScriptFile(s.path, finalPath, s.sha256, reason))
        {
            setResponse(responseBuf, responseBufSize, "ERR " + reason);
            return 1;
        }
        std::vector<Script> scripts = loadScripts();
        scripts.erase(std::remove_if(scripts.begin(), scripts.end(), [&](const Script &existing) { return lower(existing.id) == lower(s.id); }), scripts.end());
        scripts.push_back(s);
        if (!saveScripts(scripts))
        {
            setResponse(responseBuf, responseBufSize, "ERR failed to persist scripts");
            return 1;
        }
        emitScriptEvent("script_runner.add", s.id, "registered", "sha256-pinned", s.sha256, s.args);
        setResponse(responseBuf, responseBufSize, "OK id=" + s.id + ";sha256=" + s.sha256 + ";final_path_b64=" + base64Encode(finalPath));
        return 0;
    }
    if (op == "list")
    {
        const std::vector<Script> scripts = loadScripts();
        std::ostringstream out;
        out << "OK count=" << scripts.size();
        for (const Script &s : scripts) out << "\nSCRIPT id=" << s.id << ";path_b64=" << base64Encode(s.path) << ";sha256=" << s.sha256;
        setResponse(responseBuf, responseBufSize, out.str());
        return 0;
    }
    if (op == "run")
    {
        if (!enabled())
        {
            emitScriptEvent("script_runner.run-denied", requestValue(req, "id"), "denied", "disabled", "", "");
            setResponse(responseBuf, responseBufSize, "ERR script runner disabled");
            return 1;
        }
        if (!truthy(requestValue(req, "confirm")))
        {
            emitScriptEvent("script_runner.run-denied", requestValue(req, "id"), "denied", "confirm-required", "", "");
            setResponse(responseBuf, responseBufSize, "ERR run requires confirm=1");
            return 1;
        }
        const std::string id = requestValue(req, "id");
        const std::vector<Script> scripts = loadScripts();
        const Script *s = findScript(scripts, id);
        if (!s)
        {
            emitScriptEvent("script_runner.run-denied", id, "denied", "not-found", "", "");
            setResponse(responseBuf, responseBufSize, "ERR script not found");
            return 1;
        }
        if (s->sha256.empty())
        {
            emitScriptEvent("script_runner.run-denied", id, "denied", "hash-unavailable", "", s->args);
            setResponse(responseBuf, responseBufSize, "ERR script hash unavailable; re-add script");
            return 1;
        }
        std::string finalPath;
        std::string currentSha256;
        std::string reason;
        if (!validateScriptFile(s->path, finalPath, currentSha256, reason))
        {
            emitScriptEvent("script_runner.run-denied", id, "denied", reason, s->sha256, s->args);
            setResponse(responseBuf, responseBufSize, "ERR " + reason);
            return 1;
        }
        if (currentSha256 != s->sha256)
        {
            emitScriptEvent("script_runner.run-denied", id, "denied", "hash-mismatch", currentSha256, s->args);
            setResponse(responseBuf, responseBufSize, "ERR script hash mismatch");
            return 1;
        }
        emitScriptEvent("script_runner.run-attempt", id, "attempt", "confirm=1", s->sha256, s->args);
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        const std::wstring scriptW = utf8ToWide(finalPath);
        std::wstring command = quoteArg(scriptW);
        if (!s->args.empty()) command += L" " + utf8ToWide(s->args);
        const BOOL ok = CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        if (!ok)
        {
            emitScriptEvent("script_runner.run-failed", id, "failed", "CreateProcess failed", s->sha256, s->args);
            setResponse(responseBuf, responseBufSize, "ERR CreateProcess failed");
            return 1;
        }
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        emitScriptEvent("script_runner.run", id, "started", "pid=" + std::to_string(pi.dwProcessId), s->sha256, s->args);
        setResponse(responseBuf, responseBufSize, "OK id=" + id + ";pid=" + std::to_string(pi.dwProcessId));
        return 0;
    }
    setResponse(responseBuf, responseBufSize, "ERR unknown script_runner op");
    return 1;
}

} // extern "C"
