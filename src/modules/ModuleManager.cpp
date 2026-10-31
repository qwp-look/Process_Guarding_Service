/**
 * @file ModuleManager.cpp
 * @brief Implementation of the PGS module registry (ModuleManager).
 *
 * Loading pipeline:
 *   export preprobe -> allowlist/hash/signature -> LoadLibraryW ->
 *   GetProcAddress(PG_GetName/Invoke/...) -> ABI/name lookup
 *   (reject duplicates) -> PG_Init -> store Entry.
 *
 * The directory scan (loadFromDirectory) holds the lock for the whole scan so
 * that "module list" never observes a half-loaded set. Individual load() also
 * locks, so the two paths share loadLocked() for the actual work.
 *
 * Note on GetProcAddress casts: MinGW warns on direct FARPROC->fnptr casts
 * (-Wcast-function-type), so we cast through void* first. Functionally
 * identical, just silences the warning.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "Process_Guard/PGModule.h"
#include "Process_Guard/ModuleManager.h"
#include "Process_Guard/PGLogger.h"
#include "Process_Guard/PGUtil.h"
#include "nlohmann/json.hpp"

#include <algorithm>
#include <cctype>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>

// v3 module security: Authenticode verification via WinVerifyTrust.
#include <wintrust.h>
#include <softpub.h>

namespace ProcessGuard
{

    namespace
    {
        thread_local std::vector<const void *> g_invokeRuntimeStack;
        std::string jsonStringValue(const std::string &text, const std::string &key);
        std::string jsonEscape(const std::string &value);

        bool hasCapability(const std::vector<std::string> &caps, const std::string &required)
        {
            return std::find(caps.begin(), caps.end(), required) != caps.end() ||
                   std::find(caps.begin(), caps.end(), "core.call.any") != caps.end();
        }

        std::string addCallerModuleToJson(const std::string &requestJson, const std::string &moduleName)
        {
            const std::string text = util::trim(requestJson);
            if (text.empty() || text.front() != '{')
            {
                return requestJson;
            }
            const std::size_t close = text.find_last_of('}');
            if (close == std::string::npos)
            {
                return requestJson;
            }
            std::string out = text.substr(0, close);
            if (!out.empty() && out.back() != '{')
            {
                out += ",";
            }
            out += "\"__caller_module\":\"" + jsonEscape(moduleName) + "\"";
            out += text.substr(close);
            return out;
        }

        std::string commandVerb(const char *request)
        {
            std::string text = util::trim(request ? request : "");
            const std::size_t sp = text.find_first_of(" \t");
            if (sp != std::string::npos)
            {
                text = text.substr(0, sp);
            }
            return util::toLowerAscii(text);
        }

        bool commandAllowedForCapabilities(const std::vector<std::string> &caps, const char *request)
        {
            const std::string verb = commandVerb(request);
            if (verb.empty()) return false;
            if (verb == "ping") return true;
            if (verb == "list" || verb == "get") return hasCapability(caps, "guard.list");
            if (verb == "stats") return hasCapability(caps, "health.stats");
            if (verb == "events") return hasCapability(caps, "event.read");
            if (verb == "register" || verb == "bless" || verb == "start-register") return hasCapability(caps, "guard.register");
            if (verb == "policy" || verb == "set-policy") return hasCapability(caps, "guard.policy");
            if (verb == "unregister" || verb == "unbless") return hasCapability(caps, "guard.unregister");
            if (verb == "intentional") return hasCapability(caps, "guard.intentional") || hasCapability(caps, "guard.unregister");
            if (verb == "health-check") return hasCapability(caps, "guard.health");
            if (verb == "group") return hasCapability(caps, "guard.group");
            if (verb == "restart-hook") return hasCapability(caps, "guard.hook");
            if (verb == "module") return hasCapability(caps, "module.invoke");
            return false;
        }

        struct ServiceContext
        {
            PGS_ServicesV3 host{};
            PGS_ServicesV3 exposed{};
            std::string moduleName;
            std::vector<std::string> capabilities;
        };

        void writeResponse(char *response, size_t responseSize, const std::string &message)
        {
            if (!response || responseSize == 0) return;
            const std::size_t n = std::min(responseSize - 1, message.size());
            std::memcpy(response, message.data(), n);
            response[n] = '\0';
        }

        int moduleCallThunk(void *context, const char *request, char *response, size_t responseSize)
        {
            ServiceContext *ctx = static_cast<ServiceContext *>(context);
            if (!ctx || !ctx->host.call || !response || responseSize == 0)
            {
                return 1;
            }
            if (!commandAllowedForCapabilities(ctx->capabilities, request))
            {
                writeResponse(response, responseSize, "ERR module capability denied: " + ctx->moduleName + " -> " + commandVerb(request));
                return 0;
            }
            return ctx->host.call(ctx->host.context, request, response, responseSize);
        }

        int moduleCallJsonThunk(void *context, const char *requestJson, char *response, size_t responseSize)
        {
            ServiceContext *ctx = static_cast<ServiceContext *>(context);
            if (!ctx || !ctx->host.call_json || !response || responseSize == 0)
            {
                return 1;
            }
            const std::string method = jsonStringValue(requestJson ? requestJson : "", "method");
            if (method.empty() || !hasCapability(ctx->capabilities, method))
            {
                writeResponse(response, responseSize, "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":\"CAPABILITY_DENIED\",\"message\":\"module capability denied\"}}");
                return 0;
            }
            const std::string annotated = addCallerModuleToJson(requestJson ? requestJson : "", ctx->moduleName);
            return ctx->host.call_json(ctx->host.context, annotated.c_str(), response, responseSize);
        }

        int moduleEmitEventThunk(void *context, const char *eventJson)
        {
            ServiceContext *ctx = static_cast<ServiceContext *>(context);
            return (!ctx || !ctx->host.emit_event) ? 1 : ctx->host.emit_event(ctx->host.context, eventJson);
        }

        const char *moduleGetDataDirThunk(void *context)
        {
            ServiceContext *ctx = static_cast<ServiceContext *>(context);
            return (!ctx || !ctx->host.get_data_dir) ? "" : ctx->host.get_data_dir(ctx->host.context);
        }

        void moduleLogThunk(void *context, int level, const char *message)
        {
            ServiceContext *ctx = static_cast<ServiceContext *>(context);
            if (ctx && ctx->host.log)
            {
                const std::string prefixed = ctx->moduleName + ": " + (message ? message : "");
                ctx->host.log(ctx->host.context, level, prefixed.c_str());
            }
        }

        long long moduleNowMsThunk(void *context)
        {
            ServiceContext *ctx = static_cast<ServiceContext *>(context);
            return (!ctx || !ctx->host.now_ms) ? 0 : ctx->host.now_ms(ctx->host.context);
        }

        bool runtimeOnCurrentInvokeStack(const void *runtime)
        {
            return std::find(g_invokeRuntimeStack.begin(), g_invokeRuntimeStack.end(), runtime) != g_invokeRuntimeStack.end();
        }

        bool isSignedMarker(const std::string &value)
        {
            const std::string text = util::toLowerAscii(util::trim(value));
            return text == "signed" || text == "1" || text == "true" || text == "yes";
        }

        bool isSha256Hex(const std::string &value)
        {
            if (value.size() != 64)
            {
                return false;
            }
            return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
                return std::isxdigit(ch) != 0;
            });
        }

        std::vector<std::string> splitTrimmed(const std::string &value, char delimiter)
        {
            std::vector<std::string> out;
            std::string current;
            for (char ch : value)
            {
                if (ch == delimiter)
                {
                    const std::string trimmed = util::trim(current);
                    if (!trimmed.empty())
                    {
                        out.push_back(trimmed);
                    }
                    current.clear();
                }
                else
                {
                    current.push_back(ch);
                }
            }
            const std::string trimmed = util::trim(current);
            if (!trimmed.empty())
            {
                out.push_back(trimmed);
            }
            return out;
        }

        std::string finalPathForCompareUtf8(const std::string &pathUtf8, bool directory)
        {
            const std::wstring pathW = util::utf8ToWide(pathUtf8);
            if (pathW.empty())
            {
                return std::string();
            }

            const DWORD flags = directory ? FILE_FLAG_BACKUP_SEMANTICS : FILE_ATTRIBUTE_NORMAL;
            HANDLE h = CreateFileW(pathW.c_str(), FILE_READ_ATTRIBUTES,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING, flags, nullptr);
            if (h == INVALID_HANDLE_VALUE)
            {
                return std::string();
            }

            std::vector<wchar_t> buffer(32768, L'\0');
            const DWORD len = GetFinalPathNameByHandleW(
                h, buffer.data(), static_cast<DWORD>(buffer.size()),
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
            CloseHandle(h);
            if (len == 0 || len >= buffer.size())
            {
                return std::string();
            }

            std::wstring normalized(buffer.data(), len);
            if (normalized.rfind(L"\\\\?\\UNC\\", 0) == 0)
            {
                normalized = L"\\\\" + normalized.substr(8);
            }
            else if (normalized.rfind(L"\\\\?\\", 0) == 0)
            {
                normalized = normalized.substr(4);
            }
            std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
            std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](wchar_t ch) {
                return static_cast<wchar_t>(towlower(ch));
            });
            return util::wideToUtf8(normalized);
        }

        bool pathInsideRoot(const std::string &candidateUtf8, const std::string &rootUtf8)
        {
            if (candidateUtf8.empty() || rootUtf8.empty())
            {
                return false;
            }
            const DWORD attr = GetFileAttributesW(util::utf8ToWide(candidateUtf8).c_str());
            if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_DIRECTORY))
            {
                return false;
            }
            std::string candidateFinal = finalPathForCompareUtf8(candidateUtf8, false);
            std::string rootFinal = finalPathForCompareUtf8(rootUtf8, true);
            if (candidateFinal.empty() || rootFinal.empty())
            {
                return false;
            }
            if (candidateFinal.size() <= 4 ||
                candidateFinal.compare(candidateFinal.size() - 4, 4, ".dll") != 0)
            {
                return false;
            }
            if (!rootFinal.empty() && rootFinal.back() == '\\')
            {
                rootFinal.pop_back();
            }
            if (candidateFinal == rootFinal)
            {
                return false;
            }
            const std::string prefix = rootFinal + "\\";
            return candidateFinal.rfind(prefix, 0) == 0;
        }

        struct ProbedModule
        {
            bool hasName = false;
            bool hasInvoke = false;
            bool hasInvokeJson = false;
            bool hasManifest = false;
        };

        bool probeModuleExports(const std::wstring &path, ProbedModule &out, std::string &err)
        {
            out = ProbedModule{};
            HMODULE h = LoadLibraryExW(path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
            if (!h)
            {
                err = "LoadLibraryEx probe failed, error=" + std::to_string(GetLastError());
                return false;
            }

            const auto closeHandle = [&]() {
                FreeLibrary(h);
            };

            out.hasName = GetProcAddress(h, "PG_GetName") != nullptr;
            out.hasInvoke = GetProcAddress(h, "PG_Invoke") != nullptr;
            out.hasInvokeJson = GetProcAddress(h, "PG_InvokeJson") != nullptr;
            out.hasManifest = GetProcAddress(h, "PG_GetManifest") != nullptr;
            if (!out.hasName || (!out.hasInvoke && !out.hasInvokeJson))
            {
                closeHandle();
                err = "missing required PG_ exports";
                return false;
            }

            closeHandle();
            return true;
        }

        std::string moduleSidecarManifestPath(const std::string &modulePath)
        {
            const std::string dir = util::parentDirectoryUtf8(modulePath);
            if (dir.empty())
            {
                return std::string("module.manifest");
            }
            return dir + "\\module.manifest";
        }

        std::string moduleSidecarJsonManifestPath(const std::string &modulePath)
        {
            const std::string dir = util::parentDirectoryUtf8(modulePath);
            return dir.empty() ? std::string("module.manifest.json") : (dir + "\\module.manifest.json");
        }

        std::string modulesLockPath(const std::string &dir)
        {
            return dir.empty() ? std::string("modules.lock") : (dir + "\\modules.lock");
        }

        bool fileExistsUtf8(const std::string &path)
        {
            std::error_code ec;
            return std::filesystem::exists(std::filesystem::path(util::utf8ToWide(path)), ec);
        }

        std::string jsonStringValue(const std::string &text, const std::string &key)
        {
            try
            {
                const auto j = nlohmann::json::parse(text);
                if (j.contains(key) && j.at(key).is_string())
                    return j.at(key).get<std::string>();
            }
            catch (...) {}
            return std::string();
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
                        out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(ch)
                            << std::dec << std::setfill(' ');
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

        std::string moduleMethodFromJson(const std::string &requestJson)
        {
            return jsonStringValue(requestJson, "method");
        }

        bool readSmallTextFile(const std::string &path, std::string &out)
        {
            out.clear();
            std::ifstream in(path, std::ios::in | std::ios::binary);
            if (!in.is_open())
            {
                return false;
            }
            std::ostringstream oss;
            oss << in.rdbuf();
            out = oss.str();
            return true;
        }

        ModuleManager::ModuleManifest parseJsonSidecarManifest(const std::string &jsonText)
        {
            ModuleManager::ModuleManifest manifest;
            manifest.raw = jsonText;
            try
            {
                const auto j = nlohmann::json::parse(jsonText);
                if (j.contains("name") && j.at("name").is_string())
                    manifest.name = j.at("name").get<std::string>();
                if (j.contains("version") && j.at("version").is_string())
                    manifest.version = j.at("version").get<std::string>();
                if (j.contains("summary") && j.at("summary").is_string())
                    manifest.summary = j.at("summary").get<std::string>();
                if (j.contains("capabilities") && j.at("capabilities").is_array())
                {
                    for (const auto &item : j.at("capabilities"))
                        if (item.is_string())
                            manifest.capabilities.push_back(item.get<std::string>());
                }
                if (j.contains("abi"))
                {
                    try
                    {
                        const auto &abiVal = j.at("abi");
                        if (abiVal.is_number_integer())
                            manifest.abiVersion = abiVal.get<unsigned int>();
                        else if (abiVal.is_string())
                            manifest.abiVersion = static_cast<unsigned int>(
                                std::stoul(abiVal.get<std::string>()));
                        manifest.hasAbiVersion = true;
                    }
                    catch (...) { manifest.hasAbiVersion = false; manifest.abiVersion = 0; }
                }
            }
            catch (...) {}
            return manifest;
        }
    } // namespace


    ModuleManager::ModuleManager() = default;

    // On destruction, shut every module down and free its DLL. Order does not
    // matter; modules must not call back into PGS during shutdown.
    ModuleManager::~ModuleManager()
    {
        std::vector<Entry> entries;
        {
            std::unique_lock<std::shared_mutex> lock(m_mutex);
            for (Entry &e : m_modules)
            {
                if (e.runtime)
                {
                    std::lock_guard<std::mutex> rtLock(e.runtime->mutex);
                    e.runtime->unloading = true;
                }
            }
            entries = std::move(m_modules);
            m_modules.clear();
        }
        for (Entry &e : entries)
        {
            if (e.runtime)
            {
                std::unique_lock<std::mutex> rtLock(e.runtime->mutex);
                e.runtime->cv.wait(rtLock, [&e]() { return e.runtime->activeInvokes == 0; });
            }
            if (e.shutdown)
                e.shutdown();
            if (e.handle)
                FreeLibrary(e.handle);
        }
    }

    // ASCII lowercase for case-insensitive module-name keys. Module names are
    // short ASCII identifiers, so locale-insensitive tolower is intentional.
    std::string ModuleManager::lower(const std::string &s)
    {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }

    std::string ModuleManager::allowlistKeyForPath(const std::string &path)
    {
        return moduleKeyFromPath(path);
    }

    ModuleManager::ModuleManifest ModuleManager::parseManifest(const std::string &text)
    {
        ModuleManifest manifest;
        manifest.raw = text;
        for (const std::string &field : util::split(text, ';'))
        {
            const std::size_t eq = field.find('=');
            if (eq == std::string::npos)
            {
                continue;
            }
            const std::string key = util::toLowerAscii(util::trim(field.substr(0, eq)));
            const std::string value = util::trim(field.substr(eq + 1));
            if (key == "name")
            {
                manifest.name = value;
            }
            else if (key == "version")
            {
                manifest.version = value;
            }
            else if (key == "abi" || key == "abi_version" || key == "abi-version")
            {
                try
                {
                    const unsigned long parsed = std::stoul(value);
                    manifest.abiVersion = static_cast<unsigned int>(parsed);
                    manifest.hasAbiVersion = true;
                }
                catch (...)
                {
                    manifest.hasAbiVersion = false;
                    manifest.abiVersion = 0;
                }
            }
            else if (key == "summary")
            {
                manifest.summary = value;
            }
            else if (key == "capabilities" || key == "caps")
            {
                manifest.capabilities = splitTrimmed(value, ',');
            }
        }
        return manifest;
    }

    bool ModuleManager::parseAllowlistLine(const std::string &line, AllowEntry &entry)
    {
        entry = AllowEntry{};
        const std::string trimmed = util::trim(line);
        if (trimmed.empty() || trimmed[0] == '#')
        {
            return false;
        }

        std::vector<std::string> parts;
        std::string current;
        for (char ch : trimmed)
        {
            if (ch == '|')
            {
                parts.push_back(util::trim(current));
                current.clear();
            }
            else
            {
                current.push_back(ch);
            }
        }
        parts.push_back(util::trim(current));
        if (parts.empty() || parts[0].empty())
        {
            return false;
        }

        entry.name = util::toLowerAscii(parts[0]);
        if (parts.size() >= 2)
        {
            const std::string second = util::trim(parts[1]);
            if (parts.size() == 2 && isSignedMarker(second))
            {
                entry.requireSigned = true;
            }
            else
            {
                entry.sha256 = util::toLowerAscii(second);
            }
        }
        if (parts.size() >= 3)
        {
            entry.requireSigned = isSignedMarker(parts[2]);
        }

        if (!entry.sha256.empty() && !isSha256Hex(entry.sha256))
        {
            return false;
        }
        return true;
    }

    std::string ModuleManager::formatAllowlistLine(const AllowEntry &entry)
    {
        const std::string name = util::toLowerAscii(util::trim(entry.name));
        const std::string sha = util::toLowerAscii(util::trim(entry.sha256));
        if (name.empty())
        {
            return std::string();
        }
        if (!sha.empty() && !isSha256Hex(sha))
        {
            return std::string();
        }
        if (!sha.empty() && entry.requireSigned)
        {
            return name + "|" + sha + "|signed";
        }
        if (!sha.empty())
        {
            return name + "|" + sha;
        }
        if (entry.requireSigned)
        {
            return name + "||signed";
        }
        return name;
    }

    std::vector<ModuleManager::AllowEntry> ModuleManager::loadAllowlistEntries(
        const std::string &filePath,
        std::vector<std::string> *diagnostics)
    {
        std::vector<AllowEntry> entries;
        std::ifstream in(filePath, std::ios::in | std::ios::binary);
        if (!in.is_open())
        {
            if (diagnostics)
            {
                diagnostics->push_back("allowlist file not found: " + filePath);
            }
            return entries;
        }

        std::string line;
        int lineNo = 0;
        while (std::getline(in, line))
        {
            ++lineNo;
            if (!line.empty() && line.back() == '\r')
            {
                line.pop_back();
            }
            const std::string trimmed = util::trim(line);
            if (trimmed.empty() || trimmed[0] == '#')
            {
                continue;
            }
            AllowEntry entry;
            if (!parseAllowlistLine(trimmed, entry))
            {
                if (diagnostics)
                {
                    diagnostics->push_back("invalid allowlist line " + std::to_string(lineNo) + ": " + trimmed);
                }
                continue;
            }
            entries.push_back(std::move(entry));
        }
        return entries;
    }

    std::string ModuleManager::modulesRootForPath(const std::string &path)
    {
        std::wstring wpath = util::utf8ToWide(path);
        if (wpath.empty())
        {
            return std::string();
        }

        std::vector<wchar_t> fullPathBuf(32768, L'\0');
        const DWORD fullLen = GetFullPathNameW(wpath.c_str(), static_cast<DWORD>(fullPathBuf.size()), fullPathBuf.data(), nullptr);
        if (fullLen == 0 || fullLen >= fullPathBuf.size())
        {
            return std::string();
        }
        std::filesystem::path p{std::wstring(fullPathBuf.data(), fullLen)};
        p = p.lexically_normal();
        std::filesystem::path parent = p.parent_path();
        if (parent.empty())
        {
            return std::string();
        }

        auto lowerLeaf = [](const std::filesystem::path &value) {
            return util::toLowerAscii(util::wideToUtf8(value.filename().wstring()));
        };
        if (lowerLeaf(parent) == "modules")
        {
            return util::wideToUtf8(parent.wstring());
        }
        std::filesystem::path grand = parent.parent_path();
        if (!grand.empty() && lowerLeaf(grand) == "modules")
        {
            return util::wideToUtf8(grand.wstring());
        }
        return util::wideToUtf8(parent.wstring());
    }

    bool ModuleManager::inspectModulePath(const std::string &path, ModuleInspection &out, std::string &err)
    {
        out = ModuleInspection{};
        out.path = path;
        out.allowlistKey = moduleKeyFromPath(path);

        const std::wstring wpath = util::utf8ToWide(path);
        if (wpath.empty())
        {
            err = "invalid module path";
            return false;
        }

        ProbedModule probed;
        if (!probeModuleExports(wpath, probed, err))
        {
            return false;
        }

        out.hasNameExport = probed.hasName;
        out.hasInvokeExport = probed.hasInvoke;
        out.hasInvokeJsonExport = probed.hasInvokeJson;
        out.hasManifestExport = probed.hasManifest;
        std::string sidecarManifest;
        std::string sidecarJsonManifest;
        if (readSmallTextFile(moduleSidecarJsonManifestPath(path), sidecarJsonManifest))
        {
            out.manifest = parseJsonSidecarManifest(sidecarJsonManifest);
            out.name = out.manifest.name;
            out.version = out.manifest.version;
            out.abiVersion = out.manifest.abiVersion;
            out.hasAbiVersion = out.manifest.hasAbiVersion;
        }
        if (out.manifest.name.empty() && readSmallTextFile(moduleSidecarManifestPath(path), sidecarManifest))
        {
            out.manifest = parseManifest(sidecarManifest);
            out.name = out.manifest.name;
            out.version = out.manifest.version;
            out.abiVersion = out.manifest.abiVersion;
            out.hasAbiVersion = out.manifest.hasAbiVersion;
        }
        if (!util::sha256FileHex(path, out.sha256))
        {
            err = "failed to compute sha256 for module";
            return false;
        }
        out.signatureChecked = true;
        out.signatureValid = verifySignature(wpath);
        return true;
    }

    void ModuleManager::setModulesRoot(const std::string &dir)
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        if (m_modulesRoot != dir)
        {
            m_modulesRoot = dir;
            m_allowlistLoaded = false;
        }
    }

    void ModuleManager::setPermissive(bool v)
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        m_permissive = v;
    }

    void ModuleManager::setEnabledModules(std::vector<std::string> names)
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        m_enabledModules.clear();
        for (std::string &name : names)
        {
            name = lower(util::trim(name));
            if (!name.empty() && std::find(m_enabledModules.begin(), m_enabledModules.end(), name) == m_enabledModules.end())
            {
                m_enabledModules.push_back(name);
            }
        }
    }
    // Probe whether a candidate DLL exports the given symbol WITHOUT running its
    // DllMain or loading/initializing its dependencies. We map it with
    // DONT_RESOLVE_DLL_REFERENCES: per MSDN the system maps the image, makes its
    // exports resolvable via GetProcAddress, but does NOT call DllMain and does
    // NOT load referenced modules. This is the only safe way to inspect a
    // candidate before a real LoadLibraryW: loading a second copy of a runtime
    // DLL (e.g. libstdc++-6.dll placed beside a module) would re-run its
    // DllMain/static init and deadlock the loader. Only DLLs that actually
    // export PG_GetName (a mandatory PGS module export) get a real load.
    bool ModuleManager::hasExportByName(const std::wstring &path, const char *exportName)
    {
        HMODULE h = LoadLibraryExW(path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!h)
        {
            return false;
        }
        const bool found = (GetProcAddress(h, exportName) != nullptr);
        FreeLibrary(h);
        return found;
    }


    bool ModuleManager::loadLocked(const std::string &path, std::string &err)
    {
        const std::wstring wpath = util::utf8ToWide(path);

        if (!m_modulesRoot.empty() && !isInsideConfiguredModulesRoot(path))
        {
            err = "module path outside modules dir";
            return false;
        }

        // Refuse obvious non-modules before the real LoadLibraryW. This probe
        // maps the image without running DllMain.
        ProbedModule probed;
        if (!probeModuleExports(wpath, probed, err))
        {
            return false;
        }

        const std::string candidateKey = moduleKeyFromPath(path);
        if (!isModuleEnabled(candidateKey))
        {
            err = "module disabled by risk/module enablement policy: " + candidateKey;
            return false;
        }

        // v3 security gate: refuse to LoadLibrary a module that is not on the
        // allowlist (fail-closed when the allowlist is empty and we are not in
        // permissive/development mode), and enforce an Authenticode signature
        // when the allowlist entry requires one. This runs BEFORE the real
        // LoadLibraryW so an untrusted DLL never gets its DllMain under PGS.
        std::string allowKey;
        if (!m_permissive)
        {
            allowKey = candidateKey;
            if (allowKey.empty())
            {
                err = "module not in allowlist (cannot derive key)";
                return false;
            }
            const AllowEntry *entry = findAllowEntry(allowKey);
            if (!entry)
            {
                err = "module not in allowlist: " + allowKey;
                return false;
            }
            if (entry->requireSigned && !verifySignature(wpath))
            {
                err = "signature verification failed: " + allowKey;
                return false;
            }
            // Optional pinned-hash check against the file on disk.
            if (!entry->sha256.empty())
            {
                std::string actual;
                if (!util::sha256FileHex(path, actual) ||
                    util::toLowerAscii(actual) != util::toLowerAscii(entry->sha256))
                {
                    err = "hash mismatch: " + allowKey;
                    return false;
                }
            }
        }

        HMODULE handle = LoadLibraryW(wpath.c_str());
        if (!handle)
        {
            err = "LoadLibrary failed, error=" + std::to_string(GetLastError());
            return false;
        }

        // Resolve every export. PG_GetName + PG_Invoke are mandatory; the rest
        // are optional (NULL-safe). Cast via void* to silence -Wcast-function-type.
        Entry e{};
        e.path = path;
        e.handle = handle;
        e.runtime = std::make_shared<Entry::RuntimeState>();
        e.getName = reinterpret_cast<const char *(*)(void)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_GetName")));
        e.getVersion = reinterpret_cast<const char *(*)(void)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_GetVersion")));
        e.getAbiVersion = reinterpret_cast<unsigned int (*)(void)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_GetAbiVersion")));
        e.getManifest = reinterpret_cast<const char *(*)(void)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_GetManifest")));
        e.init = reinterpret_cast<int (*)(void *)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_Init")));
        e.shutdown = reinterpret_cast<void (*)(void)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_Shutdown")));
        e.invoke = reinterpret_cast<int (*)(const char *, char *, size_t)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_Invoke")));
        e.invokeJson = reinterpret_cast<int (*)(const char *, char *, size_t)>(reinterpret_cast<void *>(GetProcAddress(handle, "PG_InvokeJson")));

        // A module without any invoke entry is useless to PGS.
        if (!e.getName || (!e.invoke && !e.invokeJson))
        {
            FreeLibrary(handle);
            err = "missing required PG_ exports";
            return false;
        }

        const char *namePtr = e.getName();
        if (!namePtr || namePtr[0] == '\0')
        {
            FreeLibrary(handle);
            err = "module returned empty name";
            return false;
        }
        e.name = namePtr;

        const char *versionPtr = e.getVersion ? e.getVersion() : "";
        e.version = versionPtr ? versionPtr : "";

        if (e.getAbiVersion)
        {
            e.abiVersion = e.getAbiVersion();
            e.hasAbiVersion = true;
        }
        if (e.getManifest)
        {
            const char *manifestPtr = e.getManifest();
            e.manifest = parseManifest(manifestPtr ? manifestPtr : "");
        }
        std::string sidecarJson;
        if (readSmallTextFile(moduleSidecarJsonManifestPath(path), sidecarJson))
        {
            ModuleManifest sidecar = parseJsonSidecarManifest(sidecarJson);
            if (!sidecar.name.empty() && lower(sidecar.name) != lower(e.name))
            {
                FreeLibrary(handle);
                err = "module sidecar manifest name mismatch: " + sidecar.name + " != " + e.name;
                return false;
            }
            if (sidecar.hasAbiVersion && e.hasAbiVersion && sidecar.abiVersion != e.abiVersion)
            {
                FreeLibrary(handle);
                err = "module sidecar manifest ABI mismatch: manifest " + std::to_string(sidecar.abiVersion) +
                      ", export " + std::to_string(e.abiVersion);
                return false;
            }
            if (!sidecar.raw.empty())
            {
                if (e.manifest.raw.empty() || !sidecar.capabilities.empty())
                {
                    e.manifest = std::move(sidecar);
                }
            }
        }
        if (!e.manifest.name.empty() && lower(e.manifest.name) != lower(e.name))
        {
            FreeLibrary(handle);
            err = "module manifest name mismatch: " + e.manifest.name + " != " + e.name;
            return false;
        }
        if (e.version.empty() && !e.manifest.version.empty())
        {
            e.version = e.manifest.version;
        }
        if (e.manifest.hasAbiVersion)
        {
            if (e.hasAbiVersion && e.manifest.abiVersion != e.abiVersion)
            {
                FreeLibrary(handle);
                err = "module manifest ABI mismatch: manifest " +
                      std::to_string(e.manifest.abiVersion) + ", export " +
                      std::to_string(e.abiVersion);
                return false;
            }
            e.abiVersion = e.manifest.abiVersion;
            e.hasAbiVersion = true;
        }
        if (e.hasAbiVersion && (e.abiVersion < PG_MODULE_ABI_MIN_SUPPORTED || e.abiVersion > PG_MODULE_ABI_VERSION_JSON))
        {
            FreeLibrary(handle);
            err = "module ABI mismatch: got " + std::to_string(e.abiVersion) +
                  ", supported " + std::to_string(PG_MODULE_ABI_MIN_SUPPORTED) + ".." +
                  std::to_string(PG_MODULE_ABI_VERSION_JSON);
            return false;
        }

        if (e.name.empty())
        {
            FreeLibrary(handle);
            err = "module returned empty name";
            return false;
        }
        if (!m_permissive && lower(e.name) != lower(allowKey))
        {
            FreeLibrary(handle);
            err = "module name mismatch: allowlist key " + allowKey + ", PG_GetName " + e.name;
            return false;
        }

        // Reject duplicate names (case-insensitive) so a re-scan or explicit
        // load cannot double-register the same plugin.
        const std::string key = lower(e.name);
        for (const Entry &existing : m_modules)
        {
            if (lower(existing.name) == key)
            {
                if (e.shutdown)
                    e.shutdown();
                FreeLibrary(handle);
                err = "module already loaded: " + e.name;
                return false;
            }
        }

        // Run the module's one-time init. A non-zero return aborts the load.
        if (e.init)
        {
            void *initArg = nullptr;
            std::shared_ptr<ServiceContext> serviceContext;
            if (m_servicesReady)
            {
                serviceContext = std::make_shared<ServiceContext>();
                serviceContext->host = m_services;
                serviceContext->moduleName = e.name;
                serviceContext->capabilities = e.manifest.capabilities;
                serviceContext->exposed = m_services;
                serviceContext->exposed.size = static_cast<unsigned int>(sizeof(PGS_ServicesV3));
                serviceContext->exposed.context = serviceContext.get();
                serviceContext->exposed.call = &moduleCallThunk;
                serviceContext->exposed.now_ms = &moduleNowMsThunk;
                serviceContext->exposed.call_json = &moduleCallJsonThunk;
                serviceContext->exposed.emit_event = &moduleEmitEventThunk;
                serviceContext->exposed.get_data_dir = &moduleGetDataDirThunk;
                serviceContext->exposed.log = &moduleLogThunk;
                e.serviceContext = serviceContext;
                initArg = static_cast<void *>(&serviceContext->exposed);
            }
            const int rc = e.init(initArg);
            if (rc != 0)
            {
                if (e.shutdown)
                    e.shutdown();
                e.serviceContext.reset();
                FreeLibrary(handle);
                err = "PG_Init failed, rc=" + std::to_string(rc);
                return false;
            }
        }

        m_modules.push_back(std::move(e));
        return true;
    }

    bool ModuleManager::load(const std::string &path, std::string &err)
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        const bool ok = loadLocked(path, err);
        if (!ok)
        {
            Logger::warning("PGS: module load failed path=" + path + ", reason=" + err);
        }
        return ok;
    }

    void ModuleManager::ensureAllowlistLoaded(const std::string &dir)
    {
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        if (m_modulesRoot != dir)
        {
            m_modulesRoot = dir;
            m_allowlistLoaded = false;
        }
        if (!m_allowlistLoaded)
        {
            loadAllowlist(dir);
        }
    }

    bool ModuleManager::unload(const std::string &name, std::string &err)
    {
        const std::string key = lower(name);
        std::shared_ptr<Entry::RuntimeState> runtime;
        {
            std::shared_lock<std::shared_mutex> lock(m_mutex);
            for (const Entry &e : m_modules)
            {
                if (lower(e.name) == key)
                {
                    runtime = e.runtime;
                    break;
                }
            }
        }
        if (!runtime)
        {
            err = "module not found: " + name;
            return false;
        }
        if (runtimeOnCurrentInvokeStack(runtime.get()))
        {
            err = "module cannot unload itself during invoke: " + name;
            return false;
        }

        Entry entry{};
        {
            std::unique_lock<std::shared_mutex> lock(m_mutex);
            for (auto it = m_modules.begin(); it != m_modules.end(); ++it)
            {
                if (lower(it->name) == key)
                {
                    if (it->runtime)
                    {
                        std::lock_guard<std::mutex> rtLock(it->runtime->mutex);
                        it->runtime->unloading = true;
                    }
                    entry = std::move(*it);
                    m_modules.erase(it);
                    break;
                }
            }
        }
        if (!entry.handle)
        {
            err = "module not found: " + name;
            return false;
        }
        if (entry.runtime)
        {
            std::unique_lock<std::mutex> rtLock(entry.runtime->mutex);
            entry.runtime->cv.wait(rtLock, [&entry]() { return entry.runtime->activeInvokes == 0; });
        }
        if (entry.shutdown)
            entry.shutdown();
        if (entry.handle)
            FreeLibrary(entry.handle);
        return true;
    }

    // Scan <dir> for modules: load loose *.dll directly under <dir> AND descend
    // one level into subdirectories (modules\<name>\<name>.dll layout, where each
    // folder also holds the module's UI HTML / assets). Logs and skips failures
    // so one bad DLL cannot block the rest. Holds the lock for the whole scan so
    // observers (module list) never see a partial set.
    int ModuleManager::loadFromDirectory(const std::string &dir)
    {
        const std::wstring wdir = util::utf8ToWide(dir);
        auto ensureSep = [](std::wstring &p) {
            if (!p.empty() && p.back() != L'\\' && p.back() != L'/')
                p += L'\\';
        };

        int loaded = 0;
        std::unique_lock<std::shared_mutex> lock(m_mutex);
        m_modulesRoot = dir;
        // v3: load (or reload) the allowlist from <dir>\modules.allow BEFORE
        // scanning so every candidate loadLocked sees an up-to-date gate.
        loadAllowlist(dir);

        // Load a DLL given by a wide path: widen->UTF-8->loadLocked (caller holds lock).
        auto loadWide = [&](const std::wstring &full) {
            // Skip DLLs that are not PGS modules. A full LoadLibraryW on a
            // non-module DLL (e.g. libstdc++-6.dll placed beside a module) would
            // load a second copy of a runtime library, re-run its DllMain/static
            // init and can deadlock the loader. Probe for the mandatory PG_GetName
            // export via an image-resource map (no DllMain) first.
            if (!hasExportByName(full, "PG_GetName"))
            {
                return;
            }
            int len = WideCharToMultiByte(CP_UTF8, 0, full.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string utf8(len > 0 ? len - 1 : 0, '\0');
            if (len > 0)
                WideCharToMultiByte(CP_UTF8, 0, full.c_str(), -1, utf8.data(), len, nullptr, nullptr);
            std::string err;
            if (loadLocked(utf8, err))
                ++loaded;
            else
                Logger::warning("PGS: module scan skipped path=" + utf8 + ", reason=" + err);
        };

        std::wstring topPattern = wdir;
        ensureSep(topPattern);
        topPattern += L"*";

        WIN32_FIND_DATAW fd{};
        HANDLE hFind = FindFirstFileW(topPattern.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE)
            return 0;

        do
        {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                // Skip "." / ".."
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
                    continue;
                // modules\<sub>\*.dll
                std::wstring subPattern = wdir;
                ensureSep(subPattern);
                subPattern += fd.cFileName;
                subPattern += L"\\*.dll";
                WIN32_FIND_DATAW sfd{};
                HANDLE hSub = FindFirstFileW(subPattern.c_str(), &sfd);
                if (hSub == INVALID_HANDLE_VALUE)
                    continue;
                do
                {
                    if (sfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                        continue;
                    std::wstring full = wdir;
                    ensureSep(full);
                    full += fd.cFileName;
                    full += L"\\";
                    full += sfd.cFileName;
                    loadWide(full);
                } while (FindNextFileW(hSub, &sfd));
                FindClose(hSub);
            }
            else
            {
                // Loose *.dll directly under <dir>
                const wchar_t *dot = wcsrchr(fd.cFileName, L'.');
                if (dot && _wcsicmp(dot, L".dll") == 0)
                {
                    std::wstring full = wdir;
                    ensureSep(full);
                    full += fd.cFileName;
                    loadWide(full);
                }
            }
        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
        return loaded;
    }

    std::vector<ModuleManager::ModuleInfo> ModuleManager::list() const
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        std::vector<ModuleInfo> out;
        out.reserve(m_modules.size());
        for (const Entry &e : m_modules)
            out.push_back({e.name, e.version, e.path, e.abiVersion, e.hasAbiVersion, e.manifest, e.invokeJson != nullptr, false});
        return out;
    }

    // Dispatch a call to the named module. 8 KB response buffer is plenty for
    // the short KV status lines modules produce. Returns false ONLY when the
    // module is not found; module-internal errors are delivered via response.
    bool ModuleManager::invoke(const std::string &name, const std::string &request,
                               std::string &response, std::string &err)
    {
        const std::string key = lower(name);
        int (*invokeFn)(const char *, char *, size_t) = nullptr;
        std::shared_ptr<Entry::RuntimeState> runtime;
        {
            std::shared_lock<std::shared_mutex> lock(m_mutex);
            for (const Entry &e : m_modules)
            {
                if (lower(e.name) == key)
                {
                    invokeFn = e.invoke;
                    runtime = e.runtime;
                    break;
                }
            }
        }
        if (!invokeFn || !runtime)
        {
            err = "module not found: " + name;
            return false;
        }

        {
            std::lock_guard<std::mutex> rtLock(runtime->mutex);
            if (runtime->unloading)
            {
                err = "module unloading: " + name;
                return false;
            }
            ++runtime->activeInvokes;
        }

        g_invokeRuntimeStack.push_back(runtime.get());
        struct ActiveInvokeGuard
        {
            std::shared_ptr<Entry::RuntimeState> runtime;
            ~ActiveInvokeGuard()
            {
                if (!runtime)
                {
                    return;
                }
                std::lock_guard<std::mutex> rtLock(runtime->mutex);
                --runtime->activeInvokes;
                runtime->cv.notify_all();
                if (!g_invokeRuntimeStack.empty() && g_invokeRuntimeStack.back() == runtime.get())
                {
                    g_invokeRuntimeStack.pop_back();
                }
                else
                {
                    const auto it = std::find(g_invokeRuntimeStack.begin(), g_invokeRuntimeStack.end(), runtime.get());
                    if (it != g_invokeRuntimeStack.end())
                    {
                        g_invokeRuntimeStack.erase(it);
                    }
                }
            }
        } guard{runtime};

        std::vector<char> buf(8192, '\0');
        const int rc = invokeFn(request.c_str(), buf.data(), buf.size());

        response.assign(buf.data());
        if (rc != 0 && response.empty())
            response = "ERR module invoke failed rc=" + std::to_string(rc);
        return true;
    }

    bool ModuleManager::invokeJson(const std::string &name, const std::string &requestJson,
                                   std::string &responseJson, std::string &err)
    {
        responseJson.clear();
        if (requestJson.size() > PG_MODULE_DEFAULT_MAX_JSON_BYTES)
        {
            err = "module JSON request too large";
            return false;
        }

        const std::string key = lower(name);
        int (*invokeJsonFn)(const char *, char *, size_t) = nullptr;
        int (*invokeFn)(const char *, char *, size_t) = nullptr;
        std::shared_ptr<Entry::RuntimeState> runtime;
        {
            std::shared_lock<std::shared_mutex> lock(m_mutex);
            for (const Entry &e : m_modules)
            {
                if (lower(e.name) == key)
                {
                    invokeJsonFn = e.invokeJson;
                    invokeFn = e.invoke;
                    runtime = e.runtime;
                    break;
                }
            }
        }
        if ((!invokeJsonFn && !invokeFn) || !runtime)
        {
            err = "module not found: " + name;
            return false;
        }

        {
            std::lock_guard<std::mutex> rtLock(runtime->mutex);
            if (runtime->unloading)
            {
                err = "module unloading: " + name;
                return false;
            }
            ++runtime->activeInvokes;
        }

        g_invokeRuntimeStack.push_back(runtime.get());
        struct ActiveInvokeGuard
        {
            std::shared_ptr<Entry::RuntimeState> runtime;
            ~ActiveInvokeGuard()
            {
                if (!runtime)
                {
                    return;
                }
                std::lock_guard<std::mutex> rtLock(runtime->mutex);
                --runtime->activeInvokes;
                runtime->cv.notify_all();
                const auto it = std::find(g_invokeRuntimeStack.begin(), g_invokeRuntimeStack.end(), runtime.get());
                if (it != g_invokeRuntimeStack.end())
                {
                    g_invokeRuntimeStack.erase(it);
                }
            }
        } guard{runtime};

        std::vector<char> buf(PG_MODULE_DEFAULT_MAX_JSON_BYTES + 1, '\0');
        int rc = 0;
        if (invokeJsonFn)
        {
            rc = invokeJsonFn(requestJson.c_str(), buf.data(), buf.size());
            responseJson.assign(buf.data());
            if (rc != 0 && responseJson.empty())
            {
                responseJson = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":\"MODULE_INVOKE_FAILED\",\"message\":\"module JSON invoke failed rc=" + std::to_string(rc) + "\"}}";
            }
            return true;
        }

        const std::string method = moduleMethodFromJson(requestJson);
        std::string op = method;
        const std::size_t dot = op.find_last_of('.');
        if (dot != std::string::npos && dot + 1 < op.size())
        {
            op = op.substr(dot + 1);
        }
        const std::string fallbackRequest = "op=" + op + ";method=" + method +
                                            ";params_json_b64=" + util::base64Encode(requestJson);
        std::vector<char> kvBuf(8192, '\0');
        rc = invokeFn(fallbackRequest.c_str(), kvBuf.data(), kvBuf.size());
        const std::string raw(kvBuf.data());
        const std::string id = jsonStringValue(requestJson, "id");
        const std::string idJson = id.empty() ? std::string("null") : ("\"" + jsonEscape(id) + "\"");
        if (rc != 0 || raw.rfind("ERR", 0) == 0)
        {
            const std::string msg = raw.empty() ? ("module invoke failed rc=" + std::to_string(rc)) : raw;
            responseJson = "{\"jsonrpc\":\"2.0\",\"id\":" + idJson +
                           ",\"error\":{\"code\":\"MODULE_ERROR\",\"message\":\"" +
                           jsonEscape(msg) + "\"}}";
        }
        else
        {
            responseJson = "{\"jsonrpc\":\"2.0\",\"id\":" + idJson +
                           ",\"result\":{\"legacy_response\":\"" + jsonEscape(raw) + "\"}}";
        }
        return true;
    }

    // ---- v3 allowlist + Authenticode helpers --------------------------------

    std::string ModuleManager::moduleKeyFromPath(const std::string &path)
    {
        // Per-folder layout: <dir>\<name>\<name>.dll -> key = "<name>" (folder).
        // Loose layout: <dir>\<name>.dll -> key = "<name>" (stem). Mirrored from
        // the per-folder convention so the allowlist matches either shape.
        const auto pos = path.find_last_of("\\/");
        const std::string leaf = (pos == std::string::npos) ? path : path.substr(pos + 1);
        const std::string leafLower = lower(leaf);
        if (leafLower.size() > 4 && leafLower.substr(leafLower.size() - 4) == ".dll")
        {
            const std::string stem = lower(leaf.substr(0, leaf.size() - 4));
            if (pos == std::string::npos)
            {
                return stem;
            }

            const std::string parent = path.substr(0, pos);
            const auto ppos = parent.find_last_of("\\/");
            const std::string parentLeaf = (ppos == std::string::npos) ? parent : parent.substr(ppos + 1);
            const std::string parentKey = lower(parentLeaf);
            if (parentKey == "modules")
            {
                return stem;
            }
            return parentKey;
        }
        return leafLower;
    }

    const ModuleManager::AllowEntry *ModuleManager::findAllowEntry(const std::string &moduleKey) const
    {
        const std::string key = lower(moduleKey);
        for (auto it = m_allowlist.rbegin(); it != m_allowlist.rend(); ++it)
        {
            if (lower(it->name) == key)
            {
                return &(*it);
            }
        }
        return nullptr;
    }

    bool ModuleManager::isModuleEnabled(const std::string &moduleKey) const
    {
        const std::string key = lower(util::trim(moduleKey));
        if (key.empty())
        {
            return false;
        }
        if (m_permissive)
        {
            return true;
        }
        if (std::find(m_enabledModules.begin(), m_enabledModules.end(), "!" + key) != m_enabledModules.end())
        {
            return false;
        }
        if (std::find(m_enabledModules.begin(), m_enabledModules.end(), "*") != m_enabledModules.end())
        {
            return true;
        }
        return std::find(m_enabledModules.begin(), m_enabledModules.end(), key) != m_enabledModules.end();
    }

    bool ModuleManager::isInsideConfiguredModulesRoot(const std::string &path) const
    {
        return pathInsideRoot(path, m_modulesRoot);
    }

    void ModuleManager::loadAllowlist(const std::string &dir)
    {
        // modules.lock is the release trust source. If present, it must parse
        // into strict hash-pinned entries; corruption keeps the allowlist empty
        // so non-permissive loading fails closed instead of falling back to
        // name-only modules.allow.
        const std::string lockFile = modulesLockPath(dir);
        std::vector<AllowEntry> lockEntries;
        const bool lockFileExists = fileExistsUtf8(lockFile);
        bool lockInvalid = false;
        {
            std::ifstream in(lockFile, std::ios::in | std::ios::binary);
            std::string body;
            if (in.is_open())
            {
                std::ostringstream oss;
                oss << in.rdbuf();
                body = oss.str();
            }
            else if (lockFileExists)
            {
                lockInvalid = true;
            }
            if (lockFileExists && !body.empty())
            {
                try
                {
                    const auto lockJson = nlohmann::json::parse(body);
                    if (!lockJson.contains("modules") || !lockJson.at("modules").is_array())
                    {
                        lockInvalid = true;
                    }
                    else
                    {
                        for (const auto &obj : lockJson.at("modules"))
                        {
                            if (!obj.is_object()) { lockInvalid = true; continue; }
                            AllowEntry entry;
                            if (obj.contains("name") && obj.at("name").is_string())
                                entry.name = util::toLowerAscii(
                                    util::trim(obj.at("name").get<std::string>()));
                            if (obj.contains("sha256") && obj.at("sha256").is_string())
                                entry.sha256 = util::toLowerAscii(
                                    util::trim(obj.at("sha256").get<std::string>()));
                            std::string sigPolicy;
                            if (obj.contains("signature_policy") &&
                                obj.at("signature_policy").is_string())
                                sigPolicy = util::toLowerAscii(
                                    util::trim(obj.at("signature_policy").get<std::string>()));
                            bool reqSigned = false;
                            if (obj.contains("require_signed") &&
                                obj.at("require_signed").is_boolean())
                                reqSigned = obj.at("require_signed").get<bool>();
                            else if (obj.contains("signed") &&
                                     obj.at("signed").is_boolean())
                                reqSigned = obj.at("signed").get<bool>();
                            entry.requireSigned = reqSigned || (sigPolicy == "signed");
                            if (!entry.name.empty() && isSha256Hex(entry.sha256))
                                lockEntries.push_back(std::move(entry));
                            else
                                lockInvalid = true;
                        }
                    }
                }
                catch (...) { lockInvalid = true; }
            }
        }
        if (lockFileExists && (lockInvalid || lockEntries.empty()))
        {
            m_allowlist.clear();
            m_allowlistLoaded = true;
            Logger::warning("PGS: modules.lock invalid or empty; module loading will fail closed: " + lockFile);
            return;
        }
        if (!lockEntries.empty())
        {
            m_allowlist = std::move(lockEntries);
            m_allowlistLoaded = true;
            return;
        }

        // Legacy developer compatibility path used only when modules.lock is
        // absent. Empty allowlist still fails closed outside permissive mode.
        const std::string file = (dir.empty() ? std::string() : (dir + "\\")) + "modules.allow";
        std::vector<std::string> diagnostics;
        m_allowlist = loadAllowlistEntries(file, &diagnostics);
        for (const std::string &diag : diagnostics)
        {
            if (diag.rfind("allowlist file not found:", 0) == 0)
            {
                continue;
            }
            Logger::warning("PGS: " + diag);
        }
        m_allowlistLoaded = true;
    }

    bool ModuleManager::verifySignature(const std::wstring &path)
    {
        // WinVerifyTrust with the published-software policy. Authenticode
        // chain validation; returns true only when the file is signed AND the
        // signing chain is trusted by the system.
        WINTRUST_FILE_INFO fi{};
        fi.cbStruct = sizeof(fi);
        fi.pcwszFilePath = path.c_str();

        WINTRUST_DATA wd{};
        wd.cbStruct = sizeof(wd);
        wd.dwUIChoice = WTD_UI_NONE;
        wd.dwUnionChoice = WTD_CHOICE_FILE;
        wd.pFile = &fi;
        wd.dwStateAction = WTD_STATEACTION_VERIFY;
        wd.dwProvFlags = WTD_SAFER_FLAG;

        GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const LONG rc = WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &wd);
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &policy, &wd);
        return rc == 0;
    }} // namespace ProcessGuard
