/**
 * @file PGSModuleInstall.cpp
 * @brief Service-owned module install and rollback handlers.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "Process_Guard/PGS.h"
#include "Process_Guard/PGModulePolicy.h"
#include "PGSServiceHelpers.h"
#include "nlohmann/json.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

namespace ProcessGuard
{

using namespace util;

namespace
{
    std::int64_t epochMs()
    {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    struct ModuleInstallArgs
    {
        std::string sourcePathUtf8;
        bool confirm = false;
        bool load = false;
        std::string source = "local-install";
    };

    std::filesystem::path jsonManifestPathForDll(const std::filesystem::path &dllPath)
    {
        return dllPath.parent_path() / L"module.manifest.json";
    }

    std::string safeModuleName(const ModuleManager::ModuleInspection &info)
    {
        std::string key = info.name.empty() ? info.allowlistKey : info.name;
        key = toLowerAscii(trim(key));
        for (char ch : key)
        {
            const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
                            ch == '_' || ch == '-' || ch == '.';
            if (!ok)
            {
                return std::string();
            }
        }
        return key;
    }

    std::string moduleLockObject(const ModuleManager::ModuleInspection &info,
                                 const std::string &name,
                                 const std::string &source)
    {
        module_policy::ManifestSpec manifest;
        std::string parseErr;
        if (!module_policy::parseManifestJson(info.manifest.raw, manifest, parseErr))
        {
            manifest.name = name;
            manifest.version = info.version.empty() ? "1.0.0" : info.version;
            manifest.risk = "medium";
            manifest.publisher = "local";
            manifest.capabilities = info.manifest.capabilities;
        }

        nlohmann::json obj = nlohmann::json::object();
        obj["name"] = name;
        obj["version"] = manifest.version.empty() ? (info.version.empty() ? "1.0.0" : info.version) : manifest.version;
        obj["class"] = manifest.json.value("class", "command");
        obj["sha256"] = toLowerAscii(info.sha256);
        obj["publisher"] = manifest.publisher.empty() ? (manifest.author.empty() ? "local" : manifest.author) : manifest.publisher;
        obj["source"] = source.empty() ? "local-install" : source;
        obj["capabilities"] = manifest.capabilities;
        obj["risk"] = manifest.risk.empty() ? std::string("medium") : manifest.risk;
        obj["trustedAt"] = std::to_string(epochMs());
        obj["signature_policy"] = "hash";
        obj["require_signed"] = false;
        return obj.dump();
    }

    bool writeOrUpdateModulesLock(const std::filesystem::path &lockPath,
                                  const ModuleManager::ModuleInspection &info,
                                  const std::string &name,
                                  const std::string &source,
                                  std::string &err)
    {
        nlohmann::json lock = nlohmann::json::object();
        lock["version"] = 1;
        lock["generated_at"] = "service";
        lock["modules"] = nlohmann::json::array();

        std::error_code ec;
        if (std::filesystem::exists(lockPath, ec))
        {
            std::string body;
            if (!service_util::readTextFileLimited(lockPath, body, 4 * 1024 * 1024))
            {
                err = "failed to read existing modules.lock";
                return false;
            }
            try
            {
                lock = nlohmann::json::parse(body);
            }
            catch (const std::exception &e)
            {
                err = std::string("existing modules.lock is invalid JSON: ") + e.what();
                return false;
            }
            if (!lock.is_object() || !lock.contains("modules") || !lock.at("modules").is_array())
            {
                err = "existing modules.lock has invalid structure";
                return false;
            }
        }
        else if (ec)
        {
            err = "failed to inspect modules.lock";
            return false;
        }

        nlohmann::json modules = nlohmann::json::array();
        for (const auto &obj : lock.at("modules"))
        {
            if (!obj.is_object() || !obj.contains("name") || !obj.at("name").is_string())
            {
                err = "existing modules.lock contains an invalid module entry";
                return false;
            }
            const std::string existingName = module_policy::normalizeIdentifier(obj.at("name").get<std::string>());
            if (existingName.empty())
            {
                err = "existing modules.lock contains an invalid module name";
                return false;
            }
            if (!obj.contains("sha256") || !obj.at("sha256").is_string() ||
                module_policy::normalizeSha256(obj.at("sha256").get<std::string>()).empty())
            {
                err = "existing modules.lock contains an invalid module sha256";
                return false;
            }
            if (existingName != name)
            {
                modules.push_back(obj);
            }
        }
        modules.push_back(nlohmann::json::parse(moduleLockObject(info, name, source)));
        lock["version"] = 1;
        lock["generated_at"] = "service";
        lock["modules"] = modules;

        std::filesystem::create_directories(lockPath.parent_path(), ec);
        if (ec)
        {
            err = "failed to create modules dir for modules.lock";
            return false;
        }
        const std::filesystem::path tempPath = lockPath.wstring() + L".tmp";
        if (!service_util::writeWholeFile(tempPath, lock.dump(2) + "\n"))
        {
            err = "failed to write temporary modules.lock";
            return false;
        }
        if (!MoveFileExW(tempPath.c_str(), lockPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            std::filesystem::remove(tempPath, ec);
            err = "failed to replace modules.lock: " + win32ErrorText(GetLastError());
            return false;
        }
        return true;
    }

    bool parseModuleInstallArgs(const std::string &rest, ModuleInstallArgs &out, std::string &err)
    {
        out = ModuleInstallArgs{};
        std::vector<std::string> parts;
        for (const std::string &part : split(rest, ' '))
        {
            const std::string value = trim(part);
            if (!value.empty())
            {
                parts.push_back(value);
            }
        }
        if (parts.empty())
        {
            err = "module install requires a base64 path to a module DLL";
            return false;
        }
        out.sourcePathUtf8 = base64Decode(parts[0]);
        if (out.sourcePathUtf8.empty())
        {
            err = "invalid module install path";
            return false;
        }
        for (std::size_t i = 1; i < parts.size(); ++i)
        {
            const std::string &arg = parts[i];
            if (arg == "--confirm")
            {
                out.confirm = true;
                continue;
            }
            if (arg == "--load")
            {
                out.load = true;
                continue;
            }
            if (arg == "--source")
            {
                if (i + 1 >= parts.size())
                {
                    err = "module install --source requires a value";
                    return false;
                }
                out.source = toLowerAscii(trim(parts[++i]));
                continue;
            }
            const std::string prefix = "--source=";
            if (arg.rfind(prefix, 0) == 0)
            {
                out.source = toLowerAscii(trim(arg.substr(prefix.size())));
                continue;
            }
            err = "unknown module install option: " + arg;
            return false;
        }
        if (out.source == "local")
        {
            out.source = "local-install";
        }
        if (out.source != "local-install" && out.source != "registry")
        {
            err = "module install source must be local-install or registry";
            return false;
        }
        return true;
    }

    bool loadAndValidateModuleManifest(const std::filesystem::path &dllPath,
                                       const ModuleManager::ModuleInspection &info,
                                       const std::string &expectedName,
                                       module_policy::ManifestSpec &manifest,
                                       std::string &err)
    {
        std::string manifestText;
        const std::filesystem::path manifestPath = jsonManifestPathForDll(dllPath);
        if (!service_util::readTextFileLimited(manifestPath, manifestText))
        {
            err = "module install requires module.manifest.json beside the DLL";
            return false;
        }
        if (!module_policy::parseManifestJson(manifestText, manifest, err))
        {
            return false;
        }
        if (!expectedName.empty() && manifest.name != expectedName)
        {
            err = "module manifest name does not match install key";
            return false;
        }
        if (!info.name.empty() && toLowerAscii(info.name) != manifest.name)
        {
            err = "module inspection name does not match manifest";
            return false;
        }
        if (info.hasAbiVersion && info.abiVersion != manifest.abi)
        {
            err = "module inspection ABI does not match manifest";
            return false;
        }
        return true;
    }

    void restoreModuleInstallBackup(const std::filesystem::path &finalDir,
                                    const std::filesystem::path &backupDir)
    {
        std::error_code ec;
        if (std::filesystem::exists(finalDir, ec))
        {
            std::filesystem::remove_all(finalDir, ec);
        }
        if (std::filesystem::exists(backupDir, ec))
        {
            std::filesystem::rename(backupDir, finalDir, ec);
        }
    }

    bool copyModulePayloadToStage(const std::filesystem::path &sourceDll,
                                  const std::filesystem::path &stageDir,
                                  std::string &err)
    {
        std::error_code ec;
        std::filesystem::create_directories(stageDir, ec);
        if (ec)
        {
            err = "failed to create staging directory";
            return false;
        }
        const std::filesystem::path sourceDir = sourceDll.parent_path();
        for (const auto &entry : std::filesystem::directory_iterator(sourceDir, ec))
        {
            if (ec) break;
            if (!entry.is_regular_file())
            {
                continue;
            }
            const std::string extLower = toLowerAscii(wideToUtf8(entry.path().extension().wstring()));
            if (extLower != ".dll" && extLower != ".json" && extLower != ".manifest" &&
                extLower != ".html" && extLower != ".sys" && extLower != ".txt")
            {
                continue;
            }
            std::filesystem::copy_file(entry.path(), stageDir / entry.path().filename(),
                                       std::filesystem::copy_options::overwrite_existing, ec);
            if (ec)
            {
                err = "failed to copy module payload file";
                return false;
            }
        }
        return true;
    }

    std::filesystem::path firstDllInDir(const std::filesystem::path &dir)
    {
        std::error_code ec;
        for (const auto &entry : std::filesystem::directory_iterator(dir, ec))
        {
            if (entry.is_regular_file() && service_util::pathHasExtension(entry.path(), ".dll"))
            {
                return entry.path();
            }
        }
        return std::filesystem::path();
    }

    std::filesystem::path newestRollbackDir(const std::filesystem::path &rollbackRoot,
                                            const std::string &name)
    {
        std::filesystem::path newest;
        std::error_code ec;
        const std::wstring prefix = utf8ToWide(name + "-");
        for (const auto &entry : std::filesystem::directory_iterator(rollbackRoot, ec))
        {
            if (!entry.is_directory()) continue;
            const std::wstring leaf = entry.path().filename().wstring();
            if (leaf.rfind(prefix, 0) != 0) continue;
            if (newest.empty() || leaf > newest.filename().wstring())
            {
                newest = entry.path();
            }
        }
        return newest;
    }
}

std::string PGS::handleModuleInstallCommand(const std::string &rest)
{
    ModuleInstallArgs installArgs;
    std::string err;
    if (!parseModuleInstallArgs(rest, installArgs, err))
    {
        return "ERR " + err;
    }
    std::filesystem::path sourceDll = std::filesystem::path(utf8ToWide(installArgs.sourcePathUtf8));
    std::error_code ec;
    if (!std::filesystem::is_regular_file(sourceDll, ec) || !service_util::pathHasExtension(sourceDll, ".dll"))
    {
        return "ERR module install source must be a DLL file";
    }
    ModuleManager::ModuleInspection info;
    if (!ModuleManager::inspectModulePath(installArgs.sourcePathUtf8, info, err))
    {
        return "ERR " + err;
    }
    module_policy::ManifestSpec sourceManifest;
    if (!loadAndValidateModuleManifest(sourceDll, info, std::string(), sourceManifest, err))
    {
        return "ERR " + err;
    }
    const std::string name = sourceManifest.name;
    if (name.empty() || safeModuleName(info) != name)
    {
        return "ERR invalid module name in manifest/path";
    }
    if (module_policy::riskAtLeast(sourceManifest.risk, module_policy::RiskLevel::High) && !installArgs.confirm)
    {
        return "ERR high/critical risk module install requires --confirm";
    }
    if (sourceManifest.trust == "community" && !installArgs.confirm)
    {
        return "ERR community module install requires --confirm";
    }

    const std::filesystem::path modulesRoot = std::filesystem::path(utf8ToWide(m_modulesDir));
    const std::filesystem::path stagingRoot = service_util::moduleStagingRootForModulesDir(m_modulesDir);
    const std::string stamp = std::to_string(epochMs());
    const std::filesystem::path stageDir = stagingRoot / utf8ToWide(name + "-stage-" + stamp);
    const std::filesystem::path finalDir = modulesRoot / utf8ToWide(name);
    const std::filesystem::path rollbackRoot = stagingRoot / L"rollback";
    const std::filesystem::path backupDir = rollbackRoot / utf8ToWide(name + "-" + stamp);

    std::filesystem::create_directories(stagingRoot, ec);
    if (ec)
    {
        return "ERR failed to create modules staging root";
    }
    std::filesystem::create_directories(rollbackRoot, ec);
    if (ec)
    {
        return "ERR failed to create modules rollback root";
    }
    if (!copyModulePayloadToStage(sourceDll, stageDir, err))
    {
        std::filesystem::remove_all(stageDir, ec);
        return "ERR " + err;
    }

    const std::filesystem::path stagedDll = stageDir / sourceDll.filename();
    ModuleManager::ModuleInspection stagedInfo;
    if (!ModuleManager::inspectModulePath(wideToUtf8(stagedDll.wstring()), stagedInfo, err))
    {
        std::filesystem::remove_all(stageDir, ec);
        return "ERR staged module verification failed: " + err;
    }
    module_policy::ManifestSpec stagedManifest;
    if (!loadAndValidateModuleManifest(stagedDll, stagedInfo, name, stagedManifest, err))
    {
        std::filesystem::remove_all(stageDir, ec);
        return "ERR staged manifest verification failed: " + err;
    }
    if (safeModuleName(stagedInfo) != name || stagedInfo.sha256 != info.sha256 || stagedManifest.json != sourceManifest.json)
    {
        std::filesystem::remove_all(stageDir, ec);
        return "ERR staged module changed during install";
    }

    m_modules.unload(name, err);
    if (std::filesystem::exists(finalDir, ec))
    {
        std::filesystem::rename(finalDir, backupDir, ec);
        if (ec)
        {
            std::filesystem::remove_all(stageDir, ec);
            return "ERR failed to backup existing module for rollback";
        }
    }
    std::filesystem::rename(stageDir, finalDir, ec);
    if (ec)
    {
        restoreModuleInstallBackup(finalDir, backupDir);
        return "ERR failed to promote staged module";
    }

    const std::filesystem::path finalDll = finalDir / sourceDll.filename();
    ModuleManager::ModuleInspection finalInfo;
    if (!ModuleManager::inspectModulePath(wideToUtf8(finalDll.wstring()), finalInfo, err))
    {
        restoreModuleInstallBackup(finalDir, backupDir);
        return "ERR installed module verification failed: " + err;
    }
    module_policy::ManifestSpec finalManifest;
    if (!loadAndValidateModuleManifest(finalDll, finalInfo, name, finalManifest, err))
    {
        restoreModuleInstallBackup(finalDir, backupDir);
        return "ERR installed manifest verification failed: " + err;
    }
    if (finalInfo.sha256 != info.sha256 || finalManifest.json != sourceManifest.json)
    {
        restoreModuleInstallBackup(finalDir, backupDir);
        return "ERR installed module changed during promote";
    }
    if (!writeOrUpdateModulesLock(modulesRoot / L"modules.lock", finalInfo, name, installArgs.source, err))
    {
        restoreModuleInstallBackup(finalDir, backupDir);
        return "ERR " + err;
    }

    m_modules.setModulesRoot(std::string());
    m_modules.ensureAllowlistLoaded(m_modulesDir);
    std::string loadSuffix = ";loaded=0";
    if (installArgs.load)
    {
        std::string loadErr;
        if (m_modules.load(wideToUtf8(finalDll.wstring()), loadErr))
        {
            loadSuffix = ";loaded=1";
            recordEvent("module.load", "path=" + wideToUtf8(finalDll.wstring()) + ";name=" + name);
        }
        else
        {
            loadSuffix = ";loaded=0;load_error_b64=" + base64Encode(loadErr);
            recordEvent("module.load-failed", "path=" + wideToUtf8(finalDll.wstring()) + ";name=" + name + ";error=" + loadErr);
        }
    }
    const std::string finalDllUtf8 = wideToUtf8(finalDll.wstring());
    recordEvent("module.install", "name=" + name + ";source=" + installArgs.source + ";path=" + finalDllUtf8);
    return "OK installed " + name + ";staged=1;trusted=1;source=" + installArgs.source + loadSuffix;
}

std::string PGS::handleModuleRollbackCommand(const std::string &rest)
{
    if (rest.empty())
    {
        return "ERR module rollback requires a name";
    }
    const std::string name = toLowerAscii(trim(rest));
    const std::filesystem::path modulesRoot = std::filesystem::path(utf8ToWide(m_modulesDir));
    const std::filesystem::path stagingRoot = service_util::moduleStagingRootForModulesDir(m_modulesDir);
    const std::filesystem::path rollbackRoot = stagingRoot / L"rollback";
    const std::filesystem::path rollbackDir = newestRollbackDir(rollbackRoot, name);
    if (rollbackDir.empty())
    {
        return "ERR no rollback found for module " + name;
    }
    std::filesystem::path rollbackDll = firstDllInDir(rollbackDir);
    if (rollbackDll.empty())
    {
        return "ERR rollback payload has no DLL";
    }
    ModuleManager::ModuleInspection info;
    std::string err;
    if (!ModuleManager::inspectModulePath(wideToUtf8(rollbackDll.wstring()), info, err))
    {
        return "ERR rollback verification failed: " + err;
    }
    if (safeModuleName(info) != name)
    {
        return "ERR rollback module name mismatch";
    }

    std::error_code ec;
    const std::filesystem::path finalDir = modulesRoot / utf8ToWide(name);
    const std::filesystem::path currentBackupRoot = stagingRoot / L"current";
    std::filesystem::create_directories(currentBackupRoot, ec);
    const std::filesystem::path currentBackup = currentBackupRoot / utf8ToWide(name + "-" + std::to_string(epochMs()));
    m_modules.unload(name, err);
    if (std::filesystem::exists(finalDir, ec))
    {
        std::filesystem::rename(finalDir, currentBackup, ec);
        if (ec)
        {
            return "ERR failed to backup current module before rollback";
        }
    }
    std::filesystem::rename(rollbackDir, finalDir, ec);
    if (ec)
    {
        if (std::filesystem::exists(currentBackup))
        {
            std::filesystem::rename(currentBackup, finalDir, ec);
        }
        return "ERR failed to restore rollback payload";
    }
    rollbackDll = firstDllInDir(finalDir);
    if (!rollbackDll.empty() && ModuleManager::inspectModulePath(wideToUtf8(rollbackDll.wstring()), info, err))
    {
        writeOrUpdateModulesLock(modulesRoot / L"modules.lock", info, name, "rollback", err);
    }
    m_modules.setModulesRoot(std::string());
    m_modules.ensureAllowlistLoaded(m_modulesDir);
    recordEvent("module.rollback", "name=" + name);
    return "OK rolled back " + name;
}

} // namespace ProcessGuard
