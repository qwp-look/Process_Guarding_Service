/**
 * @file PGSRegistryInstall.cpp
 * @brief pgs_bless registry-backed module install flow.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "PGSRegistryInstall.h"

#include <windows.h>
#include <winhttp.h>

#include "nlohmann/json.hpp"
#include "Process_Guard/ModuleManager.h"
#include "Process_Guard/PGModulePolicy.h"
#include "Process_Guard/PGSClient.h"
#include "Process_Guard/PGUtil.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace ProcessGuard::tools
{
namespace
{
    std::string downloadHttps(const std::wstring &host,
                              const std::wstring &path,
                              std::string &errOut,
                              std::size_t maxBytes = 64 * 1024 * 1024)
    {
        errOut.clear();
        HINTERNET session = WinHttpOpen(L"pgs_bless/1.0",
                                        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                        WINHTTP_NO_PROXY_NAME,
                                        WINHTTP_NO_PROXY_BYPASS,
                                        0);
        if (!session)
        {
            errOut = "WinHttpOpen failed";
            return {};
        }

        HINTERNET conn = WinHttpConnect(session, host.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!conn)
        {
            WinHttpCloseHandle(session);
            errOut = "WinHttpConnect failed";
            return {};
        }

        HINTERNET req = WinHttpOpenRequest(conn,
                                           L"GET",
                                           path.c_str(),
                                           nullptr,
                                           WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES,
                                           WINHTTP_FLAG_SECURE);
        if (!req)
        {
            WinHttpCloseHandle(conn);
            WinHttpCloseHandle(session);
            errOut = "WinHttpOpenRequest failed";
            return {};
        }

        DWORD timeout = 15000;
        WinHttpSetOption(req, WINHTTP_OPTION_CONNECT_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(req, WINHTTP_OPTION_SEND_TIMEOUT, &timeout, sizeof(timeout));
        WinHttpSetOption(req, WINHTTP_OPTION_RESOLVE_TIMEOUT, &timeout, sizeof(timeout));

        if (!WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(req, nullptr))
        {
            WinHttpCloseHandle(req);
            WinHttpCloseHandle(conn);
            WinHttpCloseHandle(session);
            errOut = "HTTP request failed";
            return {};
        }

        DWORD statusCode = 0;
        DWORD statusLen = sizeof(statusCode);
        WinHttpQueryHeaders(req,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX,
                            &statusCode,
                            &statusLen,
                            WINHTTP_NO_HEADER_INDEX);
        if (statusCode != 200)
        {
            WinHttpCloseHandle(req);
            WinHttpCloseHandle(conn);
            WinHttpCloseHandle(session);
            errOut = "HTTP " + std::to_string(statusCode);
            return {};
        }

        std::string body;
        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(req, &avail) && avail > 0)
        {
            std::string chunk(avail, '\0');
            DWORD read = 0;
            WinHttpReadData(req, &chunk[0], avail, &read);
            if (body.size() + static_cast<std::size_t>(read) > maxBytes)
            {
                WinHttpCloseHandle(req);
                WinHttpCloseHandle(conn);
                WinHttpCloseHandle(session);
                errOut = "HTTP response exceeds size limit";
                return {};
            }
            body.append(chunk.data(), read);
        }
        WinHttpCloseHandle(req);
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return body;
    }

    bool downloadAllowedHttpsUrl(const std::string &url,
                                 bool restrictToGithubRaw,
                                 std::string &bodyOut,
                                 std::string &errOut,
                                 std::size_t maxBytes)
    {
        std::string host;
        std::string path;
        if (!module_policy::isAllowedHttpsUrl(url, restrictToGithubRaw, host, path))
        {
            errOut = restrictToGithubRaw ? "URL must be https://raw.githubusercontent.com/..." : "URL must be HTTPS";
            return false;
        }
        bodyOut = downloadHttps(util::utf8ToWide(host), util::utf8ToWide(path), errOut, maxBytes);
        return !bodyOut.empty();
    }

    bool writeBinaryFile(const std::filesystem::path &path, const std::string &bytes, std::string &err)
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out)
        {
            err = "failed to open output file";
            return false;
        }
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        out.flush();
        if (!out.good())
        {
            err = "failed to write output file";
            return false;
        }
        return true;
    }

    std::filesystem::path currentExecutableDirectory()
    {
        std::wstring exePath(32768, L'\0');
        const DWORD len = GetModuleFileNameW(nullptr, exePath.data(), static_cast<DWORD>(exePath.size()));
        if (len == 0 || len >= exePath.size())
        {
            return std::filesystem::current_path();
        }
        exePath.resize(len);
        return std::filesystem::path(exePath).parent_path();
    }

    bool manifestMatchesRegistry(const module_policy::ManifestSpec &manifest,
                                 const module_policy::RegistryModule &module,
                                 std::string &err)
    {
        if (manifest.name != module.name)
        {
            err = "manifest name does not match registry entry";
            return false;
        }
        if (manifest.trust.empty())
        {
            err = "registry manifests must declare trust";
            return false;
        }
        if (util::trim(manifest.author).empty())
        {
            err = "registry manifests must declare author";
            return false;
        }
        if (!manifest.trust.empty() && manifest.trust != module.trust)
        {
            err = "manifest trust does not match registry entry";
            return false;
        }
        const std::string selectedRisk = module.selected.risk.empty() ? module.risk : module.selected.risk;
        if (!selectedRisk.empty() && manifest.risk != selectedRisk)
        {
            err = "manifest risk does not match registry entry";
            return false;
        }
        for (const std::string &capability : module.capabilities)
        {
            if (!module_policy::containsString(manifest.capabilities, capability))
            {
                err = "manifest capabilities do not cover registry entry";
                return false;
            }
        }
        return true;
    }
}

int runModuleInstallFromRegistry(const std::string &moduleName,
                                 bool trustCurated,
                                 bool trustCommunity,
                                 bool confirmOperation,
                                 const std::string &token,
                                 const std::string &host,
                                 int port)
{
    const std::wstring registryHost = L"raw.githubusercontent.com";
    const std::wstring registryPath = L"/qwp-look/PGS_Model/master/registry.json";

    std::cerr << "Fetching registry...\n";
    std::string httpErr;
    const std::string regJson = downloadHttps(registryHost, registryPath, httpErr, 4 * 1024 * 1024);
    if (regJson.empty())
    {
        std::cerr << "Failed to fetch registry: " << httpErr << "\n";
        return 1;
    }

    nlohmann::json reg;
    try
    {
        reg = nlohmann::json::parse(regJson);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Registry JSON parse error: " << e.what() << "\n";
        return 1;
    }

    std::string registryErr;
    if (!module_policy::validateRegistryRoot(reg, registryErr))
    {
        std::cerr << "Registry format invalid: " << registryErr << "\n";
        return 1;
    }

    const std::string requestedName = module_policy::normalizeIdentifier(moduleName);
    if (requestedName.empty())
    {
        std::cerr << "Invalid module name: " << moduleName << "\n";
        return 1;
    }

    nlohmann::json entry;
    for (const auto &m : reg["modules"])
    {
        std::string candidate;
        if (m.is_object() && module_policy::jsonString(m, "name", candidate) &&
            module_policy::normalizeIdentifier(candidate) == requestedName)
        {
            entry = m;
            break;
        }
    }
    if (entry.is_null())
    {
        std::cerr << "Module '" << moduleName << "' not found in registry\n";
        return 1;
    }

    module_policy::RegistryModule registryModule;
    if (!module_policy::validateRegistryModuleEntry(entry, requestedName, registryModule, registryErr))
    {
        std::cerr << "Registry module entry invalid: " << registryErr << "\n";
        return 1;
    }
    if (registryModule.deprecated)
    {
        const std::string reason = registryModule.deprecationReason.empty() ? "no reason given" : registryModule.deprecationReason;
        std::cerr << "WARNING: module '" << registryModule.name << "' is deprecated: " << reason << "\n";
    }
    if (registryModule.bundled)
    {
        std::cerr << "Module '" << registryModule.name << "' is bundled with PGS and already installed.\n";
        return 0;
    }

    const auto decision = module_policy::evaluateInstallDecision(
        registryModule, trustCurated, trustCommunity, confirmOperation);
    if (!decision.allowed)
    {
        std::cerr << "ERROR: " << decision.reason << "\n";
        return 1;
    }
    if (!decision.warning.empty())
    {
        std::cerr << "[WARNING] " << decision.warning << "\n";
    }
    if (registryModule.trust == "curated")
    {
        std::cerr << "[INFO] Curated module - reviewed by qwp-look.\n";
    }
    if (decision.requiresTypedYes)
    {
        std::cerr << "Type YES to confirm installation: ";
        std::string confirm;
        std::getline(std::cin, confirm);
        if (confirm != "YES")
        {
            std::cerr << "Aborted.\n";
            return 1;
        }
    }

    const std::string expectedHash = registryModule.selected.sha256;
    std::cerr << "Downloading " << registryModule.name << " v" << registryModule.latest << " ...\n";
    std::string dllBytes;
    if (!downloadAllowedHttpsUrl(registryModule.selected.downloadUrl, true, dllBytes, httpErr, 64 * 1024 * 1024))
    {
        std::cerr << "Download failed: " << httpErr << "\n";
        return 1;
    }

    const std::string actualHash = util::sha256Hex(dllBytes);
    if (actualHash != expectedHash)
    {
        std::cerr << "SHA-256 mismatch!\n"
                  << "  expected: " << expectedHash << "\n"
                  << "  actual:   " << actualHash << "\n";
        return 1;
    }
    std::cerr << "SHA-256 verified: " << actualHash << "\n";

    std::string manifestText;
    if (!downloadAllowedHttpsUrl(registryModule.selected.manifestUrl, true, manifestText, httpErr, 1024 * 1024))
    {
        std::cerr << "Manifest download failed: " << httpErr << "\n";
        return 1;
    }
    module_policy::ManifestSpec manifest;
    std::string manifestErr;
    if (!module_policy::parseManifestJson(manifestText, manifest, manifestErr))
    {
        std::cerr << "Manifest invalid: " << manifestErr << "\n";
        return 1;
    }
    if (!manifestMatchesRegistry(manifest, registryModule, manifestErr))
    {
        std::cerr << "Manifest mismatch: " << manifestErr << "\n";
        return 1;
    }

    const std::filesystem::path exeDir = currentExecutableDirectory();
    const std::filesystem::path stagingDir = exeDir / "modules_staging" /
        (registryModule.name + "-registry-" + std::to_string(GetTickCount64()));
    std::error_code ec;
    std::filesystem::create_directories(stagingDir, ec);
    if (ec)
    {
        std::cerr << "Failed to create staging dir: " << ec.message() << "\n";
        return 1;
    }

    const std::filesystem::path stagingDll = stagingDir / (registryModule.name + "_module.dll");
    const std::filesystem::path stagingManifest = stagingDir / "module.manifest.json";
    std::string fileErr;
    if (!writeBinaryFile(stagingDll, dllBytes, fileErr) || !writeBinaryFile(stagingManifest, manifestText, fileErr))
    {
        std::filesystem::remove_all(stagingDir, ec);
        std::cerr << "Failed to write staging payload: " << fileErr << "\n";
        return 1;
    }

    ModuleManager::ModuleInspection stagedInfo;
    std::string inspectErr;
    if (!ModuleManager::inspectModulePath(util::wideToUtf8(stagingDll.wstring()), stagedInfo, inspectErr))
    {
        std::filesystem::remove_all(stagingDir, ec);
        std::cerr << "Staged DLL inspection failed: " << inspectErr << "\n";
        return 1;
    }
    if (util::toLowerAscii(stagedInfo.sha256) != expectedHash ||
        module_policy::normalizeIdentifier(stagedInfo.name.empty() ? stagedInfo.allowlistKey : stagedInfo.name) != registryModule.name)
    {
        std::filesystem::remove_all(stagingDir, ec);
        std::cerr << "Staged DLL does not match registry metadata\n";
        return 1;
    }

    const std::string stagedDllUtf8 = util::wideToUtf8(stagingDll.wstring());
    const std::string installCmd = "module install " + util::base64Encode(stagedDllUtf8) +
                                   " --confirm --load --source registry";
    client::ClientOptions opts;
    opts.host = host;
    opts.port = static_cast<std::uint16_t>(port);
    opts.token = token;
    const auto resp = client::sendCommand(opts, client::withAuthToken(token, installCmd));
    const std::string response = resp.payload;
    std::filesystem::remove_all(stagingDir, ec);
    if (!resp.ok)
    {
        std::cerr << "Service install failed: " << (resp.error.empty() ? response : resp.error) << "\n";
        return 1;
    }
    if (response.rfind("ERR", 0) == 0)
    {
        std::cerr << response << "\n";
        return 1;
    }
    std::cout << response << "\n";
    return 0;
}

} // namespace ProcessGuard::tools
