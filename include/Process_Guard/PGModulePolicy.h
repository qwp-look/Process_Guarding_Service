#ifndef PROCESS_GUARD_PG_MODULE_POLICY_H
#define PROCESS_GUARD_PG_MODULE_POLICY_H

#include "PGUtil.h"
#include "nlohmann/json.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ProcessGuard::module_policy
{
    enum class RiskLevel
    {
        Low = 0,
        Medium = 1,
        High = 2,
        Critical = 3,
        Unknown = 4
    };

    struct MethodSpec
    {
        std::string name;
        std::string risk;
        bool sync = true;
        std::vector<std::string> requiredCapabilities;
    };

    struct ManifestSpec
    {
        std::string raw;
        std::string name;
        std::string version;
        unsigned int abi = 0;
        bool hasAbi = false;
        std::string summary;
        std::string publisher;
        std::string author;
        std::string trust;
        std::string risk;
        std::vector<std::string> capabilities;
        std::vector<MethodSpec> methods;
        nlohmann::json json = nlohmann::json::object();
    };

    struct RegistryVersion
    {
        std::string version;
        std::string pgsMinVersion;
        std::string releasedAt;
        std::string downloadUrl;
        std::string sha256;
        std::string manifestUrl;
        std::string risk;
        bool yanked = false;
    };

    struct RegistryModule
    {
        std::string name;
        std::string trust;
        std::string description;
        std::string author;
        std::string homepage;
        std::string risk;
        std::vector<std::string> capabilities;
        bool bundled = false;
        bool deprecated = false;
        std::string deprecationReason;
        std::string latest;
        RegistryVersion selected;
    };

    struct InstallDecision
    {
        bool allowed = false;
        bool requiresTypedYes = false;
        std::string reason;
        std::string warning;
    };

    inline bool isIdentifier(const std::string &value)
    {
        if (value.empty() || value.size() > 64)
        {
            return false;
        }
        for (unsigned char ch : value)
        {
            const bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                            (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    inline std::string normalizeIdentifier(const std::string &value)
    {
        const std::string trimmed = ProcessGuard::util::trim(value);
        return isIdentifier(trimmed) ? ProcessGuard::util::toLowerAscii(trimmed) : std::string();
    }

    inline bool isNamespacedMethod(const std::string &value)
    {
        if (value.empty() || value.size() > 128 || value.find('.') == std::string::npos)
        {
            return false;
        }
        for (unsigned char ch : value)
        {
            const bool ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
                            (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
            if (!ok)
            {
                return false;
            }
        }
        return true;
    }

    inline bool isSha256Hex(const std::string &value)
    {
        if (value.size() != 64)
        {
            return false;
        }
        return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return std::isxdigit(ch) != 0;
        });
    }

    inline std::string normalizeSha256(const std::string &value)
    {
        std::string trimmed = ProcessGuard::util::toLowerAscii(ProcessGuard::util::trim(value));
        return isSha256Hex(trimmed) ? trimmed : std::string();
    }

    inline bool isTrust(const std::string &value)
    {
        const std::string v = ProcessGuard::util::toLowerAscii(ProcessGuard::util::trim(value));
        return v == "official" || v == "curated" || v == "community";
    }

    inline RiskLevel parseRisk(const std::string &value)
    {
        const std::string v = ProcessGuard::util::toLowerAscii(ProcessGuard::util::trim(value));
        if (v == "low") return RiskLevel::Low;
        if (v == "medium") return RiskLevel::Medium;
        if (v == "high") return RiskLevel::High;
        if (v == "critical") return RiskLevel::Critical;
        return RiskLevel::Unknown;
    }

    inline std::string normalizeRisk(const std::string &value)
    {
        const std::string v = ProcessGuard::util::toLowerAscii(ProcessGuard::util::trim(value));
        return parseRisk(v) == RiskLevel::Unknown ? std::string() : v;
    }

    inline bool riskAtLeast(const std::string &value, RiskLevel threshold)
    {
        const RiskLevel risk = parseRisk(value);
        if (risk == RiskLevel::Unknown)
        {
            return true;
        }
        return static_cast<int>(risk) >= static_cast<int>(threshold);
    }

    inline bool jsonString(const nlohmann::json &obj, const char *key, std::string &out)
    {
        const auto it = obj.find(key);
        if (it == obj.end() || !it->is_string())
        {
            return false;
        }
        out = it->get<std::string>();
        return true;
    }

    inline std::vector<std::string> stringArray(const nlohmann::json &obj, const char *key)
    {
        std::vector<std::string> out;
        const auto it = obj.find(key);
        if (it == obj.end() || !it->is_array())
        {
            return out;
        }
        bool invalid = false;
        std::set<std::string> seen;
        for (const auto &item : *it)
        {
            if (!item.is_string())
            {
                invalid = true;
                break;
            }
            std::string value = ProcessGuard::util::trim(item.get<std::string>());
            if (value.empty() || value.size() > 128 || seen.count(value) != 0)
            {
                invalid = true;
                break;
            }
            seen.insert(value);
            out.push_back(std::move(value));
        }
        if (invalid)
        {
            out.clear();
        }
        return out;
    }

    inline bool containsString(const std::vector<std::string> &values, const std::string &needle)
    {
        return std::find(values.begin(), values.end(), needle) != values.end();
    }

    inline bool parseManifestJson(const std::string &text, ManifestSpec &out, std::string &err)
    {
        out = ManifestSpec{};
        out.raw = text;
        nlohmann::json j;
        try
        {
            j = nlohmann::json::parse(text);
        }
        catch (const std::exception &e)
        {
            err = std::string("manifest JSON parse error: ") + e.what();
            return false;
        }
        if (!j.is_object())
        {
            err = "manifest must be a JSON object";
            return false;
        }
        out.json = j;
        std::string name;
        if (!jsonString(j, "name", name) || !isIdentifier(name))
        {
            err = "manifest name is required and must match [A-Za-z0-9_.-]{1,64}";
            return false;
        }
        out.name = ProcessGuard::util::toLowerAscii(name);
        if (!jsonString(j, "version", out.version) || ProcessGuard::util::trim(out.version).empty())
        {
            err = "manifest version is required";
            return false;
        }
        const auto abiIt = j.find("abi");
        if (abiIt == j.end() || !abiIt->is_number_integer())
        {
            err = "manifest abi integer is required";
            return false;
        }
        const int abi = abiIt->get<int>();
        if (abi < 2 || abi > 3)
        {
            err = "manifest abi must be 2 or 3";
            return false;
        }
        out.abi = static_cast<unsigned int>(abi);
        out.hasAbi = true;
        jsonString(j, "summary", out.summary);
        jsonString(j, "publisher", out.publisher);
        jsonString(j, "author", out.author);
        if (j.contains("trust"))
        {
            if (!jsonString(j, "trust", out.trust) || !isTrust(out.trust))
            {
                err = "manifest trust must be official, curated, or community when present";
                return false;
            }
            out.trust = ProcessGuard::util::toLowerAscii(ProcessGuard::util::trim(out.trust));
        }
        if (!jsonString(j, "risk", out.risk) || normalizeRisk(out.risk).empty())
        {
            err = "manifest risk must be low, medium, high, or critical";
            return false;
        }
        out.risk = normalizeRisk(out.risk);
        out.capabilities = stringArray(j, "capabilities");
        if (out.capabilities.empty())
        {
            err = "manifest capabilities must contain at least one string";
            return false;
        }
        const auto methodsIt = j.find("methods");
        if (methodsIt == j.end() || !methodsIt->is_array() || methodsIt->empty())
        {
            err = "manifest methods must contain at least one method object";
            return false;
        }
        for (const auto &methodObj : *methodsIt)
        {
            if (!methodObj.is_object())
            {
                err = "manifest method entries must be objects";
                return false;
            }
            MethodSpec method;
            if (!jsonString(methodObj, "name", method.name) || !isNamespacedMethod(method.name))
            {
                err = "manifest method name must be namespaced";
                return false;
            }
            if (!jsonString(methodObj, "risk", method.risk) || normalizeRisk(method.risk).empty())
            {
                err = "manifest method risk is invalid";
                return false;
            }
            method.risk = normalizeRisk(method.risk);
            const auto syncIt = methodObj.find("sync");
            if (syncIt == methodObj.end() || !syncIt->is_boolean())
            {
                err = "manifest method sync boolean is required";
                return false;
            }
            method.sync = syncIt->get<bool>();
            method.requiredCapabilities = stringArray(methodObj, "required_capabilities");
            if (method.requiredCapabilities.empty())
            {
                err = "manifest method required_capabilities must contain at least one string";
                return false;
            }
            for (const std::string &capability : method.requiredCapabilities)
            {
                if (!containsString(out.capabilities, capability))
                {
                    err = "manifest method required_capabilities must be declared in top-level capabilities";
                    return false;
                }
            }
            out.methods.push_back(std::move(method));
        }
        return true;
    }

    inline bool parseManifestJsonLenient(const std::string &text, ManifestSpec &out)
    {
        std::string err;
        return parseManifestJson(text, out, err);
    }

    inline bool validateRegistryModuleEntry(const nlohmann::json &entry,
                                            const std::string &requestedName,
                                            RegistryModule &out,
                                            std::string &err)
    {
        out = RegistryModule{};
        if (!entry.is_object())
        {
            err = "registry module entry must be an object";
            return false;
        }
        if (!jsonString(entry, "name", out.name) || !isIdentifier(out.name))
        {
            err = "registry module name is invalid";
            return false;
        }
        out.name = ProcessGuard::util::toLowerAscii(out.name);
        if (!requestedName.empty() && out.name != ProcessGuard::util::toLowerAscii(requestedName))
        {
            err = "registry module name mismatch";
            return false;
        }
        if (!jsonString(entry, "trust", out.trust) || !isTrust(out.trust))
        {
            err = "registry trust is invalid";
            return false;
        }
        out.trust = ProcessGuard::util::toLowerAscii(ProcessGuard::util::trim(out.trust));
        if (!jsonString(entry, "description", out.description) || out.description.size() > 512)
        {
            err = "registry description is invalid";
            return false;
        }
        if (!jsonString(entry, "author", out.author) || ProcessGuard::util::trim(out.author).empty())
        {
            err = "registry author is required";
            return false;
        }
        jsonString(entry, "homepage", out.homepage);
        if (!jsonString(entry, "risk", out.risk) || normalizeRisk(out.risk).empty())
        {
            err = "registry risk is invalid";
            return false;
        }
        out.risk = normalizeRisk(out.risk);
        out.capabilities = stringArray(entry, "capabilities");
        if (out.capabilities.empty())
        {
            err = "registry capabilities must contain at least one string";
            return false;
        }
        if (entry.contains("bundled"))
        {
            if (!entry.at("bundled").is_boolean())
            {
                err = "registry bundled must be boolean";
                return false;
            }
            out.bundled = entry.at("bundled").get<bool>();
        }
        if (entry.contains("deprecated"))
        {
            if (!entry.at("deprecated").is_boolean())
            {
                err = "registry deprecated must be boolean";
                return false;
            }
            out.deprecated = entry.at("deprecated").get<bool>();
        }
        jsonString(entry, "deprecation_reason", out.deprecationReason);
        if (!jsonString(entry, "latest", out.latest) || ProcessGuard::util::trim(out.latest).empty())
        {
            err = "registry latest is required";
            return false;
        }
        const auto versionsIt = entry.find("versions");
        if (versionsIt == entry.end() || !versionsIt->is_array() || versionsIt->empty())
        {
            err = "registry versions must contain at least one version";
            return false;
        }
        bool foundLatest = false;
        for (const auto &versionObj : *versionsIt)
        {
            if (!versionObj.is_object())
            {
                err = "registry version entry must be an object";
                return false;
            }
            RegistryVersion version;
            if (!jsonString(versionObj, "version", version.version) || version.version.empty())
            {
                err = "registry version is required";
                return false;
            }
            jsonString(versionObj, "pgs_min_version", version.pgsMinVersion);
            jsonString(versionObj, "released_at", version.releasedAt);
            jsonString(versionObj, "download_url", version.downloadUrl);
            jsonString(versionObj, "sha256", version.sha256);
            jsonString(versionObj, "manifest_url", version.manifestUrl);
            if (versionObj.contains("risk"))
            {
                if (!jsonString(versionObj, "risk", version.risk) || normalizeRisk(version.risk).empty())
                {
                    err = "registry version risk is invalid";
                    return false;
                }
                version.risk = normalizeRisk(version.risk);
            }
            if (versionObj.contains("yanked"))
            {
                if (!versionObj.at("yanked").is_boolean())
                {
                    err = "registry yanked must be boolean";
                    return false;
                }
                version.yanked = versionObj.at("yanked").get<bool>();
            }
            if (version.version == out.latest && !version.yanked)
            {
                out.selected = version;
                foundLatest = true;
            }
        }
        if (!foundLatest)
        {
            err = "registry latest version is missing or yanked";
            return false;
        }
        out.selected.sha256 = normalizeSha256(out.selected.sha256);
        if (out.selected.risk.empty())
        {
            out.selected.risk = out.risk;
        }
        if (!out.bundled)
        {
            if (out.selected.downloadUrl.empty())
            {
                err = "registry download_url is required for non-bundled modules";
                return false;
            }
            if (out.selected.manifestUrl.empty())
            {
                err = "registry manifest_url is required for non-bundled modules";
                return false;
            }
            if (out.selected.sha256.empty())
            {
                err = "registry sha256 is required for non-bundled modules";
                return false;
            }
        }
        return true;
    }

    inline bool validateRegistryRoot(const nlohmann::json &root, std::string &err)
    {
        if (!root.is_object())
        {
            err = "registry root must be an object";
            return false;
        }
        std::string value;
        if (!jsonString(root, "version", value) || value.empty())
        {
            err = "registry version is required";
            return false;
        }
        if (!jsonString(root, "pgs_min_version", value) || value.empty())
        {
            err = "registry pgs_min_version is required";
            return false;
        }
        if (!jsonString(root, "generated_at", value) || value.empty())
        {
            err = "registry generated_at is required";
            return false;
        }
        const auto modulesIt = root.find("modules");
        if (modulesIt == root.end() || !modulesIt->is_array())
        {
            err = "registry modules array is required";
            return false;
        }
        return true;
    }

    inline bool isAllowedHttpsUrl(const std::string &url, bool restrictToGithubRaw, std::string &host, std::string &path)
    {
        host.clear();
        path.clear();
        const std::string prefix = "https://";
        if (url.rfind(prefix, 0) != 0)
        {
            return false;
        }
        const std::string rest = url.substr(prefix.size());
        const auto slash = rest.find('/');
        if (slash == std::string::npos || slash == 0)
        {
            return false;
        }
        host = rest.substr(0, slash);
        path = rest.substr(slash);
        if (host.find('@') != std::string::npos || host.find(':') != std::string::npos ||
            host.find('\\') != std::string::npos || path.empty() || path[0] != '/')
        {
            return false;
        }
        if (path.find('\\') != std::string::npos || path.find("//") != std::string::npos)
        {
            return false;
        }
        const std::string lowerHost = ProcessGuard::util::toLowerAscii(host);
        if (restrictToGithubRaw && lowerHost != "raw.githubusercontent.com")
        {
            return false;
        }
        return true;
    }

    inline InstallDecision evaluateInstallDecision(const RegistryModule &module,
                                                   bool trustCurated,
                                                   bool trustCommunity,
                                                   bool confirmHighRisk)
    {
        InstallDecision decision;
        (void)trustCurated;
        const bool highRisk = riskAtLeast(module.selected.risk.empty() ? module.risk : module.selected.risk,
                                          RiskLevel::High);
        if (module.trust == "community" && !trustCommunity)
        {
            decision.reason = "community module requires --trust-community";
            return decision;
        }
        if (highRisk && !confirmHighRisk)
        {
            decision.reason = "high/critical risk module requires --confirm";
            return decision;
        }
        decision.allowed = true;
        decision.requiresTypedYes = module.trust == "community";
        if (module.trust == "community")
        {
            decision.warning = "Community modules are not reviewed by PGS maintainers. A malicious DLL runs as LocalSystem.";
        }
        else if (highRisk)
        {
            decision.warning = "High-risk module install requested. Review capabilities and source before continuing.";
        }
        return decision;
    }
}

#endif // PROCESS_GUARD_PG_MODULE_POLICY_H
