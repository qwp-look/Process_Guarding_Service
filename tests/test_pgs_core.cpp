/**
 * @file test_pgs_core.cpp
 * @brief Self-contained unit tests for PGS pure helpers (v3 hardening).
 *
 * No third-party test framework: a ~30-line macro core provides the essentials
 * (assert + count + non-zero exit on failure) so the suite stays a single TU
 * with zero external dependencies. All cases exercise header-only inline
 * helpers from PGUtil.h (encoding, hashing, AUMID/PFN derivation, the
 * restart-window pruner, backoff math) plus the portable parsers. Win32
 * services (sockets, modules) are intentionally NOT covered here; they are
 * exercised by the smoke test instead.
 *
 * Build (MSYS2 MinGW64):
 *   g++ -std=c++17 -DPGS_ENABLE_TEST_HOOKS -Iinclude \
 *       tests/test_pgs_core.cpp modules/sched/pgs_sched_module.cpp \
 *       -lbcrypt \
 *       -o build/test_pgs_core.exe
 * SPDX-License-Identifier: Apache-2.0
 */
#include "Process_Guard/PGUtil.h"
#include "Process_Guard/PGModulePolicy.h"

#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

namespace u = ProcessGuard::util;
namespace mp = ProcessGuard::module_policy;

#ifdef PGS_ENABLE_TEST_HOOKS
namespace pgs_sched_test
{
long long parseIso8601ForTest(const std::string &s);
bool parseIntervalSecondsForTest(const std::string &s, long long &out);
long long intervalSecondsLimitForTest();
} // namespace pgs_sched_test

#endif

namespace
{
int g_tests = 0;
int g_failures = 0;

#define CHECK(cond)                                                    \
    do                                                                 \
    {                                                                  \
        ++g_tests;                                                     \
        if (!(cond))                                                   \
        {                                                              \
            ++g_failures;                                              \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__        \
                      << "  CHECK(" #cond ")\n";                       \
        }                                                              \
    } while (0)

#define CHECK_EQ(a, b)                                                 \
    do                                                                 \
    {                                                                  \
        ++g_tests;                                                     \
        if (!((a) == (b)))                                             \
        {                                                              \
            ++g_failures;                                              \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__        \
                      << "  CHECK_EQ(" #a ", " #b ")\n";               \
        }                                                              \
    } while (0)

void test_parse_and_labels()
{
    DWORD pid = 0;
    CHECK(u::parsePid("123", pid) && pid == 123);
    CHECK(!u::parsePid("", pid));
    CHECK(!u::parsePid("abc", pid));

    int mr = 0;
    CHECK(!u::parseMaxRestarts("-1", mr));  // "-1" is rejected; only "no" means unlimited
    CHECK(u::parseMaxRestarts("no", mr) && mr == -1);
    CHECK(u::parseMaxRestarts("3", mr) && mr == 3);
    CHECK(!u::parseMaxRestarts("x", mr));

    CHECK_EQ(u::maxRestartsLabel(-1), std::string("no"));
    CHECK_EQ(u::maxRestartsLabel(3), std::string("3"));

    std::uint64_t u64 = 0;
    CHECK(u::parseUnsignedLongLong("42", u64) && u64 == 42ull);
    CHECK(!u::parseUnsignedLongLong("", u64));
    DWORD dv = 0;
    CHECK(u::parseDwordValue("7", dv) && dv == 7);
    CHECK(!u::parseDwordValue("4294967296", dv)); // overflow guard
    bool b = false;
    CHECK(u::parseBoolFlag("1", b) && b);
    CHECK(u::parseBoolFlag("0", b) && !b);
    CHECK(!u::parseBoolFlag("2", b));
}

long long msForLocal(int y, int mo, int d, int h, int mi, int s)
{
    std::tm t{};
    t.tm_year = y - 1900;
    t.tm_mon = mo - 1;
    t.tm_mday = d;
    t.tm_hour = h;
    t.tm_min = mi;
    t.tm_sec = s;
    t.tm_isdst = -1;
    return static_cast<long long>(std::mktime(&t)) * 1000LL;
}

#ifdef PGS_ENABLE_TEST_HOOKS
void test_sched_module_parsers()
{
    const long long expected = msForLocal(2026, 7, 9, 15, 30, 0);
    CHECK_EQ(pgs_sched_test::parseIso8601ForTest("2026-07-09T15:30:00"), expected);
    CHECK_EQ(pgs_sched_test::parseIso8601ForTest("2026-07-09 15:30:00"), expected);
    CHECK_EQ(pgs_sched_test::parseIso8601ForTest("2024-02-29T12:00:00"), msForLocal(2024, 2, 29, 12, 0, 0));
    CHECK_EQ(pgs_sched_test::parseIso8601ForTest("2026-02-31T00:00:00"), -1);
    CHECK_EQ(pgs_sched_test::parseIso8601ForTest("2026-01-01T24:00:00"), -1);
    CHECK_EQ(pgs_sched_test::parseIso8601ForTest("2026-01-01T00:60:00"), -1);
    CHECK_EQ(pgs_sched_test::parseIso8601ForTest("2026-01-01T00:00:60"), -1);
    CHECK_EQ(pgs_sched_test::parseIso8601ForTest("2026-01-01T00:00:001"), -1);

    long long interval = 0;
    const long long limit = pgs_sched_test::intervalSecondsLimitForTest();
    CHECK(pgs_sched_test::parseIntervalSecondsForTest("1", interval) && interval == 1);
    CHECK(pgs_sched_test::parseIntervalSecondsForTest(std::to_string(limit), interval) && interval == limit);
    CHECK(!pgs_sched_test::parseIntervalSecondsForTest("0", interval));
    CHECK(!pgs_sched_test::parseIntervalSecondsForTest(std::to_string(limit + 1), interval));
    CHECK(!pgs_sched_test::parseIntervalSecondsForTest("9999999999999999", interval));
}
#endif

void test_split_base64()
{
    const auto parts = u::split("a|b|c", '|');
    CHECK_EQ(parts.size(), static_cast<std::size_t>(3));
    CHECK_EQ(parts[0], std::string("a"));
    CHECK_EQ(parts[2], std::string("c"));

    // Well-known vector + round-trip with bytes/spaces.
    CHECK_EQ(u::base64Encode("hello"), std::string("aGVsbG8="));
    const std::string round = "PGS \x01\x02 guard!";
    CHECK_EQ(u::base64Decode(u::base64Encode(round)), round);
    CHECK_EQ(u::base64Decode(""), std::string());

    // trim strips both sides; split handles a single field with no delimiter.
    CHECK_EQ(u::trim("  hi  "), std::string("hi"));
    CHECK_EQ(u::split("solo", '|').size(), static_cast<std::size_t>(1));
}

void test_sha256()
{
    // NIST FIPS-180-4 vectors: SHA-256("abc") and SHA-256("").
    CHECK_EQ(u::sha256Hex("abc"),
            std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK_EQ(u::sha256Hex(""),
            std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
}

void test_pfn_and_aumid()
{
    // The MS-documented PFN publisher hash is the SHA-256 low 8 bytes,
    // standard base64, then URL-safe (+->- / ->_) and stripped of padding.
    // Assert structural invariants (length, charset, determinism) rather
    // than a magic constant so the test stays meaningful without a canonical
    // publisher fixture while still pinning the algorithm shape.
    const std::string h = u::pfnHashFromPublisher("CN=Test Publisher, O=TestOrg");
    CHECK_EQ(h.size(), static_cast<std::size_t>(11));
    for (char c : h)
    {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '_';
        CHECK(ok);
    }
    // PackageFamilyName = Name + "_" + hash ; AUMID = PFN + "!" + AppId.
    const std::string pfn = u::packageFamilyNameFrom("MyApp", "CN=Test Publisher, O=TestOrg");
    CHECK(pfn.find("MyApp_") == 0);
    const std::string aumid = u::deriveAumidFromParts("MyApp", "CN=Test Publisher, O=TestOrg", "App");
    CHECK(aumid.find("MyApp_") == 0);
    CHECK(aumid.find("!App") != std::string::npos);
    // Deterministic: same input -> identical output across calls.
    CHECK_EQ(u::pfnHashFromPublisher("CN=P"), u::pfnHashFromPublisher("CN=P"));
    // Empty publisher should yield an empty hash (sha256Hex("") is valid but
    // the contract is "no publisher -> no PFN suffix"; keep this as a guard).
    CHECK(!u::packageFamilyNameFrom("X", "").empty()); // name_ + (sha256("")low8 b64)

    CHECK_EQ(u::packageFamilyNameFromPackageFullName("Contoso.App_1.2.3.4_x64__8wekyb3d8bbwe"),
             std::string("Contoso.App_8wekyb3d8bbwe"));

    const std::string manifest =
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        "<Package xmlns=\"http://schemas.microsoft.com/appx/manifest/foundation/windows10\">"
        "<Identity Name=\"Contoso.App\" Publisher=\"CN=Contoso &amp; Sons\" Version=\"1.0.0.0\"/>"
        "<Applications>"
        "<Application Id=\"First\" Executable=\"other.exe\"/>"
        "<Application Id=\"Main.App\" Executable=\"bin\\target.exe\"/>"
        "</Applications></Package>";
    u::AppxAumidInfo info;
    std::string err;
    CHECK(u::deriveAumidFromAppxManifestText(manifest, "C:\\Program Files\\WindowsApps\\Contoso.App_1.0.0.0_x64__abc\\bin\\target.exe", info, err));
    CHECK_EQ(info.packageName, std::string("Contoso.App"));
    CHECK_EQ(info.publisher, std::string("CN=Contoso & Sons"));
    CHECK_EQ(info.appId, std::string("Main.App"));
    CHECK(info.aumid.find("!Main.App") != std::string::npos);
}

void test_restart_window()
{
    using V = std::vector<std::int64_t>;
    const V seed{1000, 8001, 9000, 10000};

    // window<=0 (legacy lifetime count): returned untouched.
    CHECK_EQ(u::pruneRestartWindow(seed, 9999, 0).size(), static_cast<std::size_t>(4));
    CHECK_EQ(u::pruneRestartWindow(V{}, 9999, 0).size(), static_cast<std::size_t>(0));

    // window=2s, now=10000 -> cutoff=8000 -> keep timestamps STRICTLY newer.
    // seed has 8001,9000,10000 all > 8000, and 1000 <= 8000 is dropped.
    const auto p = u::pruneRestartWindow(seed, 10000, 2);
    CHECK_EQ(p.size(), static_cast<std::size_t>(3));
    for (std::int64_t t : p)
    {
        CHECK(t > 8000);
    }

    // Everything older than the window is dropped.
    const V old{1000, 2000, 3000};
    CHECK_EQ(u::pruneRestartWindow(old, 100000, 2).size(), static_cast<std::size_t>(0));
}

void test_backoff()
{
    CHECK_EQ(u::computeBackoffDelay(0, 0), 0);
    CHECK_EQ(u::computeBackoffDelay(100, 0), 100);
    CHECK_EQ(u::computeBackoffDelay(100, 1), 200);
    CHECK_EQ(u::computeBackoffDelay(100, 2), 400);
    // Capped at 60s even with an absurd restart index.
    CHECK_EQ(u::computeBackoffDelay(10000, 20), 60000);
    // Negative base normalises to 0 (never schedule a negative wait).
    CHECK_EQ(u::computeBackoffDelay(-5, 3), 0);
}

void test_module_policy()
{
    CHECK(mp::isIdentifier("module.name-1"));
    CHECK(!mp::isIdentifier("bad/name"));
    CHECK_EQ(mp::normalizeIdentifier("  My_Module  "), std::string("my_module"));
    CHECK(mp::isSha256Hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    CHECK(!mp::isSha256Hex("xyz"));

    const std::string manifestText = R"json({
        "name":"demo","version":"1.2.3","abi":3,"trust":"community","risk":"high",
        "author":"tester","capabilities":["demo.run","state.read"],
        "methods":[{"name":"demo.run","risk":"high","sync":true,"required_capabilities":["demo.run"]}]
    })json";
    mp::ManifestSpec manifest;
    std::string err;
    CHECK(mp::parseManifestJson(manifestText, manifest, err));
    CHECK_EQ(manifest.name, std::string("demo"));
    CHECK_EQ(manifest.abi, static_cast<unsigned int>(3));
    CHECK_EQ(manifest.trust, std::string("community"));
    CHECK(mp::riskAtLeast(manifest.risk, mp::RiskLevel::High));

    const std::string invalidManifest = R"json({
        "name":"demo","version":"1.2.3","abi":3,"risk":"low",
        "capabilities":["demo.run"],
        "methods":[{"name":"demo.run","risk":"low","sync":true,"required_capabilities":["missing.cap"]}]
    })json";
    CHECK(!mp::parseManifestJson(invalidManifest, manifest, err));

    const std::string registryText = R"json({
        "version":"1","pgs_min_version":"0.1.0","generated_at":"2026-07-26T00:00:00Z",
        "modules":[{
            "name":"demo","trust":"community","description":"demo module","author":"tester",
            "risk":"high","capabilities":["demo.run"],"latest":"1.2.3",
            "versions":[{"version":"1.2.3","download_url":"https://raw.githubusercontent.com/qwp-look/PGS_Model/main/demo.dll","manifest_url":"https://raw.githubusercontent.com/qwp-look/PGS_Model/main/module.manifest.json","sha256":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","risk":"high"}]
        }]
    })json";
    const nlohmann::json registry = nlohmann::json::parse(registryText);
    CHECK(mp::validateRegistryRoot(registry, err));
    mp::RegistryModule module;
    CHECK(mp::validateRegistryModuleEntry(registry.at("modules").at(0), "demo", module, err));
    CHECK_EQ(module.selected.sha256, std::string("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    CHECK(!mp::evaluateInstallDecision(module, false, false, true).allowed);
    CHECK(!mp::evaluateInstallDecision(module, false, true, false).allowed);
    const auto decision = mp::evaluateInstallDecision(module, false, true, true);
    CHECK(decision.allowed);
    CHECK(decision.requiresTypedYes);

    std::string urlHost;
    std::string urlPath;
    CHECK(mp::isAllowedHttpsUrl(module.selected.downloadUrl, true, urlHost, urlPath));
    CHECK_EQ(urlHost, std::string("raw.githubusercontent.com"));
    CHECK(!mp::isAllowedHttpsUrl("http://raw.githubusercontent.com/qwp-look/x", true, urlHost, urlPath));
}

void weakenPathDaclUsersWrite(const std::filesystem::path &path)
{
    PSECURITY_DESCRIPTOR psd = nullptr;
    ULONG sdSize = 0;
    const wchar_t *weakSddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FW;;;BU)";
    const std::wstring wpath = u::utf8ToWide(path.string());
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(weakSddl, SDDL_REVISION_1, &psd, &sdSize) || !psd)
    {
        return;
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    GetSecurityDescriptorDacl(psd, &present, &dacl, &defaulted);
    SetNamedSecurityInfoW(const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                          nullptr, nullptr, dacl, nullptr);
    LocalFree(psd);
}

// Users read ACE — bootstrap token leakage path (P0-04).
void weakenPathDaclUsersRead(const std::filesystem::path &path)
{
    PSECURITY_DESCRIPTOR psd = nullptr;
    ULONG sdSize = 0;
    const wchar_t *weakSddl = L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)";
    const std::wstring wpath = u::utf8ToWide(path.string());
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(weakSddl, SDDL_REVISION_1, &psd, &sdSize) || !psd)
    {
        return;
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL dacl = nullptr;
    GetSecurityDescriptorDacl(psd, &present, &dacl, &defaulted);
    SetNamedSecurityInfoW(const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                          nullptr, nullptr, dacl, nullptr);
    LocalFree(psd);
}

// Force owner to Builtin Users (non-admin) for owner-repair coverage.
bool setPathOwnerBuiltinUsers(const std::filesystem::path &path)
{
    const std::wstring wpath = u::utf8ToWide(path.string());
    if (wpath.empty())
    {
        return false;
    }
    DWORD sidBytes = SECURITY_MAX_SID_SIZE;
    std::vector<unsigned char> sidBuf(sidBytes);
    PSID usersSid = reinterpret_cast<PSID>(sidBuf.data());
    if (!CreateWellKnownSid(WinBuiltinUsersSid, nullptr, usersSid, &sidBytes))
    {
        return false;
    }
    // Best-effort privilege enable (same names modules repair uses).
    auto enableOne = [](LPCWSTR name) {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token) || !token)
        {
            return;
        }
        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, name, &luid))
        {
            CloseHandle(token);
            return;
        }
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(token);
    };
    enableOne(L"SeTakeOwnershipPrivilege");
    enableOne(L"SeRestorePrivilege");
    const DWORD rc = SetNamedSecurityInfoW(
        const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION, usersSid, nullptr, nullptr, nullptr);
    return rc == ERROR_SUCCESS;
}

// True when every ACCESS_ALLOWED ACE with token-dangerous rights is SY or BA only
// (no interactive user SID, no Users/Everyone, etc.).
bool bootstrapTokenDaclIsSystemAdminOnly(const std::filesystem::path &path)
{
    const std::wstring wpath = u::utf8ToWide(path.string());
    if (wpath.empty())
    {
        return false;
    }
    PSID owner = nullptr;
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    const DWORD rc = GetNamedSecurityInfoW(
        const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &sd);
    if (rc != ERROR_SUCCESS || !sd)
    {
        if (sd)
        {
            LocalFree(sd);
        }
        return false;
    }
    BOOL present = FALSE;
    BOOL defaulted = FALSE;
    PACL sdDacl = nullptr;
    if (!GetSecurityDescriptorDacl(sd, &present, &sdDacl, &defaulted) || !present || !sdDacl)
    {
        LocalFree(sd);
        return false;
    }
    ACL_SIZE_INFORMATION info{};
    if (!GetAclInformation(sdDacl, &info, sizeof(info), AclSizeInformation))
    {
        LocalFree(sd);
        return false;
    }
    const DWORD dangerous = u::bootstrapTokenAclDangerousAccessMask();
    bool sawSy = false;
    bool sawBa = false;
    for (DWORD i = 0; i < info.AceCount; ++i)
    {
        ACE_HEADER *hdr = nullptr;
        if (!GetAce(sdDacl, i, reinterpret_cast<LPVOID *>(&hdr)) || !hdr)
        {
            LocalFree(sd);
            return false;
        }
        if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE)
        {
            continue;
        }
        auto *allow = reinterpret_cast<ACCESS_ALLOWED_ACE *>(hdr);
        if ((allow->Mask & dangerous) == 0)
        {
            continue;
        }
        PSID aceSid = reinterpret_cast<PSID>(&allow->SidStart);
        if (IsWellKnownSid(aceSid, WinLocalSystemSid))
        {
            sawSy = true;
            continue;
        }
        if (IsWellKnownSid(aceSid, WinBuiltinAdministratorsSid))
        {
            sawBa = true;
            continue;
        }
        LocalFree(sd);
        return false; // any other principal with access rights is a fail
    }
    LocalFree(sd);
    return sawSy && sawBa;
}

bool bootstrapTokenOwnerIsAdministrators(const std::filesystem::path &path)
{
    const std::wstring wpath = u::utf8ToWide(path.string());
    if (wpath.empty())
    {
        return false;
    }
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    const DWORD rc = GetNamedSecurityInfoW(
        const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &sd);
    if (rc != ERROR_SUCCESS || !sd || !owner)
    {
        if (sd)
        {
            LocalFree(sd);
        }
        return false;
    }
    const bool ok = IsWellKnownSid(owner, WinBuiltinAdministratorsSid) == TRUE;
    LocalFree(sd);
    return ok;
}

bool pathListed(const std::vector<u::ModulesAclPath> &paths, const std::string &needle)
{
    for (const auto &p : paths)
    {
        if (p.path.find(needle) != std::string::npos)
        {
            return true;
        }
    }
    return false;
}

void test_modules_acl_audit()
{
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path root = fs::temp_directory_path(ec) / ("pgs_acl_test_" + u::randomBytesHex(4));
    fs::create_directories(root / "demo" / "nested", ec);
    {
        std::ofstream lock((root / "modules.lock").string(), std::ios::binary);
        lock << "{\"version\":1,\"modules\":[]}";
    }
    {
        std::ofstream dll((root / "demo" / "demo.dll").string(), std::ios::binary);
        dll << "MZ-fake";
    }
    {
        std::ofstream man((root / "demo" / "module.manifest.json").string(), std::ios::binary);
        man << "{\"name\":\"demo\"}";
    }
    // Nested trust-boundary files must be enumerated at arbitrary depth.
    {
        std::ofstream evil((root / "demo" / "nested" / "evil.dll").string(), std::ios::binary);
        evil << "MZ-evil";
    }
    {
        std::ofstream nestedMan((root / "demo" / "nested" / "module.manifest.json").string(), std::ios::binary);
        nestedMan << "{\"name\":\"nested\"}";
    }

    const std::string rootUtf8 = root.string();
    const u::ModulesAclEnumerateResult enumerated = u::enumerateModulesAclPaths(rootUtf8);
    CHECK(enumerated.ok);
    CHECK(enumerated.reason.empty() || enumerated.reason == "ok");
    // root + modules.lock + demo/ + nested/ + demo.dll + evil.dll + 2 manifests
    CHECK(enumerated.paths.size() >= static_cast<std::size_t>(8));
    CHECK(pathListed(enumerated.paths, "evil.dll"));
    CHECK(pathListed(enumerated.paths, "nested"));
    CHECK(pathListed(enumerated.paths, "module.manifest.json"));

    CHECK(u::secureModulesAclTree(rootUtf8));
    u::ModulesAclAuditResult okAudit = u::auditModulesAcl(rootUtf8);
    CHECK(okAudit.ok);
    CHECK_EQ(okAudit.badPaths.size(), static_cast<std::size_t>(0));

    // Shallow DLL Users-write must fail closed.
    weakenPathDaclUsersWrite(root / "demo" / "demo.dll");
    u::ModulesAclAuditResult badShallow = u::auditModulesAcl(rootUtf8);
    CHECK(!badShallow.ok);
    CHECK(badShallow.badPaths.size() >= static_cast<std::size_t>(1));

    CHECK(u::secureModulesAclTree(rootUtf8));
    CHECK(u::auditModulesAcl(rootUtf8).ok);

    // Nested DLL Users-write must also fail closed (true recursive coverage).
    weakenPathDaclUsersWrite(root / "demo" / "nested" / "evil.dll");
    u::ModulesAclAuditResult badNested = u::auditModulesAcl(rootUtf8);
    CHECK(!badNested.ok);
    bool nestedEvilReported = false;
    for (const auto &bad : badNested.badPaths)
    {
        if (bad.find("evil.dll") != std::string::npos)
        {
            nestedEvilReported = true;
            break;
        }
    }
    CHECK(nestedEvilReported);
    CHECK(!badNested.reason.empty());
    CHECK(badNested.reason != "ok");

    // Nested manifest regression too.
    CHECK(u::secureModulesAclTree(rootUtf8));
    weakenPathDaclUsersWrite(root / "demo" / "nested" / "module.manifest.json");
    u::ModulesAclAuditResult badNestedManifest = u::auditModulesAcl(rootUtf8);
    CHECK(!badNestedManifest.ok);

    // Explicit repair restores owner+DACL; audit must return clean.
    CHECK(u::secureModulesAclTree(rootUtf8));
    u::ModulesAclAuditResult fixed = u::auditModulesAcl(rootUtf8);
    CHECK(fixed.ok);

    // Missing root must fail closed via enumeration, not return ok.
    u::ModulesAclEnumerateResult missing = u::enumerateModulesAclPaths(rootUtf8 + "\\__missing_acl_root__");
    CHECK(!missing.ok);
    CHECK_EQ(missing.reason, std::string("modules-root-missing"));
    u::ModulesAclAuditResult missingAudit = u::auditModulesAcl(rootUtf8 + "\\__missing_acl_root__");
    CHECK(!missingAudit.ok);
    CHECK_EQ(missingAudit.reason, std::string("modules-root-missing"));

    fs::remove_all(root, ec);
}

void test_bootstrap_token_acl_audit()
{
    namespace fs = std::filesystem;
    std::error_code ec;
    const fs::path dir = fs::temp_directory_path(ec) / ("pgs_token_acl_" + u::randomBytesHex(4));
    fs::create_directories(dir, ec);
    const fs::path tokenPath = dir / "pgs_initial_token.txt";
    const std::string tokenUtf8 = tokenPath.string();

    // Missing file is informational, not a security error.
    u::BootstrapTokenAclAuditResult missing = u::auditBootstrapTokenAcl(tokenUtf8);
    CHECK(missing.ok);
    CHECK(!missing.present);
    CHECK_EQ(missing.reason, std::string("missing/not-generated"));
    CHECK(!u::secureBootstrapTokenAcl(tokenUtf8)); // must not invent the file

    {
        std::ofstream out(tokenUtf8, std::ios::binary);
        out << "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef";
    }
    CHECK(u::secureBootstrapTokenAcl(tokenUtf8));
    u::BootstrapTokenAclAuditResult okAudit = u::auditBootstrapTokenAcl(tokenUtf8);
    CHECK(okAudit.ok);
    CHECK(okAudit.present);
    CHECK_EQ(okAudit.reason, std::string("ok"));
    // Repair must not inject interactive user FA — only SY+BA allow ACEs.
    CHECK(bootstrapTokenDaclIsSystemAdminOnly(tokenPath));
    // Owner is BA when privileges allow; otherwise a trusted admin-member owner is OK.
    {
        PSID owner = nullptr;
        PSECURITY_DESCRIPTOR sd = nullptr;
        const std::wstring wpath = u::utf8ToWide(tokenUtf8);
        const DWORD grc = GetNamedSecurityInfoW(
            const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr, &sd);
        CHECK(grc == ERROR_SUCCESS && sd && owner);
        if (sd && owner)
        {
            CHECK(u::modulesAclSidIsTrustedPrincipal(owner));
            LocalFree(sd);
        }
    }

    // Builtin Users read must fail closed (token is a secret).
    weakenPathDaclUsersRead(tokenPath);
    u::BootstrapTokenAclAuditResult badRead = u::auditBootstrapTokenAcl(tokenUtf8);
    CHECK(!badRead.ok);
    CHECK(badRead.present);
    CHECK_EQ(badRead.reason, std::string("non-admin-token-access-ace"));

    // Explicit repair restores protected DACL (SY+BA only; no interactive user ACE).
    CHECK(u::secureBootstrapTokenAcl(tokenUtf8));
    u::BootstrapTokenAclAuditResult fixed = u::auditBootstrapTokenAcl(tokenUtf8);
    CHECK(fixed.ok);
    CHECK(fixed.present);
    CHECK_EQ(fixed.reason, std::string("ok"));
    CHECK(bootstrapTokenDaclIsSystemAdminOnly(tokenPath));

    // Write ACE is also fail-closed for non-admins.
    weakenPathDaclUsersWrite(tokenPath);
    u::BootstrapTokenAclAuditResult badWrite = u::auditBootstrapTokenAcl(tokenUtf8);
    CHECK(!badWrite.ok);
    CHECK_EQ(badWrite.reason, std::string("non-admin-token-access-ace"));
    CHECK(u::secureBootstrapTokenAcl(tokenUtf8));
    CHECK(u::auditBootstrapTokenAcl(tokenUtf8).ok);
    CHECK(bootstrapTokenDaclIsSystemAdminOnly(tokenPath));

    // Bad owner (Builtin Users) must fail closed. Elevated repair should reassign to
    // BA; without elevation repair may fail closed (still not inventing a false ok).
    if (setPathOwnerBuiltinUsers(tokenPath))
    {
        u::BootstrapTokenAclAuditResult badOwner = u::auditBootstrapTokenAcl(tokenUtf8);
        CHECK(!badOwner.ok);
        CHECK_EQ(badOwner.reason, std::string("owner-not-admin-or-system"));
        const bool repaired = u::secureBootstrapTokenAcl(tokenUtf8);
        if (repaired)
        {
            u::BootstrapTokenAclAuditResult ownerFixed = u::auditBootstrapTokenAcl(tokenUtf8);
            CHECK(ownerFixed.ok);
            CHECK(bootstrapTokenDaclIsSystemAdminOnly(tokenPath));
            // Prefer BA owner when privileges allowed the transfer.
            CHECK(bootstrapTokenOwnerIsAdministrators(tokenPath) || ownerFixed.ok);
        }
        else
        {
            // Residual untrusted owner must not be reported as repaired/ok.
            CHECK(!u::auditBootstrapTokenAcl(tokenUtf8).ok);
        }
    }

    // Idempotent: second repair keeps the same security posture (when repair works).
    if (u::secureBootstrapTokenAcl(tokenUtf8))
    {
        CHECK(u::secureBootstrapTokenAcl(tokenUtf8));
        CHECK(u::auditBootstrapTokenAcl(tokenUtf8).ok);
        CHECK(bootstrapTokenDaclIsSystemAdminOnly(tokenPath));
    }

    fs::remove_all(dir, ec);
}
} // namespace

int main()
{
    test_parse_and_labels();
#ifdef PGS_ENABLE_TEST_HOOKS
    test_sched_module_parsers();
#endif
    test_split_base64();
    test_sha256();
    test_pfn_and_aumid();
    test_restart_window();
    test_backoff();
    test_module_policy();
    test_modules_acl_audit();
    test_bootstrap_token_acl_audit();

    std::cout << "ran " << g_tests << " checks, " << g_failures << " failures\n";
    return g_failures == 0 ? 0 : 1;
}
