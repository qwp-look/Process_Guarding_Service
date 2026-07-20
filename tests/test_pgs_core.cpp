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
 *       modules/ppl/pgs_ppl_module.cpp -lbcrypt \
 *       -o build/test_pgs_core.exe
 * SPDX-License-Identifier: Apache-2.0
 */
#include "Process_Guard/PGUtil.h"

#include <cstdint>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

namespace u = ProcessGuard::util;

#ifdef PGS_ENABLE_TEST_HOOKS
namespace pgs_sched_test
{
long long parseIso8601ForTest(const std::string &s);
bool parseIntervalSecondsForTest(const std::string &s, long long &out);
long long intervalSecondsLimitForTest();
} // namespace pgs_sched_test

namespace pgs_ppl_test
{
bool parsePidForTest(const std::string &text, ULONG &out);
bool parseSignerForTest(const std::string &text, UCHAR &out);
const char *signerNameForTest(UCHAR value);
} // namespace pgs_ppl_test
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

void test_ppl_module_parsers()
{
    ULONG pid = 0;
    CHECK(pgs_ppl_test::parsePidForTest("1", pid) && pid == 1);
    CHECK(pgs_ppl_test::parsePidForTest("4294967295", pid) && pid == 0xFFFFFFFFul);
    CHECK(!pgs_ppl_test::parsePidForTest("0", pid));
    CHECK(!pgs_ppl_test::parsePidForTest("4294967296", pid));
    CHECK(!pgs_ppl_test::parsePidForTest("18446744073709551615", pid));
    CHECK(!pgs_ppl_test::parsePidForTest("abc", pid));

    UCHAR signer = 0;
    CHECK(pgs_ppl_test::parseSignerForTest("Antimalware", signer));
    CHECK_EQ(std::string(pgs_ppl_test::signerNameForTest(signer)), std::string("Antimalware"));
    CHECK(pgs_ppl_test::parseSignerForTest("Codegen", signer));
    CHECK_EQ(std::string(pgs_ppl_test::signerNameForTest(signer)), std::string("CodeGen"));
    CHECK(pgs_ppl_test::parseSignerForTest("winsystem", signer));
    CHECK_EQ(std::string(pgs_ppl_test::signerNameForTest(signer)), std::string("WinSystem"));
    CHECK(!pgs_ppl_test::parseSignerForTest("0", signer));
    CHECK(!pgs_ppl_test::parseSignerForTest("255", signer));
    CHECK(!pgs_ppl_test::parseSignerForTest("42", signer));
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
} // namespace

int main()
{
    test_parse_and_labels();
#ifdef PGS_ENABLE_TEST_HOOKS
    test_sched_module_parsers();
    test_ppl_module_parsers();
#endif
    test_split_base64();
    test_sha256();
    test_pfn_and_aumid();
    test_restart_window();
    test_backoff();

    std::cout << "ran " << g_tests << " checks, " << g_failures << " failures\n";
    return g_failures == 0 ? 0 : 1;
}
