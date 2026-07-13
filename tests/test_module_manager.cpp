#include "Process_Guard/ModuleManager.h"

#include <iostream>
#include <string>

namespace
{
int g_tests = 0;
int g_failures = 0;

#define CHECK_EQ(actual, expected)                                            \
    do                                                                       \
    {                                                                        \
        ++g_tests;                                                           \
        const std::string a = (actual);                                      \
        const std::string e = (expected);                                    \
        if (a != e)                                                          \
        {                                                                    \
            ++g_failures;                                                    \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__            \
                      << " expected '" << e << "' got '" << a << "'\n";    \
        }                                                                    \
    } while (0)

#define CHECK_TRUE(expr)                                                      \
    do                                                                       \
    {                                                                        \
        ++g_tests;                                                           \
        if (!(expr))                                                         \
        {                                                                    \
            ++g_failures;                                                    \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__            \
                      << " expected true: " << #expr << "\n";             \
        }                                                                    \
    } while (0)

void test_allowlist_key_for_path()
{
    using ProcessGuard::ModuleManager;

    CHECK_EQ(ModuleManager::allowlistKeyForPath("C:\\pgs\\modules\\ppl\\pgs_ppl_module.dll"), "ppl");
    CHECK_EQ(ModuleManager::allowlistKeyForPath("C:\\pgs\\modules\\foo.dll"), "foo");
    CHECK_EQ(ModuleManager::allowlistKeyForPath("C:/pgs/modules/foo/foo.dll"), "foo");
    CHECK_EQ(ModuleManager::allowlistKeyForPath("C:/pgs/modules/foo/Bar.DLL"), "foo");
    CHECK_EQ(ModuleManager::allowlistKeyForPath("C:/pgs/modules/SCHED.DLL"), "sched");
    CHECK_EQ(ModuleManager::allowlistKeyForPath("C:/pgs/runtime/foo.dll"), "runtime");
    CHECK_EQ(ModuleManager::allowlistKeyForPath("loose.dll"), "loose");
    CHECK_EQ(ModuleManager::allowlistKeyForPath("foo"), "foo");
}

void test_manifest_parser()
{
    using ProcessGuard::ModuleManager;

    const auto manifest = ModuleManager::parseManifest(
        "name=ppl;version=1.0.0;abi=2;summary=Protected Process Light;"
        "capabilities=ppl.set,ppl.get,ppl.clear");
    CHECK_EQ(manifest.name, "ppl");
    CHECK_EQ(manifest.version, "1.0.0");
    CHECK_TRUE(manifest.hasAbiVersion);
    CHECK_EQ(std::to_string(manifest.abiVersion), "2");
    CHECK_EQ(manifest.summary, "Protected Process Light");
    CHECK_EQ(std::to_string(manifest.capabilities.size()), "3");
    CHECK_EQ(manifest.capabilities[0], "ppl.set");
    CHECK_EQ(manifest.capabilities[2], "ppl.clear");
}

void test_allowlist_line_parser()
{
    using ProcessGuard::ModuleManager;

    const std::string hash(64, 'a');
    ModuleManager::AllowEntry entry;

    CHECK_TRUE(ModuleManager::parseAllowlistLine("PPL|" + hash + "|signed", entry));
    CHECK_EQ(entry.name, "ppl");
    CHECK_EQ(entry.sha256, hash);
    CHECK_TRUE(entry.requireSigned);
    CHECK_EQ(ModuleManager::formatAllowlistLine(entry), "ppl|" + hash + "|signed");

    CHECK_TRUE(ModuleManager::parseAllowlistLine("sched||signed", entry));
    CHECK_EQ(entry.name, "sched");
    CHECK_EQ(entry.sha256, "");
    CHECK_TRUE(entry.requireSigned);
    CHECK_EQ(ModuleManager::formatAllowlistLine(entry), "sched||signed");

    CHECK_TRUE(ModuleManager::parseAllowlistLine("example|signed", entry));
    CHECK_EQ(entry.name, "example");
    CHECK_EQ(entry.sha256, "");
    CHECK_TRUE(entry.requireSigned);

    CHECK_TRUE(!ModuleManager::parseAllowlistLine("bad|not-a-hash", entry));
}

void test_modules_root_for_path()
{
    using ProcessGuard::ModuleManager;

    CHECK_EQ(ModuleManager::modulesRootForPath("C:\\pgs\\modules\\ppl\\pgs_ppl_module.dll"), "C:\\pgs\\modules");
    CHECK_EQ(ModuleManager::modulesRootForPath("C:\\pgs\\modules\\sched.dll"), "C:\\pgs\\modules");
}
} // namespace

int main()
{
    test_allowlist_key_for_path();
    test_manifest_parser();
    test_allowlist_line_parser();
    test_modules_root_for_path();
    std::cout << "ran " << g_tests << " checks, " << g_failures << " failures\n";
    return g_failures == 0 ? 0 : 1;
}
