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
} // namespace

int main()
{
    test_allowlist_key_for_path();
    std::cout << "ran " << g_tests << " checks, " << g_failures << " failures\n";
    return g_failures == 0 ? 0 : 1;
}
