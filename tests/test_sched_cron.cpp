/**
 * @file test_sched_cron.cpp
 * @brief Unit tests for the scheduler cron parser + next-fire computation.
 *
 * Pure-logic tests (no Win32 services). Build (MSYS2 MinGW64):
 *   g++ -std=c++17 -Iinclude tests/test_sched_cron.cpp \
 *       modules/sched/SchedCron.cpp -o build/test_sched_cron.exe
 * SPDX-License-Identifier: Apache-2.0
 */
#include "SchedCron.h"

#include <chrono>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>

namespace sc = pgs_sched;

namespace
{
int g_tests = 0;
int g_failures = 0;

#define CHECK(cond)                                                  \
    do                                                               \
    {                                                                \
        ++g_tests;                                                   \
        if (!(cond))                                                 \
        {                                                            \
            ++g_failures;                                            \
            std::cerr << "FAIL " << __FILE__ << ":" << __LINE__      \
                      << "  CHECK(" #cond ")\n";                     \
        }                                                            \
    } while (0)

    // epoch ms for a local time, for readable assertions
    long long msFor(int y, int mo, int d, int h, int mi, int s)
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

    void test_parse_valid()
    {
        sc::CronExpr e;
        CHECK(sc::parseCron("* * * * *", e));
        // bare star => empty set (any), not a full range
        CHECK(e.minutes.empty());
        CHECK(e.hours.empty());

        sc::CronExpr e2;
        CHECK(sc::parseCron("5 14 * * *", e2));
        CHECK(e2.minutes == std::vector<int>{5});
        CHECK(e2.hours == std::vector<int>{14});
        CHECK(e2.doms.empty()); // empty = any (star)
        CHECK(e2.dows.empty());
    }

    void test_parse_invalid()
    {
        sc::CronExpr e;
        CHECK(!sc::parseCron("* * * *", e));    // 4 fields
        CHECK(!sc::parseCron("* * * * * *", e)); // 6 fields
        CHECK(!sc::parseCron("60 * * * *", e));  // minute out of range
        CHECK(!sc::parseCron("* 25 * * *", e));  // hour out of range
        CHECK(!sc::parseCron("* * 0 * *", e));   // dom out of range (min 1)
        CHECK(!sc::parseCron("* * * 13 *", e));  // month out of range
        CHECK(!sc::parseCron("* * * * 7", e));   // dow out of range (max 6)
        CHECK(!sc::parseCron("abc * * * *", e)); // non-numeric
        CHECK(!sc::parseCron("*/0 * * * *", e)); // step 0
    }

    void test_parse_step_and_range()
    {
        sc::CronExpr e;
        CHECK(sc::parseCron("*/15 * * * *", e));
        // 0,15,30,45
        CHECK(e.minutes == (std::vector<int>{0, 15, 30, 45}));

        sc::CronExpr e2;
        CHECK(sc::parseCron("10-12 * * * *", e2));
        CHECK(e2.minutes == (std::vector<int>{10, 11, 12}));

        sc::CronExpr e3;
        CHECK(sc::parseCron("1,3,5 * * * *", e3));
        CHECK(e3.minutes == (std::vector<int>{1, 3, 5}));
    }

    void test_next_run_basic()
    {
        sc::CronExpr e;
        CHECK(sc::parseCron("30 14 * * *", e)); // daily at 14:30
        // From 2026-07-09 10:00:00, next is 2026-07-09 14:30:00
        long long from = msFor(2026, 7, 9, 10, 0, 0);
        long long expected = msFor(2026, 7, 9, 14, 30, 0);
        CHECK(sc::nextRunMs(e, from) == expected);
    }
    void test_next_run_subminute_ms_offset()
    {
        sc::CronExpr e;
        CHECK(sc::parseCron("* * * * *", e));
        // afterMs sits mid-minute with a sub-second offset (14:30:30.500) —
        // exactly what nowMs() feeds nextRunMs at runtime. The next fire must
        // be the NEXT whole-minute boundary strictly later than afterMs, never
        // the current minute start (which is in the past relative to afterMs).
        long long from = msFor(2026, 7, 9, 14, 30, 30) + 500;
        long long expected = msFor(2026, 7, 9, 14, 31, 0);
        long long got = sc::nextRunMs(e, from);
        CHECK(got == expected);
        CHECK(got > from);
    }

    void test_next_run_next_day()
    {
        sc::CronExpr e;
        CHECK(sc::parseCron("0 0 * * *", e)); // daily at 00:00
        // From 2026-07-09 15:00:00, next is 2026-07-10 00:00:00
        long long from = msFor(2026, 7, 9, 15, 0, 0);
        long long expected = msFor(2026, 7, 10, 0, 0, 0);
        CHECK(sc::nextRunMs(e, from) == expected);
    }

    void test_next_run_every_minute()
    {
        sc::CronExpr e;
        CHECK(sc::parseCron("* * * * *", e));
        // From 2026-07-09 14:30:45 (sec=45), next minute boundary is 14:31:00
        long long from = msFor(2026, 7, 9, 14, 30, 45);
        long long expected = msFor(2026, 7, 9, 14, 31, 0);
        CHECK(sc::nextRunMs(e, from) == expected);
    }

    void test_next_run_dow_specific()
    {
        sc::CronExpr e;
        // every Sunday at 02:00
        CHECK(sc::parseCron("0 2 * * 0", e));
        long long from = msFor(2026, 7, 9, 12, 0, 0); // 2026-07-09 is Thursday
        long long got = sc::nextRunMs(e, from);
        CHECK(got > 0);
        // verify the result is a Sunday at 02:00
        std::time_t t = static_cast<std::time_t>(got / 1000);
        std::tm local{};
        localtime_s(&local, &t);
        CHECK(local.tm_wday == 0);
        CHECK(local.tm_hour == 2);
        CHECK(local.tm_min == 0);
    }

    void test_next_run_dom_and_dow_or()
    {
        sc::CronExpr e;
        // 1st of month OR Sunday at 03:00 (Vixie OR semantics)
        CHECK(sc::parseCron("0 3 1 * 0", e));
        long long from = msFor(2026, 7, 9, 12, 0, 0);
        long long got = sc::nextRunMs(e, from);
        CHECK(got > 0);
        std::time_t t = static_cast<std::time_t>(got / 1000);
        std::tm local{};
        localtime_s(&local, &t);
        CHECK(local.tm_hour == 3 && local.tm_min == 0);
        CHECK(local.tm_mday == 1 || local.tm_wday == 0);
    }

    void test_next_run_impossible_date()
    {
        sc::CronExpr e;
        // Feb 31 does not exist; cron ORs nothing here (dom=31 restricted,
        // dow=* unrestricted), so nextRun must skip Feb and land on Mar 31.
        CHECK(sc::parseCron("0 0 31 2 *", e));
        long long from = msFor(2026, 1, 1, 0, 0, 0);
        long long got = sc::nextRunMs(e, from);
        // Feb 31 never exists; should return -1 (no valid Feb-31 in search).
        CHECK(got == -1);
    }
} // namespace

int main()
{
    test_parse_valid();
    test_parse_invalid();
    test_parse_step_and_range();
    test_next_run_basic();
    test_next_run_next_day();
    test_next_run_every_minute();
    test_next_run_subminute_ms_offset();
    test_next_run_dow_specific();
    test_next_run_dom_and_dow_or();
    test_next_run_impossible_date();

    std::cout << "sched cron tests: " << g_tests << " ran, " << g_failures << " failed\n";
    return g_failures == 0 ? 0 : 1;
}
