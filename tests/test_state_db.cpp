/**
 * @file test_state_db.cpp
 * @brief Unit tests for the SQLite state archive (phase E).
 *
 * Covers: full snapshot round-trip through PGSStateDb, legacy v5 text parsing
 * (including version normalization and malformed-line fail-closed), and the
 * SQLite header probe. Zero PGS-object dependencies: the store is a free
 * layer over PersistedGuardState/GuardGroupState/RestartPolicyState.
 *
 * Build (MSYS2 MinGW64):
 *   g++ -std=c++17 -Iinclude -Isrc/service tests/test_state_db.cpp \
 *       src/service/PGSSqliteStore.cpp src/common/PGLogger.cpp \
 *       -lsqlite3 -o build/test_state_db.exe
 * SPDX-License-Identifier: Apache-2.0
 */
#include "PGSSqliteStore.h"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

using namespace ProcessGuard;

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

    std::string readFile(const std::string &path)
    {
        std::ifstream in(path, std::ios::in | std::ios::binary);
        std::string out;
        std::string line;
        while (std::getline(in, line)) out += line + "\n";
        return out;
    }

    PersistedGuardState makeGuard(std::uint64_t id)
    {
        PersistedGuardState g;
        g.guardId = id;
        g.lastKnownPid = 1000 + static_cast<DWORD>(id);
        g.sessionId = 1;
        g.path = "C:\\Program Files\\App " + std::to_string(id) + "\\app.exe";
        g.maxRestarts = 3;
        g.restartArgs = "--flag value" + std::to_string(id);
        g.fileHash = "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8";
        g.intentional = false;
        g.hashVerified = true;
        g.appKind = (id % 2 == 0) ? AppKind::WinApp : AppKind::Win32;
        g.aumid = (id % 2 == 0) ? "Vendor.App_" + std::to_string(id) + "!App" : std::string();
        g.restartWindowSec = 60;
        g.restartDelayMs = 500;
        g.backoff = true;
        g.hangTimeoutMs = 5000;
        g.killOnExit = (id == 2);
        g.healthCheckJson = "{\"type\":\"tcp\",\"port\":8080}";
        g.groupName = (id == 1) ? "web" : std::string();
        g.paused = false;
        g.createdAtMs = 1700000000000LL + static_cast<std::int64_t>(id);
        g.lastStartMs = 1700000001000LL + static_cast<std::int64_t>(id);
        g.lastExitMs = 1700000002000LL;
        g.lastExitCode = 1;
        g.cumulativeRunMs = 123456;
        g.restartIntervalSumMs = 9000;
        g.restartIntervalCount = 2;
        g.crashLoop = (id == 1);
        g.restartHookJson = "{\"action\":\"event\"}";
        g.quarantined = (id == 2);
        g.lastFailure = "restart window exhausted";
        g.nextRetryMs = 1700000100000LL;
        g.failureCount = 2;
        g.lastFailureCode = "restart.window_exhausted";
        return g;
    }

    StateSnapshot makeSnapshot()
    {
        StateSnapshot snap;
        snap.version = PGS_SQLITE_STATE_VERSION;
        snap.nextGuardId = 3;
        snap.authTokenHash = "0f5d1a3b7c9e0f5d1a3b7c9e0f5d1a3b7c9e0f5d1a3b7c9e0f5d1a3b7c9e0f5d";
        snap.serverPort = 12399;
        snap.modulesPermissive = false;
        snap.guards.push_back(makeGuard(1));
        snap.guards.push_back(makeGuard(2));
        GuardGroupState group;
        group.name = "web";
        group.paused = false;
        group.startupOrder = 2;
        group.dependencies = {"db", "cache"};
        snap.groups.push_back(group);
        RestartPolicyState policy;
        policy.maxRestarts = 3;
        policy.restartCount = 2;
        policy.recentRestartMs = {1700000009000LL, 1700000010000LL};
        snap.policy.emplace_back(1, policy);
        return snap;
    }

    void checkGuardsEqual(const PersistedGuardState &a, const PersistedGuardState &b, const char *label)
    {
        CHECK_EQ(a.guardId, b.guardId);
        CHECK_EQ(a.lastKnownPid, b.lastKnownPid);
        CHECK_EQ(a.sessionId, b.sessionId);
        CHECK_EQ(a.path, b.path);
        CHECK_EQ(a.maxRestarts, b.maxRestarts);
        CHECK_EQ(a.restartArgs, b.restartArgs);
        CHECK_EQ(a.fileHash, b.fileHash);
        CHECK_EQ(a.intentional, b.intentional);
        CHECK_EQ(a.hashVerified, b.hashVerified);
        CHECK_EQ(a.appKind, b.appKind);
        CHECK_EQ(a.aumid, b.aumid);
        CHECK_EQ(a.restartWindowSec, b.restartWindowSec);
        CHECK_EQ(a.restartDelayMs, b.restartDelayMs);
        CHECK_EQ(a.backoff, b.backoff);
        CHECK_EQ(a.hangTimeoutMs, b.hangTimeoutMs);
        CHECK_EQ(a.killOnExit, b.killOnExit);
        CHECK_EQ(a.healthCheckJson, b.healthCheckJson);
        CHECK_EQ(a.groupName, b.groupName);
        CHECK_EQ(a.paused, b.paused);
        CHECK_EQ(a.createdAtMs, b.createdAtMs);
        CHECK_EQ(a.lastStartMs, b.lastStartMs);
        CHECK_EQ(a.lastExitMs, b.lastExitMs);
        CHECK_EQ(a.lastExitCode, b.lastExitCode);
        CHECK_EQ(a.cumulativeRunMs, b.cumulativeRunMs);
        CHECK_EQ(a.restartIntervalSumMs, b.restartIntervalSumMs);
        CHECK_EQ(a.restartIntervalCount, b.restartIntervalCount);
        CHECK_EQ(a.crashLoop, b.crashLoop);
        CHECK_EQ(a.restartHookJson, b.restartHookJson);
        CHECK_EQ(a.quarantined, b.quarantined);
        CHECK_EQ(a.lastFailure, b.lastFailure);
        CHECK_EQ(a.nextRetryMs, b.nextRetryMs);
        CHECK_EQ(a.failureCount, b.failureCount);
        CHECK_EQ(a.lastFailureCode, b.lastFailureCode);
        (void)label;
    }

    void testRoundTrip(const std::string &dbPath)
    {
        StateSnapshot snap = makeSnapshot();
        PGSStateDb db;
        std::string err;
        CHECK(db.open(dbPath, err));
        CHECK(db.saveAll(snap, err));
        db.close();

        CHECK(PGSStateDb::isSqliteFile(dbPath));

        PGSStateDb reader;
        CHECK(reader.open(dbPath, err));
        StateSnapshot loaded;
        CHECK(reader.loadAll(loaded, err));
        CHECK_EQ(loaded.version, PGS_SQLITE_STATE_VERSION);
        CHECK_EQ(loaded.nextGuardId, 3ull);
        CHECK_EQ(loaded.authTokenHash, snap.authTokenHash);
        CHECK_EQ(loaded.serverPort, 12399);
        CHECK_EQ(loaded.modulesPermissive, false);
        CHECK_EQ(loaded.guards.size(), static_cast<std::size_t>(2));
        if (loaded.guards.size() == 2)
        {
            checkGuardsEqual(loaded.guards[0], snap.guards[0], "guard1");
            checkGuardsEqual(loaded.guards[1], snap.guards[1], "guard2");
        }
        CHECK_EQ(loaded.groups.size(), static_cast<std::size_t>(1));
        if (!loaded.groups.empty())
        {
            CHECK_EQ(loaded.groups[0].name, std::string("web"));
            CHECK_EQ(loaded.groups[0].startupOrder, 2);
            CHECK_EQ(loaded.groups[0].dependencies.size(), static_cast<std::size_t>(2));
            if (loaded.groups[0].dependencies.size() == 2)
            {
                CHECK_EQ(loaded.groups[0].dependencies[0], std::string("db"));
                CHECK_EQ(loaded.groups[0].dependencies[1], std::string("cache"));
            }
        }
        CHECK_EQ(loaded.policy.size(), static_cast<std::size_t>(1));
        if (!loaded.policy.empty())
        {
            CHECK_EQ(loaded.policy[0].first, 1ull);
            CHECK_EQ(loaded.policy[0].second.restartCount, 2);
            CHECK_EQ(loaded.policy[0].second.recentRestartMs.size(), static_cast<std::size_t>(2));
        }

        // Save-over (snapshot replace) keeps exactly the new content.
        StateSnapshot smaller = makeSnapshot();
        smaller.guards.resize(1);
        smaller.nextGuardId = 2;
        CHECK(reader.saveAll(smaller, err));
        StateSnapshot reloaded;
        CHECK(reader.loadAll(reloaded, err));
        CHECK_EQ(reloaded.guards.size(), static_cast<std::size_t>(1));
        reader.close();
    }

    void testLegacyTextParse(const std::string &legacyPath)
    {
        // A v5 archive with one guard covering all trailing fields, one group
        // and policy rows — mirroring what persistState() used to write.
        const std::string text =
            "VERSION\t5\n"
            "NEXT_GUARD_ID\t2\n"
            "AUTH_TOKEN_HASH\t0f5d1a3b7c9e0f5d1a3b7c9e0f5d1a3b7c9e0f5d1a3b7c9e0f5d1a3b7c9e0f5d\n"
            "SERVER_PORT\t12400\n"
            "MODULES_PERMISSIVE\t1\n"
            "GROUP_COUNT\t1\n"
            "GROUP\td2Vi\t0\t2\tZGIsY2FjaGU=\n"          // "web", paused=0, order=2, "db,cache"
            "GUARD\t1\t1234\t1\t3\tQzpcYXBwLmV4ZQ==\tLWZsYWc=\ta1b2c3d4\t0\t1\twinapp\tdGVzdC5BcHAhQXBw\t60\t500\t1\t5000\t1\teyJhIjoxfQ==\td2Vi\t0\t1700000000000\t1700000001000\t1700000002000\t1\t123456\t9000\t2\t1\teyJiIjoxfQ==\t1\tZmFpbA==\t1700000100000\t2\trestart.window_exhausted\n"
            "RESTART_COUNT\t1\t2\n"
            "RESTART\t1\t1700000009000\n"
            "RESTART\t1\t1700000010000\n";
        std::ofstream out(legacyPath, std::ios::out | std::ios::binary | std::ios::trunc);
        out << text;
        out.close();

        StateSnapshot snap;
        std::string err;
        CHECK(parseLegacyStateText(readFile(legacyPath), snap, err));
        CHECK_EQ(snap.version, PGS_SQLITE_STATE_VERSION);
        CHECK_EQ(snap.nextGuardId, 2ull);
        CHECK_EQ(snap.serverPort, 12400);
        CHECK_EQ(snap.modulesPermissive, true);
        CHECK_EQ(snap.guards.size(), static_cast<std::size_t>(1));
        if (!snap.guards.empty())
        {
            const PersistedGuardState &g = snap.guards[0];
            CHECK_EQ(g.guardId, 1ull);
            CHECK_EQ(g.lastKnownPid, 1234u);
            CHECK_EQ(g.path, std::string("C:\\app.exe"));
            CHECK_EQ(g.restartArgs, std::string("-flag"));
            CHECK_EQ(g.appKind, AppKind::WinApp);
            CHECK_EQ(g.aumid, std::string("test.App!App"));
            CHECK_EQ(g.restartWindowSec, 60);
            CHECK_EQ(g.backoff, true);
            CHECK_EQ(g.healthCheckJson, std::string("{\"a\":1}"));
            CHECK_EQ(g.groupName, std::string("web"));
            CHECK_EQ(g.quarantined, true);
            CHECK_EQ(g.lastFailure, std::string("fail"));
            CHECK_EQ(g.lastFailureCode, std::string("restart.window_exhausted"));
        }
        CHECK_EQ(snap.groups.size(), static_cast<std::size_t>(1));
        if (!snap.groups.empty())
        {
            CHECK_EQ(snap.groups[0].name, std::string("web"));
            CHECK_EQ(snap.groups[0].dependencies.size(), static_cast<std::size_t>(2));
        }
        CHECK_EQ(snap.policy.size(), static_cast<std::size_t>(1));
        if (!snap.policy.empty())
        {
            CHECK_EQ(snap.policy[0].second.restartCount, 2);
            CHECK_EQ(snap.policy[0].second.recentRestartMs.size(), static_cast<std::size_t>(2));
        }

        // The parsed legacy snapshot must survive a SQLite round-trip intact.
        const std::string dbPath = legacyPath + ".sqlite";
        PGSStateDb db;
        CHECK(db.open(dbPath, err));
        CHECK(db.saveAll(snap, err));
        StateSnapshot loaded;
        CHECK(db.loadAll(loaded, err));
        CHECK_EQ(loaded.guards.size(), snap.guards.size());
        if (!loaded.guards.empty() && !snap.guards.empty())
        {
            checkGuardsEqual(loaded.guards[0], snap.guards[0], "legacy-migrated");
        }
        db.close();
    }

    void testVersionAndCorruption(const std::string &tmpDir)
    {
        // v4 archive: forward-compatible parse, normalized to the SQLite version.
        {
            const std::string v4 =
                "VERSION\t4\nNEXT_GUARD_ID\t2\nAUTH_TOKEN_HASH\t0f5d1a3b7c9e0f5d1a3b7c9e0f5d1a3b7c9e0f5d1a3b7c9e0f5d1a3b7c9e0f5d\n"
                "GUARD\t1\t1234\t1\tno\tQzpcYXBwLmV4ZQ==\t-\t-\t0\t0\n";
            StateSnapshot snap;
            std::string err;
            CHECK(parseLegacyStateText(v4, snap, err));
            CHECK_EQ(snap.version, PGS_SQLITE_STATE_VERSION);
            CHECK_EQ(snap.guards.size(), static_cast<std::size_t>(1));
            if (!snap.guards.empty())
            {
                CHECK_EQ(snap.guards[0].maxRestarts, -1);
                CHECK_EQ(snap.guards[0].appKind, AppKind::Win32);
            }
        }

        // v1 archive: FNV-1a auth hash must be dropped by migration.
        {
            const std::string v1 =
                "VERSION\t1\nNEXT_GUARD_ID\t2\nAUTH_TOKEN_HASH\tdeadbeef\n"
                "GUARD\t1\t1234\t1\t3\tQzpcYXBwLmV4ZQ==\t-\t-\t0\t0\n";
            StateSnapshot snap;
            std::string err;
            CHECK(parseLegacyStateText(v1, snap, err));
            CHECK(snap.authTokenHash.empty());
        }

        // Malformed GUARD line: fail closed with an error, no partial commit.
        {
            const std::string bad =
                "VERSION\t5\nNEXT_GUARD_ID\t2\nGUARD\t1\t1234\n";
            StateSnapshot snap;
            std::string err;
            CHECK(!parseLegacyStateText(bad, snap, err));
            CHECK(!err.empty());
        }

        // A text file is not a SQLite database.
        CHECK(!PGSStateDb::isSqliteFile(tmpDir + "/plain.txt"));
    }
}

int main()
{
    const std::string tmpDir = (std::filesystem::temp_directory_path() / "pgs_state_db_test").string();
    std::error_code ec;
    std::filesystem::create_directories(tmpDir, ec);
    const std::string dbPath = tmpDir + "/state.db";

    testRoundTrip(dbPath);
    testLegacyTextParse(tmpDir + "/legacy_state.db");
    testVersionAndCorruption(tmpDir);

    std::filesystem::remove_all(tmpDir, ec);
    std::cout << "state db tests: " << g_tests << " ran, " << g_failures << " failed" << std::endl;
    return g_failures == 0 ? 0 : 1;
}
