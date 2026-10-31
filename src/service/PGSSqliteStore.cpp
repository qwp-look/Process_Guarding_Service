/**
 * @file PGSSqliteStore.cpp
 * @brief SQLite-backed guard state archive (see PGSSqliteStore.h).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "PGSSqliteStore.h"
#include "PGSInternal.h"

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <limits>
#include <sstream>

#include <nlohmann/json.hpp>

namespace ProcessGuard
{
    namespace
    {
        using namespace pgs_internal;

        std::int64_t epochMsNow()
        {
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }

        std::string trimLocal(std::string value)
        {
            const char *ws = " \t\r\n";
            const std::size_t first = value.find_first_not_of(ws);
            if (first == std::string::npos) return std::string();
            const std::size_t last = value.find_last_not_of(ws);
            return value.substr(first, last - first + 1);
        }

        std::vector<std::string> splitTab(const std::string &value)
        {
            return util::split(value, '\t');
        }

        // Local mirror of PGS::parseMaxRestarts (private static in PGS.cpp);
        // the store keeps its own copy so it has no dependency on PGS members.
        // Semantics: "no"/"none" = unlimited (-1); "-1" and junk are rejected.
        bool parseMaxRestartsField(const std::string &value, int &out)
        {
            const std::string v = trimLocal(value);
            if (v == "no" || v == "none")
            {
                out = -1;
                return true;
            }
            if (v.empty() || v == "-1") return false;
            for (char ch : v)
            {
                if (ch < '0' || ch > '9') return false;
            }
            try
            {
                out = std::stoi(v);
            }
            catch (const std::exception &)
            {
                return false;
            }
            return true;
        }

        bool parseDwordField(const std::string &value, DWORD &out)
        {
            std::uint64_t v = 0;
            if (!util::parseUnsignedLongLong(value, v) || v > 0xFFFFFFFFull) return false;
            out = static_cast<DWORD>(v);
            return true;
        }

        bool parseGuardRecordFields(const std::vector<std::string> &fields, PersistedGuardState &persisted)
        {
            if (fields.size() < 10) return false;
            if (!util::parseUnsignedLongLong(fields[1], persisted.guardId) ||
                !parseDwordField(fields[2], persisted.lastKnownPid) ||
                !parseDwordField(fields[3], persisted.sessionId))
            {
                return false;
            }
            if (!parseMaxRestartsField(fields[4], persisted.maxRestarts)) return false;
            persisted.path = util::base64Decode(fields[5]);
            persisted.restartArgs = util::base64Decode(fields[6]);
            persisted.fileHash = (fields[7] == "-") ? std::string() : trimLocal(fields[7]);
            if (!util::parseBoolFlag(fields[8], persisted.intentional) ||
                !util::parseBoolFlag(fields[9], persisted.hashVerified))
            {
                return false;
            }

            // v3 advanced guard-policy fields (trailing the v2 base). Older
            // archives that stop at field[9] get the legacy defaults here.
            DWORD dv = 0;
            if (fields.size() > 12 && parseDwordField(fields[12], dv)) persisted.restartWindowSec = static_cast<int>(dv);
            if (fields.size() > 13 && parseDwordField(fields[13], dv)) persisted.restartDelayMs = static_cast<int>(dv);
            if (fields.size() > 15 && parseDwordField(fields[15], dv)) persisted.hangTimeoutMs = static_cast<int>(dv);
            if (fields.size() > 10)
            {
                const std::string aks = trimLocal(fields[10]);
                if (aks == "1" || aks == "winapp" || aks == "uwp" || aks == "store")
                {
                    persisted.appKind = AppKind::WinApp;
                }
            }
            if (fields.size() > 11 && fields[11] != "-") persisted.aumid = util::base64Decode(fields[11]);
            if (fields.size() > 14)
            {
                const std::string bv = trimLocal(fields[14]);
                persisted.backoff = (bv == "1" || bv == "true" || bv == "yes");
            }
            if (fields.size() > 16)
            {
                const std::string bv = trimLocal(fields[16]);
                persisted.killOnExit = (bv == "1" || bv == "true" || bv == "yes");
            }
            if (fields.size() > 17 && fields[17] != "-")
            {
                persisted.healthCheckJson = util::base64Decode(fields[17]);
                if (!persisted.healthCheckJson.empty() && !looksLikeJsonObjectOrArray(persisted.healthCheckJson))
                {
                    persisted.healthCheckJson.clear();
                }
            }
            if (fields.size() > 18 && fields[18] != "-")
            {
                persisted.groupName = sanitizeGroupName(util::base64Decode(fields[18]));
            }
            if (fields.size() > 19)
            {
                bool b = false;
                if (util::parseBoolFlag(fields[19], b)) persisted.paused = b;
            }
            if (fields.size() > 20) parseInt64Field(fields[20], persisted.createdAtMs);
            if (fields.size() > 21) parseInt64Field(fields[21], persisted.lastStartMs);
            if (fields.size() > 22) parseInt64Field(fields[22], persisted.lastExitMs);
            if (fields.size() > 23) parseIntField(fields[23], persisted.lastExitCode);
            if (fields.size() > 24) parseInt64Field(fields[24], persisted.cumulativeRunMs);
            if (fields.size() > 25) parseInt64Field(fields[25], persisted.restartIntervalSumMs);
            if (fields.size() > 26) parseIntField(fields[26], persisted.restartIntervalCount);
            if (fields.size() > 27)
            {
                bool b = false;
                if (util::parseBoolFlag(fields[27], b)) persisted.crashLoop = b;
            }
            if (fields.size() > 28 && fields[28] != "-")
            {
                persisted.restartHookJson = util::base64Decode(fields[28]);
                if (!persisted.restartHookJson.empty() && !looksLikeJsonObjectOrArray(persisted.restartHookJson))
                {
                    persisted.restartHookJson.clear();
                }
            }
            if (fields.size() > 29)
            {
                bool b = false;
                if (util::parseBoolFlag(fields[29], b)) persisted.quarantined = b;
            }
            if (fields.size() > 30 && fields[30] != "-") persisted.lastFailure = util::base64Decode(fields[30]);
            if (fields.size() > 31) parseInt64Field(fields[31], persisted.nextRetryMs);
            if (fields.size() > 32) parseIntField(fields[32], persisted.failureCount);
            if (persisted.failureCount < 0) persisted.failureCount = 0;
            if (fields.size() > 33 && fields[33] != "-") persisted.lastFailureCode = trimLocal(fields[33]);

            if (persisted.createdAtMs <= 0) persisted.createdAtMs = epochMsNow();
            if (persisted.lastStartMs <= 0 && persisted.lastKnownPid != 0)
            {
                persisted.lastStartMs = persisted.createdAtMs;
            }
            return !persisted.path.empty() && persisted.guardId != 0;
        }

        // Shared version normalization: v1 archives carry an FNV-1a hash that
        // SHA-256 auth must not trust; v2/v3/v4 records upgrade in place.
        bool normalizeSnapshotVersion(StateSnapshot &snap, std::string &err)
        {
            if (snap.version == PGS_SQLITE_STATE_VERSION) return true;
            if (snap.version == 1)
            {
                Logger::warning("PGS: migrating state v1 -> v5 (guard records kept, auth token reset)");
                snap.authTokenHash.clear();
                snap.version = PGS_SQLITE_STATE_VERSION;
                return true;
            }
            if (snap.version == kLegacyStateFileVersion ||
                snap.version == kAdvancedStateFileVersion ||
                snap.version == kPreviousStateFileVersion)
            {
                Logger::warning("PGS: migrating state v" + std::to_string(snap.version) + " -> v5 (guard records kept)");
                snap.version = PGS_SQLITE_STATE_VERSION;
                return true;
            }
            err = "unsupported state version " + std::to_string(snap.version);
            return false;
        }

        std::string recentToJson(const std::vector<std::int64_t> &v)
        {
            const nlohmann::json j = v;
            return j.dump();
        }

        std::vector<std::int64_t> jsonToRecent(const std::string &text)
        {
            std::vector<std::int64_t> out;
            try
            {
                const auto j = nlohmann::json::parse(text);
                if (j.is_array())
                {
                    for (const auto &item : j)
                    {
                        if (item.is_number_integer()) out.push_back(item.get<std::int64_t>());
                    }
                }
            }
            catch (const std::exception &) {}
            return out;
        }

        std::string depsToJson(const std::vector<std::string> &v)
        {
            const nlohmann::json j = v;
            return j.dump();
        }

        std::vector<std::string> jsonToDeps(const std::string &text)
        {
            std::vector<std::string> out;
            try
            {
                const auto j = nlohmann::json::parse(text);
                if (j.is_array())
                {
                    for (const auto &item : j)
                    {
                        if (item.is_string()) out.push_back(item.get<std::string>());
                    }
                }
            }
            catch (const std::exception &) {}
            return out;
        }

        bool bindTextOrNull(sqlite3_stmt *stmt, int index, const std::string &value)
        {
            if (value.empty()) return sqlite3_bind_null(stmt, index) == SQLITE_OK;
            return sqlite3_bind_text(stmt, index, value.c_str(), static_cast<int>(value.size()), SQLITE_TRANSIENT) == SQLITE_OK;
        }

        std::string columnTextOrNull(sqlite3_stmt *stmt, int index)
        {
            if (sqlite3_column_type(stmt, index) == SQLITE_NULL) return std::string();
            const unsigned char *text = sqlite3_column_text(stmt, index);
            if (!text) return std::string();
            return std::string(reinterpret_cast<const char *>(text),
                               static_cast<std::size_t>(sqlite3_column_bytes(stmt, index)));
        }

        const char *kSchema =
            "CREATE TABLE IF NOT EXISTS meta ("
            "  key TEXT PRIMARY KEY,"
            "  value TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS guards ("
            "  guard_id INTEGER PRIMARY KEY,"
            "  last_known_pid INTEGER NOT NULL,"
            "  session_id INTEGER NOT NULL,"
            "  path TEXT NOT NULL,"
            "  max_restarts INTEGER NOT NULL,"
            "  restart_args TEXT NOT NULL,"
            "  file_hash TEXT,"
            "  intentional INTEGER NOT NULL,"
            "  hash_verified INTEGER NOT NULL,"
            "  app_kind INTEGER NOT NULL,"
            "  aumid TEXT NOT NULL,"
            "  restart_window_sec INTEGER NOT NULL,"
            "  restart_delay_ms INTEGER NOT NULL,"
            "  backoff INTEGER NOT NULL,"
            "  hang_timeout_ms INTEGER NOT NULL,"
            "  kill_on_exit INTEGER NOT NULL,"
            "  health_check_json TEXT,"
            "  group_name TEXT,"
            "  paused INTEGER NOT NULL,"
            "  created_at_ms INTEGER NOT NULL,"
            "  last_start_ms INTEGER NOT NULL,"
            "  last_exit_ms INTEGER NOT NULL,"
            "  last_exit_code INTEGER NOT NULL,"
            "  cumulative_run_ms INTEGER NOT NULL,"
            "  restart_interval_sum_ms INTEGER NOT NULL,"
            "  restart_interval_count INTEGER NOT NULL,"
            "  crash_loop INTEGER NOT NULL,"
            "  restart_hook_json TEXT,"
            "  quarantined INTEGER NOT NULL,"
            "  last_failure TEXT,"
            "  next_retry_ms INTEGER NOT NULL,"
            "  failure_count INTEGER NOT NULL,"
            "  last_failure_code TEXT);"
            "CREATE TABLE IF NOT EXISTS groups ("
            "  name TEXT PRIMARY KEY,"
            "  paused INTEGER NOT NULL,"
            "  startup_order INTEGER NOT NULL,"
            "  dependencies TEXT NOT NULL);"
            "CREATE TABLE IF NOT EXISTS restart_policy ("
            "  guard_id INTEGER PRIMARY KEY,"
            "  restart_count INTEGER NOT NULL,"
            "  recent_restart_ms TEXT NOT NULL);";
    } // namespace

    bool parseLegacyStateText(const std::string &text, StateSnapshot &out, std::string &err)
    {
        out = StateSnapshot{};
        std::istringstream in(text);
        std::string line;
        std::unordered_map<std::uint64_t, RestartPolicyState> policy;
        int declaredGroups = -1;
        int parsedGroupLines = 0;
        while (std::getline(in, line))
        {
            const std::string trimmed = trimLocal(line);
            if (trimmed.empty()) continue;
            const std::vector<std::string> fields = splitTab(trimmed);
            if (fields.empty()) continue;

            if (fields[0] == "VERSION")
            {
                if (fields.size() < 2) { err = "VERSION line truncated"; return false; }
                try { out.version = std::stoi(fields[1]); }
                catch (const std::exception &) { err = "VERSION parse failed"; return false; }
                continue;
            }
            if (fields[0] == "NEXT_GUARD_ID")
            {
                if (fields.size() >= 2) util::parseUnsignedLongLong(fields[1], out.nextGuardId);
                continue;
            }
            if (fields[0] == "AUTH_TOKEN_HASH")
            {
                if (fields.size() >= 2) out.authTokenHash = util::toLowerAscii(trimLocal(fields[1]));
                continue;
            }
            if (fields[0] == "SERVER_PORT")
            {
                DWORD sp = 0;
                if (fields.size() >= 2 && parseDwordField(fields[1], sp) && sp > 0)
                {
                    out.serverPort = static_cast<std::uint16_t>(sp);
                }
                continue;
            }
            if (fields[0] == "MODULES_PERMISSIVE")
            {
                if (fields.size() >= 2) util::parseBoolFlag(fields[1], out.modulesPermissive);
                continue;
            }
            if (fields[0] == "RESTART_COUNT")
            {
                std::uint64_t guardId = 0, count = 0;
                if (fields.size() >= 3 && util::parseUnsignedLongLong(fields[1], guardId) &&
                    util::parseUnsignedLongLong(fields[2], count) && guardId != 0)
                {
                    policy[guardId].restartCount = static_cast<int>(std::min<std::uint64_t>(
                        count, static_cast<std::uint64_t>(std::numeric_limits<int>::max())));
                }
                continue;
            }
            if (fields[0] == "RESTART")
            {
                std::uint64_t guardId = 0, epoch = 0;
                if (fields.size() >= 3 && util::parseUnsignedLongLong(fields[1], guardId) &&
                    util::parseUnsignedLongLong(fields[2], epoch) && guardId != 0)
                {
                    policy[guardId].recentRestartMs.push_back(static_cast<std::int64_t>(epoch));
                }
                continue;
            }
            if (fields[0] == "GROUP_COUNT")
            {
                std::uint64_t n = 0;
                if (fields.size() >= 2 && util::parseUnsignedLongLong(fields[1], n))
                {
                    declaredGroups = static_cast<int>(n);
                }
                continue;
            }
            if (fields[0] == "GROUP")
            {
                if (fields.size() < 3) { err = "GROUP line truncated"; return false; }
                GuardGroupState group;
                group.name = sanitizeGroupName(util::base64Decode(fields[1]));
                if (group.name.empty()) { err = "GROUP name invalid"; return false; }
                if (!util::parseBoolFlag(fields[2], group.paused)) { err = "GROUP paused invalid"; return false; }
                if (fields.size() > 3) parseIntField(fields[3], group.startupOrder);
                if (fields.size() > 4 && fields[4] != "-")
                {
                    group.dependencies = splitCsvTrimmed(util::base64Decode(fields[4]));
                }
                bool replaced = false;
                for (auto &existing : out.groups)
                {
                    if (existing.name == group.name)
                    {
                        existing = group;
                        replaced = true;
                        break;
                    }
                }
                if (!replaced) out.groups.push_back(std::move(group));
                ++parsedGroupLines;
                continue;
            }
            if (fields[0] == "GUARD")
            {
                PersistedGuardState persisted;
                if (!parseGuardRecordFields(fields, persisted))
                {
                    err = "GUARD line malformed (guardId=" + (fields.size() > 1 ? fields[1] : std::string("?")) + ")";
                    return false;
                }
                if (persisted.guardId >= out.nextGuardId)
                {
                    out.nextGuardId = persisted.guardId + 1;
                }
                out.guards.push_back(std::move(persisted));
                continue;
            }
            // Unknown record kinds are ignored so future minor versions stay
            // loadable, matching the tolerant reading of trailing fields.
        }

        // Deduplicate guard ids: last record wins, matching the old map-based
        // parse where a repeated GUARD line overwrote the previous entry.
        std::sort(out.guards.begin(), out.guards.end(), [](const PersistedGuardState &a, const PersistedGuardState &b) {
            return (a.guardId == b.guardId) ? (a.createdAtMs < b.createdAtMs) : (a.guardId < b.guardId);
        });
        out.guards.erase(std::unique(out.guards.begin(), out.guards.end(),
                                     [](const PersistedGuardState &a, const PersistedGuardState &b) {
                                         return a.guardId == b.guardId;
                                     }),
                         out.guards.end());

        if (!normalizeSnapshotVersion(out, err)) return false;
        if (!out.authTokenHash.empty() && !isSha256Hex(out.authTokenHash))
        {
            Logger::warning("PGS: persisted auth hash is invalid, generating a fresh token");
            out.authTokenHash.clear();
        }
        if (declaredGroups != -1 && declaredGroups != parsedGroupLines)
        {
            Logger::warning("PGS: persisted group count mismatch, parsed=" + std::to_string(parsedGroupLines) +
                            ", declared=" + std::to_string(declaredGroups));
        }
        out.policy.reserve(policy.size());
        for (const auto &entry : policy) out.policy.emplace_back(entry.first, entry.second);
        return true;
    }

    PGSStateDb::~PGSStateDb()
    {
        close();
    }

    bool PGSStateDb::isSqliteFile(const std::string &pathUtf8)
    {
        std::ifstream in(pathUtf8, std::ios::in | std::ios::binary);
        if (!in.is_open()) return false;
        char header[16] = {0};
        in.read(header, 15);
        return in.gcount() == 15 && std::strncmp(header, "SQLite format 3", 15) == 0;
    }

    bool PGSStateDb::open(const std::string &pathUtf8, std::string &err)
    {
        close();
        const int rc = sqlite3_open_v2(pathUtf8.c_str(), &m_db,
                                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        if (rc != SQLITE_OK)
        {
            err = "sqlite open failed: " + std::string(m_db ? sqlite3_errmsg(m_db) : sqlite3_errstr(rc));
            close();
            return false;
        }
        sqlite3_busy_timeout(m_db, 3000);
        return ensureSchema(err);
    }

    void PGSStateDb::close()
    {
        if (m_db)
        {
            sqlite3_close_v2(m_db);
            m_db = nullptr;
        }
    }

    bool PGSStateDb::ensureSchema(std::string &err)
    {
        char *errMsg = nullptr;
        const int rc = sqlite3_exec(m_db, kSchema, nullptr, nullptr, &errMsg);
        if (rc != SQLITE_OK)
        {
            err = "sqlite schema failed: " + std::string(errMsg ? errMsg : sqlite3_errmsg(m_db));
            sqlite3_free(errMsg);
            return false;
        }
        return true;
    }

    bool PGSStateDb::loadAll(StateSnapshot &out, std::string &err)
    {
        if (!m_db) { err = "state db not open"; return false; }

        // Fail closed on a foreign/unknown schema version: never half-trust an
        // archive written by a different PGS generation.
        {
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(m_db, "SELECT value FROM meta WHERE key='state_version'", -1, &stmt, nullptr) != SQLITE_OK)
            {
                err = "sqlite meta read failed: " + std::string(sqlite3_errmsg(m_db));
                return false;
            }
            bool have = false;
            std::string value;
            if (sqlite3_step(stmt) == SQLITE_ROW)
            {
                have = true;
                value = columnTextOrNull(stmt, 0);
            }
            sqlite3_finalize(stmt);
            if (!have)
            {
                err = "state db missing state_version";
                return false;
            }
            try
            {
                out.version = std::stoi(value);
            }
            catch (const std::exception &)
            {
                err = "state db state_version invalid: " + value;
                return false;
            }
            if (out.version != PGS_SQLITE_STATE_VERSION)
            {
                err = "state db version " + value + " unsupported (expected " +
                      std::to_string(PGS_SQLITE_STATE_VERSION) + ")";
                return false;
            }
        }

        auto readMetaText = [&](const char *key) -> std::string {
            sqlite3_stmt *stmt = nullptr;
            std::string value;
            const std::string sql = std::string("SELECT value FROM meta WHERE key='") + key + "'";
            if (sqlite3_prepare_v2(m_db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK)
            {
                if (sqlite3_step(stmt) == SQLITE_ROW) value = columnTextOrNull(stmt, 0);
            }
            sqlite3_finalize(stmt);
            return value;
        };

        {
            const std::string ngid = readMetaText("next_guard_id");
            std::uint64_t v = 0;
            if (!ngid.empty() && util::parseUnsignedLongLong(ngid, v)) out.nextGuardId = std::max<std::uint64_t>(1ull, v);
            out.authTokenHash = readMetaText("auth_token_hash");
            if (!out.authTokenHash.empty() && !isSha256Hex(out.authTokenHash))
            {
                Logger::warning("PGS: persisted auth hash is invalid, generating a fresh token");
                out.authTokenHash.clear();
            }
            std::uint64_t port = 0;
            const std::string portText = readMetaText("server_port");
            if (!portText.empty() && util::parseUnsignedLongLong(portText, port) && port > 0 && port <= 65535)
            {
                out.serverPort = static_cast<std::uint16_t>(port);
            }
            out.modulesPermissive = (readMetaText("modules_permissive") == "1");
        }

        // Guards.
        {
            sqlite3_stmt *stmt = nullptr;
            const char *sql =
                "SELECT guard_id,last_known_pid,session_id,path,max_restarts,restart_args,file_hash,"
                "intentional,hash_verified,app_kind,aumid,restart_window_sec,restart_delay_ms,backoff,"
                "hang_timeout_ms,kill_on_exit,health_check_json,group_name,paused,created_at_ms,"
                "last_start_ms,last_exit_ms,last_exit_code,cumulative_run_ms,restart_interval_sum_ms,"
                "restart_interval_count,crash_loop,restart_hook_json,quarantined,last_failure,"
                "next_retry_ms,failure_count,last_failure_code FROM guards ORDER BY guard_id";
            if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
            {
                err = "sqlite guards read failed: " + std::string(sqlite3_errmsg(m_db));
                return false;
            }
            int rc = SQLITE_OK;
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
            {
                PersistedGuardState g;
                g.guardId = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 0));
                g.lastKnownPid = static_cast<DWORD>(sqlite3_column_int64(stmt, 1));
                g.sessionId = static_cast<DWORD>(sqlite3_column_int64(stmt, 2));
                g.path = columnTextOrNull(stmt, 3);
                g.maxRestarts = sqlite3_column_int(stmt, 4);
                g.restartArgs = columnTextOrNull(stmt, 5);
                g.fileHash = columnTextOrNull(stmt, 6);
                g.intentional = sqlite3_column_int(stmt, 7) != 0;
                g.hashVerified = sqlite3_column_int(stmt, 8) != 0;
                g.appKind = sqlite3_column_int(stmt, 9) != 0 ? AppKind::WinApp : AppKind::Win32;
                g.aumid = columnTextOrNull(stmt, 10);
                g.restartWindowSec = sqlite3_column_int(stmt, 11);
                g.restartDelayMs = sqlite3_column_int(stmt, 12);
                g.backoff = sqlite3_column_int(stmt, 13) != 0;
                g.hangTimeoutMs = sqlite3_column_int(stmt, 14);
                g.killOnExit = sqlite3_column_int(stmt, 15) != 0;
                g.healthCheckJson = columnTextOrNull(stmt, 16);
                g.groupName = columnTextOrNull(stmt, 17);
                g.paused = sqlite3_column_int(stmt, 18) != 0;
                g.createdAtMs = sqlite3_column_int64(stmt, 19);
                g.lastStartMs = sqlite3_column_int64(stmt, 20);
                g.lastExitMs = sqlite3_column_int64(stmt, 21);
                g.lastExitCode = sqlite3_column_int(stmt, 22);
                g.cumulativeRunMs = sqlite3_column_int64(stmt, 23);
                g.restartIntervalSumMs = sqlite3_column_int64(stmt, 24);
                g.restartIntervalCount = sqlite3_column_int(stmt, 25);
                g.crashLoop = sqlite3_column_int(stmt, 26) != 0;
                g.restartHookJson = columnTextOrNull(stmt, 27);
                g.quarantined = sqlite3_column_int(stmt, 28) != 0;
                g.lastFailure = columnTextOrNull(stmt, 29);
                g.nextRetryMs = sqlite3_column_int64(stmt, 30);
                g.failureCount = sqlite3_column_int(stmt, 31);
                if (g.failureCount < 0) g.failureCount = 0;
                g.lastFailureCode = columnTextOrNull(stmt, 32);
                if (g.createdAtMs <= 0) g.createdAtMs = epochMsNow();
                if (g.lastStartMs <= 0 && g.lastKnownPid != 0) g.lastStartMs = g.createdAtMs;
                if (g.path.empty() || g.guardId == 0)
                {
                    err = "state db guard row malformed (guard_id=" + std::to_string(g.guardId) + ")";
                    sqlite3_finalize(stmt);
                    return false;
                }
                out.guards.push_back(std::move(g));
            }
            sqlite3_finalize(stmt);
            if (rc != SQLITE_DONE)
            {
                err = "sqlite guards scan failed: " + std::string(sqlite3_errmsg(m_db));
                return false;
            }
        }

        // Groups.
        {
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(m_db, "SELECT name,paused,startup_order,dependencies FROM groups ORDER BY name", -1, &stmt, nullptr) != SQLITE_OK)
            {
                err = "sqlite groups read failed: " + std::string(sqlite3_errmsg(m_db));
                return false;
            }
            int rc = SQLITE_OK;
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
            {
                GuardGroupState group;
                group.name = columnTextOrNull(stmt, 0);
                group.paused = sqlite3_column_int(stmt, 1) != 0;
                group.startupOrder = sqlite3_column_int(stmt, 2);
                group.dependencies = jsonToDeps(columnTextOrNull(stmt, 3));
                if (!group.name.empty()) out.groups.push_back(std::move(group));
            }
            sqlite3_finalize(stmt);
            if (rc != SQLITE_DONE)
            {
                err = "sqlite groups scan failed: " + std::string(sqlite3_errmsg(m_db));
                return false;
            }
        }

        // Restart policy.
        {
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(m_db, "SELECT guard_id,restart_count,recent_restart_ms FROM restart_policy", -1, &stmt, nullptr) != SQLITE_OK)
            {
                err = "sqlite policy read failed: " + std::string(sqlite3_errmsg(m_db));
                return false;
            }
            int rc = SQLITE_OK;
            while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
            {
                const std::uint64_t guardId = static_cast<std::uint64_t>(sqlite3_column_int64(stmt, 0));
                if (guardId == 0) continue;
                RestartPolicyState policy;
                policy.restartCount = sqlite3_column_int(stmt, 1);
                policy.recentRestartMs = jsonToRecent(columnTextOrNull(stmt, 2));
                out.policy.emplace_back(guardId, std::move(policy));
            }
            sqlite3_finalize(stmt);
            if (rc != SQLITE_DONE)
            {
                err = "sqlite policy scan failed: " + std::string(sqlite3_errmsg(m_db));
                return false;
            }
        }
        return true;
    }

    bool PGSStateDb::saveAll(const StateSnapshot &in, std::string &err)
    {
        if (!m_db) { err = "state db not open"; return false; }

        char *errMsg = nullptr;
        if (sqlite3_exec(m_db, "BEGIN IMMEDIATE", nullptr, nullptr, &errMsg) != SQLITE_OK)
        {
            err = "sqlite begin failed: " + std::string(errMsg ? errMsg : sqlite3_errmsg(m_db));
            sqlite3_free(errMsg);
            return false;
        }
        auto rollback = [&](const std::string &what) {
            std::string detail = what;
            sqlite3_exec(m_db, "ROLLBACK", nullptr, nullptr, nullptr);
            err = detail;
            return false;
        };

        {
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(m_db, "DELETE FROM meta", -1, &stmt, nullptr) != SQLITE_OK ||
                sqlite3_step(stmt) != SQLITE_DONE)
            {
                const std::string detail = "sqlite meta clear failed: " + std::string(sqlite3_errmsg(m_db));
                sqlite3_finalize(stmt);
                return rollback(detail);
            }
            sqlite3_finalize(stmt);
        }
        {
            const char *sql = "INSERT INTO meta(key,value) VALUES(?1,?2)";
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
            {
                return rollback(std::string("sqlite meta insert prepare failed: ") + sqlite3_errmsg(m_db));
            }
            auto put = [&](const char *key, const std::string &value) {
                sqlite3_reset(stmt);
                sqlite3_bind_text(stmt, 1, key, -1, SQLITE_TRANSIENT);
                sqlite3_bind_text(stmt, 2, value.c_str(), static_cast<int>(value.size()), SQLITE_TRANSIENT);
                return sqlite3_step(stmt) == SQLITE_DONE;
            };
            const bool ok = put("state_version", std::to_string(PGS_SQLITE_STATE_VERSION)) &&
                            put("next_guard_id", std::to_string(std::max<std::uint64_t>(1ull, in.nextGuardId))) &&
                            put("auth_token_hash", in.authTokenHash) &&
                            put("server_port", in.serverPort > 0 ? std::to_string(in.serverPort) : std::string()) &&
                            put("modules_permissive", in.modulesPermissive ? "1" : "0");
            sqlite3_finalize(stmt);
            if (!ok) return rollback("sqlite meta insert failed");
        }

        {
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(m_db, "DELETE FROM guards", -1, &stmt, nullptr) != SQLITE_OK ||
                sqlite3_step(stmt) != SQLITE_DONE)
            {
                sqlite3_finalize(stmt);
                return rollback(std::string("sqlite guards clear failed: ") + sqlite3_errmsg(m_db));
            }
            sqlite3_finalize(stmt);
        }
        if (!in.guards.empty())
        {
            const char *sql =
                "INSERT INTO guards(guard_id,last_known_pid,session_id,path,max_restarts,restart_args,file_hash,"
                "intentional,hash_verified,app_kind,aumid,restart_window_sec,restart_delay_ms,backoff,"
                "hang_timeout_ms,kill_on_exit,health_check_json,group_name,paused,created_at_ms,"
                "last_start_ms,last_exit_ms,last_exit_code,cumulative_run_ms,restart_interval_sum_ms,"
                "restart_interval_count,crash_loop,restart_hook_json,quarantined,last_failure,"
                "next_retry_ms,failure_count,last_failure_code) VALUES "
                "(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,"
                "?21,?22,?23,?24,?25,?26,?27,?28,?29,?30,?31,?32,?33)";
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
            {
                return rollback(std::string("sqlite guards insert prepare failed: ") + sqlite3_errmsg(m_db));
            }
            for (const PersistedGuardState &g : in.guards)
            {
                sqlite3_reset(stmt);
                bool ok = sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(g.guardId)) == SQLITE_OK &&
                          sqlite3_bind_int64(stmt, 2, static_cast<sqlite3_int64>(g.lastKnownPid)) == SQLITE_OK &&
                          sqlite3_bind_int64(stmt, 3, static_cast<sqlite3_int64>(g.sessionId)) == SQLITE_OK &&
                          bindTextOrNull(stmt, 4, g.path) &&
                          sqlite3_bind_int(stmt, 5, g.maxRestarts) == SQLITE_OK &&
                          sqlite3_bind_text(stmt, 6, g.restartArgs.c_str(), static_cast<int>(g.restartArgs.size()), SQLITE_TRANSIENT) == SQLITE_OK &&
                          bindTextOrNull(stmt, 7, g.fileHash) &&
                          sqlite3_bind_int(stmt, 8, g.intentional ? 1 : 0) == SQLITE_OK &&
                          sqlite3_bind_int(stmt, 9, g.hashVerified ? 1 : 0) == SQLITE_OK &&
                          sqlite3_bind_int(stmt, 10, g.appKind == AppKind::WinApp ? 1 : 0) == SQLITE_OK &&
                          sqlite3_bind_text(stmt, 11, g.aumid.c_str(), static_cast<int>(g.aumid.size()), SQLITE_TRANSIENT) == SQLITE_OK &&
                          sqlite3_bind_int(stmt, 12, g.restartWindowSec) == SQLITE_OK &&
                          sqlite3_bind_int(stmt, 13, g.restartDelayMs) == SQLITE_OK &&
                          sqlite3_bind_int(stmt, 14, g.backoff ? 1 : 0) == SQLITE_OK &&
                          sqlite3_bind_int(stmt, 15, g.hangTimeoutMs) == SQLITE_OK &&
                          sqlite3_bind_int(stmt, 16, g.killOnExit ? 1 : 0) == SQLITE_OK &&
                          bindTextOrNull(stmt, 17, g.healthCheckJson) &&
                          bindTextOrNull(stmt, 18, g.groupName) &&
                          sqlite3_bind_int(stmt, 19, g.paused ? 1 : 0) == SQLITE_OK &&
                          sqlite3_bind_int64(stmt, 20, g.createdAtMs) == SQLITE_OK &&
                          sqlite3_bind_int64(stmt, 21, g.lastStartMs) == SQLITE_OK &&
                          sqlite3_bind_int64(stmt, 22, g.lastExitMs) == SQLITE_OK &&
                          sqlite3_bind_int(stmt, 23, g.lastExitCode) == SQLITE_OK &&
                          sqlite3_bind_int64(stmt, 24, g.cumulativeRunMs) == SQLITE_OK &&
                          sqlite3_bind_int64(stmt, 25, g.restartIntervalSumMs) == SQLITE_OK &&
                          sqlite3_bind_int(stmt, 26, g.restartIntervalCount) == SQLITE_OK &&
                          sqlite3_bind_int(stmt, 27, g.crashLoop ? 1 : 0) == SQLITE_OK &&
                          bindTextOrNull(stmt, 28, g.restartHookJson) &&
                          sqlite3_bind_int(stmt, 29, g.quarantined ? 1 : 0) == SQLITE_OK &&
                          bindTextOrNull(stmt, 30, g.lastFailure) &&
                          sqlite3_bind_int64(stmt, 31, g.nextRetryMs) == SQLITE_OK &&
                          sqlite3_bind_int(stmt, 32, g.failureCount) == SQLITE_OK &&
                          bindTextOrNull(stmt, 33, g.lastFailureCode);
                if (!ok || sqlite3_step(stmt) != SQLITE_DONE)
                {
                    const std::string detail = "sqlite guards insert failed (guard_id=" +
                                               std::to_string(g.guardId) + "): " + sqlite3_errmsg(m_db);
                    sqlite3_finalize(stmt);
                    return rollback(detail);
                }
            }
            sqlite3_finalize(stmt);
        }

        {
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(m_db, "DELETE FROM groups", -1, &stmt, nullptr) != SQLITE_OK ||
                sqlite3_step(stmt) != SQLITE_DONE)
            {
                sqlite3_finalize(stmt);
                return rollback(std::string("sqlite groups clear failed: ") + sqlite3_errmsg(m_db));
            }
            sqlite3_finalize(stmt);
        }
        if (!in.groups.empty())
        {
            const char *sql = "INSERT INTO groups(name,paused,startup_order,dependencies) VALUES(?1,?2,?3,?4)";
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
            {
                return rollback(std::string("sqlite groups insert prepare failed: ") + sqlite3_errmsg(m_db));
            }
            for (const GuardGroupState &g : in.groups)
            {
                sqlite3_reset(stmt);
                const std::string deps = depsToJson(g.dependencies);
                const bool ok = sqlite3_bind_text(stmt, 1, g.name.c_str(), static_cast<int>(g.name.size()), SQLITE_TRANSIENT) == SQLITE_OK &&
                                sqlite3_bind_int(stmt, 2, g.paused ? 1 : 0) == SQLITE_OK &&
                                sqlite3_bind_int(stmt, 3, g.startupOrder) == SQLITE_OK &&
                                sqlite3_bind_text(stmt, 4, deps.c_str(), static_cast<int>(deps.size()), SQLITE_TRANSIENT) == SQLITE_OK;
                if (!ok || sqlite3_step(stmt) != SQLITE_DONE)
                {
                    const std::string detail = "sqlite groups insert failed: " + std::string(sqlite3_errmsg(m_db));
                    sqlite3_finalize(stmt);
                    return rollback(detail);
                }
            }
            sqlite3_finalize(stmt);
        }

        {
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(m_db, "DELETE FROM restart_policy", -1, &stmt, nullptr) != SQLITE_OK ||
                sqlite3_step(stmt) != SQLITE_DONE)
            {
                sqlite3_finalize(stmt);
                return rollback(std::string("sqlite policy clear failed: ") + sqlite3_errmsg(m_db));
            }
            sqlite3_finalize(stmt);
        }
        if (!in.policy.empty())
        {
            const char *sql = "INSERT INTO restart_policy(guard_id,restart_count,recent_restart_ms) VALUES(?1,?2,?3)";
            sqlite3_stmt *stmt = nullptr;
            if (sqlite3_prepare_v2(m_db, sql, -1, &stmt, nullptr) != SQLITE_OK)
            {
                return rollback(std::string("sqlite policy insert prepare failed: ") + sqlite3_errmsg(m_db));
            }
            for (const auto &entry : in.policy)
            {
                const RestartPolicyState &p = entry.second;
                if (p.restartCount <= 0 && p.recentRestartMs.empty()) continue;
                sqlite3_reset(stmt);
                const std::string recent = recentToJson(p.recentRestartMs);
                const bool ok = sqlite3_bind_int64(stmt, 1, static_cast<sqlite3_int64>(entry.first)) == SQLITE_OK &&
                                sqlite3_bind_int(stmt, 2, p.restartCount) == SQLITE_OK &&
                                sqlite3_bind_text(stmt, 3, recent.c_str(), static_cast<int>(recent.size()), SQLITE_TRANSIENT) == SQLITE_OK;
                if (!ok || sqlite3_step(stmt) != SQLITE_DONE)
                {
                    const std::string detail = "sqlite policy insert failed: " + std::string(sqlite3_errmsg(m_db));
                    sqlite3_finalize(stmt);
                    return rollback(detail);
                }
            }
            sqlite3_finalize(stmt);
        }

        if (sqlite3_exec(m_db, "COMMIT", nullptr, nullptr, &errMsg) != SQLITE_OK)
        {
            const std::string detail = "sqlite commit failed: " + std::string(errMsg ? errMsg : sqlite3_errmsg(m_db));
            sqlite3_free(errMsg);
            sqlite3_exec(m_db, "ROLLBACK", nullptr, nullptr, nullptr);
            err = detail;
            return false;
        }
        return true;
    }
}
