/**
 * @file PGSSqliteStore.h
 * @brief SQLite-backed persistence for the PGS guard state archive (phase E).
 *
 * Replaces the hand-serialized v5 tab-separated text archive with a SQLite
 * database at the same path (pgs_guard_state.db). Benefits: transactional
 * writes (no torn snapshots), typed columns (SQL-queryable archive), and a
 * real schema instead of positional fields.
 *
 * Migration: when the service opens the state path and finds the legacy text
 * file, loadPersistedState() parses it via parseLegacyStateText(), saves the
 * snapshot through PGSStateDb, and renames the text file to
 * <name>.text-imported. SQLite databases are created at
 * PGS_SQLITE_STATE_VERSION (= the text format version they mirror, 5) and are
 * fail-closed on version mismatch.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PGS_SQLITE_STORE_H
#define PGS_SQLITE_STORE_H

#include "Process_Guard/PGS.h"

#include <cstdint>
#include <string>
#include <vector>

struct sqlite3;

namespace ProcessGuard
{
    // SQLite archives carry the same logical version as the text format they
    // replaced, so archived content stays comparable across backends.
    constexpr int PGS_SQLITE_STATE_VERSION = 5;

    // One complete state snapshot: exactly what the legacy text archive held.
    struct StateSnapshot
    {
        int version = PGS_SQLITE_STATE_VERSION;
        std::uint64_t nextGuardId = 1;
        std::string authTokenHash;
        std::uint16_t serverPort = 0;
        bool modulesPermissive = false;
        std::vector<PersistedGuardState> guards;               // sorted by guardId on save
        std::vector<GuardGroupState> groups;                   // sorted by name on save
        std::vector<std::pair<std::uint64_t, RestartPolicyState>> policy; // per guardId
    };

    // Parse a legacy v1..v5 text archive (the tab-separated format) into a
    // snapshot. Applies the historical version migrations (v1 drops the FNV-1a
    // auth hash; v2/v3/v4 keep records and upgrade defaults). Returns false on
    // a malformed record with err describing the line.
    bool parseLegacyStateText(const std::string &text, StateSnapshot &out, std::string &err);

    class PGSStateDb
    {
    public:
        PGSStateDb() = default;
        ~PGSStateDb();
        PGSStateDb(const PGSStateDb &) = delete;
        PGSStateDb &operator=(const PGSStateDb &) = delete;

        // True when the file exists and carries the SQLite magic header.
        static bool isSqliteFile(const std::string &pathUtf8);

        // Open (creating the file and schema when absent). WAL is intentionally
        // not used: the archive is a single-writer snapshot and sidecar files in
        // ProgramData\state would be surprising.
        bool open(const std::string &pathUtf8, std::string &err);
        void close();
        bool isOpen() const { return m_db != nullptr; }

        // Read the full snapshot. Fails closed on a version mismatch or a
        // malformed row so the caller never half-trusts an archive.
        bool loadAll(StateSnapshot &out, std::string &err);

        // Replace the whole archive in one transaction (DELETE + re-INSERT).
        bool saveAll(const StateSnapshot &in, std::string &err);

    private:
        bool ensureSchema(std::string &err);
        sqlite3 *m_db = nullptr;
    };
}

#endif // PGS_SQLITE_STORE_H
