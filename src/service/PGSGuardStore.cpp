#include "Process_Guard/PGS.h"
#include "PGSSqliteStore.h"

#include <ws2tcpip.h>
#include <winhttp.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <shellapi.h>
#include <objbase.h>
#include <initguid.h>
#include <shobjidl.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cwctype>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#endif

#include "PGSInternal.h"

namespace ProcessGuard
{
using namespace util;
using namespace pgs_internal;


std::int64_t PGS::currentEpochMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}


GuardInfo PGS::desiredGuardFromPersisted(const PersistedGuardState &persisted)
{
    GuardInfo guard{};
    guard.pid = persisted.lastKnownPid;
    guard.sessionId = persisted.sessionId;
    guard.path = persisted.path;
    guard.maxRestarts = persisted.maxRestarts;
    guard.restartArgs = persisted.restartArgs;
    guard.fileHash = persisted.fileHash;
    guard.intentional = persisted.intentional;
    guard.hashVerified = persisted.hashVerified;
    guard.guardId = persisted.guardId;
    guard.appKind = persisted.appKind;
    guard.aumid = persisted.aumid;
    guard.restartWindowSec = persisted.restartWindowSec;
    guard.restartDelayMs = persisted.restartDelayMs;
    guard.backoff = persisted.backoff;
    guard.hangTimeoutMs = persisted.hangTimeoutMs;
    guard.killOnExit = persisted.killOnExit;
    guard.healthCheckJson = persisted.healthCheckJson;
    resetHealthRuntimeState(guard);
    guard.groupName = persisted.groupName;
    guard.paused = persisted.paused;
    guard.createdAtMs = persisted.createdAtMs;
    guard.lastStartMs = persisted.lastStartMs;
    guard.lastExitMs = persisted.lastExitMs;
    guard.lastExitCode = persisted.lastExitCode;
    guard.cumulativeRunMs = persisted.cumulativeRunMs;
    guard.restartIntervalSumMs = persisted.restartIntervalSumMs;
    guard.restartIntervalCount = persisted.restartIntervalCount;
    guard.crashLoop = persisted.crashLoop;
    guard.restartHookJson = persisted.restartHookJson;
    guard.quarantined = persisted.quarantined;
    guard.lastFailureCode = persisted.lastFailureCode;
    guard.lastFailure = persisted.lastFailure;
    guard.nextRetryMs = persisted.nextRetryMs;
    guard.failureCount = persisted.failureCount;
    return guard;
}


void PGS::copyGuardToPersisted(const GuardInfo &guard, PersistedGuardState &persisted)
{
    persisted.guardId = guard.guardId;
    persisted.lastKnownPid = guard.pid;
    persisted.sessionId = guard.sessionId;
    persisted.path = guard.path;
    persisted.maxRestarts = guard.maxRestarts;
    persisted.restartArgs = guard.restartArgs;
    persisted.fileHash = guard.fileHash;
    persisted.intentional = guard.intentional;
    persisted.hashVerified = guard.hashVerified;
    persisted.appKind = guard.appKind;
    persisted.aumid = guard.aumid;
    persisted.restartWindowSec = guard.restartWindowSec;
    persisted.restartDelayMs = guard.restartDelayMs;
    persisted.backoff = guard.backoff;
    persisted.hangTimeoutMs = guard.hangTimeoutMs;
    persisted.killOnExit = guard.killOnExit;
    persisted.healthCheckJson = guard.healthCheckJson;
    persisted.groupName = guard.groupName;
    persisted.paused = guard.paused;
    persisted.createdAtMs = guard.createdAtMs;
    persisted.lastStartMs = guard.lastStartMs;
    persisted.lastExitMs = guard.lastExitMs;
    persisted.lastExitCode = guard.lastExitCode;
    persisted.cumulativeRunMs = guard.cumulativeRunMs;
    persisted.restartIntervalSumMs = guard.restartIntervalSumMs;
    persisted.restartIntervalCount = guard.restartIntervalCount;
    persisted.crashLoop = guard.crashLoop;
    persisted.restartHookJson = guard.restartHookJson;
    persisted.quarantined = guard.quarantined;
    persisted.lastFailureCode = guard.lastFailureCode;
    persisted.lastFailure = guard.lastFailure;
    persisted.nextRetryMs = guard.nextRetryMs;
    persisted.failureCount = guard.failureCount;
}


void PGS::inheritRestartProfile(GuardInfo &newGuard, const GuardInfo &oldGuard)
{
    const std::int64_t nowMs = currentEpochMs();
    newGuard.healthCheckJson = oldGuard.healthCheckJson;
    resetHealthRuntimeState(newGuard);
    newGuard.groupName = oldGuard.groupName;
    newGuard.paused = oldGuard.paused;
    newGuard.createdAtMs = oldGuard.createdAtMs > 0 ? oldGuard.createdAtMs : nowMs;
    newGuard.lastStartMs = nowMs;
    newGuard.lastExitMs = oldGuard.lastExitMs;
    newGuard.lastExitCode = oldGuard.lastExitCode;
    newGuard.cumulativeRunMs = oldGuard.cumulativeRunMs;
    newGuard.restartHookJson = oldGuard.restartHookJson;
    clearFailureState(newGuard);
    if (oldGuard.lastStartMs > 0)
    {
        newGuard.restartIntervalSumMs = oldGuard.restartIntervalSumMs + std::max<std::int64_t>(0, nowMs - oldGuard.lastStartMs);
        newGuard.restartIntervalCount = oldGuard.restartIntervalCount + 1;
    }
    else
    {
        newGuard.restartIntervalSumMs = oldGuard.restartIntervalSumMs;
        newGuard.restartIntervalCount = oldGuard.restartIntervalCount;
    }
    const std::int64_t avgMs = newGuard.restartIntervalCount > 0
        ? (newGuard.restartIntervalSumMs / newGuard.restartIntervalCount)
        : 0;
    newGuard.crashLoop = (newGuard.restartIntervalCount >= 3 && avgMs > 0 && avgMs < 60000);
}


void PGS::markGuardExitForProfile(GuardInfo &guard, DWORD exitCode, std::int64_t exitMs)
{
    guard.lastExitMs = exitMs;
    guard.lastExitCode = static_cast<int>(exitCode);
    if (guard.lastStartMs > 0 && exitMs > guard.lastStartMs)
    {
        guard.cumulativeRunMs += exitMs - guard.lastStartMs;
    }
}


std::int64_t PGS::effectiveCumulativeRunMs(const GuardInfo &guard, std::int64_t nowMs)
{
    std::int64_t total = guard.cumulativeRunMs;
    if (guard.handle && guard.lastStartMs > 0 && nowMs > guard.lastStartMs &&
        WaitForSingleObject(guard.handle, 0) == WAIT_TIMEOUT)
    {
        total += nowMs - guard.lastStartMs;
    }
    return total;
}


std::string PGS::defaultStateFilePath(const std::string &logFilePath)
{
    // The archive lives next to the host's data root rather than inside the
    // executable directory so that an installed service can survive upgrades
    // and working-directory changes. When the log root already ends in "logs",
    // we intentionally place state beside it under a sibling "state" folder.
    std::filesystem::path logPath = logFilePath.empty() ? std::filesystem::path("pgs_service.log")
                                                        : std::filesystem::path(logFilePath);
    std::filesystem::path root = logPath.parent_path();
    if (!root.empty() && root.filename() == "logs")
    {
        root = root.parent_path();
    }
    if (root.empty())
    {
        root = std::filesystem::current_path();
    }
    return (root / "state" / "pgs_guard_state.db").string();
}


bool PGS::loadPersistedState()
{
    // Two storage backends behind one snapshot: new archives are SQLite
    // (transactional, typed columns); legacy v1..v5 text archives are parsed
    // once, migrated into SQLite, and renamed aside. A malformed archive fails
    // closed instead of half-populating the runtime state.
    std::lock_guard<std::mutex> lock(m_guardsMutex);
    m_persistedGuards.clear();
    m_policyByGuardId.clear();
    m_guardGroups.clear();

    if (m_stateFilePath.empty())
    {
        return true;
    }

    StateSnapshot snap;
    PGSStateDb db;
    std::string dbErr;
    bool fromSqlite = false;
    if (PGSStateDb::isSqliteFile(m_stateFilePath))
    {
        if (!db.open(m_stateFilePath, dbErr) || !db.loadAll(snap, dbErr))
        {
            Logger::error("PGS: failed to load sqlite state archive: " + dbErr);
            m_nextGuardId = 1ull;
            return false;
        }
        fromSqlite = true;
    }
    else
    {
        std::ifstream in(m_stateFilePath, std::ios::in | std::ios::binary);
        if (!in.is_open())
        {
            m_nextGuardId = 1ull;
            return true;
        }
        std::ostringstream buffer;
        buffer << in.rdbuf();
        if (!parseLegacyStateText(buffer.str(), snap, dbErr))
        {
            Logger::error("PGS: failed to parse legacy state file: " + dbErr);
            m_nextGuardId = 1ull;
            return false;
        }
    }

    // Commit the snapshot into the runtime structures (copy, not move: the
    // snapshot is reused for the one-time text -> sqlite migration below).
    std::unordered_map<std::uint64_t, RestartPolicyState> parsedPolicy;
    for (const auto &entry : snap.policy)
    {
        parsedPolicy[entry.first] = entry.second;
    }
    std::unordered_map<std::uint64_t, PersistedGuardState> parsedGuards;
    std::uint64_t nextGuardId = std::max<std::uint64_t>(1ull, snap.nextGuardId);
    for (const PersistedGuardState &g : snap.guards)
    {
        parsedGuards[g.guardId] = g;
        if (g.guardId >= nextGuardId)
        {
            nextGuardId = g.guardId + 1;
        }
    }

    const std::int64_t nowMs = currentEpochMs();
    for (const auto &entry : parsedGuards)
    {
        RestartPolicyState policy = RestartPolicyState{entry.second.maxRestarts, 0, {}};
        auto pit = parsedPolicy.find(entry.first);
        if (pit != parsedPolicy.end())
        {
            policy = pit->second;
            policy.maxRestarts = entry.second.maxRestarts;
        }
        if (entry.second.restartWindowSec > 0)
        {
            policy.recentRestartMs = util::pruneRestartWindow(
                policy.recentRestartMs, nowMs, entry.second.restartWindowSec);
            policy.restartCount = static_cast<int>(policy.recentRestartMs.size());
        }
        else
        {
            policy.recentRestartMs.clear();
        }
        m_policyByGuardId[entry.first] = std::move(policy);
    }

    m_persistedGuards = std::move(parsedGuards);
    for (const GuardGroupState &group : snap.groups)
    {
        m_guardGroups[group.name] = group;
    }
    m_nextGuardId = nextGuardId;
    {
        std::lock_guard<std::mutex> authLock(m_authMutex);
        m_authTokenHash = snap.authTokenHash;
    }
    if (!m_serverPortUserSet && m_serverPort == kServerPort && snap.serverPort != 0)
    {
        m_serverPort = snap.serverPort;
    }
    if (!m_modulesPermissiveUserSet.load())
    {
        m_modulesPermissive.store(snap.modulesPermissive);
    }

    Logger::warning("PGS: loaded persisted archive entries=" + std::to_string(m_persistedGuards.size()) +
                    ", state-file=" + m_stateFilePath +
                    (fromSqlite ? ", backend=sqlite" : ", backend=text"));

    // One-time migration: persist the parsed legacy snapshot into SQLite and
    // retire the text file. On failure keep the text file as the source of
    // truth; the next successful persist will retry the conversion.
    if (!fromSqlite)
    {
        std::string migrateErr;
        if (db.open(m_stateFilePath, migrateErr) && db.saveAll(snap, migrateErr))
        {
            std::error_code ec;
            const std::filesystem::path textPath(m_stateFilePath);
            const std::filesystem::path retired = textPath.parent_path() /
                (textPath.filename().string() + ".text-imported");
            std::filesystem::rename(textPath, retired, ec);
            Logger::warning("PGS: migrated legacy text archive to sqlite" +
                            std::string(ec ? " (rename of old file failed: keep manually)" : ", old file renamed to .text-imported"));
        }
        else
        {
            Logger::warning("PGS: sqlite migration deferred: " + migrateErr);
        }
    }
    return true;
}

void PGS::persistState()
{
    // Persist a snapshot, never a live structure. We copy the archive under
    // lock, then write outside the guards lock through one SQLite transaction
    // (BEGIN IMMEDIATE ... COMMIT), which is atomic on disk: an interrupted
    // service leaves the previous snapshot intact instead of a torn file.
    std::lock_guard<std::mutex> persistLock(m_persistMutex);
    std::string authHash;
    {
        std::lock_guard<std::mutex> authLock(m_authMutex);
        authHash = m_authTokenHash;
    }

    StateSnapshot snapshot;
    snapshot.version = PGS_SQLITE_STATE_VERSION;
    snapshot.authTokenHash = authHash;
    snapshot.serverPort = m_serverPort;
    snapshot.modulesPermissive = m_modulesPermissive.load();
    {
        std::lock_guard<std::mutex> guardsLock(m_guardsMutex);
        snapshot.nextGuardId = m_nextGuardId.load();
        snapshot.guards.reserve(m_persistedGuards.size());
        for (const auto &entry : m_persistedGuards)
        {
            snapshot.guards.push_back(entry.second);
        }
        for (const auto &entry : m_policyByGuardId)
        {
            snapshot.policy.emplace_back(entry.first, entry.second);
        }
        for (const auto &entry : m_guardGroups)
        {
            snapshot.groups.push_back(entry.second);
        }
    }

    std::sort(snapshot.guards.begin(), snapshot.guards.end(), [](const PersistedGuardState &a, const PersistedGuardState &b) {
        return a.guardId < b.guardId;
    });
    std::sort(snapshot.groups.begin(), snapshot.groups.end(), [](const GuardGroupState &a, const GuardGroupState &b) {
        return a.name < b.name;
    });

    if (m_stateFilePath.empty())
    {
        return;
    }

    std::error_code ec;
    const std::filesystem::path statePath(m_stateFilePath);
    if (!statePath.parent_path().empty())
    {
        std::filesystem::create_directories(statePath.parent_path(), ec);
    }

    PGSStateDb db;
    std::string dbErr;
    if (!db.open(m_stateFilePath, dbErr) || !db.saveAll(snapshot, dbErr))
    {
        Logger::error("PGS: failed to persist state archive: " + dbErr);
        return;
    }
}

bool PGS::tryAttachPersistedGuard(const PersistedGuardState &persisted, GuardInfo &outGuard)
{
    // Best-case recovery path: the guarded process outlived the service crash.
    // In that case we should not restart it. Instead, verify pid -> image path
    // still matches the archived executable and then rebuild the runtime HANDLE.
    outGuard = GuardInfo{};
    if (persisted.lastKnownPid == 0)
    {
        return false;
    }

    std::string actualPath;
    if (!queryProcessPath(persisted.lastKnownPid, actualPath))
    {
        return false;
    }

    const std::string expectedPath = normalizePathForCompare(persisted.path);
    const std::string actualNormalized = normalizePathForCompare(actualPath);
    if (expectedPath.empty() || actualNormalized.empty() || expectedPath != actualNormalized)
    {
        return false;
    }

    constexpr DWORD kGuardProcessAccess =
        SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA | PROCESS_TERMINATE;
    HANDLE processHandle = OpenProcess(kGuardProcessAccess, FALSE, persisted.lastKnownPid);
    if (!processHandle)
    {
        processHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, persisted.lastKnownPid);
    }
    if (!processHandle)
    {
        return false;
    }

    DWORD sessionId = 0xFFFFFFFF;
    ProcessIdToSessionId(persisted.lastKnownPid, &sessionId);
    outGuard = desiredGuardFromPersisted(persisted);
    outGuard.pid = persisted.lastKnownPid;
    outGuard.sessionId = sessionId;
    outGuard.path = actualPath;
    outGuard.handle = processHandle;
    outGuard.jobHandle = nullptr;
    if (outGuard.createdAtMs <= 0)
    {
        outGuard.createdAtMs = currentEpochMs();
    }
    if (outGuard.lastStartMs <= 0)
    {
        outGuard.lastStartMs = outGuard.createdAtMs;
    }
    // v3: reopen (or create) the survivor's per-guard Job so monitoring of the
    // whole process family resumes after a service crash.
    assignGuardToJob(outGuard);
    return true;
}


bool PGS::restorePersistedGuards()
{
    // Restore desired-state before the listener/monitor threads start so the
    // service comes up with a coherent guard table instead of briefly exposing
    // an empty world and then mutating under concurrent client traffic.
    //
    // Recovery policy:
    // - if archived pid is still alive and path still matches, reattach
    // - if the guard had already been marked intentional, drop it from archive
    // - otherwise treat the archive as desired-state and relaunch it
    std::vector<PersistedGuardState> snapshot;
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        snapshot.reserve(m_persistedGuards.size());
        for (const auto &entry : m_persistedGuards)
        {
            snapshot.push_back(entry.second);
        }
    }

    bool allRestored = true;
    bool changed = false;
    for (const auto &persisted : snapshot)
    {
        GuardInfo restored;
        if (persisted.quarantined)
        {
            Logger::warning("PGS: persisted guard remains quarantined during restore, guard-id=" +
                            std::to_string(persisted.guardId));
            recordEvent("guard.restore-quarantine",
                        "guard_id=" + std::to_string(persisted.guardId) +
                        ";path=" + persisted.path +
                        ";reason_b64=" + base64Encode(persisted.lastFailure));
            continue;
        }
        if (tryAttachPersistedGuard(persisted, restored))
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            m_guards[restored.pid] = restored;
            clearFailureState(m_guards[restored.pid]);
            auto &policy = m_policyByGuardId[restored.guardId];
            policy.maxRestarts = persisted.maxRestarts;
            auto it = m_persistedGuards.find(restored.guardId);
            if (it != m_persistedGuards.end())
            {
                copyGuardToPersisted(restored, it->second);
            }
            Logger::warning("PGS: restored persisted live guard pid=" + std::to_string(restored.pid) +
                            ", guard-id=" + std::to_string(restored.guardId));
            recordEvent("guard.restore-attach",
                        "pid=" + std::to_string(restored.pid) +
                        ";guard_id=" + std::to_string(restored.guardId) +
                        ";path=" + restored.path);
            changed = true;
            continue;
        }

        if (persisted.intentional)
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            m_persistedGuards.erase(persisted.guardId);
            Logger::warning("PGS: dropped persisted intentional guard guard-id=" + std::to_string(persisted.guardId));
            changed = true;
            continue;
        }

        GuardInfo desired = desiredGuardFromPersisted(persisted);
        desired.pid = 0;
        desired.handle = nullptr;
        desired.jobHandle = nullptr;
        desired.intentional = false;

        bool restorePaused = desired.paused;
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            const auto git = desired.groupName.empty() ? m_guardGroups.end() : m_guardGroups.find(desired.groupName);
            restorePaused = restorePaused || (git != m_guardGroups.end() && git->second.paused);
            if (restorePaused)
            {
                auto &stored = m_persistedGuards[desired.guardId];
                stored = persisted;
                stored.lastKnownPid = 0;
                stored.intentional = false;
            }
        }
        if (restorePaused)
        {
            Logger::warning("PGS: persisted missing guard kept paused during restore, guard-id=" +
                            std::to_string(persisted.guardId));
            recordEvent("guard.restore-paused",
                        "guard_id=" + std::to_string(persisted.guardId) +
                        ";path=" + persisted.path);
            changed = true;
            continue;
        }

        bool shouldRestart = true;
        int restartIndex = 1;
        const bool windowed = (persisted.restartWindowSec > 0);
        const bool restartAlreadyRecorded = (persisted.lastKnownPid == 0 && persisted.restartDelayMs > 0);
        int currentRestarts = 0;
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto &policy = m_policyByGuardId[persisted.guardId];
            policy.maxRestarts = persisted.maxRestarts;
            if (windowed)
            {
                const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                policy.recentRestartMs = util::pruneRestartWindow(policy.recentRestartMs, nowMs, persisted.restartWindowSec);
                policy.restartCount = static_cast<int>(policy.recentRestartMs.size());
                currentRestarts = policy.restartCount;
            }
            else
            {
                currentRestarts = policy.restartCount;
            }

            if (restartAlreadyRecorded)
            {
                // A delayed/backoff restart records budget before it enters the
                // pending queue and persists lastKnownPid=0. If PGS is stopped
                // during that delay, restore must complete the already-counted
                // relaunch instead of charging the budget a second time.
                shouldRestart = !(policy.maxRestarts >= 0 && currentRestarts > policy.maxRestarts);
                if (shouldRestart)
                {
                    restartIndex = currentRestarts > 0 ? currentRestarts
                                                       : recordRestartAndEffectiveCount(persisted.guardId, policy, persisted.restartWindowSec);
                }
            }
            else
            {
                shouldRestart = !(policy.maxRestarts >= 0 && currentRestarts >= policy.maxRestarts);
                if (shouldRestart)
                {
                    restartIndex = recordRestartAndEffectiveCount(persisted.guardId, policy, persisted.restartWindowSec);
                }
            }
        }

        if (!shouldRestart)
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto it = m_persistedGuards.find(persisted.guardId);
            if (it != m_persistedGuards.end())
            {
                markGuardQuarantined(it->second, "restart.limit", "restart limit reached during restore", currentEpochMs());
                it->second.lastKnownPid = 0;
            }
            Logger::warning("PGS: persisted guard restart limit reached during restore, guard-id=" +
                            std::to_string(persisted.guardId) +
                            ", max=" + maxRestartsLabel(persisted.maxRestarts) +
                            (windowed ? " (sliding window)" : ""));
            recordEvent("guard.restore-limit",
                        "guard_id=" + std::to_string(persisted.guardId) +
                        ";path=" + persisted.path +
                        ";max=" + maxRestartsLabel(persisted.maxRestarts));
            changed = true;
            continue;
        }

        GuardInfo restarted;
        std::string failureCode;
        std::string failureMessage;
        if (restartGuard(desired, restartIndex, restarted, failureCode, failureMessage))
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            m_guards[restarted.pid] = restarted;
            // v3: assign the freshly restarted process to its per-guard Job.
            assignGuardToJob(m_guards[restarted.pid]);
            auto &policy = m_policyByGuardId[restarted.guardId];
            policy.maxRestarts = persisted.maxRestarts;
            auto &stored = m_persistedGuards[restarted.guardId];
            copyGuardToPersisted(restarted, stored);
            stored.intentional = false;
            Logger::warning("PGS: restored persisted missing guard by restart pid=" + std::to_string(restarted.pid) +
                            ", guard-id=" + std::to_string(restarted.guardId));
            recordEvent("guard.restore-restart",
                        "pid=" + std::to_string(restarted.pid) +
                        ";guard_id=" + std::to_string(restarted.guardId) +
                        ";path=" + restarted.path);
            changed = true;
            continue;
        }

        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto it = m_persistedGuards.find(persisted.guardId);
            if (it != m_persistedGuards.end())
            {
                markGuardQuarantined(it->second, failureCode.empty() ? "restart.restore_failed" : failureCode,
                                     failureMessage.empty() ? "restore restart failed" : failureMessage, currentEpochMs());
                it->second.lastKnownPid = 0;
            }
        }
        Logger::error("PGS: failed to restore persisted guard guard-id=" + std::to_string(persisted.guardId) +
                      ", guard quarantined path=" + persisted.path);
        recordEvent("guard.restore-failed",
                    "guard_id=" + std::to_string(persisted.guardId) +
                    ";path=" + persisted.path);
        allRestored = false;
        changed = true;
    }

    if (changed)
    {
        persistState();
    }
    return allRestored;
}


} // namespace ProcessGuard
