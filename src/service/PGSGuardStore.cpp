#include "Process_Guard/PGS.h"

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
    // State-file format is intentionally line-oriented and append-safe to keep
    // recovery independent from third-party storage libraries. Each line is a
    // complete record so field additions can be versioned explicitly.
    std::lock_guard<std::mutex> lock(m_guardsMutex);
    m_persistedGuards.clear();

    // Parse into a local buffer first and only commit to m_persistedGuards on
    // full success. A malformed line mid-file must not leave a half-populated
    // archive (and a stale m_nextGuardId) behind for restorePersistedGuards().
    std::unordered_map<std::uint64_t, PersistedGuardState> parsedGuards;
    std::unordered_map<std::uint64_t, RestartPolicyState> parsedPolicy;
    std::unordered_map<std::string, GuardGroupState> parsedGroups;
    std::uint64_t groupCount = 0;
    std::uint64_t parsedGroupLines = 0;

    if (m_stateFilePath.empty())
    {
        return true;
    }

    std::ifstream in(m_stateFilePath, std::ios::in | std::ios::binary);
    if (!in.is_open())
    {
        m_nextGuardId = 1ull;
        return true;
    }

    int version = 0;
    std::uint64_t nextGuardId = 1;
    std::string persistedAuthHash;
    std::uint16_t archivedServerPort = 0;
    bool archivedModulesPermissive = false;
    std::string line;
    while (std::getline(in, line))
    {
        const std::string trimmed = trim(line);
        if (trimmed.empty())
        {
            continue;
        }

        const std::vector<std::string> fields = splitByChar(trimmed, '\t');
        if (fields.empty())
        {
            continue;
        }

        if (fields[0] == "VERSION")
        {
            if (fields.size() < 2)
            {
                return false;
            }
            try
            {
                version = std::stoi(fields[1]);
            }
            catch (const std::exception &)
            {
                return false;
            }
            continue;
        }

        if (fields[0] == "NEXT_GUARD_ID")
        {
            if (fields.size() < 2 || !parseUnsignedLongLong(fields[1], nextGuardId))
            {
                return false;
            }
            continue;
        }

        if (fields[0] == "AUTH_TOKEN_HASH")
        {
            if (fields.size() < 2)
            {
                return false;
            }
            persistedAuthHash = toLowerAscii(trim(fields[1]));
            continue;
        }

        if (fields[0] == "SERVER_PORT")
        {
            if (fields.size() >= 2)
            {
                DWORD sp = 0;
                if (parseDwordValue(fields[1], sp) && sp > 0)
                {
                    archivedServerPort = static_cast<std::uint16_t>(sp);
                }
            }
            continue;
        }

        if (fields[0] == "MODULES_PERMISSIVE")
        {
            if (fields.size() >= 2)
            {
                bool b = false;
                if (parseBoolFlag(fields[1], b))
                {
                    archivedModulesPermissive = b;
                }
            }
            continue;
        }

        if (fields[0] == "RESTART_COUNT")
        {
            std::uint64_t guardId = 0;
            std::uint64_t count = 0;
            if (fields.size() >= 3 &&
                parseUnsignedLongLong(fields[1], guardId) &&
                parseUnsignedLongLong(fields[2], count) &&
                guardId != 0)
            {
                auto &policy = parsedPolicy[guardId];
                policy.restartCount = static_cast<int>(std::min<std::uint64_t>(
                    count, static_cast<std::uint64_t>(std::numeric_limits<int>::max())));
            }
            continue;
        }

        if (fields[0] == "RESTART")
        {
            std::uint64_t guardId = 0;
            std::uint64_t epochMs = 0;
            if (fields.size() >= 3 &&
                parseUnsignedLongLong(fields[1], guardId) &&
                parseUnsignedLongLong(fields[2], epochMs) &&
                guardId != 0)
            {
                parsedPolicy[guardId].recentRestartMs.push_back(static_cast<std::int64_t>(epochMs));
            }
            continue;
        }

        if (fields[0] == "GROUP_COUNT")
        {
            if (fields.size() >= 2)
            {
                parseUnsignedLongLong(fields[1], groupCount);
            }
            continue;
        }

        if (fields[0] == "GROUP")
        {
            if (fields.size() < 3)
            {
                return false;
            }
            GuardGroupState group;
            group.name = sanitizeGroupName(base64Decode(fields[1]));
            if (group.name.empty())
            {
                return false;
            }
            if (!parseBoolFlag(fields[2], group.paused))
            {
                return false;
            }
            if (fields.size() > 3)
            {
                parseIntField(fields[3], group.startupOrder);
            }
            if (fields.size() > 4 && fields[4] != "-")
            {
                group.dependencies = splitCsvTrimmed(base64Decode(fields[4]));
            }
            parsedGroups[group.name] = group;
            ++parsedGroupLines;
            continue;
        }

        if (fields[0] == "GUARD")
        {
            if (fields.size() < 10)
            {
                return false;
            }

            PersistedGuardState persisted;
            if (!parseUnsignedLongLong(fields[1], persisted.guardId) ||
                !parseDwordValue(fields[2], persisted.lastKnownPid) ||
                !parseDwordValue(fields[3], persisted.sessionId))
            {
                return false;
            }

            if (!parseMaxRestarts(fields[4], persisted.maxRestarts))
            {
                return false;
            }

            persisted.path = base64Decode(fields[5]);
            persisted.restartArgs = base64Decode(fields[6]);
            persisted.fileHash = (fields[7] == "-") ? std::string() : trim(fields[7]);
            if (!parseBoolFlag(fields[8], persisted.intentional) ||
                !parseBoolFlag(fields[9], persisted.hashVerified))
            {
                return false;
            }

            // v3 advanced guard-policy fields (trailing the v2 base). Older
            // archives that stop at field[9] get the legacy defaults here.
            {
                DWORD dv = 0;
                if (fields.size() > 12 && parseDwordValue(fields[12], dv))
                {
                    persisted.restartWindowSec = static_cast<int>(dv);
                }
                if (fields.size() > 13 && parseDwordValue(fields[13], dv))
                {
                    persisted.restartDelayMs = static_cast<int>(dv);
                }
                if (fields.size() > 15 && parseDwordValue(fields[15], dv))
                {
                    persisted.hangTimeoutMs = static_cast<int>(dv);
                }
            }
            if (fields.size() > 10)
            {
                const std::string aks = trim(fields[10]);
                if (aks == "1" || aks == "winapp" || aks == "uwp" || aks == "store")
                {
                    persisted.appKind = AppKind::WinApp;
                }
            }
            if (fields.size() > 11 && fields[11] != "-")
            {
                persisted.aumid = base64Decode(fields[11]);
            }
            if (fields.size() > 14)
            {
                const std::string bv = trim(fields[14]);
                persisted.backoff = (bv == "1" || bv == "true" || bv == "yes");
            }
            if (fields.size() > 16)
            {
                const std::string bv = trim(fields[16]);
                persisted.killOnExit = (bv == "1" || bv == "true" || bv == "yes");
            }
            if (fields.size() > 17 && fields[17] != "-")
            {
                persisted.healthCheckJson = base64Decode(fields[17]);
                if (!persisted.healthCheckJson.empty() && !looksLikeJsonObjectOrArray(persisted.healthCheckJson))
                {
                    persisted.healthCheckJson.clear();
                }
            }
            if (fields.size() > 18 && fields[18] != "-")
            {
                persisted.groupName = sanitizeGroupName(base64Decode(fields[18]));
            }
            if (fields.size() > 19)
            {
                bool b = false;
                if (parseBoolFlag(fields[19], b))
                {
                    persisted.paused = b;
                }
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
                if (parseBoolFlag(fields[27], b))
                {
                    persisted.crashLoop = b;
                }
            }
            if (fields.size() > 28 && fields[28] != "-")
            {
                persisted.restartHookJson = base64Decode(fields[28]);
                if (!persisted.restartHookJson.empty() && !looksLikeJsonObjectOrArray(persisted.restartHookJson))
                {
                    persisted.restartHookJson.clear();
                }
            }
            if (fields.size() > 29)
            {
                bool b = false;
                if (parseBoolFlag(fields[29], b))
                {
                    persisted.quarantined = b;
                }
            }
            if (fields.size() > 30 && fields[30] != "-")
            {
                persisted.lastFailure = base64Decode(fields[30]);
            }
            if (fields.size() > 31) parseInt64Field(fields[31], persisted.nextRetryMs);
            if (fields.size() > 32) parseIntField(fields[32], persisted.failureCount);
            if (persisted.failureCount < 0) persisted.failureCount = 0;
            if (fields.size() > 33 && fields[33] != "-")
            {
                persisted.lastFailureCode = trim(fields[33]);
            }
            if (persisted.createdAtMs <= 0)
            {
                persisted.createdAtMs = currentEpochMs();
            }
            if (persisted.lastStartMs <= 0 && persisted.lastKnownPid != 0)
            {
                persisted.lastStartMs = persisted.createdAtMs;
            }

            if (persisted.path.empty() || persisted.guardId == 0)
            {
                return false;
            }

            parsedGuards[persisted.guardId] = persisted;
            if (persisted.guardId >= nextGuardId)
            {
                nextGuardId = persisted.guardId + 1;
            }
        }
    }

    if (version != kStateFileVersion)
    {
        // Migration: the v3 archive only ADDS trailing fields over v2, so v1 and
        // v2 are forward-compatible. v1's FNV-1a token hash is not trusted under
        // SHA-256 auth, so we drop only the auth hash (initialize() will mint a
        // fresh random token) while KEEPING guard records for SCM-restart
        // recovery. v2 already has the SHA-256 hash; its guards parsed with the
        // advanced-policy defaults above. The next persistState() rewrites at v3.
        if (version == 1)
        {
            Logger::warning("PGS: migrating state file v1 -> v3 (guard records kept, auth token reset)");
            persistedAuthHash.clear();
        }
        else if (version == kLegacyStateFileVersion || version == kAdvancedStateFileVersion || version == kPreviousStateFileVersion)
        {
            Logger::warning("PGS: migrating state file v" + std::to_string(version) + " -> v5 (guard records kept)");
        }
        else
        {
            Logger::warning("PGS: unsupported state file version " + std::to_string(version) + ", ignoring persisted archive");
            m_persistedGuards.clear();
            m_nextGuardId = 1ull;
            return false;
        }
    }
    if (!persistedAuthHash.empty() && !isSha256Hex(persistedAuthHash))
    {
        Logger::warning("PGS: persisted auth hash is invalid, generating a fresh token");
        persistedAuthHash.clear();
    }

    const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    m_policyByGuardId.clear();
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
    m_guardGroups = std::move(parsedGroups);
    m_nextGuardId = std::max<std::uint64_t>(1ull, nextGuardId);
    {
        std::lock_guard<std::mutex> authLock(m_authMutex);
        // Accept a persisted auth hash at v2/v3. An empty hash here makes
        // initialize() generate a fresh random token.
        m_authTokenHash = persistedAuthHash;
    }

    // v3: restore the archived listen port only when the host has not
    // explicitly overridden it (here: m_serverPort still at the default). The
    // module-permissive flag gates the ModuleManager allowlist (see E).
    if (!m_serverPortUserSet && m_serverPort == kServerPort && archivedServerPort != 0)
    {
        m_serverPort = archivedServerPort;
    }
    if (!m_modulesPermissiveUserSet.load())
    {
        m_modulesPermissive.store(archivedModulesPermissive);
    }

    Logger::warning("PGS: loaded persisted archive entries=" + std::to_string(m_persistedGuards.size()) +
                    ", state-file=" + m_stateFilePath);
    if (groupCount != 0 && groupCount != parsedGroupLines)
    {
        Logger::warning("PGS: persisted group count mismatch, parsed=" + std::to_string(parsedGroupLines) +
                        ", declared=" + std::to_string(groupCount));
    }
    return true;
}


void PGS::persistState()
{
    // Persist a snapshot, never a live structure. We first copy the archive
    // under lock, then write outside the lock, then atomically replace the
    // old file. That keeps the runtime hot path short and avoids half-written
    // files when the service is interrupted mid-write.
    std::lock_guard<std::mutex> persistLock(m_persistMutex);
    std::string authHash;
    {
        std::lock_guard<std::mutex> authLock(m_authMutex);
        authHash = m_authTokenHash;
    }

    std::uint64_t nextGuardId = 1;
    std::vector<PersistedGuardState> snapshot;
    std::unordered_map<std::uint64_t, RestartPolicyState> policySnapshot;
    std::vector<GuardGroupState> groupSnapshot;
    {
        std::lock_guard<std::mutex> guardsLock(m_guardsMutex);
        nextGuardId = m_nextGuardId.load();
        snapshot.reserve(m_persistedGuards.size());
        for (const auto &entry : m_persistedGuards)
        {
            snapshot.push_back(entry.second);
        }
        policySnapshot = m_policyByGuardId;
        groupSnapshot.reserve(m_guardGroups.size());
        for (const auto &entry : m_guardGroups)
        {
            groupSnapshot.push_back(entry.second);
        }
    }

    std::sort(snapshot.begin(), snapshot.end(), [](const PersistedGuardState &a, const PersistedGuardState &b) {
        return a.guardId < b.guardId;
    });
    std::sort(groupSnapshot.begin(), groupSnapshot.end(), [](const GuardGroupState &a, const GuardGroupState &b) {
        return a.name < b.name;
    });

    if (m_stateFilePath.empty())
    {
        return;
    }

    const std::filesystem::path statePath(m_stateFilePath);
    const std::filesystem::path tempPath = statePath.parent_path() / (statePath.filename().string() + ".tmp");
    std::error_code ec;
    if (!statePath.parent_path().empty())
    {
        std::filesystem::create_directories(statePath.parent_path(), ec);
    }

    std::ofstream out(tempPath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!out.is_open())
    {
        Logger::error("PGS: failed to open temp state file for write: " + tempPath.string());
        return;
    }

    out << "VERSION\t" << kStateFileVersion << "\n";
    out << "NEXT_GUARD_ID\t" << std::max<std::uint64_t>(1ull, nextGuardId) << "\n";
    out << "AUTH_TOKEN_HASH\t" << authHash << "\n";
    out << "SERVER_PORT\t" << m_serverPort << "\n";
    out << "MODULES_PERMISSIVE\t" << (m_modulesPermissive.load() ? "1" : "0") << "\n";
    out << "GROUP_COUNT\t" << groupSnapshot.size() << "\n";
    for (const auto &group : groupSnapshot)
    {
        out << "GROUP\t"
            << base64Encode(group.name) << "\t"
            << (group.paused ? "1" : "0") << "\t"
            << group.startupOrder << "\t"
            << (group.dependencies.empty() ? "-" : base64Encode(joinCsv(group.dependencies))) << "\n";
    }
    for (const auto &guard : snapshot)
    {
        out << "GUARD\t"
            << guard.guardId << "\t"
            << guard.lastKnownPid << "\t"
            << guard.sessionId << "\t"
            << maxRestartsLabel(guard.maxRestarts) << "\t"
            << base64Encode(guard.path) << "\t"
            << base64Encode(guard.restartArgs) << "\t"
            << (guard.fileHash.empty() ? "-" : guard.fileHash) << "\t"
            << (guard.intentional ? "1" : "0") << "\t"
            << (guard.hashVerified ? "1" : "0") << "\t"
            << (guard.appKind == AppKind::WinApp ? "winapp" : "win32") << "\t"
            << (guard.aumid.empty() ? "-" : base64Encode(guard.aumid)) << "\t"
            << guard.restartWindowSec << "\t"
            << guard.restartDelayMs << "\t"
            << (guard.backoff ? "1" : "0") << "\t"
            << guard.hangTimeoutMs << "\t"
            << (guard.killOnExit ? "1" : "0") << "\t"
            << (guard.healthCheckJson.empty() ? "-" : base64Encode(guard.healthCheckJson)) << "\t"
            << (guard.groupName.empty() ? "-" : base64Encode(guard.groupName)) << "\t"
            << (guard.paused ? "1" : "0") << "\t"
            << guard.createdAtMs << "\t"
            << guard.lastStartMs << "\t"
            << guard.lastExitMs << "\t"
            << guard.lastExitCode << "\t"
            << guard.cumulativeRunMs << "\t"
            << guard.restartIntervalSumMs << "\t"
            << guard.restartIntervalCount << "\t"
            << (guard.crashLoop ? "1" : "0") << "\t"
            << (guard.restartHookJson.empty() ? "-" : base64Encode(guard.restartHookJson)) << "\t"
            << (guard.quarantined ? "1" : "0") << "\t"
            << (guard.lastFailure.empty() ? "-" : base64Encode(guard.lastFailure)) << "\t"
            << guard.nextRetryMs << "\t"
            << guard.failureCount << "\t"
            << (guard.lastFailureCode.empty() ? "-" : guard.lastFailureCode) << "\n";
        const auto pit = policySnapshot.find(guard.guardId);
        if (pit != policySnapshot.end())
        {
            if (pit->second.restartCount > 0)
            {
                out << "RESTART_COUNT\t" << guard.guardId << "\t" << pit->second.restartCount << "\n";
            }
            if (guard.restartWindowSec > 0)
            {
                const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                const auto recent = util::pruneRestartWindow(
                    pit->second.recentRestartMs, nowMs, guard.restartWindowSec);
                for (const std::int64_t t : recent)
                {
                    out << "RESTART\t" << guard.guardId << "\t" << t << "\n";
                }
            }
        }
    }
    out.flush();
    out.close();

    if (!MoveFileExW(utf8ToWide(tempPath.string()).c_str(),
                     utf8ToWide(statePath.string()).c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
    {
        Logger::error("PGS: failed to replace persisted state file, error=" + std::to_string(GetLastError()));
        DeleteFileW(utf8ToWide(tempPath.string()).c_str());
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
