/**
 * @file PGS.h
 * @brief ProcessGuard Service core (C++17)
 */

#ifndef PGS_H
#define PGS_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "PGDefines.h"
#include "PGLogger.h"
#include "ModuleManager.h"
#include "PGUtil.h"
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <queue>
#include <thread>
#include <vector>

namespace ProcessGuard
{

    struct GuardInfo
    {
        DWORD pid = 0;
        DWORD sessionId = 0xFFFFFFFF;
        std::string path;
        int maxRestarts = -1;    // -1 means unlimited
        std::string restartArgs; // arguments used when PGS restarts this guard
        std::string fileHash;    // optional file hash (SHA-256 hex via CNG).
                                 // Note: an earlier comment here claimed FNV-1a
                                 // 64-bit; that was stale — the implementation in
                                 // PGUtil::sha256FileHex has always been SHA-256.
        HANDLE handle = nullptr;
        bool intentional = false;
        bool hashVerified = false;

        // Stable guard identity independent from pid/path.
        //
        // Why this exists:
        // - pid changes after every restart
        // - path is not a safe policy key when multiple instances of the same
        //   executable are guarded at the same time
        //
        // The guardId allows restart counters and policies to stay attached to a
        // single logical guard object across pid changes without leaking into
        // sibling processes that happen to share the same executable path.
        std::uint64_t guardId = 0;

        // v3 hardening: launch kind + advanced restart policy, all defaulting to
        // the legacy behaviour so that v2 archives and old clients keep working.
        //
        // appKind        : Win32 -> CreateProcess*; WinApp -> AUMID activation
        // aumid          : only meaningful for WinApp guards
        // restartWindowSec : 0 = lifetime restart count (legacy); >0 = sliding
        //                  window in which maxRestarts is enforced (self-heals)
        // restartDelayMs : delay before relaunch (0 = immediate)
        // backoff        : when true, delay doubles per restart (cap kMaxBackoffMs)
        // hangTimeoutMs  : >0 enables GUI hang detection (IsHungAppWindow probe)
        // killOnExit     : open JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE so the whole
        //                  process family dies when PGS exits (default off, so a
        //                  crashed PGS leaves guards alive for re-attach)
        // jobHandle      : per-guard Job Object used for cascade observation and
        //                  TerminateJobObject("restart clears the whole family")
        AppKind appKind = AppKind::Win32;
        std::string aumid;
        int restartWindowSec = 0;
        int restartDelayMs = 0;
        bool backoff = false;
        int hangTimeoutMs = 0;
        bool killOnExit = false;
        HANDLE jobHandle = nullptr;

        // Phase 8 guard metadata. These fields are deliberately data-only:
        // health checks and restart hooks are stored/validated by the core,
        // while execution remains opt-in via trusted modules/future runners.
        std::string healthCheckJson;
        std::string healthStatus = "disabled";
        std::string healthLastMessage;
        std::int64_t healthLastCheckMs = 0;
        std::int64_t healthLastOkMs = 0;
        std::int64_t healthLastFailureMs = 0;
        std::int64_t healthNextCheckMs = 0;
        int healthFailureCount = 0;
        std::string groupName;
        bool paused = false;
        std::int64_t createdAtMs = 0;
        std::int64_t lastStartMs = 0;
        std::int64_t lastExitMs = 0;
        int lastExitCode = 0;
        std::int64_t cumulativeRunMs = 0;
        std::int64_t restartIntervalSumMs = 0;
        int restartIntervalCount = 0;
        bool crashLoop = false;
        std::string restartHookJson;
        bool quarantined = false;
        std::string lastFailureCode;
        std::string lastFailure;
        std::int64_t nextRetryMs = 0;
        int failureCount = 0;
    };

    struct GuardGroupState
    {
        std::string name;
        bool paused = false;
        int startupOrder = 0;
        std::vector<std::string> dependencies;
    };

    struct RestartPolicyState
    {
        // Policy state is now tracked per guardId instead of per path. This
        // keeps restart counters isolated when multiple guarded processes share
        // the same executable image.
        int maxRestarts = -1; // -1 means unlimited
        int restartCount = 0;
        // Epoch-millis timestamps of recent relaunches. Pruned to
        // restartWindowSec by pruneRecentRestarts(); when window==0 this vector
        // is unused and restartCount is the authoritative lifetime counter
        // (exactly the legacy behaviour).
        std::vector<std::int64_t> recentRestartMs;
    };

    struct PersistedGuardState
    {
        // Durable desired-state record for one logical guard object.
        //
        // Unlike GuardInfo, this record is not tied to a live HANDLE. It exists
        // so PGS can be restarted by SCM, read its archive, and reconstruct the
        // guard set even after its own process memory was lost.
        std::uint64_t guardId = 0;
        DWORD lastKnownPid = 0;
        DWORD sessionId = 0xFFFFFFFF;
        std::string path;
        int maxRestarts = -1;
        std::string restartArgs;
        std::string fileHash;
        bool intentional = false;
        bool hashVerified = false;

        // v3 durable mirror of GuardInfo advanced fields (see GuardInfo docs).
        AppKind appKind = AppKind::Win32;
        std::string aumid;
        int restartWindowSec = 0;
        int restartDelayMs = 0;
        bool backoff = false;
        int hangTimeoutMs = 0;
        bool killOnExit = false;
        std::string healthCheckJson;
        std::string groupName;
        bool paused = false;
        std::int64_t createdAtMs = 0;
        std::int64_t lastStartMs = 0;
        std::int64_t lastExitMs = 0;
        int lastExitCode = 0;
        std::int64_t cumulativeRunMs = 0;
        std::int64_t restartIntervalSumMs = 0;
        int restartIntervalCount = 0;
        bool crashLoop = false;
        std::string restartHookJson;
        bool quarantined = false;
        std::string lastFailureCode;
        std::string lastFailure;
        std::int64_t nextRetryMs = 0;
        int failureCount = 0;
    };

    class PGS
    {
    public:
        // PGS is the in-process service core. It owns:
        // - the local TCP management endpoint
        // - the active guard table
        // - the monitor thread that detects exits
        // - the restart policy state that survives pid changes
        //
        // The surrounding executable (`pgs_service`) is only a lifecycle host.
        // All guard behavior lives here so console mode and SCM mode share the
        // exact same protection logic.
        PGS();
        ~PGS();

        PGS(const PGS &) = delete;
        PGS &operator=(const PGS &) = delete;
        PGS(PGS &&) = delete;
        PGS &operator=(PGS &&) = delete;

        bool initialize(const std::string &logFilePath = "pgs_service.log", const std::string &authTokenHash = "");
        bool start();
        void stop();
        bool isRunning() const;
        // Compatibility opt-in toggle for PPL/module loading (default off).
        // New code should use setModulesEnabled()/setKernelModulesEnabled().
        void setPplEnabled(bool enabled) { m_pplEnabled = enabled; if (enabled) m_modulesEnabled = true; }
        void setModulesEnabled(bool enabled) { m_modulesEnabled = enabled; }
        void setKernelModulesEnabled(bool enabled) { m_kernelModulesEnabled = enabled; if (enabled) m_modulesEnabled = true; }
        // Override the listen port (default kServerPort); must be set before
        // initialize()/start(). Honoured by createListenSocket().
        void setServerPort(std::uint16_t port) { m_serverPort = port ? port : kServerPort; m_serverPortUserSet = true; }
        bool isModulesPermissive() const { return m_modulesPermissive.load(); }
        void setModulesPermissive(bool v) { m_modulesPermissive.store(v); m_modulesPermissiveUserSet.store(true); }

        static constexpr const char *kServerIp = "127.0.0.1";
        static constexpr uint16_t kServerPort = 12345;
        static constexpr DWORD kMonitorIntervalMs = 200;
        static constexpr int kBufferSize = 4096;
        // Conservative upper bound for one line-oriented management message.
        // The goal is not to support arbitrary payloads, but to avoid silent
        // truncation while still rejecting abusive or malformed requests.
        static constexpr std::size_t kMaxMessageSize = 64 * 1024;
        // Socket timeouts keep one broken client from pinning a worker forever.
        static constexpr DWORD kSocketTimeoutMs = 3000;
        // Small fixed-size worker pool because request traffic is low-volume and
        // command-oriented; dynamic thread-per-connection would be unnecessary.
        static constexpr std::size_t kClientWorkerCount = 4;
        static constexpr std::size_t kMaxClientQueueSize = 64;
        static constexpr std::size_t kMaxEventHistory = 512;
        static constexpr int kDefaultMaxRestarts = 3;
        // v3 policy defaults (all preserve legacy behaviour when untouched).
        static constexpr int kDefaultRestartWindowSec = 0; // 0 = lifetime count
        static constexpr int kDefaultRestartDelayMs = 0;
        static constexpr int kDefaultHangTimeoutMs = 0;
        static constexpr int kMaxHangTimeoutMs = 60000;
        static constexpr int kMaxBackoffMs = 60000; // backoff cap

        enum class RecvResult { Ok, Closed, Error, TooLarge };
    private:
        struct GuardPolicyPatch
        {
            bool hasRestartWindowSec = false;
            int restartWindowSec = 0;
            bool hasRestartDelayMs = false;
            int restartDelayMs = 0;
            bool hasBackoff = false;
            bool backoff = false;
            bool hasHangTimeoutMs = false;
            int hangTimeoutMs = 0;
            bool hasKillOnExit = false;
            bool killOnExit = false;
            bool hasAppKind = false;
            AppKind appKind = AppKind::Win32;
            bool hasAumid = false;
            std::string aumid;
        };

        bool m_initialized = false;
        std::atomic<bool> m_running{false};
        std::thread m_listenerThread;
        std::thread m_monitorThread;
        std::thread m_healthThread;
        std::thread m_notifyThread;

        SOCKET m_listenSocket = INVALID_SOCKET;

        std::mutex m_guardsMutex;
        // key by pid so the monitor can O(1) the live entry for a guard that
        // reports a new pid on restart.
        std::unordered_map<DWORD, GuardInfo> m_guards;
        std::unordered_map<std::uint64_t, RestartPolicyState> m_policyByGuardId;
        // Durable desired-state archive: what should still be guarded after the
        // service host is restarted by the SCM. Independent from live handles.
        std::unordered_map<std::uint64_t, PersistedGuardState> m_persistedGuards;
        std::unordered_map<std::string, GuardGroupState> m_guardGroups;
        std::atomic<std::uint64_t> m_nextGuardId{1};

    public:

        struct OperationRecord
        {
            std::string id;
            std::string module;
            std::string method;
            std::string status;
            int progress = -1;
            std::string message;
            std::string resultJson;
            std::string errorCode;
            std::string errorMessage;
            std::vector<std::string> artifactIds;
            std::int64_t createdMs = 0;
            std::int64_t updatedMs = 0;
            std::int64_t expiresMs = 0;
            std::string traceId;
            std::string caller;
        };

        struct ArtifactRecord
        {
            std::string id;
            std::string module;
            std::string method;
            std::string contentType;
            std::string filename;
            std::uint64_t size = 0;
            std::string sha256;
            std::int64_t createdMs = 0;
            std::int64_t expiresMs = 0;
            std::string traceId;
            std::string operationId;
            bool sensitive = false;
            std::string sensitivity;
            std::string storageHash;
            bool storageHashVerified = false;
        };

        struct ArtifactCleanupResult
        {
            std::size_t removed = 0;
            std::uint64_t reclaimedBytes = 0;
            std::size_t verified = 0;
            std::size_t corruptRemoved = 0;
            std::size_t sensitiveRemoved = 0;
        };

        struct ArtifactStoreStatus
        {
            bool storeExists = false;
            bool rootSecured = false;
            std::size_t count = 0;
            std::uint64_t totalBytes = 0;
            std::size_t expired = 0;
            std::size_t corrupt = 0;
            std::size_t orphaned = 0;
            std::size_t verified = 0;
            std::size_t sensitive = 0;
        };

    private:

        std::mutex m_operationMutex;
        std::unordered_map<std::string, OperationRecord> m_operations;
        mutable std::mutex m_artifactMutex;
        std::unordered_map<std::string, ArtifactRecord> m_artifacts;
        std::int64_t m_artifactRetentionTtlMs = 24LL * 60LL * 60LL * 1000LL;
        bool m_artifactAutoCleanup = true;
        bool m_artifactVerifyOnStatus = false;
        std::int64_t m_lastArtifactMaintenanceMs = 0;
        ArtifactCleanupResult cleanupArtifactsLocked(bool removeExpired, bool removeAll, bool verifyContentHash, std::string &detail);
        ArtifactStoreStatus artifactStoreStatusLocked(bool verifyContentHash, std::string &detail);
        void runArtifactMaintenanceIfDue(std::int64_t nowMs);
        void loadArtifactPolicyLocked();
        bool saveArtifactPolicyLocked(std::string &error) const;
        std::string artifactPolicySummaryLocked() const;

        // Modules: loaded DLL plugins discovered under m_modulesDir.
        ModuleManager m_modules;
        std::string m_modulesDir;
        bool m_pplEnabled{false}; // legacy alias for kernel/PPL module opt-in
        bool m_modulesEnabled{false};
        bool m_kernelModulesEnabled{false};
        // When false (default), ModuleManager refuses any DLL not listed in
        // <exe>\modules\modules.allow. When true, the legacy permissive load-all
        // behaviour is restored for development. Persisted as MODULES_PERMISSIVE.
        std::atomic<bool> m_modulesPermissive{false};
        // True once the host has explicitly chosen permissive mode, so that a
        // later loadPersistedState() does NOT silently override the operator choice.
        std::atomic<bool> m_modulesPermissiveUserSet{false};

        // Persisted/restored listen port. Defaults to kServerPort; install/run
        // can override via --port; loadPersistedState() may restore an archived
        // SERVER_PORT so a reinstalled service remembers its port.
        std::uint16_t m_serverPort{kServerPort};
        bool m_serverPortUserSet{false};

        // Service uptime baseline for the stats command.
        std::chrono::steady_clock::time_point m_startTime{std::chrono::steady_clock::now()};

        // Per-guard Job Objects (full cascade observation). guardId -> HANDLE.
        // A job is created when a guard is (re)launched and assigns the process;
        // child/grandchild processes stay in the job (breakaway disabled) so
        // restart can TerminateJobObject the whole family, and so a surviving
        // job can be reopened and re-attached after a PGS crash.
        std::mutex m_jobMutex;
        std::unordered_map<std::uint64_t, HANDLE> m_jobs;
        // Single IOCP shared by all guard jobs; the monitor thread pumps it.
        HANDLE m_ioPort = nullptr;

        // The persisted archive path. Derived from the host log root so console-
        // mode test runs and installed-service runs keep their archives separate.
        std::string m_stateFilePath;
        // Serializes persistState() writes. Multiple client workers and the
        // monitor thread can all decide to persist near-simultaneously; without
        // a dedicated write lock they would share the same .tmp path.
        std::mutex m_persistMutex;

        // The listener thread only accepts sockets and pushes them into a queue.
        // A small fixed worker pool performs recv/process/send so that a slow or
        // stalled client cannot block every other management request.
        std::mutex m_clientQueueMutex;
        std::condition_variable m_clientQueueCv;
        std::queue<SOCKET> m_clientQueue;
        std::vector<std::thread> m_clientWorkers;
        std::mutex m_healthMutex;
        std::condition_variable m_healthCv;
        std::mutex m_notifyMutex;
        std::condition_variable m_notifyCv;
        std::queue<std::pair<std::string, std::string>> m_notifyQueue;

        std::mutex m_eventsMutex;
        std::deque<std::string> m_events;
        std::atomic<std::uint64_t> m_nextEventId{1};

        void listenerLoop();
        void monitorLoop();
        void healthLoop();
        void notifyLoop();
        void clientWorkerLoop();
        void handleClient(SOCKET clientSocket);

        std::string processMessage(const std::string &message);
        // Dispatch a command after authentication has already been handled.
        // TCP clients must go through processMessage(); ABI v2 module callbacks
        // use this path so they do not need to know the operator token.
        std::string dispatchCommandLine(const std::string &commandLine);
        // "module list|load|unload|call|invoke" sub-protocol handler.
        std::string handleModuleCommand(const std::string &args);
        std::string handleModulePermissiveCommand(const std::string &rest);
        std::string handleModuleInstallCommand(const std::string &rest);
        std::string handleModuleRollbackCommand(const std::string &rest);
        std::string handleCoreJsonRpc(const std::string &requestJson);
        std::string handleArtifactChunkCommand(const std::string &args);
        std::string handleArtifactCleanupCommand(const std::string &args);
        std::string handleArtifactStatusCommand(const std::string &args);
        std::string handleArtifactPolicyCommand(const std::string &args);
        // "ppl set|get|clear" convenience wrapper that routes to the ppl module.
        std::string handlePplCommand(const std::string &args);
        // Phase 8 guard metadata and batch-control commands.
        std::string handleHealthCheckCommand(const std::string &args);
        std::string handleGroupCommand(const std::string &args);
        std::string handleGuardCommand(const std::string &args);
        std::string handleRestartHookCommand(const std::string &args);
        // "events list [limit]" returns a bounded in-memory action timeline.
        std::string handleEventsCommand(const std::string &args);
        void recordEvent(const std::string &type, const std::string &detail);
        // Resolve <pgs_service.exe dir>\modules for the plugin scan.
        static std::string moduleDirectoryOfSelf();
        // ABI v2 thunks: let modules call back into PGS via PGS_Services.
        // callThunk routes a trusted in-process command to dispatchCommandLine;
        // nowMsThunk returns epoch millis for schedule arithmetic.
        static int callThunk(void *context, const char *request, char *response, size_t responseSize);
        static int callJsonThunk(void *context, const char *requestJson, char *responseJson, size_t responseSize);
        static int emitEventThunk(void *context, const char *eventJson);
        static const char *getDataDirThunk(void *context);
        static void logThunk(void *context, int level, const char *message);
        static long long nowMsThunk(void *context);
        bool isPathInsideModulesDir(const std::string &candidateUtf8) const;
        bool writeInitialTokenFile(const std::string &stateDir, const std::string &token) const;
        // v3: handleRegister also accepts the advanced guard-policy fields
        // (appKind/aumid/restartWindow/restartDelay/backoff/hang/killOnExit).
        // Callers that do not supply them get the legacy defaults.
        std::string handleRegister(DWORD pid, const std::string &encodedPath, int maxRestarts,
                                  const std::string &restartArgs, const std::string &declaredHash,
                                  AppKind appKind, const std::string &aumid,
                                  int restartWindowSec, int restartDelayMs, bool backoff,
                                  int hangTimeoutMs, bool killOnExit);
        std::string handleIntentionalExit(DWORD pid);
        std::string handleUnregister(DWORD pid);
        std::string handleSetPolicy(DWORD pid, int maxRestarts, const std::string &restartArgs,
                                    const GuardPolicyPatch &patch);
        std::string handleSetToken(const std::string &encodedOldToken, const std::string &encodedNewToken);
        std::string handleList();
        std::string handleGet(DWORD pid);
        bool isGuardAlive(const GuardInfo &info) const;
        bool restartGuard(const GuardInfo &info, int restartIndex, GuardInfo &newGuard, std::string &failureCode, std::string &failureMessage);
        bool restartGuardInSession(const GuardInfo &info, int restartIndex, GuardInfo &newGuard, std::string &failureCode, std::string &failureMessage);
        // Restart a WindowsApps (UWP/Store) guard via AUMID activation.
        bool restartAppGuard(const GuardInfo &info, int restartIndex, GuardInfo &newGuard, std::string &failureCode, std::string &failureMessage);

        // ---- Job Object helpers (full cascade, IOCP-driven monitoring) ----
        // Create a named job Global\PGS-Job-<guardId>, bind its completion port
        // to m_ioPort, and apply killOnExit. Returns the job HANDLE on success.
        bool createGuardJob(std::uint64_t guardId, bool killOnExit, HANDLE &outJob);
        // Create (if absent) the per-guard Job Object bound to m_ioPort and assign
        // the live guard process to it. Sets guard.jobHandle. On failure logs and
        // leaves jobHandle null (monitor still works via poll + family terminate).
        bool assignGuardToJob(GuardInfo &guard);
        // Reopen a survivor job after a PGS restart so the still-running guard
        // (and its family) are observed again. Returns false if the job is gone.
        bool attachGuardJob(std::uint64_t guardId, HANDLE &outJob);
        // Terminate every process in a guard's job (the whole family), used by
        // restart / unregister / intentional to "clear the field" before relaunch.
        void terminateGuardFamily(std::uint64_t guardId);
        // Close + forget a guard's job handle.
        void closeGuardJob(std::uint64_t guardId, bool preserveProcesses = false);
        bool setGuardJobKillOnExit(std::uint64_t guardId, bool killOnExit);

        // GUI hang probe: returns true if the guard's main window is unresponsive.
        bool isGuardHung(const GuardInfo &info) const;

        // Persistence / recovery pipeline:
        // - loadPersistedState(): read the durable desired-state archive from disk
        // - restorePersistedGuards(): rebuild runtime guards from that archive
        // - tryAttachPersistedGuard(): reconnect to a still-running pid when possible
        // - persistState(): write the latest desired-state snapshot back to disk
        //
        // We intentionally persist "what should still be guarded" instead of only
        // transient runtime counters. That lets SCM restart the service and have
        // PGS continue protecting the same logical guard set.
        bool loadPersistedState();
        bool restorePersistedGuards();
        bool tryAttachPersistedGuard(const PersistedGuardState &persisted, GuardInfo &outGuard);
        void persistState();
        static std::int64_t currentEpochMs();
        static GuardInfo desiredGuardFromPersisted(const PersistedGuardState &persisted);
        static void copyGuardToPersisted(const GuardInfo &guard, PersistedGuardState &persisted);
        static void inheritRestartProfile(GuardInfo &newGuard, const GuardInfo &oldGuard);
        static void markGuardExitForProfile(GuardInfo &guard, DWORD exitCode, std::int64_t exitMs);
        static std::int64_t effectiveCumulativeRunMs(const GuardInfo &guard, std::int64_t nowMs);
        static bool parsePid(const std::string &value, DWORD &outPid);
        static bool parseMaxRestarts(const std::string &value, int &outMaxRestarts);
        static std::string maxRestartsLabel(int maxRestarts);
        static std::vector<std::string> splitByChar(const std::string &value, char delimiter);
        static std::string base64Encode(const std::string &input);
        static bool computeFileHash(const std::string &path, std::string &outHash);
        static bool queryProcessPath(DWORD pid, std::string &outPath);
        static std::string defaultStateFilePath(const std::string &logFilePath);
        static RecvResult recvMessage(SOCKET socket, std::string &payload);
        static bool sendAll(SOCKET socket, const std::string &payload);
        static std::string makeGuardSummaryLine(const GuardInfo &guard, int restartCount, bool groupPaused = false);
        static std::string makePersistedGuardSummaryLine(const PersistedGuardState &guard, int restartCount, bool groupPaused = false);
        static void clearFailureState(GuardInfo &guard);
        static void clearFailureState(PersistedGuardState &guard);
        static void resetHealthRuntimeState(GuardInfo &guard);
        static bool validateHealthCheckConfig(const std::string &configJson, std::string &error);
        static void markGuardQuarantined(PersistedGuardState &guard, const std::string &code, const std::string &reason, std::int64_t nowMs);
        void quarantineGuardLocked(const GuardInfo &guard, const std::string &code, const std::string &reason);
        std::string retryQuarantinedGuard(std::uint64_t guardId);
        std::string clearQuarantinedGuard(std::uint64_t guardId);
        static std::string parentDirectory(const std::string &path);
        static std::string maxRestartsLabelFor(int maxRestarts) { return maxRestartsLabel(maxRestarts); }
        bool stripAuthEnvelope(const std::string &message, std::string &commandLine) const;
        bool createListenSocket();
        void closeListenSocket();
        void cleanupGuards();
        // Record a restart timestamp and prune to the guard's window; returns the
        // effective (post-prune) restart count to compare against maxRestarts.
        int recordRestartAndEffectiveCount(std::uint64_t guardId, RestartPolicyState &policy, int windowSec);

        std::string m_authTokenHash;
        bool m_requireAuth{true};
        mutable std::mutex m_authMutex;
    };

} // namespace ProcessGuard

#endif // PGS_H
