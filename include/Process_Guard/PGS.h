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
#include <condition_variable>
#include <cstdint>
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
        std::string fileHash;    // optional file hash (FNV-1a 64-bit hex)
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
    };

    struct RestartPolicyState
    {
        // Policy state is now tracked per guardId instead of per path. This
        // keeps restart counters isolated when multiple guarded processes share
        // the same executable image.
        int maxRestarts = -1; // -1 means unlimited
        int restartCount = 0;
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

    private:
        std::atomic<bool> m_running{false};
        std::atomic<bool> m_initialized{false};
        SOCKET m_listenSocket = INVALID_SOCKET;
        std::thread m_listenerThread;
        std::thread m_monitorThread;
        std::mutex m_guardsMutex;
        std::unordered_map<DWORD, GuardInfo> m_guards;
        std::unordered_map<std::uint64_t, RestartPolicyState> m_policyByGuardId;
        std::unordered_map<std::uint64_t, PersistedGuardState> m_persistedGuards;
        // On the stock service host this resolves under:
        //   C:\ProgramData\ProcessGuard\state\pgs_guard_state.db
        //
        // The exact path is derived from the log root so console-mode test runs
        // and installed-service runs can keep their archives separate.
        std::string m_stateFilePath;

        // The listener thread only accepts sockets and pushes them into a queue.
        // A small fixed worker pool performs recv/process/send so that a slow or
        // stalled client cannot block every other management request.
        std::mutex m_clientQueueMutex;
        std::condition_variable m_clientQueueCv;
        std::queue<SOCKET> m_clientQueue;
        std::vector<std::thread> m_clientWorkers;
        std::atomic<std::uint64_t> m_nextGuardId{1};
        // Plugin registry: loads DLLs from m_modulesDir and dispatches PG_Invoke
        // calls for the "module" / "ppl" management commands.
        ModuleManager m_modules;
        // <pgs_service.exe dir>\modules; scanned once during initialize().
        std::string m_modulesDir;

        void listenerLoop();
        void monitorLoop();
        void clientWorkerLoop();
        void handleClient(SOCKET clientSocket);

        std::string processMessage(const std::string &message);
        // "module list|load|unload|call" sub-protocol handler.
        std::string handleModuleCommand(const std::string &args);
        // "ppl set|get|clear" convenience wrapper that routes to the ppl module.
        std::string handlePplCommand(const std::string &args);
        // Resolve <pgs_service.exe dir>\modules for the plugin scan.
        static std::string moduleDirectoryOfSelf();
        std::string handleRegister(DWORD pid, const std::string &encodedPath, int maxRestarts, const std::string &restartArgs, const std::string &declaredHash);
        std::string handleIntentionalExit(DWORD pid);
        std::string handleUnregister(DWORD pid);
        std::string handleSetPolicy(DWORD pid, int maxRestarts, const std::string &restartArgs);
        std::string handleSetToken(const std::string &encodedOldToken, const std::string &encodedNewToken);
        std::string handleList();
        std::string handleGet(DWORD pid);
        bool isGuardAlive(const GuardInfo &info) const;
        bool restartGuard(const GuardInfo &info, int restartIndex, GuardInfo &newGuard);
        bool restartGuardInSession(const GuardInfo &info, int restartIndex, GuardInfo &newGuard);

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
        static bool parsePid(const std::string &value, DWORD &outPid);
        static bool parseMaxRestarts(const std::string &value, int &outMaxRestarts);
        static std::string maxRestartsLabel(int maxRestarts);
        static std::vector<std::string> splitByChar(const std::string &value, char delimiter);
        static std::string base64Encode(const std::string &input);
        static bool computeFileHash(const std::string &path, std::string &outHash);
        static bool queryProcessPath(DWORD pid, std::string &outPath);
        static std::string defaultStateFilePath(const std::string &logFilePath);
        static bool recvMessage(SOCKET socket, std::string &payload);
        static bool sendAll(SOCKET socket, const std::string &payload);
        static std::string makeGuardSummaryLine(const GuardInfo &guard, int restartCount);
        static std::string parentDirectory(const std::string &path);
        bool stripAuthEnvelope(const std::string &message, std::string &commandLine) const;
        bool createListenSocket();
        void closeListenSocket();
        void cleanupGuards();

        std::string m_authTokenHash;
        bool m_requireAuth{true};
        mutable std::mutex m_authMutex;
    };

} // namespace ProcessGuard

#endif // PGS_H
