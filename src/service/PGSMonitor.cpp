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


void PGS::monitorLoop()
{
    // monitorLoop owns the "watch / decide / restart / cleanup" cycle:
    // 1. fire deferred (backoff/delay) restarts whose delay has elapsed
    // 2. drain the shared IOCP so process/family exits wake us within ~50ms
    //    (IOCP is the fast wake path; the handle poll below is the backstop)
    // 3. scan the live guard map for dead handles (+ optional GUI hang probe)
    // 4. for newly-dead guards, decide restart under sliding-window policy
    // 5. either relaunch+reattach (and reassign its per-guard Job) or retire
    //
    // All restart/create work runs outside m_guardsMutex so a slow CreateProcess
    // cannot block list/get/register requests.
    struct PendingRestart
    {
        GuardInfo guard;
        int restartIndex;
        std::chrono::steady_clock::time_point readyAt;
    };
    std::vector<PendingRestart> pending;

    while (m_running.load())
    {
        const auto now = std::chrono::steady_clock::now();

        // Fire deferred restarts whose backoff/delay has elapsed.
        for (auto pit = pending.begin(); pit != pending.end();)
        {
            if (pit->readyAt > now)
            {
                ++pit;
                continue;
            }
            GuardInfo restarted;
            std::string failureCode;
            std::string failureMessage;
            if (restartGuard(pit->guard, pit->restartIndex, restarted, failureCode, failureMessage))
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    auto existingNew = m_guards.find(restarted.pid);
                    if (existingNew != m_guards.end() && existingNew->second.handle)
                    {
                        CloseHandle(existingNew->second.handle);
                    }
                    m_guards[restarted.pid] = restarted;
                    clearFailureState(m_guards[restarted.pid]);
                    assignGuardToJob(m_guards[restarted.pid]);
                    auto &persisted = m_persistedGuards[restarted.guardId];
                    copyGuardToPersisted(restarted, persisted);
                    persisted.intentional = false;
                }
                persistState();
                Logger::warning("PGS: auto-attached restarted guard pid=" + std::to_string(restarted.pid));
                recordEvent("guard.restart",
                            "pid=" + std::to_string(restarted.pid) +
                            ";guard_id=" + std::to_string(restarted.guardId) +
                            ";path=" + restarted.path);
            }
            else
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    quarantineGuardLocked(pit->guard, failureCode.empty() ? "restart.deferred_failed" : failureCode,
                                          failureMessage.empty() ? "deferred restart failed" : failureMessage);
                }
                persistState();
                closeGuardJob(pit->guard.guardId, true);
                Logger::error("PGS: restart failed permanently, guard quarantined path=" + pit->guard.path);
                recordEvent("guard.restart-failed",
                            "guard_id=" + std::to_string(pit->guard.guardId) +
                            ";path=" + pit->guard.path);
            }
            if (pit->guard.handle)
            {
                CloseHandle(pit->guard.handle);
            }
            pit = pending.erase(pit);
        }

        // IOCP fast wake: consume one completion (50ms cap) so a fresh exit
        // notification short-circuits the wait; the poll below is still the
        // authoritative liveness source.
        if (m_ioPort)
        {
            DWORD code = 0;
            ULONG_PTR key = 0;
            LPOVERLAPPED ov = nullptr;
            GetQueuedCompletionStatus(m_ioPort, &code, &key, &ov, 50);
            (void)code;
            (void)key;
            (void)ov;
        }
        else
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }

        std::vector<GuardInfo> deadGuards;
        std::vector<GuardInfo> hangCandidates;
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            for (auto it = m_guards.begin(); it != m_guards.end();)
            {
                if (isGuardAlive(it->second))
                {
                    if (it->second.hangTimeoutMs > 0)
                    {
                        hangCandidates.push_back(it->second);
                    }
                    ++it;
                    continue;
                }

                DWORD exitCode = 0;
                if (it->second.handle)
                {
                    GetExitCodeProcess(it->second.handle, &exitCode);
                }
                markGuardExitForProfile(it->second, exitCode, currentEpochMs());
                deadGuards.push_back(it->second);
                it = m_guards.erase(it);
            }
        }
        for (const GuardInfo &candidate : hangCandidates)
        {
            if (!isGuardHung(candidate))
            {
                continue;
            }

            Logger::warning("PGS: guard hung (unresponsive GUI), pid=" +
                            std::to_string(candidate.pid) +
                            ", hang-timeout=" + std::to_string(candidate.hangTimeoutMs) + "ms");
            recordEvent("guard.hung",
                        "pid=" + std::to_string(candidate.pid) +
                        ";guard_id=" + std::to_string(candidate.guardId) +
                        ";path=" + candidate.path);
            terminateGuardFamily(candidate.guardId);

            std::lock_guard<std::mutex> lock(m_guardsMutex);
            auto it = m_guards.find(candidate.pid);
            if (it != m_guards.end() && it->second.guardId == candidate.guardId)
            {
                markGuardExitForProfile(it->second, 1, currentEpochMs());
                deadGuards.push_back(it->second);
                m_guards.erase(it);
            }
        }

        // Process restart decisions outside the main guard map lock so creating
        // processes / waiting on system APIs cannot block register/list/get.
        for (const auto &guard : deadGuards)
        {
            bool guardPaused = guard.paused;
            {
                std::lock_guard<std::mutex> lock(m_guardsMutex);
                const auto git = guard.groupName.empty() ? m_guardGroups.end() : m_guardGroups.find(guard.groupName);
                guardPaused = guardPaused || (git != m_guardGroups.end() && git->second.paused);
            }

            if (guard.intentional)
            {
                if (guard.handle)
                {
                    CloseHandle(guard.handle);
                }
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    m_policyByGuardId.erase(guard.guardId);
                    m_persistedGuards.erase(guard.guardId);
                }
                closeGuardJob(guard.guardId);
                persistState();
                Logger::warning("PGS: guard exited intentionally, pid=" + std::to_string(guard.pid));
                recordEvent("guard.intentional-exit",
                            "pid=" + std::to_string(guard.pid) +
                            ";guard_id=" + std::to_string(guard.guardId) +
                            ";path=" + guard.path);
                continue;
            }

            if (guardPaused)
            {
                if (guard.handle)
                {
                    CloseHandle(guard.handle);
                }
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    auto &persisted = m_persistedGuards[guard.guardId];
                    copyGuardToPersisted(guard, persisted);
                    persisted.lastKnownPid = 0;
                    persisted.intentional = false;
                    persisted.paused = guard.paused;
                }
                closeGuardJob(guard.guardId, true);
                persistState();
                Logger::warning("PGS: guard exited while paused, restart suppressed pid=" + std::to_string(guard.pid));
                recordEvent("guard.paused-exit",
                            "pid=" + std::to_string(guard.pid) +
                            ";guard_id=" + std::to_string(guard.guardId) +
                            ";path=" + guard.path);
                continue;
            }

            bool shouldRestart = true;
            int currentRestarts = 0;
            int maxRestarts = guard.maxRestarts;
            const int windowSec = guard.restartWindowSec;
            const bool windowed = (windowSec > 0);
            {
                std::lock_guard<std::mutex> lock(m_guardsMutex);
                auto &policy = m_policyByGuardId[guard.guardId];
                if (policy.maxRestarts != guard.maxRestarts)
                {
                    policy.maxRestarts = guard.maxRestarts;
                }
                if (windowed)
                {
                    const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    policy.recentRestartMs = util::pruneRestartWindow(policy.recentRestartMs, nowMs, windowSec);
                    currentRestarts = static_cast<int>(policy.recentRestartMs.size());
                }
                else
                {
                    currentRestarts = policy.restartCount;
                }
                maxRestarts = policy.maxRestarts;
                shouldRestart = !(policy.maxRestarts >= 0 && currentRestarts >= policy.maxRestarts);
            }

            if (!shouldRestart)
            {
                Logger::warning("PGS: guard restart limit reached, path=" + guard.path +
                                ", max=" + maxRestartsLabel(maxRestarts) +
                                (windowed ? " (sliding window)" : ""));
                if (guard.handle)
                {
                    CloseHandle(guard.handle);
                }
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    quarantineGuardLocked(guard, "restart.limit", "restart limit reached");
                }
                closeGuardJob(guard.guardId, true);
                persistState();
                recordEvent("guard.restart-limit",
                            "pid=" + std::to_string(guard.pid) +
                            ";guard_id=" + std::to_string(guard.guardId) +
                            ";path=" + guard.path +
                            ";max=" + maxRestartsLabel(maxRestarts));
                continue;
            }

            // Terminate the whole family (orphan/child processes) before
            // relaunching so a crash-looping parent cannot leave ghosts behind.
            terminateGuardFamily(guard.guardId);

            const int restartIndex = currentRestarts + 1;
            int delayMs = guard.restartDelayMs;
            if (guard.backoff)
            {
                delayMs = util::computeBackoffDelay(guard.restartDelayMs, restartIndex);
            }

            // Record the restart now; if relaunch fails below, policy is retired
            // and the recorded timestamp/count is effectively discarded.
            {
                std::lock_guard<std::mutex> lock(m_guardsMutex);
                auto &policy = m_policyByGuardId[guard.guardId];
                if (windowed)
                {
                    const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    policy.recentRestartMs.push_back(nowMs);
                    policy.recentRestartMs = util::pruneRestartWindow(policy.recentRestartMs, nowMs, windowSec);
                    policy.restartCount = static_cast<int>(policy.recentRestartMs.size());
                }
                else
                {
                    if (policy.restartCount < std::numeric_limits<int>::max())
                    {
                        ++policy.restartCount;
                    }
                }
                currentRestarts = windowed ? static_cast<int>(policy.recentRestartMs.size()) : policy.restartCount;
            }

            Logger::warning("PGS: guard died unexpectedly, pid=" + std::to_string(guard.pid) +
                            (guard.appKind == AppKind::WinApp ? " (winapp)" : ""));
            recordEvent("guard.died",
                        "pid=" + std::to_string(guard.pid) +
                        ";guard_id=" + std::to_string(guard.guardId) +
                        ";path=" + guard.path);
            Logger::warning("PGS: restart count " + std::to_string(currentRestarts) + "/" +
                            maxRestartsLabel(maxRestarts) +
                            ", path=" + guard.path +
                            ", app-kind=" + (guard.appKind == AppKind::WinApp ? "winapp" : "win32") +
                            (delayMs > 0 ? ", delay=" + std::to_string(delayMs) + "ms" : ""));

            if (delayMs > 0)
            {
                // Defer the relaunch so backoff/delay cannot stall monitoring of
                // other guards. Mark the archive as "pending and already
                // counted" before persisting so an SCM/service restart during
                // the delay resumes the same attempt without double-counting it.
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    auto it = m_persistedGuards.find(guard.guardId);
                    if (it != m_persistedGuards.end())
                    {
                        copyGuardToPersisted(guard, it->second);
                        it->second.lastKnownPid = 0;
                        it->second.intentional = false;
                    }
                }
                persistState();
                // The dead pid handle is kept in the pending copy and closed
                // when the deferred relaunch fires.
                const auto readyAt = std::chrono::steady_clock::now() + std::chrono::milliseconds(delayMs);
                pending.push_back({guard, restartIndex, readyAt});
                continue;
            }

            GuardInfo newGuard;
            std::string failureCode;
            std::string failureMessage;
            if (restartGuard(guard, restartIndex, newGuard, failureCode, failureMessage))
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    auto existingNew = m_guards.find(newGuard.pid);
                    if (existingNew != m_guards.end() && existingNew->second.handle)
                    {
                        CloseHandle(existingNew->second.handle);
                    }
                    m_guards[newGuard.pid] = newGuard;
                    clearFailureState(m_guards[newGuard.pid]);
                    assignGuardToJob(m_guards[newGuard.pid]);
                    auto &persisted = m_persistedGuards[newGuard.guardId];
                    copyGuardToPersisted(newGuard, persisted);
                    persisted.intentional = false;
                }
                persistState();
                Logger::warning("PGS: auto-attached restarted guard pid=" + std::to_string(newGuard.pid));
                recordEvent("guard.restart",
                            "pid=" + std::to_string(newGuard.pid) +
                            ";guard_id=" + std::to_string(newGuard.guardId) +
                            ";path=" + newGuard.path);
            }
            else
            {
                {
                    std::lock_guard<std::mutex> lock(m_guardsMutex);
                    quarantineGuardLocked(guard, failureCode.empty() ? "restart.failed" : failureCode,
                                          failureMessage.empty() ? "restart failed" : failureMessage);
                }
                persistState();
                closeGuardJob(guard.guardId, true);
                Logger::error("PGS: restart failed permanently, guard quarantined pid=" + std::to_string(guard.pid));
                recordEvent("guard.restart-failed",
                            "pid=" + std::to_string(guard.pid) +
                            ";guard_id=" + std::to_string(guard.guardId) +
                            ";path=" + guard.path);
            }
            if (guard.handle)
            {
                CloseHandle(guard.handle);
            }
        }
    }

    for (PendingRestart &restart : pending)
    {
        if (restart.guard.handle)
        {
            CloseHandle(restart.guard.handle);
            restart.guard.handle = nullptr;
        }
    }
}


bool PGS::isGuardAlive(const GuardInfo &info) const
{
    if (!info.handle)
    {
        return false;
    }
    return WaitForSingleObject(info.handle, 0) == WAIT_TIMEOUT;
}


bool PGS::restartGuard(const GuardInfo &info, int restartIndex, GuardInfo &newGuard, std::string &failureCode, std::string &failureMessage)
{
    failureCode.clear();
    failureMessage.clear();
    // TOCTOU defense: if a file hash was recorded at registration time,
    // recompute it now and refuse to relaunch if the image on disk has
    // changed. Without this, a binary swapped between crash and restart
    // would be launched while still carrying the stale hashVerified badge.
    if (!info.fileHash.empty())
    {
        std::string currentHash;
        if (!computeFileHash(info.path, currentHash))
        {
            Logger::error("PGS: restart refused, failed to recompute file hash for path=" + info.path);
            return setRestartFailure(failureCode, failureMessage, "restart.hash_unreadable", "failed to recompute file hash for path=" + info.path);
        }
        if (!constantTimeEquals(toLowerAscii(currentHash), toLowerAscii(info.fileHash)))
        {
            Logger::error("PGS: restart refused, file hash mismatch (image changed since registration) path=" + info.path);
            return setRestartFailure(failureCode, failureMessage, "restart.hash_mismatch", "file hash mismatch for path=" + info.path);
        }
    }
    // v3: WindowsApps (UWP/Store) cannot be (re)launched with CreateProcessW*
    // — they must be activated through their AUMID. Route the whole restart to
    // restartAppGuard (it impersonates the user session and shell-activates the
    // app, returning the new pid/handle).
    if (info.appKind == AppKind::WinApp && !info.aumid.empty())
    {
        return restartAppGuard(info, restartIndex, newGuard, failureCode, failureMessage);
    }

    // Restart tries to preserve user experience first. We prefer re-launching
    // inside the original session so GUI apps come back on the right desktop.
    // If that fails, we still fall back to a normal CreateProcessW restart so
    // service-side recovery remains possible for console/background workers.
    if (restartGuardInSession(info, restartIndex, newGuard, failureCode, failureMessage))
    {
        return true;
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    const std::wstring exeW = utf8ToWide(info.path);
    if (exeW.empty())
    {
        Logger::error("PGS: restart failed, utf8ToWide path conversion failed for path=" + info.path);
        return setRestartFailure(failureCode, failureMessage, "restart.path_encoding", "path conversion failed for path=" + info.path);
    }
    std::wstring commandLine = quoteArgW(exeW);
    if (!info.restartArgs.empty())
    {
        const std::string argsUtf8 = replaceAll(info.restartArgs, kRestartIndexToken, std::to_string(restartIndex));
        const std::wstring argsW = utf8ToWide(argsUtf8);
        if (!argsW.empty())
        {
            commandLine.push_back(L' ');
            commandLine += argsW;
        }
    }
    std::vector<wchar_t> writableCmd(commandLine.begin(), commandLine.end());
    writableCmd.push_back(L'\0');

    const std::wstring workDirW = utf8ToWide(parentDirectory(info.path));
    const BOOL ok = CreateProcessW(
        nullptr,
        writableCmd.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_CONSOLE,
        nullptr,
        workDirW.empty() ? nullptr : workDirW.c_str(),
        &si,
        &pi);

    if (!ok)
    {
        const DWORD err = GetLastError();
        Logger::error("PGS: restart failed for path=" + info.path + ", error=" + std::to_string(err));
        return setRestartFailure(failureCode, failureMessage, "restart.create_process", "CreateProcessW failed for path=" + info.path + ", error=" + std::to_string(err));
    }

    DWORD targetSession = 0xFFFFFFFF;
    ProcessIdToSessionId(pi.dwProcessId, &targetSession);
    newGuard = info;
    newGuard.pid = pi.dwProcessId;
    newGuard.sessionId = targetSession;
    newGuard.handle = pi.hProcess;
    newGuard.intentional = false;
    newGuard.jobHandle = nullptr;
    inheritRestartProfile(newGuard, info);

    Logger::warning("PGS: restart launched in fallback session, pid=" + std::to_string(pi.dwProcessId) +
                    ", session=" + std::to_string(targetSession));
    CloseHandle(pi.hThread);
    return true;
}


bool PGS::restartGuardInSession(const GuardInfo &info, int restartIndex, GuardInfo &newGuard, std::string &failureCode, std::string &failureMessage)
{
    // Session-aware restart path:
    // - obtain a user token for the original session when possible
    // - duplicate it into a primary token
    // - build a fresh user environment block
    // - CreateProcessAsUserW on the interactive desktop
    //
    // This is heavier than the fallback path, but it is the only way to bring
    // UI processes back into the intended user session from a service context.
    HANDLE userToken = nullptr;
    DWORD targetSessionId = info.sessionId;
    if (!queryUserTokenForSession(targetSessionId, userToken))
    {
        const DWORD activeSession = WTSGetActiveConsoleSessionId();
        if (!queryUserTokenForSession(activeSession, userToken))
        {
            return setRestartFailure(failureCode, failureMessage, "restart.session_token", "failed to query user token for session=" + std::to_string(targetSessionId) + " or active session=" + std::to_string(activeSession));
        }
        targetSessionId = activeSession;
    }

    HANDLE primaryToken = nullptr;
    const BOOL dupOk = DuplicateTokenEx(
        userToken,
        TOKEN_ALL_ACCESS,
        nullptr,
        SecurityImpersonation,
        TokenPrimary,
        &primaryToken);
    CloseHandle(userToken);
    if (!dupOk)
    {
        const DWORD err = GetLastError();
        Logger::warning("PGS: DuplicateTokenEx failed for restart session=" +
                        std::to_string(targetSessionId) +
                        ", error=" + std::to_string(err));
        return setRestartFailure(failureCode, failureMessage, "restart.duplicate_token", "DuplicateTokenEx failed for restart session=" + std::to_string(targetSessionId) + ", error=" + std::to_string(err));
    }

    if (!SetTokenInformation(primaryToken, TokenSessionId, &targetSessionId, sizeof(targetSessionId)))
    {
        const DWORD err = GetLastError();
        Logger::warning("PGS: SetTokenInformation(TokenSessionId) failed for restart session=" +
                        std::to_string(targetSessionId) +
                        ", error=" + std::to_string(err));
        CloseHandle(primaryToken);
        return setRestartFailure(failureCode, failureMessage, "restart.session_token", "SetTokenInformation(TokenSessionId) failed for restart session=" + std::to_string(targetSessionId) + ", error=" + std::to_string(err));
    }

    LPVOID envBlock = nullptr;
    if (!CreateEnvironmentBlock(&envBlock, primaryToken, FALSE))
    {
        const DWORD err = GetLastError();
        Logger::warning("PGS: CreateEnvironmentBlock failed for restart session=" +
                        std::to_string(targetSessionId) +
                        ", error=" + std::to_string(err));
        CloseHandle(primaryToken);
        return setRestartFailure(failureCode, failureMessage, "restart.environment", "CreateEnvironmentBlock failed for restart session=" + std::to_string(targetSessionId) + ", error=" + std::to_string(err));
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<wchar_t *>(L"winsta0\\default");

    PROCESS_INFORMATION pi{};
    const std::wstring exeW = utf8ToWide(info.path);
    if (exeW.empty())
    {
        if (envBlock)
        {
            DestroyEnvironmentBlock(envBlock);
        }
        CloseHandle(primaryToken);
        return setRestartFailure(failureCode, failureMessage, "restart.path_encoding", "path conversion failed for path=" + info.path);
    }
    std::wstring commandLine = quoteArgW(exeW);
    if (!info.restartArgs.empty())
    {
        const std::string argsUtf8 = replaceAll(info.restartArgs, kRestartIndexToken, std::to_string(restartIndex));
        const std::wstring argsW = utf8ToWide(argsUtf8);
        if (!argsW.empty())
        {
            commandLine.push_back(L' ');
            commandLine += argsW;
        }
    }
    std::vector<wchar_t> writableCmd(commandLine.begin(), commandLine.end());
    writableCmd.push_back(L'\0');

    const std::wstring workDirW = utf8ToWide(parentDirectory(info.path));
    const BOOL ok = CreateProcessAsUserW(
        primaryToken,
        nullptr,
        writableCmd.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT,
        envBlock,
        workDirW.empty() ? nullptr : workDirW.c_str(),
        &si,
        &pi);
    const DWORD createErr = ok ? ERROR_SUCCESS : GetLastError();

    if (envBlock)
    {
        DestroyEnvironmentBlock(envBlock);
    }
    CloseHandle(primaryToken);

    if (!ok)
    {
        Logger::warning("PGS: CreateProcessAsUserW failed for restart path=" + info.path +
                        ", session=" + std::to_string(targetSessionId) +
                        ", error=" + std::to_string(createErr));
        return setRestartFailure(failureCode, failureMessage, "restart.create_process_as_user", "CreateProcessAsUserW failed for restart path=" + info.path + ", session=" + std::to_string(targetSessionId) + ", error=" + std::to_string(createErr));
    }

    newGuard = info;
    newGuard.pid = pi.dwProcessId;
    newGuard.sessionId = targetSessionId;
    newGuard.handle = pi.hProcess;
    newGuard.intentional = false;
    newGuard.jobHandle = nullptr;
    inheritRestartProfile(newGuard, info);

    Logger::warning("PGS: restart launched in user session, pid=" + std::to_string(pi.dwProcessId) +
                    ", session=" + std::to_string(targetSessionId));
    CloseHandle(pi.hThread);
    return true;
}


void PGS::cleanupGuards()
{
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        for (auto &entry : m_guards)
        {
            if (entry.second.handle)
            {
                CloseHandle(entry.second.handle);
            }
        }
        m_guards.clear();
        m_policyByGuardId.clear();
    }
    // v3: release all per-guard Job Objects and the shared IOCP.
    {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        for (auto &kv : m_jobs)
        {
            if (kv.second)
            {
                CloseHandle(kv.second);
            }
        }
        m_jobs.clear();
    }
    if (m_ioPort)
    {
        CloseHandle(m_ioPort);
        m_ioPort = nullptr;
    }
}


// "module" sub-protocol dispatcher. Wire format (after auth envelope):
//   module list
//   module load <base64-path>
//   module unload <name>
//   module call <name> <kv-request>   (response forwarded verbatim)
// ---- v3 Job Object / cascade / WindowsApps helpers ---------------------------

bool PGS::createGuardJob(std::uint64_t guardId, bool killOnExit, HANDLE &outJob)
{
    // A named job Global\PGS-Job-<guardId> groups one guarded process and all
    // of its descendants. Breakaway is NOT enabled, so child/grandchild
    // processes stay in the job and TerminateJobObject can clear the whole
    // family on restart. The "Global\" namespace needs SeCreateGlobalPrivilege
    // (LocalSystem/Administrators), which is why cascade requires LocalSystem.
    outJob = nullptr;
    const std::wstring name = utf8ToWide(std::string(kJobNamePrefix) + std::to_string(guardId));
    HANDLE job = CreateJobObjectW(nullptr, name.c_str());
    if (!job)
    {
        Logger::warning("PGS: CreateJobObjectW failed guard-id=" + std::to_string(guardId) +
                        ", error=" + std::to_string(GetLastError()));
        return false;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli{};
    eli.BasicLimitInformation.LimitFlags = killOnExit ? JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE : 0;
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &eli, sizeof(eli)))
    {
        Logger::warning("PGS: SetInformationJobObject(limit) failed guard-id=" + std::to_string(guardId) +
                        ", error=" + std::to_string(GetLastError()));
    }
    if (m_ioPort)
    {
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT acp{};
        acp.CompletionPort = m_ioPort;
        acp.CompletionKey = reinterpret_cast<PVOID>(static_cast<uintptr_t>(guardId));
        if (!SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &acp, sizeof(acp)))
        {
            Logger::warning("PGS: job completion-port bind failed guard-id=" + std::to_string(guardId) +
                            ", error=" + std::to_string(GetLastError()));
        }
    }
    outJob = job;
    return true;
}


bool PGS::attachGuardJob(std::uint64_t guardId, HANDLE &outJob)
{
    // Reopen a survivor job (the process still running after a PGS crash) so we
    // resume observing it. Returns false if the named job is gone (e.g. the
    // process was never in a job, or the kernel object was already released).
    outJob = nullptr;
    const std::wstring name = utf8ToWide(std::string(kJobNamePrefix) + std::to_string(guardId));
    HANDLE job = OpenJobObjectW(JOB_OBJECT_ALL_ACCESS, FALSE, name.c_str());
    if (!job)
    {
        return false;
    }
    if (m_ioPort)
    {
        JOBOBJECT_ASSOCIATE_COMPLETION_PORT acp{};
        acp.CompletionPort = m_ioPort;
        acp.CompletionKey = reinterpret_cast<PVOID>(static_cast<uintptr_t>(guardId));
        if (!SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, &acp, sizeof(acp)))
        {
            Logger::warning("PGS: survivor job completion-port rebind failed guard-id=" +
                            std::to_string(guardId) +
                            ", error=" + std::to_string(GetLastError()));
        }
    }
    outJob = job;
    return true;
}


bool PGS::assignGuardToJob(GuardInfo &guard)
{
    // Reuse an existing job for this guardId, else reopen a survivor job, else
    // create a fresh one; then assign the live process into it. On any failure
    // we leave guard.jobHandle null - poll-based exit detection still works, we
    // just lose cascade observe/terminate for this guard.
    if (!guard.handle || guard.guardId == 0)
    {
        return false;
    }
    HANDLE job = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_jobMutex);
        auto it = m_jobs.find(guard.guardId);
        if (it != m_jobs.end())
        {
            job = it->second;
        }
    }
    if (!job)
    {
        HANDLE reopened = nullptr;
        if (attachGuardJob(guard.guardId, reopened) && reopened)
        {
            job = reopened;
        }
        else
        {
            if (reopened)
            {
                CloseHandle(reopened);
                reopened = nullptr;
            }
            if (!createGuardJob(guard.guardId, guard.killOnExit, job))
            {
                return false;
            }
        }
        {
            std::lock_guard<std::mutex> lock(m_jobMutex);
            m_jobs[guard.guardId] = job;
        }
    }
    if (!AssignProcessToJobObject(job, guard.handle))
    {
        // Common cause: the process is already in an incompatible job, or a
        // permission shortfall. Guarding continues via polling.
        Logger::warning("PGS: AssignProcessToJobObject failed guard-id=" + std::to_string(guard.guardId) +
                        ", pid=" + std::to_string(guard.pid) +
                        ", error=" + std::to_string(GetLastError()));
        return false;
    }
    guard.jobHandle = job;
    return true;
}


void PGS::terminateGuardFamily(std::uint64_t guardId)
{
    // Kill every process in this guard's job (the guarded process plus all
    // descendant/orphan processes still attached) so a relaunch starts clean.
    std::lock_guard<std::mutex> lock(m_jobMutex);
    const auto it = m_jobs.find(guardId);
    if (it == m_jobs.end() || !it->second)
    {
        return;
    }
    if (!TerminateJobObject(it->second, 1))
    {
        Logger::warning("PGS: TerminateJobObject failed guard-id=" + std::to_string(guardId) +
                        ", error=" + std::to_string(GetLastError()));
    }
}


void PGS::closeGuardJob(std::uint64_t guardId, bool preserveProcesses)
{
    std::lock_guard<std::mutex> lock(m_jobMutex);
    const auto it = m_jobs.find(guardId);
    if (it != m_jobs.end())
    {
        if (it->second)
        {
            if (preserveProcesses)
            {
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli{};
                if (QueryInformationJobObject(it->second, JobObjectExtendedLimitInformation, &eli, sizeof(eli), nullptr))
                {
                    eli.BasicLimitInformation.LimitFlags &= ~JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                    if (!SetInformationJobObject(it->second, JobObjectExtendedLimitInformation, &eli, sizeof(eli)))
                    {
                        Logger::warning("PGS: failed to clear kill-on-job-close guard-id=" +
                                        std::to_string(guardId) +
                                        ", error=" + std::to_string(GetLastError()));
                    }
                }
                else
                {
                    Logger::warning("PGS: failed to query job limits guard-id=" +
                                    std::to_string(guardId) +
                                    ", error=" + std::to_string(GetLastError()));
                }
            }
            CloseHandle(it->second);
        }
        m_jobs.erase(it);
    }
}


bool PGS::setGuardJobKillOnExit(std::uint64_t guardId, bool killOnExit)
{
    std::lock_guard<std::mutex> lock(m_jobMutex);
    const auto it = m_jobs.find(guardId);
    if (it == m_jobs.end() || !it->second)
    {
        return false;
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION eli{};
    if (!QueryInformationJobObject(it->second, JobObjectExtendedLimitInformation, &eli, sizeof(eli), nullptr))
    {
        Logger::warning("PGS: failed to query job limits for policy update guard-id=" +
                        std::to_string(guardId) +
                        ", error=" + std::to_string(GetLastError()));
        return false;
    }

    if (killOnExit)
    {
        eli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }
    else
    {
        eli.BasicLimitInformation.LimitFlags &= ~JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }

    if (!SetInformationJobObject(it->second, JobObjectExtendedLimitInformation, &eli, sizeof(eli)))
    {
        Logger::warning("PGS: failed to update kill-on-exit for job guard-id=" +
                        std::to_string(guardId) +
                        ", error=" + std::to_string(GetLastError()));
        return false;
    }
    return true;
}


bool PGS::isGuardHung(const GuardInfo &info) const
{
    // Probe each visible top-level window owned by the guard's pid with
    // SendMessageTimeout(WM_NULL); any timeout >= hangTimeoutMs flags the
    // guard as hung. Non-GUI guards have no such window and report false, so
    // this never false-triggers on background workers. Reliable mainly when
    // PGS runs in the interactive session (a Session 0 service can see
    // cross-session ACCESS_DENIED instead of a clean timeout).
    if (info.hangTimeoutMs <= 0 || !info.handle)
    {
        return false;
    }
    struct Ctx
    {
        DWORD pid;
        DWORD timeoutMs;
        bool hung;
    };
    Ctx ctx{info.pid, static_cast<DWORD>(info.hangTimeoutMs), false};
    auto enumProc = [](HWND hwnd, LPARAM lp) -> BOOL
    {
        auto *c = reinterpret_cast<Ctx *>(lp);
        DWORD wpid = 0;
        GetWindowThreadProcessId(hwnd, &wpid);
        if (wpid != c->pid)
        {
            return TRUE;
        }
        if (!IsWindowVisible(hwnd) || GetWindow(hwnd, GW_OWNER) != nullptr)
        {
            return TRUE;
        }
        DWORD_PTR res = 0;
        const LRESULT r = SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, SMTO_ABORTIFHUNG | SMTO_BLOCK, c->timeoutMs, &res);
        if (r == 0)
        {
            const DWORD err = GetLastError();
            if (err == ERROR_TIMEOUT)
            {
                c->hung = true;
                return FALSE; // stop enumerating; we have our answer
            }
        }
        return TRUE;
    };
    EnumWindows(enumProc, reinterpret_cast<LPARAM>(&ctx));
    return ctx.hung;
}


bool PGS::restartAppGuard(const GuardInfo &info, int restartIndex, GuardInfo &newGuard, std::string &failureCode, std::string &failureMessage)
{
    // Activate a WindowsApps (UWP/Store) guard via its AUMID. The primary path is
    // IApplicationActivationManager::ActivateApplication (the documented Start-menu
    // activation entry), which returns the real packaged app pid so we can keep a
    // handle for liveness watching. We impersonate the original user token so a
    // Session 0 service lands the app in the interactive session. ShellExecuteExW
    // with "shell:AppsFolder\<AUMID>" is the fallback when COM activation is
    // unavailable; the broker there rarely yields a usable hProcess.
    if (info.aumid.empty())
    {
        Logger::error("PGS: winapp restart refused, missing AUMID, path=" + info.path);
        return setRestartFailure(failureCode, failureMessage, "winapp.missing_aumid", "WindowsApps restart requires AUMID for path=" + info.path);
    }

    HANDLE userToken = nullptr;
    DWORD targetSessionId = info.sessionId;
    // When PGS itself runs inside the target session (console `run` mode under an
    // interactive admin), it already holds that session's user token and we can
    // clone it directly -- no SE_TCB_NAME required (that privilege is granted
    // only to LocalSystem, which an elevated admin token does NOT carry, so
    // WTSQueryUserToken would always fail here). WTSQueryUserToken remains the
    // path for the Session-0 service case below.
    DWORD mySession = 0xFFFFFFFF;
    ProcessIdToSessionId(GetCurrentProcessId(), &mySession);
    if (mySession != 0xFFFFFFFF && mySession == targetSessionId)
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &userToken))
        {
            Logger::warning("PGS: winapp restart could not open current process token, error=" +
                            std::to_string(GetLastError()));
        }
    }
    if (!userToken && !queryUserTokenForSession(targetSessionId, userToken))
    {
        const DWORD activeSession = WTSGetActiveConsoleSessionId();
        if (mySession != 0xFFFFFFFF && mySession == activeSession)
        {
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &userToken))
            {
                Logger::warning("PGS: winapp restart could not open active-session process token, error=" +
                                std::to_string(GetLastError()));
            }
        }
    if (!userToken && !queryUserTokenForSession(activeSession, userToken))
        {
            Logger::error("PGS: winapp restart failed, no user token for any session, aumid=" + info.aumid);
            return setRestartFailure(failureCode, failureMessage, "winapp.no_user_token", "no user token for WindowsApps restart, aumid=" + info.aumid);
        }
        targetSessionId = activeSession;
    }
    HANDLE primaryToken = nullptr;
    if (!DuplicateTokenEx(userToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenImpersonation, &primaryToken))
    {
        const DWORD err = GetLastError();
        CloseHandle(userToken);
        Logger::error("PGS: winapp restart failed, DuplicateTokenEx error=" + std::to_string(err));
        return setRestartFailure(failureCode, failureMessage, "winapp.duplicate_token", "DuplicateTokenEx failed for WindowsApps restart, error=" + std::to_string(err));
    }
    CloseHandle(userToken);
    // Impersonation-token form: ActivateApplication runs under the thread token;
    // we do NOT set TokenSessionId (that is a primary-token concern for
    // CreateProcessAsUser, which this winapp path never uses).

    std::string argsUtf8 = info.restartArgs;
    if (!argsUtf8.empty())
    {
        argsUtf8 = replaceAll(argsUtf8, kRestartIndexToken, std::to_string(restartIndex));
    }
    const std::wstring aumidW = utf8ToWide(info.aumid);
    const std::wstring argsW = utf8ToWide(argsUtf8);

    bool ok = false;
    DWORD activatedPid = 0;
    HANDLE procHandle = nullptr;

    if (!SetThreadToken(nullptr, primaryToken))
    {
        const DWORD err = GetLastError();
        CloseHandle(primaryToken);
        Logger::error("PGS: winapp restart failed, SetThreadToken error=" + std::to_string(err));
        return setRestartFailure(failureCode, failureMessage, "winapp.set_thread_token", "SetThreadToken failed for WindowsApps restart, error=" + std::to_string(err));
    }

    HRESULT comInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    const bool comInited = (SUCCEEDED(comInit) || comInit == RPC_E_CHANGED_MODE);
    if (comInited)
    {
        IApplicationActivationManager *act = nullptr;
        HRESULT hr = CoCreateInstance(CLSID_ApplicationActivationManager, nullptr,
                                      CLSCTX_LOCAL_SERVER | CLSCTX_NO_FAILURE_LOG,
                                      IID_PPV_ARGS(&act));
        if (SUCCEEDED(hr) && act)
        {
            hr = act->ActivateApplication(aumidW.c_str(),
                                          (argsW.empty() ? L"" : argsW.c_str()),
                                          AO_NONE, &activatedPid);
            if (SUCCEEDED(hr) && activatedPid != 0)
            {
                procHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                                          FALSE, activatedPid);
                ok = (procHandle != nullptr);
                if (!ok)
                {
                    Logger::warning("PGS: winapp ActivateApplication ok pid=" + std::to_string(activatedPid) +
                                    " but OpenProcess failed error=" + std::to_string(GetLastError()) +
                                    ", aumid=" + info.aumid);
                    activatedPid = 0;
                }
            }
            else
            {
                Logger::warning("PGS: ActivateApplication hr=0x" +
                                std::to_string(static_cast<unsigned long>(hr)) +
                                " pid=" + std::to_string(activatedPid) +
                                ", aumid=" + info.aumid);
            }
            act->Release();
        }
        else
        {
            Logger::warning("PGS: CoCreateInstance(ApplicationActivationManager) hr=0x" +
                            std::to_string(static_cast<unsigned long>(hr)) +
                            ", falling back to ShellExecute, aumid=" + info.aumid);
        }
        if (comInit == S_OK || comInit == S_FALSE)
        {
            CoUninitialize();
        }
    }

    // Fallback: ShellExecuteExW("shell:AppsFolder\<AUMID>"). Broker often does
    // not hand back hProcess, so this is best-effort.
    if (!ok)
    {
        std::wstring file = L"shell:AppsFolder\\" + aumidW;
        std::vector<wchar_t> paramsBuf(argsW.begin(), argsW.end());
        paramsBuf.push_back(L'\0');
        SHELLEXECUTEINFOW sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC;
        sei.lpFile = file.c_str();
        sei.lpParameters = (argsW.empty() ? nullptr : paramsBuf.data());
        sei.nShow = SW_SHOWNORMAL;
        ok = (ShellExecuteExW(&sei) == TRUE);
        if (ok)
        {
            procHandle = sei.hProcess;
            activatedPid = procHandle ? GetProcessId(procHandle) : 0;
        }
    }

    SetThreadToken(nullptr, nullptr);
    CloseHandle(primaryToken);

    if (!ok || !procHandle || activatedPid == 0)
    {
        const DWORD err = GetLastError();
        Logger::error("PGS: winapp restart failed, aumid=" + info.aumid +
                      ", error=" + std::to_string(err));
        if (procHandle)
        {
            CloseHandle(procHandle);
        }
        return setRestartFailure(failureCode, failureMessage, "winapp.activate_failed", "WindowsApps activation failed, aumid=" + info.aumid + ", error=" + std::to_string(err));
    }

    DWORD sessionId = 0xFFFFFFFF;
    ProcessIdToSessionId(activatedPid, &sessionId);
    newGuard = info;
    newGuard.pid = activatedPid;
    newGuard.sessionId = sessionId;
    newGuard.handle = procHandle;
    newGuard.intentional = false;
    newGuard.appKind = AppKind::WinApp;
    newGuard.jobHandle = nullptr;
    inheritRestartProfile(newGuard, info);
    Logger::warning("PGS: winapp restart activated pid=" + std::to_string(activatedPid) +
                    ", aumid=" + info.aumid);
    return true;
}


int PGS::recordRestartAndEffectiveCount(std::uint64_t /*guardId*/, RestartPolicyState &policy, int windowSec)
{
    const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (windowSec > 0)
    {
        policy.recentRestartMs = util::pruneRestartWindow(policy.recentRestartMs, nowMs, windowSec);
        policy.recentRestartMs.push_back(nowMs);
        policy.restartCount = static_cast<int>(policy.recentRestartMs.size());
        return policy.restartCount;
    }
    if (policy.restartCount < std::numeric_limits<int>::max())
    {
        ++policy.restartCount;
    }
    return policy.restartCount;
}


} // namespace ProcessGuard
