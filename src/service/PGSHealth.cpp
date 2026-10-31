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


bool PGS::validateHealthCheckConfig(const std::string &configJson, std::string &error)
{
    HealthCheckConfig parsed;
    return parseHealthCheckConfig(configJson, parsed, error);
}


void PGS::resetHealthRuntimeState(GuardInfo &guard)
{
    guard.healthStatus = guard.healthCheckJson.empty() ? "disabled" : "pending";
    guard.healthLastMessage.clear();
    guard.healthLastCheckMs = 0;
    guard.healthLastOkMs = 0;
    guard.healthLastFailureMs = 0;
    guard.healthNextCheckMs = guard.healthCheckJson.empty() ? 0 : currentEpochMs();
    guard.healthFailureCount = 0;
}


void PGS::healthLoop()
{
    while (m_running.load())
    {
        std::vector<HealthTask> tasks;
        std::vector<std::pair<std::string, std::string>> events;
        const std::int64_t nowMs = currentEpochMs();
        runArtifactMaintenanceIfDue(nowMs);
        {
            std::lock_guard<std::mutex> lock(m_guardsMutex);
            for (auto &entry : m_guards)
            {
                GuardInfo &guard = entry.second;
                if (guard.healthCheckJson.empty())
                {
                    if (guard.healthStatus != "disabled")
                    {
                        resetHealthRuntimeState(guard);
                    }
                    continue;
                }

                HealthCheckConfig config;
                std::string configError;
                if (!parseHealthCheckConfig(guard.healthCheckJson, config, configError))
                {
                    const bool firstError = guard.healthStatus != "config-error";
                    guard.healthStatus = "config-error";
                    guard.healthLastMessage = configError;
                    guard.healthLastFailureMs = nowMs;
                    guard.healthNextCheckMs = nowMs + kDefaultHealthIntervalMs;
                    if (firstError)
                    {
                        events.emplace_back("guard.health-config-error",
                                            "pid=" + std::to_string(guard.pid) +
                                            ";guard_id=" + std::to_string(guard.guardId) +
                                            ";error_b64=" + base64Encode(configError));
                    }
                    continue;
                }
                if (!config.enabled)
                {
                    if (guard.healthStatus != "disabled")
                    {
                        resetHealthRuntimeState(guard);
                    }
                    continue;
                }

                const auto groupIt = guard.groupName.empty() ? m_guardGroups.end() : m_guardGroups.find(guard.groupName);
                const bool paused = guard.paused || (groupIt != m_guardGroups.end() && groupIt->second.paused);
                if (paused || guard.quarantined || guard.intentional)
                {
                    guard.healthStatus = paused ? "paused" : (guard.quarantined ? "quarantined" : "disabled");
                    guard.healthNextCheckMs = nowMs + config.intervalMs;
                    continue;
                }
                if (guard.healthNextCheckMs > nowMs)
                {
                    continue;
                }

                HANDLE dup = nullptr;
                if (!duplicateProcessHandle(guard.handle, dup))
                {
                    guard.healthStatus = "degraded";
                    guard.healthLastMessage = "process handle unavailable";
                    guard.healthLastFailureMs = nowMs;
                    ++guard.healthFailureCount;
                    guard.healthNextCheckMs = nowMs + config.intervalMs;
                    continue;
                }
                guard.healthStatus = "checking";
                guard.healthLastCheckMs = nowMs;
                guard.healthNextCheckMs = nowMs + config.intervalMs;
                HealthTask task;
                task.pid = guard.pid;
                task.guardId = guard.guardId;
                task.processHandle = dup;
                task.path = guard.path;
                task.configJson = guard.healthCheckJson;
                task.config = config;
                tasks.push_back(std::move(task));
            }
        }

        for (HealthTask &task : tasks)
        {
            std::string message;
            const bool ok = runHealthProbe(task, task.config, message);
            const std::int64_t checkedMs = currentEpochMs();
            bool restartGuardNow = false;
            bool terminateQuarantinedProcess = false;
            bool persistAfterAction = false;
            HANDLE staleGuardHandle = nullptr;
            {
                std::lock_guard<std::mutex> lock(m_guardsMutex);
                auto it = m_guards.find(task.pid);
                if (it == m_guards.end() || it->second.guardId != task.guardId || it->second.healthCheckJson != task.configJson)
                {
                    CloseHandle(task.processHandle);
                    task.processHandle = nullptr;
                    continue;
                }
                GuardInfo &guard = it->second;
                guard.healthLastCheckMs = checkedMs;
                guard.healthNextCheckMs = checkedMs + task.config.intervalMs;
                guard.healthLastMessage = message;
                if (ok)
                {
                    const bool recovered = guard.healthStatus == "unhealthy" || guard.healthStatus == "degraded" || guard.healthFailureCount > 0;
                    guard.healthStatus = "healthy";
                    guard.healthLastOkMs = checkedMs;
                    guard.healthFailureCount = 0;
                    if (recovered)
                    {
                        events.emplace_back("guard.health-ok",
                                            "pid=" + std::to_string(task.pid) +
                                            ";guard_id=" + std::to_string(task.guardId) +
                                            ";type=" + task.config.type +
                                            ";message_b64=" + base64Encode(message));
                    }
                }
                else
                {
                    const int previousFailures = guard.healthFailureCount;
                    guard.healthLastFailureMs = checkedMs;
                    if (guard.healthFailureCount < std::numeric_limits<int>::max())
                    {
                        ++guard.healthFailureCount;
                    }
                    const bool thresholdReached = guard.healthFailureCount >= task.config.failures;
                    guard.healthStatus = thresholdReached ? "unhealthy" : "degraded";
                    if (thresholdReached && previousFailures < task.config.failures)
                    {
                        events.emplace_back("guard.health-unhealthy",
                                            "pid=" + std::to_string(task.pid) +
                                            ";guard_id=" + std::to_string(task.guardId) +
                                            ";type=" + task.config.type +
                                            ";failures=" + std::to_string(guard.healthFailureCount) +
                                            ";message_b64=" + base64Encode(message));
                    }
                    if (thresholdReached && task.config.action == "restart")
                    {
                        guard.healthStatus = "restarting";
                        restartGuardNow = true;
                        events.emplace_back("guard.health-restart",
                                            "pid=" + std::to_string(task.pid) +
                                            ";guard_id=" + std::to_string(task.guardId) +
                                            ";type=" + task.config.type +
                                            ";message_b64=" + base64Encode(message));
                    }
                    else if (thresholdReached && task.config.action == "quarantine")
                    {
                        GuardInfo archived = guard;
                        staleGuardHandle = guard.handle;
                        quarantineGuardLocked(archived, "health.failed", "health-check failed: " + message);
                        terminateQuarantinedProcess = true;
                        persistAfterAction = true;
                    }
                }
            }

            if (restartGuardNow)
            {
                terminateGuardFamily(task.guardId);
                TerminateProcess(task.processHandle, 1);
            }
            if (terminateQuarantinedProcess)
            {
                terminateGuardFamily(task.guardId);
                TerminateProcess(task.processHandle, 1);
                closeGuardJob(task.guardId, true);
                if (staleGuardHandle)
                {
                    CloseHandle(staleGuardHandle);
                }
            }
            if (persistAfterAction)
            {
                persistState();
            }
            if (task.processHandle)
            {
                CloseHandle(task.processHandle);
                task.processHandle = nullptr;
            }
        }

        for (const auto &event : events)
        {
            recordEvent(event.first, event.second);
        }

        std::unique_lock<std::mutex> lock(m_healthMutex);
        m_healthCv.wait_for(lock, std::chrono::milliseconds(500), [this]() {
            return !m_running.load();
        });
    }
}


void PGS::notifyLoop()
{
    while (true)
    {
        std::pair<std::string, std::string> event;
        {
            std::unique_lock<std::mutex> lock(m_notifyMutex);
            m_notifyCv.wait(lock, [this]() {
                return !m_running.load() || !m_notifyQueue.empty();
            });
            if (m_notifyQueue.empty())
            {
                if (!m_running.load())
                {
                    return;
                }
                continue;
            }
            event = std::move(m_notifyQueue.front());
            m_notifyQueue.pop();
        }

        bool notifyLoaded = false;
        for (const auto &module : m_modules.list())
        {
            if (module.name == "notify" && !module.disabled)
            {
                notifyLoaded = true;
                break;
            }
        }
        if (!notifyLoaded)
        {
            continue;
        }

        std::string response;
        std::string err;
        const std::string request = "op=event;type=" + event.first + ";detail_b64=" + base64Encode(event.second);
        const bool called = m_modules.invoke("notify", request, response, err);
        if (!called || response.rfind("OK", 0) != 0)
        {
            recordEvent("notify.delivery-failed",
                        "type=" + event.first +
                        ";error_b64=" + base64Encode(called ? response : err));
        }
    }
}


} // namespace ProcessGuard
