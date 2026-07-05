/**
 * @file PGSProtocol.cpp
 * @brief PGS management-protocol dispatch and command handlers.
 *
 * Split out of PGS.cpp so the core (PGS.cpp) keeps only lifecycle, monitor,
 * persistence and socket transport. This file owns the line-oriented command
 * dispatcher (processMessage), the per-command handlers (register / list /
 * get / policy / token / module / ppl), the auth envelope and the guard
 * summary formatter. All functions are PGS members; definitions may live in
 * any TU that includes PGS.h.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "Process_Guard/PGS.h"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace ProcessGuard
{

using namespace util; // pull in base64/utf8/hash/path helpers from PGUtil.h

    // Alias the utf8 path-normalizer to the historical call-site name (matches
    // the alias kept in PGS.cpp so handlers can call normalizePathForCompare()).
    inline std::string normalizePathForCompare(const std::string &p) { return util::normalizePathForCompareUtf8(p); }
std::string PGS::processMessage(const std::string &message)
{
    // Protocol framing is line-oriented text:
    // - optional auth envelope: "token <token> <command>"
    // - command body:          "<verb> <args>"
    //
    // The dispatcher is intentionally explicit instead of clever so each
    // management command has a narrow validation path and returns predictable
    // error messages for CLI / GUI callers.
    std::string normalized;
    if (!stripAuthEnvelope(message, normalized))
    {
        return m_requireAuth ? "ERR auth failed or token missing" : "ERR empty command";
    }

    const auto spacePos = normalized.find(' ');
    std::string command = (spacePos == std::string::npos) ? normalized : normalized.substr(0, spacePos);
    const std::string args = (spacePos == std::string::npos) ? std::string() : trim(normalized.substr(spacePos + 1));

    // v3 user-facing verb aliases map to the canonical wire verbs so the CLI
    // ("bless"/"unbless") and the on-wire protocol stop diverging.
    if (command == "bless")
    {
        command = "register";
    }
    else if (command == "unbless")
    {
        command = "unregister";
    }

    if (command == "register")
    {
        const std::vector<std::string> fields = splitByChar(args, '|');
        if (fields.size() < 2)
        {
            return "ERR invalid register payload";
        }

        DWORD pid = 0;
        if (!parsePid(trim(fields[0]), pid))
        {
            return "ERR invalid pid in register";
        }

        int maxRestarts = kDefaultMaxRestarts;
        if (fields.size() >= 3 && !parseMaxRestarts(trim(fields[2]), maxRestarts))
        {
            return "ERR invalid max-restarts";
        }

        // restartArgs is base64-encoded on the wire so '|', newlines and
        // leading/trailing spaces survive intact (path is also base64). The
        // declared hash is a hex string with no '|'.
        const std::string restartArgs = (fields.size() >= 4) ? base64Decode(fields[3]) : std::string();
        const std::string declaredHash = (fields.size() >= 5) ? trim(fields[4]) : std::string();

        // v3 optional advanced guard policy. Field positions 5..10:
        //   restart-window|restart-delay|backoff|hang-timeout|kill-on-exit|appKind
        // Field 11 is a base64 AUMID (only meaningful when appKind=winapp).
        // All default to legacy behaviour (Win32, lifetime restart count).
        int restartWindowSec = 0;
        {
            DWORD v = 0;
            if (fields.size() >= 6 && util::parseDwordValue(trim(fields[5]), v))
            {
                restartWindowSec = static_cast<int>(v);
            }
        }
        int restartDelayMs = 0;
        {
            DWORD v = 0;
            if (fields.size() >= 7 && util::parseDwordValue(trim(fields[6]), v))
            {
                restartDelayMs = static_cast<int>(v);
            }
        }
        bool backoff = false;
        if (fields.size() >= 8)
        {
            const std::string bv = trim(fields[7]);
            backoff = (bv == "1" || bv == "true" || bv == "yes");
        }
        int hangTimeoutMs = 0;
        {
            DWORD v = 0;
            if (fields.size() >= 9 && util::parseDwordValue(trim(fields[8]), v))
            {
                hangTimeoutMs = static_cast<int>(v);
            }
        }
        bool killOnExit = false;
        if (fields.size() >= 10)
        {
            const std::string bv = trim(fields[9]);
            killOnExit = (bv == "1" || bv == "true" || bv == "yes");
        }
        AppKind appKind = AppKind::Win32;
        if (fields.size() >= 11)
        {
            const std::string low = toLowerAscii(trim(fields[10]));
            if (low == "1" || low == "winapp" || low == "uwp" || low == "store")
            {
                appKind = AppKind::WinApp;
            }
        }
        std::string aumid;
        if (fields.size() >= 12)
        {
            aumid = base64Decode(fields[11]);
        }

        return handleRegister(pid, trim(fields[1]), maxRestarts, restartArgs, declaredHash,
                              appKind, aumid, restartWindowSec, restartDelayMs, backoff,
                              hangTimeoutMs, killOnExit);
    }

    if (command == "intentional")
    {
        DWORD pid = 0;
        if (!parsePid(args, pid))
        {
            return "ERR invalid pid for intentional";
        }
        return handleIntentionalExit(pid);
    }

    if (command == "unregister")
    {
        DWORD pid = 0;
        if (!parsePid(args, pid))
        {
            return "ERR invalid pid for unregister";
        }
        return handleUnregister(pid);
    }

    if (command == "set-policy")
    {
        const std::vector<std::string> fields = splitByChar(args, '|');
        if (fields.size() < 2)
        {
            return "ERR invalid set-policy payload";
        }
        DWORD pid = 0;
        if (!parsePid(trim(fields[0]), pid))
        {
            return "ERR invalid pid in set-policy";
        }
        int maxRestarts = -1;
        if (!parseMaxRestarts(trim(fields[1]), maxRestarts))
        {
            return "ERR invalid max-restarts in set-policy";
        }
        const std::string restartArgs = (fields.size() >= 3) ? base64Decode(fields[2]) : std::string();
        return handleSetPolicy(pid, maxRestarts, restartArgs);
    }

    if (command == "set-token")
    {
        const std::vector<std::string> fields = splitByChar(args, '|');
        if (fields.size() < 2)
        {
            return "ERR invalid set-token payload";
        }
        return handleSetToken(trim(fields[0]), trim(fields[1]));
    }

    if (command == "list")
    {
        return handleList();
    }

    if (command == "get")
    {
        DWORD pid = 0;
        if (!parsePid(args, pid))
        {
            return "ERR invalid pid for get";
        }
        return handleGet(pid);
    }

    if (command == "module")
    {
        return handleModuleCommand(args);
    }

    if (command == "ppl")
    {
        return handlePplCommand(args);
    }

    if (command == "ping")
    {
        return "OK pong protocol=3";
    }

    if (command == "version")
    {
        // Protocol version. v3 adds advanced policy fields and WindowsApps;
        // min=2 means v2 clients (no advanced fields) still register fine.
        return "OK protocol=3 min=2";
    }

    if (command == "stats")
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        std::size_t totalRestarts = 0;
        std::size_t windowedRestarts = 0;
        const std::int64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        for (const auto &entry : m_guards)
        {
            const auto pit = m_policyByGuardId.find(entry.second.guardId);
            if (pit == m_policyByGuardId.end())
            {
                continue;
            }
            totalRestarts += static_cast<std::size_t>(pit->second.restartCount);
            const int win = entry.second.restartWindowSec;
            if (win > 0 && !pit->second.recentRestartMs.empty())
            {
                windowedRestarts += static_cast<std::size_t>(
                    util::pruneRestartWindow(pit->second.recentRestartMs, nowMs, win).size());
            }
        }
        std::size_t active = 0;
        for (const auto &entry : m_guards)
        {
            if (entry.second.handle && WaitForSingleObject(entry.second.handle, 0) == WAIT_TIMEOUT)
            {
                ++active;
            }
        }
        const auto uptimeSec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - m_startTime).count();
        return "OK guards=" + std::to_string(m_guards.size()) +
               " active=" + std::to_string(active) +
               " totalRestarts=" + std::to_string(totalRestarts) +
               " restartsInWindow=" + std::to_string(windowedRestarts) +
               " uptime=" + std::to_string(uptimeSec) +
               " protocol=3";
    }

    return "ERR unknown command";
}

std::string PGS::handleRegister(
    DWORD pid,
    const std::string &encodedPath,
    int maxRestarts,
    const std::string &restartArgs,
    const std::string &declaredHash,
    AppKind appKind,
    const std::string &aumid,
    int restartWindowSec,
    int restartDelayMs,
    bool backoff,
    int hangTimeoutMs,
    bool killOnExit)
{
    // Registration is the trust boundary between clients and the service. The
    // service re-derives everything important that it can:
    // - decode the requested path
    // - query the real image path from pid
    // - verify the two paths match
    // - optionally compute and validate the file hash
    // - open its own synchronization handle
    //
    // That way the guard record stored in memory reflects the actual process
    // being watched, not merely what the client claimed.
    const std::string requestedPath = base64Decode(encodedPath);
    if (requestedPath.empty())
    {
        Logger::warning("PGS: empty decoded path for pid=" + std::to_string(pid));
        return "ERR empty decoded path";
    }

    // Never trust the client supplied path as the source of truth.
    //
    // The CLI may provide a path for convenience, but the service must verify
    // that the pid actually points at the same image. Otherwise a caller could
    // ask PGS to monitor pid=A while later restarting executable=B.
    std::string actualPath;
    if (!queryProcessPath(pid, actualPath))
    {
        Logger::warning("PGS: failed to query image path for pid=" + std::to_string(pid));
        return "ERR failed to query process image path";
    }

    const std::string requestedNormalized = normalizePathForCompare(requestedPath);
    const std::string actualNormalized = normalizePathForCompare(actualPath);
    if (requestedNormalized.empty() || actualNormalized.empty() || requestedNormalized != actualNormalized)
    {
        Logger::warning("PGS: register rejected, path mismatch for pid=" + std::to_string(pid) +
                        ", requested=" + requestedPath + ", actual=" + actualPath);
        return "ERR pid/path mismatch";
    }

    std::string actualHash;
    const bool hasActualHash = computeFileHash(actualPath, actualHash);
    bool hashVerified = false;
    if (!declaredHash.empty())
    {
        if (!hasActualHash)
        {
            return "ERR failed to compute file hash";
        }
        hashVerified = (toLowerAscii(actualHash) == toLowerAscii(declaredHash));
        if (!hashVerified)
        {
            Logger::warning("PGS: register rejected, hash mismatch for path=" + actualPath);
            return "ERR hash mismatch";
        }
    }

    HANDLE processHandle = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!processHandle)
    {
        Logger::warning("PGS: OpenProcess failed for pid=" + std::to_string(pid) + ", error=" + std::to_string(GetLastError()));
        return "ERR OpenProcess failed";
    }

    DWORD sessionId = 0xFFFFFFFF;
    ProcessIdToSessionId(pid, &sessionId);

    const std::string storedHash = declaredHash.empty() ? actualHash : declaredHash;
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto existing = m_guards.find(pid);

        // Preserve guard identity across re-registers of the same live pid.
        // This matters when policy is updated or when a client re-submits the
        // same guard with refreshed metadata.
        const std::uint64_t guardId = (existing != m_guards.end()) ? existing->second.guardId : m_nextGuardId++;
        GuardInfo updated{
            pid,
            sessionId,
            actualPath,
            maxRestarts,
            restartArgs,
            storedHash,
            processHandle,
            false,
            hashVerified,
            guardId,
            appKind,
            aumid,
            restartWindowSec,
            restartDelayMs,
            backoff,
            hangTimeoutMs,
            killOnExit,
            nullptr};

        if (existing != m_guards.end())
        {
            if (existing->second.handle)
            {
                CloseHandle(existing->second.handle);
            }
            existing->second = updated;
        }
        else
        {
            m_guards.emplace(pid, std::move(updated));
        }

        // v3: assign the live process to a per-guard Job Object so the monitor
        // can observe the whole process family and TerminateJobObject the
        // family on restart. Harmless if it fails (poll-based exit detection
        // still works); assignGuardToJob logs the reason.
        assignGuardToJob(m_guards[pid]);

        auto policyIt = m_policyByGuardId.find(guardId);
        if (policyIt == m_policyByGuardId.end())
        {
            m_policyByGuardId.emplace(guardId, RestartPolicyState{maxRestarts, 0, {}});
        }
        else
        {
            policyIt->second.maxRestarts = maxRestarts;
        }

        auto &persisted = m_persistedGuards[guardId];
        persisted.guardId = guardId;
        persisted.lastKnownPid = pid;
        persisted.sessionId = sessionId;
        persisted.path = actualPath;
        persisted.maxRestarts = maxRestarts;
        persisted.restartArgs = restartArgs;
        persisted.fileHash = storedHash;
        persisted.intentional = false;
        persisted.hashVerified = hashVerified;
        persisted.appKind = appKind;
        persisted.aumid = aumid;
        persisted.restartWindowSec = restartWindowSec;
        persisted.restartDelayMs = restartDelayMs;
        persisted.backoff = backoff;
        persisted.hangTimeoutMs = hangTimeoutMs;
        persisted.killOnExit = killOnExit;
    }

    persistState();

    Logger::warning("PGS: registered guard pid=" + std::to_string(pid) +
                    ", path=" + actualPath +
                    ", max-restarts=" + maxRestartsLabel(maxRestarts) +
                    ", hash=" + (storedHash.empty() ? std::string("<none>") : storedHash));

    return "OK registered pid=" + std::to_string(pid);
}

std::string PGS::handleIntentionalExit(DWORD pid)
{
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        const auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            Logger::warning("PGS: intentional exit for unknown pid=" + std::to_string(pid));
            return "ERR pid not found";
        }

        it->second.intentional = true;
        auto persisted = m_persistedGuards.find(it->second.guardId);
        if (persisted != m_persistedGuards.end())
        {
            persisted->second.intentional = true;
        }
    }

    persistState();
    Logger::warning("PGS: marked intentional exit for pid=" + std::to_string(pid));
    return "OK intentional marked pid=" + std::to_string(pid);
}

std::string PGS::handleUnregister(DWORD pid)
{
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            return "ERR pid not found";
        }

        const std::uint64_t guardId = it->second.guardId;
        if (it->second.handle)
        {
            CloseHandle(it->second.handle);
        }
        m_guards.erase(it);
        m_policyByGuardId.erase(guardId);
        m_persistedGuards.erase(guardId);
        // v3: stop observing this guard's Job Object. The guarded process is
        // left running - "unregister" means stop protecting, not kill. Closing
        // PGS's job handle leaves the process alive; the kernel job lingers
        // until the last process in it exits. See docs/GUARD_POLICIES.md.
        closeGuardJob(guardId);
    }

    persistState();
    Logger::warning("PGS: unregistered pid=" + std::to_string(pid));
    return "OK unregistered pid=" + std::to_string(pid);
}

std::string PGS::handleSetPolicy(DWORD pid, int maxRestarts, const std::string &restartArgs)
{
    {
        std::lock_guard<std::mutex> lock(m_guardsMutex);
        auto it = m_guards.find(pid);
        if (it == m_guards.end())
        {
            return "ERR pid not found";
        }

        it->second.maxRestarts = maxRestarts;
        it->second.restartArgs = restartArgs;
        auto &policy = m_policyByGuardId[it->second.guardId];
        policy.maxRestarts = maxRestarts;
        auto persisted = m_persistedGuards.find(it->second.guardId);
        if (persisted != m_persistedGuards.end())
        {
            persisted->second.maxRestarts = maxRestarts;
            persisted->second.restartArgs = restartArgs;
        }
    }

    persistState();
    Logger::warning("PGS: updated policy pid=" + std::to_string(pid) +
                    ", max=" + maxRestartsLabel(maxRestarts));
    return "OK policy updated pid=" + std::to_string(pid);
}

std::string PGS::handleSetToken(const std::string &encodedOldToken, const std::string &encodedNewToken)
{
    const std::string oldToken = base64Decode(encodedOldToken);
    const std::string newToken = base64Decode(encodedNewToken);
    const std::string oldHash = sha256Hex(oldToken);
    const std::string newHash = sha256Hex(newToken);

    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        if (!constantTimeEquals(oldHash, m_authTokenHash))
        {
            return "ERR old token mismatch";
        }

        m_authTokenHash = toLowerAscii(newHash);
    }

    persistState();
    Logger::warning("PGS: auth token updated in-memory and persisted");
    return "OK token updated";
}

std::string PGS::handleList()
{
    std::lock_guard<std::mutex> lock(m_guardsMutex);
    std::ostringstream oss;
    oss << "OK count=" << m_guards.size();
    for (const auto &entry : m_guards)
    {
        const auto policyIt = m_policyByGuardId.find(entry.second.guardId);
        const int restartCount = (policyIt == m_policyByGuardId.end()) ? 0 : policyIt->second.restartCount;
        oss << "\n" << makeGuardSummaryLine(entry.second, restartCount);
    }
    return oss.str();
}

std::string PGS::handleGet(DWORD pid)
{
    std::lock_guard<std::mutex> lock(m_guardsMutex);
    const auto it = m_guards.find(pid);
    if (it == m_guards.end())
    {
        return "ERR pid not found";
    }
    const auto policyIt = m_policyByGuardId.find(it->second.guardId);
    const int restartCount = (policyIt == m_policyByGuardId.end()) ? 0 : policyIt->second.restartCount;
    return "OK\n" + makeGuardSummaryLine(it->second, restartCount);
}

std::string PGS::makeGuardSummaryLine(const GuardInfo &guard, int restartCount)
{
    const bool alive = (guard.handle && WaitForSingleObject(guard.handle, 0) == WAIT_TIMEOUT);
    std::ostringstream oss;
    oss << "PID=" << guard.pid
        << ";SESSION=" << guard.sessionId
        << ";ALIVE=" << (alive ? "1" : "0")
        << ";INTENTIONAL=" << (guard.intentional ? "1" : "0")
        << ";MAX_RESTARTS=" << maxRestartsLabel(guard.maxRestarts)
        << ";RESTART_COUNT=" << restartCount
        << ";HASH_VERIFIED=" << (guard.hashVerified ? "1" : "0")
        << ";HASH=" << (guard.fileHash.empty() ? "-" : guard.fileHash)
        << ";PATH_B64=" << base64Encode(guard.path)
        << ";RESTART_ARGS_B64=" << base64Encode(guard.restartArgs)
        << ";APP_KIND=" << (guard.appKind == AppKind::WinApp ? "winapp" : "win32")
        << ";AUMID_B64=" << base64Encode(guard.aumid)
        << ";RESTART_WINDOW=" << guard.restartWindowSec
        << ";RESTART_DELAY=" << guard.restartDelayMs
        << ";BACKOFF=" << (guard.backoff ? "1" : "0")
        << ";HANG_TIMEOUT=" << guard.hangTimeoutMs
        << ";KILL_ON_EXIT=" << (guard.killOnExit ? "1" : "0");
    return oss.str();
}

bool PGS::stripAuthEnvelope(const std::string &message, std::string &commandLine) const
{
    // Authentication envelope: "token <base64(token)> <commandLine>". The token
    // is base64-encoded so it may contain arbitrary bytes/spaces; the service
    // only stores and compares a SHA-256 hash in memory. An empty token is never
    // accepted (initialize() always establishes a non-empty token).
    commandLine = trim(message);
    if (commandLine.empty())
    {
        return false;
    }
    if (!m_requireAuth)
    {
        return true;
    }

    if (commandLine.rfind("token ", 0) != 0)
    {
        return false;
    }

    const std::size_t tokenStart = 6;
    const std::size_t tokenEnd = commandLine.find(' ', tokenStart);
    if (tokenEnd == std::string::npos)
    {
        return false;
    }

    const std::string encodedToken = commandLine.substr(tokenStart, tokenEnd - tokenStart);
    const std::string token = base64Decode(encodedToken);
    if (token.empty())
    {
        return false;
    }
    const std::string inputHash = sha256Hex(token);
    std::lock_guard<std::mutex> lock(m_authMutex);
    if (!constantTimeEquals(inputHash, m_authTokenHash))
    {
        return false;
    }

    commandLine = trim(commandLine.substr(tokenEnd + 1));
    return !commandLine.empty();
}

std::string PGS::handleModuleCommand(const std::string &args)
{
    // Sub-protocol: "module <sub> <rest>"
    //   list
    //   load <base64-path>
    //   unload <name>
    //   call <name> <kv-request>
    const auto spacePos = args.find(' ');
    const std::string sub = (spacePos == std::string::npos) ? args : args.substr(0, spacePos);
    const std::string rest = (spacePos == std::string::npos) ? std::string() : trim(args.substr(spacePos + 1));

    if (sub == "list")
    {
        const auto mods = m_modules.list();
        std::string out = "OK count=" + std::to_string(mods.size());
        for (const auto &m : mods)
        {
            out += "\n" + m.name + "\t" + m.version;
        }
        return out;
    }

    if (sub == "load")
    {
        if (rest.empty())
        {
            return "ERR module load requires a base64 path";
        }
        const std::string path = base64Decode(rest);
        if (path.empty())
        {
            return "ERR invalid base64 path";
        }
        // Security: only allow loading DLLs that live inside the service's
        // modules directory. Without this, any authenticated client could
        // LoadLibrary an arbitrary DLL into the (LocalSystem) service process
        // and run code as SYSTEM.
        if (!isPathInsideModulesDir(path))
        {
            Logger::warning("PGS: rejected module load outside modules dir, path=" + path);
            return "ERR module load restricted to modules directory";
        }
        std::string err;
        if (m_modules.load(path, err))
        {
            return "OK loaded";
        }
        return "ERR " + err;
    }

    if (sub == "unload")
    {
        if (rest.empty())
        {
            return "ERR module unload requires a name";
        }
        std::string err;
        if (m_modules.unload(rest, err))
        {
            return "OK unloaded " + rest;
        }
        return "ERR " + err;
    }

    if (sub == "call")
    {
        // "call <name> <kv>"
        const auto sp = rest.find(' ');
        if (sp == std::string::npos)
        {
            return "ERR module call requires <name> <request>";
        }
        const std::string name = rest.substr(0, sp);
        const std::string request = trim(rest.substr(sp + 1));
        std::string response;
        std::string err;
        if (m_modules.invoke(name, request, response, err))
        {
            return response;
        }
        return "ERR " + err;
    }

    return "ERR unknown module subcommand";
}

// "ppl" convenience dispatcher. Routes to the ppl module so callers do not
// need the module-call syntax. If the ppl module is not loaded, returns
// "ERR ppl module not loaded" instead of a transport error.
std::string PGS::handlePplCommand(const std::string &args)
{
    // Convenience wrapper that routes to the "ppl" module so callers do not
    // need to remember the module-call syntax:
    //   ppl set <pid> <signer>
    //   ppl get <pid>
    //   ppl clear <pid>
    const auto spacePos = args.find(' ');
    const std::string sub = (spacePos == std::string::npos) ? args : args.substr(0, spacePos);
    const std::string rest = (spacePos == std::string::npos) ? std::string() : trim(args.substr(spacePos + 1));

    if (sub == "set")
    {
        // "set <pid> <signer>"
        const auto sp = rest.find(' ');
        if (sp == std::string::npos)
        {
            return "ERR ppl set requires <pid> <signer>";
        }
        DWORD pid = 0;
        if (!parsePid(trim(rest.substr(0, sp)), pid))
        {
            return "ERR invalid pid for ppl set";
        }
        const std::string signer = trim(rest.substr(sp + 1));
        if (signer.empty())
        {
            return "ERR ppl set requires a signer";
        }
        std::string request = "op=set;pid=" + std::to_string(pid) + ";signer=" + signer;
        std::string response;
        std::string err;
        if (m_modules.invoke("ppl", request, response, err))
        {
            return response;
        }
        return "ERR ppl module not loaded";
    }

    if (sub == "get" || sub == "clear")
    {
        DWORD pid = 0;
        if (!parsePid(rest, pid))
        {
            return "ERR invalid pid for ppl " + sub;
        }
        std::string request = "op=" + sub + ";pid=" + std::to_string(pid);
        std::string response;
        std::string err;
        if (m_modules.invoke("ppl", request, response, err))
        {
            return response;
        }
        return "ERR ppl module not loaded";
    }

    return "ERR unknown ppl subcommand";
}

} // namespace ProcessGuard
