/*
 * pgs_sched_module.cpp - PGS scheduled-task module (ABI v2).
 *
 * Provides cron / one-shot / interval scheduling of restricted PGS commands.
 * On PG_Init it receives a PGS_Services* so it can fire actions back into PGS
 * from its own background thread. Schedule state is persisted to
 * pgs_sched.db next to this DLL and reloaded across PGS restarts.
 *
 * Request KV examples (forwarded by PGS "module call sched ..." / the CLI
 * "schedule" subcommand):
 *   op=add;type=cron;expr=star/2 star star star star;action=bless 1234|-1
 *   op=add;type=once;expr=2026-07-09T15:30:00;action=unbless 1234
 *   op=add;type=interval;expr=300;count=5;action=policy 1234|no
 *   op=list
 *   op=remove;id=7
 *   op=enable;id=7
 *   op=disable;id=7
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#define PG_MODULE_EXPORTS

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <limits>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "Process_Guard/PGModule.h"
#include "SchedCron.h"

namespace
{
    // ---- KV helpers (same style as the ppl module) ----
    std::string kvValue(const std::string &kv, const std::string &key)
    {
        std::string needle = key + "=";
        std::size_t pos = kv.find(needle);
        if (pos == std::string::npos)
            return std::string();
        pos += needle.size();
        std::size_t end = kv.find(';', pos);
        return (end == std::string::npos) ? kv.substr(pos) : kv.substr(pos, end - pos);
    }

    std::string trim(std::string s)
    {
        const char *ws = " \t\r\n";
        s.erase(0, s.find_first_not_of(ws));
        s.erase(s.find_last_not_of(ws) + 1);
        return s;
    }

    bool parseInt(const std::string &s, long long &out)
    {
        std::string t = trim(s);
        if (t.empty())
            return false;
        try
        {
            size_t idx = 0;
            long long v = std::stoll(t, &idx);
            if (idx != t.size())
                return false;
            out = v;
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    constexpr long long kMaxIntervalSeconds = std::numeric_limits<long long>::max() / 1000LL;

    bool parseIntervalSeconds(const std::string &s, long long &out)
    {
        return parseInt(s, out) && out > 0 && out <= kMaxIntervalSeconds;
    }

    bool intervalSecondsToMilliseconds(long long seconds, long long &outMs)
    {
        if (seconds <= 0 || seconds > kMaxIntervalSeconds)
            return false;
        outMs = seconds * 1000LL;
        return true;
    }

    bool addMillisecondsChecked(long long baseMs, long long deltaMs, long long &outMs)
    {
        if (baseMs < 0 || deltaMs < 0)
            return false;
        if (baseMs > std::numeric_limits<long long>::max() - deltaMs)
            return false;
        outMs = baseMs + deltaMs;
        return true;
    }

    void setResponse(char *buf, size_t bufsize, const std::string &msg)
    {
        if (!buf || bufsize == 0)
            return;
        size_t n = msg.size();
        if (n >= bufsize)
            n = bufsize - 1;
        std::memcpy(buf, msg.c_str(), n);
        buf[n] = '\0';
    }

    // ---- Action allowlist: only guard-management verbs, no privilege-escalation ----
    // Commands a schedule may execute. Explicitly excludes token-set / module
    // load|unload / service install|stop|uninstall / ppl (kernel driver). This
    // prevents a tampered schedule file from escalating privileges or unloading
    // modules.
    bool isActionAllowed(const std::string &action)
    {
        std::string a = trim(action);
        if (a.empty())
            return false;
        // First token is the service wire verb. bless-start/start-bless are
        // CLI-side flows that launch a process before sending register, so a
        // scheduler action cannot execute them through PGS_Services::call.
        std::string verb;
        std::size_t sp = a.find(' ');
        verb = (sp == std::string::npos) ? a : a.substr(0, sp);
        return verb == "bless" || verb == "register" ||
               verb == "unbless" || verb == "unregister" ||
               verb == "policy" || verb == "set-policy" ||
               verb == "intentional" ||
               verb == "list" || verb == "get" || verb == "ping";
    }

    // ---- Schedule record ----
    enum class SchedType { Cron, Once, Interval };

    struct Schedule
    {
        long long id = 0;
        SchedType type = SchedType::Cron;
        std::string expr;        // cron string / ISO8601 timepoint / interval seconds
        std::string action;      // PGS wire command to fire
        bool enabled = true;
        long long lastRunMs = 0;
        long long nextRunMs = 0;
        long long runCount = 0;
        long long maxCount = 0;  // 0 = unlimited (for interval); ignored for cron
        // compiled cron (only for type==Cron)
        pgs_sched::CronExpr cron;
        bool cronValid = false;
    };

    // ---- Module state ----
    PGS_Services g_svc{};
    bool g_svcReady = false;
    std::string g_moduleDir;        // directory of this DLL (for pgs_sched.db)
    std::mutex g_mtx;
    std::map<long long, Schedule> g_schedules;
    std::atomic<long long> g_nextId{1};
    std::atomic<bool> g_stopThread{false};
    std::thread g_thread;
    std::atomic<bool> g_threadRunning{false};
    std::string g_dbPath;

    // ---- Time helpers (use services->now_ms when available, else local) ----
    long long nowMs()
    {
        if (g_svcReady && g_svc.now_ms)
            return g_svc.now_ms(g_svc.context);
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER u;
        u.LowPart = ft.dwLowDateTime;
        u.HighPart = ft.dwHighDateTime;
        return static_cast<long long>((u.QuadPart - 116444736000000000ULL) / 10000ULL);
    }

    // Parse ISO8601 "YYYY-MM-DDTHH:MM:SS" (local time) into epoch millis.
    // Returns -1 on failure.
    long long parseIso8601(const std::string &s)
    {
        std::string t = trim(s);
        // Accept "YYYY-MM-DDTHH:MM:SS" or "YYYY-MM-DD HH:MM:SS"
        if (t.size() != 19)
            return -1;
        for (size_t i = 0; i < t.size(); ++i)
        {
            char c = t[i];
            if (i == 4 || i == 7)
            {
                if (c != '-')
                    return -1;
            }
            else if (i == 10)
            {
                if (c != 'T' && c != ' ')
                    return -1;
            }
            else if (i == 13 || i == 16)
            {
                if (c != ':')
                    return -1;
            }
            else if (c < '0' || c > '9')
                return -1;
        }
        int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
        try
        {
            year = std::stoi(t.substr(0, 4));
            month = std::stoi(t.substr(5, 2));
            day = std::stoi(t.substr(8, 2));
            hour = std::stoi(t.substr(11, 2));
            minute = std::stoi(t.substr(14, 2));
            second = std::stoi(t.substr(17, 2));
        }
        catch (...)
        {
            return -1;
        }
        std::tm tmv{};
        tmv.tm_year = year - 1900;
        tmv.tm_mon = month - 1;
        tmv.tm_mday = day;
        tmv.tm_hour = hour;
        tmv.tm_min = minute;
        tmv.tm_sec = second;
        tmv.tm_isdst = -1;
        std::time_t tt = std::mktime(&tmv);
        if (tt == static_cast<std::time_t>(-1))
            return -1;
        std::tm roundtrip{};
        if (localtime_s(&roundtrip, &tt) != 0)
            return -1;
        if (roundtrip.tm_year != year - 1900 || roundtrip.tm_mon != month - 1 ||
            roundtrip.tm_mday != day || roundtrip.tm_hour != hour ||
            roundtrip.tm_min != minute || roundtrip.tm_sec != second)
            return -1;
        if (static_cast<long long>(tt) > std::numeric_limits<long long>::max() / 1000LL)
            return -1;
        return static_cast<long long>(tt) * 1000LL;
    }

} // namespace

#ifdef PGS_ENABLE_TEST_HOOKS
namespace pgs_sched_test
{
    long long parseIso8601ForTest(const std::string &s)
    {
        return parseIso8601(s);
    }

    bool parseIntervalSecondsForTest(const std::string &s, long long &out)
    {
        return parseIntervalSeconds(s, out);
    }

    long long intervalSecondsLimitForTest()
    {
        return kMaxIntervalSeconds;
    }
} // namespace pgs_sched_test
#endif

#ifndef PGS_ENABLE_TEST_HOOKS
namespace
{

    // ---- Persistence: simple KV file, one record per line ----
    // Format: id;type;expr;action;enabled;lastRunMs;nextRunMs;runCount;maxCount
    // expr/action may not contain ';' or newline (rejected on add).
    std::string escapeField(const std::string &s)
    {
        // We disallow ';' and '\n' at input time, so no escaping needed.
        return s;
    }

    std::string dbPathFor()
    {
        if (!g_moduleDir.empty())
            return g_moduleDir + "\\pgs_sched.db";
        return "pgs_sched.db";
    }

    void persistSchedulesLocked()
    {
        std::string path = g_dbPath;
        std::string tmp = path + ".tmp";
        std::ofstream out(tmp, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!out.is_open())
            return;
        out << "# PGS schedule db v1\n";
        for (const auto &p : g_schedules)
        {
            const Schedule &s = p.second;
            const char *typeStr =
                (s.type == SchedType::Cron) ? "cron" :
                (s.type == SchedType::Once) ? "once" : "interval";
            out << s.id << ';' << typeStr << ';' << escapeField(s.expr) << ';'
                << escapeField(s.action) << ';' << (s.enabled ? 1 : 0) << ';'
                << s.lastRunMs << ';' << s.nextRunMs << ';' << s.runCount << ';'
                << s.maxCount << '\n';
        }
        out.close();
        // Atomic replace
        if (!MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            std::cerr << "PGS sched: failed to replace db file: " << path << "\n";
        }
    }

    void persistSchedules()
    {
        std::lock_guard<std::mutex> lock(g_mtx);
        persistSchedulesLocked();
    }

    void loadSchedules()
    {
        std::ifstream in(g_dbPath);
        if (!in.is_open())
            return;
        std::string line;
        long long maxId = 0;
        std::lock_guard<std::mutex> lock(g_mtx);
        g_schedules.clear();
        while (std::getline(in, line))
        {
            if (line.empty() || line[0] == '#')
                continue;
            std::vector<std::string> f;
            std::string cur;
            for (char c : line)
            {
                if (c == ';')
                {
                    f.push_back(cur);
                    cur.clear();
                }
                else
                {
                    cur.push_back(c);
                }
            }
            f.push_back(cur);
            if (f.size() != 9)
                continue;
            Schedule s;
            long long idv = 0, lastRun = 0, nextRun = 0, runCount = 0, maxCount = 0;
            if (!parseInt(f[0], idv))
                continue;
            s.id = idv;
            if (f[1] == "cron")
                s.type = SchedType::Cron;
            else if (f[1] == "once")
                s.type = SchedType::Once;
            else if (f[1] == "interval")
                s.type = SchedType::Interval;
            else
                continue;
            s.expr = f[2];
            s.action = f[3];
            if (!isActionAllowed(s.action))
                continue;
            s.enabled = (f[4] == "1");
            if (!parseInt(f[5], lastRun))
                continue;
            s.lastRunMs = lastRun;
            if (!parseInt(f[6], nextRun))
                continue;
            s.nextRunMs = nextRun;
            if (!parseInt(f[7], runCount))
                continue;
            s.runCount = runCount;
            if (!parseInt(f[8], maxCount))
                continue;
            s.maxCount = maxCount;
            if (s.type == SchedType::Cron)
            {
                s.cronValid = pgs_sched::parseCron(s.expr, s.cron);
            }
            // Recompute nextRun for cron/interval if it is in the past (the
            // service was down). `once` keeps its nextRun so the missed-run
            // policy can decide to fire it once on restart.
            long long now = nowMs();
            if (s.type == SchedType::Cron)
            {
                if (s.cronValid)
                    s.nextRunMs = pgs_sched::nextRunMs(s.cron, now);
                else
                    s.nextRunMs = 0;
            }
            else if (s.type == SchedType::Interval)
            {
                // Roll forward to the first future boundary >= now, honoring
                // maxCount. We do NOT replay missed intervals (avoid storm).
                long long interval = 0;
                long long intervalMs = 0;
                if (parseIntervalSeconds(s.expr, interval) && intervalSecondsToMilliseconds(interval, intervalMs))
                {
                    if (s.nextRunMs < 0)
                    {
                        s.nextRunMs = 0;
                    }
                    else if (s.nextRunMs < now)
                    {
                        long long delta = now - s.nextRunMs;
                        long long remainder = delta % intervalMs;
                        long long advance = (remainder == 0) ? intervalMs : (intervalMs - remainder);
                        long long nextRun = 0;
                        if (addMillisecondsChecked(now, advance, nextRun))
                            s.nextRunMs = nextRun;
                        else
                            s.nextRunMs = 0;
                    }
                }
                else
                {
                    s.nextRunMs = 0;
                }
            }
            // once: if already disabled (fired) or in the future, keep; if in
            // the past and still enabled, leave nextRunMs so the worker fires
            // it once on restart (missed-run policy for one-shots).
            g_schedules[s.id] = s;
            if (idv > maxId)
                maxId = idv;
        }
        g_nextId.store(maxId + 1);
    }

    // ---- Next-run computation for a freshly added schedule ----
    long long computeInitialNextRun(Schedule &s, long long now)
    {
        if (s.type == SchedType::Cron)
        {
            if (!s.cronValid)
                return 0;
            return pgs_sched::nextRunMs(s.cron, now);
        }
        if (s.type == SchedType::Once)
        {
            long long t = parseIso8601(s.expr);
            if (t < 0)
                return 0;
            return t;
        }
        // interval: first fire = now + interval
        long long interval = 0;
        long long intervalMs = 0;
        long long nextRun = 0;
        if (!parseIntervalSeconds(s.expr, interval) || !intervalSecondsToMilliseconds(interval, intervalMs) ||
            !addMillisecondsChecked(now, intervalMs, nextRun))
            return 0;
        return nextRun;
    }

    // ---- Fire an action: call PGS via services ----
    void fireAction(const Schedule &s)
    {
        if (!g_svcReady || !g_svc.call)
            return;
        char resp[8192] = {0};
        g_svc.call(g_svc.context, s.action.c_str(), resp, sizeof(resp));
        // Response intentionally discarded; the worker logs nothing to avoid
        // pulling a logger dependency into this module. Operators can observe
        // effects via `pgs_bless list` / the audit stream.
    }

    // ---- Background worker thread ----
    void workerLoop()
    {
        g_threadRunning = true;
        while (!g_stopThread.load())
        {
            long long now = nowMs();
            std::vector<Schedule> due;
            {
                std::lock_guard<std::mutex> lock(g_mtx);
                for (auto &p : g_schedules)
                {
                    Schedule &s = p.second;
                    if (!s.enabled || s.nextRunMs <= 0)
                        continue;
                    if (s.nextRunMs <= now)
                        due.push_back(s);
                }
            }

            bool changed = false;
            for (const Schedule &s : due)
            {
                fireAction(s);
                std::lock_guard<std::mutex> lock(g_mtx);
                auto it = g_schedules.find(s.id);
                if (it == g_schedules.end())
                    continue;
                Schedule &cur = it->second;
                cur.lastRunMs = now;
                cur.runCount += 1;
                if (cur.type == SchedType::Once)
                {
                    // One-shot: disable after firing.
                    cur.enabled = false;
                    cur.nextRunMs = 0;
                }
                else if (cur.type == SchedType::Interval)
                {
                    // Honor maxCount: if maxCount>0 and reached, retire.
                    if (cur.maxCount > 0 && cur.runCount >= cur.maxCount)
                    {
                        cur.enabled = false;
                        cur.nextRunMs = 0;
                    }
                    else
                    {
                        long long interval = 0;
                        long long intervalMs = 0;
                        long long nextRun = 0;
                        if (parseIntervalSeconds(cur.expr, interval) &&
                            intervalSecondsToMilliseconds(interval, intervalMs) &&
                            addMillisecondsChecked(now, intervalMs, nextRun))
                            cur.nextRunMs = nextRun;
                        else
                        {
                            cur.enabled = false;
                            cur.nextRunMs = 0;
                        }
                    }
                }
                else // Cron
                {
                    cur.nextRunMs = cur.cronValid ? pgs_sched::nextRunMs(cur.cron, now) : 0;
                }
                changed = true;
            }
            if (changed)
                persistSchedules();

            // Poll at 1s granularity (cron is minute-granular; this is enough
            // for interval/once while staying cheap).
            for (int i = 0; i < 10 && !g_stopThread.load(); ++i)
                Sleep(100);
        }
        g_threadRunning = false;
    }

    void startThread()
    {
        if (g_threadRunning.load())
            return;
        g_stopThread = false;
        g_thread = std::thread(workerLoop);
    }

    void stopThread()
    {
        g_stopThread = true;
        if (g_thread.joinable())
            g_thread.join();
    }

    // ---- Resolve module dir (beside this DLL) for pgs_sched.db ----
    std::string moduleDirOf(HMODULE self)
    {
        wchar_t path[MAX_PATH] = {0};
        DWORD len = GetModuleFileNameW(self, path, MAX_PATH);
        if (len == 0 || len >= MAX_PATH)
            return "";
        std::wstring w(path);
        std::size_t slash = w.find_last_of(L"\\/");
        return (slash == std::wstring::npos) ? std::string(".") : std::string(w.begin(), w.begin() + slash);
    }
} // namespace

extern "C" BOOL WINAPI DllMain(HINSTANCE hInstDLL, DWORD reason, LPVOID /*reserved*/)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hInstDLL);
        g_moduleDir = moduleDirOf(hInstDLL);
        g_dbPath = dbPathFor();
    }
    return TRUE;
}

PG_MODULE_API const char *PG_GetName(void) { return "sched"; }
PG_MODULE_API const char *PG_GetVersion(void) { return "1.0.0"; }
PG_MODULE_API unsigned int PG_GetAbiVersion(void) { return PG_MODULE_ABI_VERSION; }

PG_MODULE_API int PG_Init(void *reserved)
{
    // ABI v2: receive the services struct.
    if (reserved != nullptr)
    {
        PGS_Services *svc = static_cast<PGS_Services *>(reserved);
        g_svc = *svc;
        g_svcReady = (g_svc.call != nullptr);
    }
    // Load persisted schedules, then (re)compute next-run times for the
    // current clock. Missed-run policy is applied in loadSchedules().
    loadSchedules();
    startThread();
    return 0;
}

PG_MODULE_API void PG_Shutdown(void)
{
    stopThread();
    persistSchedules();
}

// op=add;type=<cron|once|interval>;expr=<...>;action=<...>[;count=<N>]
// op=list
// op=remove;id=<N>
// op=enable;id=<N>
// op=disable;id=<N>
PG_MODULE_API int PG_Invoke(const char *request, char *responseBuf, size_t responseBufSize)
{
    std::string req = request ? request : "";
    std::string op = trim(kvValue(req, "op"));

    if (op == "add")
    {
        std::string type = trim(kvValue(req, "type"));
        std::string expr = trim(kvValue(req, "expr"));
        std::string action = trim(kvValue(req, "action"));
        std::string countText = trim(kvValue(req, "count"));

        if (type.empty() || expr.empty() || action.empty())
        {
            setResponse(responseBuf, responseBufSize, "ERR missing type/expr/action");
            return 1;
        }
        if (expr.find(';') != std::string::npos || action.find(';') != std::string::npos ||
            expr.find('\n') != std::string::npos || action.find('\n') != std::string::npos)
        {
            setResponse(responseBuf, responseBufSize, "ERR expr/action may not contain ; or newline");
            return 1;
        }
        if (!isActionAllowed(action))
        {
            setResponse(responseBuf, responseBufSize, "ERR action not in allowlist: " + action);
            return 1;
        }

        Schedule s;
        s.expr = expr;
        s.action = action;
        if (type == "cron")
        {
            s.type = SchedType::Cron;
            s.cronValid = pgs_sched::parseCron(expr, s.cron);
            if (!s.cronValid)
            {
                setResponse(responseBuf, responseBufSize, "ERR invalid cron expression");
                return 1;
            }
        }
        else if (type == "once")
        {
            s.type = SchedType::Once;
            if (parseIso8601(expr) < 0)
            {
                setResponse(responseBuf, responseBufSize, "ERR invalid ISO8601 timepoint (use YYYY-MM-DDTHH:MM:SS)");
                return 1;
            }
        }
        else if (type == "interval")
        {
            s.type = SchedType::Interval;
            long long iv = 0;
            if (!parseIntervalSeconds(expr, iv))
            {
                setResponse(responseBuf, responseBufSize, "ERR interval expr must be positive seconds");
                return 1;
            }
            if (!countText.empty())
            {
                long long c = 0;
                if (!parseInt(countText, c) || c <= 0)
                {
                    setResponse(responseBuf, responseBufSize, "ERR count must be positive");
                    return 1;
                }
                s.maxCount = c;
            }
        }
        else
        {
            setResponse(responseBuf, responseBufSize, "ERR unknown type: " + type);
            return 1;
        }

        s.id = g_nextId.fetch_add(1);
        s.enabled = true;
        s.nextRunMs = computeInitialNextRun(s, nowMs());
        {
            std::lock_guard<std::mutex> lock(g_mtx);
            g_schedules[s.id] = s;
            persistSchedulesLocked();
        }
        setResponse(responseBuf, responseBufSize, "OK added id=" + std::to_string(s.id) + " next_run_ms=" + std::to_string(s.nextRunMs));
        return 0;
    }

    if (op == "list")
    {
        std::string out = "OK count=";
        std::lock_guard<std::mutex> lock(g_mtx);
        out += std::to_string(g_schedules.size());
        for (const auto &p : g_schedules)
        {
            const Schedule &s = p.second;
            const char *typeStr =
                (s.type == SchedType::Cron) ? "cron" :
                (s.type == SchedType::Once) ? "once" : "interval";
            out += "\nID=" + std::to_string(s.id) +
                   ";TYPE=" + typeStr +
                   ";EXPR=" + s.expr +
                   ";ACTION=" + s.action +
                   ";ENABLED=" + (s.enabled ? "1" : "0") +
                   ";LAST_RUN_MS=" + std::to_string(s.lastRunMs) +
                   ";NEXT_RUN_MS=" + std::to_string(s.nextRunMs) +
                   ";RUN_COUNT=" + std::to_string(s.runCount) +
                   ";MAX_COUNT=" + std::to_string(s.maxCount);
        }
        setResponse(responseBuf, responseBufSize, out);
        return 0;
    }

    if (op == "remove")
    {
        long long id = 0;
        if (!parseInt(kvValue(req, "id"), id))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid or missing id");
            return 1;
        }
        std::lock_guard<std::mutex> lock(g_mtx);
        if (g_schedules.erase(id) == 0)
        {
            setResponse(responseBuf, responseBufSize, "ERR no such schedule id");
            return 1;
        }
        persistSchedulesLocked();
        setResponse(responseBuf, responseBufSize, "OK removed id=" + std::to_string(id));
        return 0;
    }

    if (op == "enable" || op == "disable")
    {
        long long id = 0;
        if (!parseInt(kvValue(req, "id"), id))
        {
            setResponse(responseBuf, responseBufSize, "ERR invalid or missing id");
            return 1;
        }
        bool enable = (op == "enable");
        std::lock_guard<std::mutex> lock(g_mtx);
        auto it = g_schedules.find(id);
        if (it == g_schedules.end())
        {
            setResponse(responseBuf, responseBufSize, "ERR no such schedule id");
            return 1;
        }
        it->second.enabled = enable;
        if (enable)
        {
            // Recompute next run when re-enabling.
            it->second.nextRunMs = computeInitialNextRun(it->second, nowMs());
        }
        else
        {
            it->second.nextRunMs = 0;
        }
        persistSchedulesLocked();
        setResponse(responseBuf, responseBufSize, "OK " + op + "d id=" + std::to_string(id));
        return 0;
    }

    setResponse(responseBuf, responseBufSize, "ERR unknown op: " + op);
    return 1;
}
#endif // !PGS_ENABLE_TEST_HOOKS
