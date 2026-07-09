/*
 * SchedCron.cpp - cron expression parser + next-fire computation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "SchedCron.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <ctime>

namespace pgs_sched
{
    namespace
    {
        // Split a single field by comma into raw tokens ("1,5,10" -> ["1","5","10"]).
        std::vector<std::string> splitComma(const std::string &field)
        {
            std::vector<std::string> out;
            std::string cur;
            for (char c : field)
            {
                if (c == ',')
                {
                    if (!cur.empty())
                        out.push_back(cur);
                    cur.clear();
                }
                else
                {
                    cur.push_back(c);
                }
            }
            if (!cur.empty())
                out.push_back(cur);
            return out;
        }

        // Parse one token (no commas) into the allowed values for `field`,
        // adding results to `out`. A bare star means "any" and adds NOTHING
        // (an empty field set is interpreted as any by the matcher); this is
        // required for correct Vixie-cron DOM/DOW OR semantics. Returns false
        // on malformed input.
        bool parseToken(const std::string &token, int lo, int hi, std::vector<int> &out)
        {
            std::string t = token;
            t.erase(std::remove_if(t.begin(), t.end(), [](unsigned char c) { return std::isspace(c); }), t.end());
            if (t.empty())
                return false;

            int step = 1;
            std::string rangePart = t;
            bool hasSlash = false;
            std::size_t slash = t.find('/');
            if (slash != std::string::npos)
            {
                hasSlash = true;
                rangePart = t.substr(0, slash);
                std::string stepText = t.substr(slash + 1);
                for (char c : stepText)
                    if (c < '0' || c > '9')
                        return false;
                step = std::atoi(stepText.c_str());
                if (step <= 0)
                    return false;
            }

            // Bare star with no step => any (empty set). star/n => stepped full range.
            if (rangePart == "*")
            {
                if (!hasSlash)
                    return true; // empty = any
                for (int v = lo; v <= hi; v += step)
                    out.push_back(v);
                return true;
            }

            int begin = lo, end = hi;
            std::size_t dash = rangePart.find('-');
            if (dash != std::string::npos)
            {
                std::string a = rangePart.substr(0, dash);
                std::string b = rangePart.substr(dash + 1);
                for (char c : a + b)
                    if (c < '0' || c > '9')
                        return false;
                begin = std::atoi(a.c_str());
                end = std::atoi(b.c_str());
                if (begin < lo || end > hi || begin > end)
                    return false;
            }
            else
            {
                for (char c : rangePart)
                    if (c < '0' || c > '9')
                        return false;
                begin = std::atoi(rangePart.c_str());
                if (begin < lo || begin > hi)
                    return false;
                end = begin;
            }

            for (int v = begin; v <= end; v += step)
                out.push_back(v);
            return true;
        }

        // Parse one full field (may contain commas) into sorted unique values.
        // An all-star field yields an empty set (any). Returns false only when
        // the field is blank or a token is malformed.
        bool parseField(const std::string &field, int lo, int hi, std::vector<int> &out)
        {
            std::vector<std::string> tokens = splitComma(field);
            if (tokens.empty())
                return false;
            std::vector<int> acc;
            for (const std::string &tok : tokens)
            {
                if (!parseToken(tok, lo, hi, acc))
                    return false;
            }
            std::sort(acc.begin(), acc.end());
            acc.erase(std::unique(acc.begin(), acc.end()), acc.end());
            out = acc;
            return true;
        }

        // A field matches a value when it is empty (any) or contains the value.
        inline bool matchField(const std::vector<int> &v, int x)
        {
            return v.empty() || std::binary_search(v.begin(), v.end(), x);
        }
    } // namespace

    bool parseCron(const std::string &expr, CronExpr &out)
    {
        std::vector<std::string> fields;
        std::string cur;
        for (char c : expr)
        {
            if (std::isspace(static_cast<unsigned char>(c)))
            {
                if (!cur.empty())
                {
                    fields.push_back(cur);
                    cur.clear();
                }
            }
            else
            {
                cur.push_back(c);
            }
        }
        if (!cur.empty())
            fields.push_back(cur);
        if (fields.size() != 5)
            return false;

        out = CronExpr{};
        if (!parseField(fields[0], 0, 59, out.minutes))
            return false;
        if (!parseField(fields[1], 0, 23, out.hours))
            return false;
        if (!parseField(fields[2], 1, 31, out.doms))
            return false;
        if (!parseField(fields[3], 1, 12, out.months))
            return false;
        if (!parseField(fields[4], 0, 6, out.dows))
            return false;
        return true;
    }

    long long nextRunMs(const CronExpr &e, long long afterMs)
    {
        // Start one second after afterMs (>= afterMs, exclusive of the instant).
        long long startSec = afterMs / 1000;
            // First whole-minute boundary strictly after afterMs. If afterMs already
            // sits on a minute boundary, the next fire is the following minute;
            // otherwise round up to the next minute.
            long long rem = afterMs % 60000LL;
            if (rem == 0)
                startSec += 60;
            else
                startSec += (60000LL - rem) / 1000LL;
        std::tm t{};
        std::time_t probe0 = static_cast<std::time_t>(startSec);
#if defined(_WIN32)
        if (localtime_s(&t, &probe0) != 0)
            return -1;
#else
        if (!localtime_r(&probe0, &t))
            return -1;
#endif
        t.tm_sec = 0;
        std::time_t probe = std::mktime(&t);
        if (probe == static_cast<std::time_t>(-1))
            return -1;

        const long long maxIters = 4LL * 366 * 24 * 60; // ~4 years
        for (long long i = 0; i < maxIters; ++i)
        {
            std::tm cur{};
            std::time_t p = probe;
#if defined(_WIN32)
            if (localtime_s(&cur, &p) != 0)
                return -1;
#else
            if (!localtime_r(&p, &cur))
                return -1;
#endif
            if (matchField(e.minutes, cur.tm_min) &&
                matchField(e.hours, cur.tm_hour) &&
                matchField(e.months, cur.tm_mon + 1))
            {
                bool domRestricted = !e.doms.empty();
                bool dowRestricted = !e.dows.empty();
                bool dayMatches;
                if (domRestricted && dowRestricted)
                    dayMatches = matchField(e.doms, cur.tm_mday) || matchField(e.dows, cur.tm_wday);
                else if (domRestricted)
                    dayMatches = matchField(e.doms, cur.tm_mday);
                else if (dowRestricted)
                    dayMatches = matchField(e.dows, cur.tm_wday);
                else
                    dayMatches = true;

                if (dayMatches)
                    return static_cast<long long>(probe) * 1000LL;
            }
            probe += 60; // next minute
        }
        return -1;
    }

} // namespace pgs_sched
