/*
 * SchedCron.h - cron expression parser + next-fire computation for pgs_sched.
 *
 * Supports the standard 5-field cron form: "minute hour dom month dow".
 * Each field accepts: star (any), a-b (range), a,b,c (list), star/n (step),
 * and plain numbers. DOM and DOW are OR-ed (cron semantics): a fire time is
 * accepted if it matches DOM-or-DOW when both are restricted (Vixie cron
 * behaviour). Month/dow names are NOT supported (numeric only) to keep the
 * parser dependency-free.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef PGS_SCHED_CRON_H
#define PGS_SCHED_CRON_H

#include <cstdint>
#include <string>
#include <vector>

namespace pgs_sched
{

    // A compiled cron expression. nextRunMs computes the next firing time >=
    // `afterMs` (epoch millis). Returns -1 on parse failure. All fields are
    // sets of allowed values; an empty set means "any".
    struct CronExpr
    {
        std::vector<int> minutes;   // 0-59
        std::vector<int> hours;     // 0-23
        std::vector<int> doms;      // 1-31
        std::vector<int> months;    // 1-12
        std::vector<int> dows;      // 0-6 (0=Sunday)

        bool empty() const
        {
            return minutes.empty() && hours.empty() && doms.empty() &&
                   months.empty() && dows.empty();
        }
    };

    // Parse "m h dom mon dow" into CronExpr. Returns false on malformed input.
    bool parseCron(const std::string &expr, CronExpr &out);

    // Compute the next epoch-millisecond time >= afterMs at which the cron
    // expression fires. Searches forward up to ~4 years; returns -1 if none
    // found (e.g. impossible date like Feb 31). Uses the system's local time
    // breakdown (std::mktime) so DST/timezone follow the host.
    long long nextRunMs(const CronExpr &e, long long afterMs);

} // namespace pgs_sched

#endif // PGS_SCHED_CRON_H
