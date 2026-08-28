/*
 * This file is part of unidoc-ndppd.
 *
 * Copyright (C) 2011-2019  Daniel Adolfsson <daniel@ashen.se>
 *
 * unidoc-ndppd is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * unidoc-ndppd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with unidoc-ndppd.  If not, see <https://www.gnu.org/licenses/>.
 */
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "ndppd.h"

bool ndL_syslog_opened;

nd_loglevel_t nd_opt_verbosity = ND_LOG_INFO;
bool nd_opt_syslog;

static void ndL_open_syslog()
{
    if (ndL_syslog_opened) {
        return;
    }

    setlogmask(LOG_UPTO(LOG_DEBUG));
    openlog("unidoc-ndppd", LOG_CONS | LOG_NDELAY | LOG_PERROR | LOG_PID, LOG_DAEMON);
    ndL_syslog_opened = true;
}

__attribute__((format(printf, 2, 3))) void nd_log_printf(nd_loglevel_t level, const char *fmt, ...)
{
    assert(level >= 0 && level <= ND_LOG_TRACE);

    if (level > nd_opt_verbosity)
        return;

    if (nd_daemonized || nd_opt_syslog)
        ndL_open_syslog();

    char buf[512];

    va_list va;
    va_start(va, fmt);

    /* fmt is checked at each callsite via the printf format attribute above;
     * the internal vprintf forwarder pattern trips -Wformat-nonliteral falsely. */
#if defined(__clang__)
#    pragma clang diagnostic push
#    pragma clang diagnostic ignored "-Wformat-nonliteral"
#elif defined(__GNUC__)
#    pragma GCC diagnostic push
#    pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
    int rc = vsnprintf(buf, sizeof(buf), fmt, va);
#if defined(__clang__)
#    pragma clang diagnostic pop
#elif defined(__GNUC__)
#    pragma GCC diagnostic pop
#endif

    va_end(va);

    if (rc < 0) {
        /* vsnprintf failed — log a short marker rather than aborting.  Truncation
         * (rc >= sizeof(buf)) is fine; buf is still valid up to sizeof(buf)-1. */
        const char *marker = "<log format error>";
        size_t n = sizeof(buf) - 1;
        size_t m = strlen(marker);
        if (m > n) m = n;
        memcpy(buf, marker, m);
        buf[m] = '\0';
    }

    if (ndL_syslog_opened) {
        const int pris[] = { LOG_ERR, LOG_INFO, LOG_DEBUG, LOG_DEBUG };
        syslog(pris[level], "%s", buf);
    } else {
        const char *names[] = { "error", "info", "debug", "trace" };

        time_t time = nd_current_time / 1000;

        struct tm tm;
        localtime_r(&time, &tm);

        char time_buf[32];
        strftime(time_buf, sizeof(time_buf), "%F %T", &tm);

        printf("%s.%03ld | %-8s | %s\n", time_buf, nd_current_time % 1000, names[level], buf);
    }
}
