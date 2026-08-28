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
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
/**/
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__
#    include <grp.h>
#    include <linux/capability.h>
#    include <sched.h>
#    include <sys/prctl.h>
#    include <sys/syscall.h>
#endif

#include "ndppd.h"

extern bool nd_iface_no_restore_flags;

#ifndef NDPPD_CONFIG_PATH
#    define NDPPD_CONFIG_PATH "/opt/unidoc/etc/unidoc-ndppd.conf"
#endif

long nd_current_time;
bool nd_daemonized;

bool nd_opt_daemonize;
char *nd_opt_config_path;
char *nd_opt_pidfile_path;
char *nd_opt_user;

static bool ndL_check_pidfile()
{
    int fd = open(nd_opt_pidfile_path, O_RDWR);

    if (fd == -1) {
        if (errno == ENOENT) {
            return true;
        }

        return false;
    }

    bool result = flock(fd, LOCK_EX | LOCK_NB) == 0;
    close(fd);
    return result;
}

static bool ndL_daemonize()
{
    int fd = open(nd_opt_pidfile_path, O_WRONLY | O_CREAT, 0644);

    if (fd == -1) {
        return false;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        close(fd);
        return false;
    }

    pid_t pid = fork();

    if (pid < 0) {
        // logger::error() << "Failed to fork during daemonize: " << logger::err();
        return false;
    }

    if (pid > 0) {
        char buf[21];
        int len = snprintf(buf, sizeof(buf), "%d", pid);

        if (ftruncate(fd, 0) == -1) {
            nd_log_error("Failed to write PID file: ftruncate(): %s", strerror(errno));
        } else if (write(fd, buf, len) != len) {
            nd_log_error("Failed to write PID file: write(): %s", strerror(errno));
        }

        /* The child daemon owns the packet socket. Tell the atexit cleanup not to remove
         * interface memberships (PROMISC) from the shared socket — the child still needs them. */
        nd_iface_no_restore_flags = true;
        exit(0);
    }

    umask(0);

    pid_t sid = setsid();
    if (sid < 0) {
        // logger::error() << "Failed to setsid during daemonize: " << logger::err();
        return false;
    }

    if (chdir("/") < 0) {
        // logger::error() << "Failed to change path during daemonize: " << logger::err();
        return false;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return true;
}

static void ndL_exit()
{
    nd_iface_cleanup();
    nd_rt_cleanup();
    nd_alloc_cleanup();
}

/* Signal handler runs from async context — only async-signal-safe operations here.
 * A volatile sig_atomic_t flag is the standard idiom; the main loop polls it and
 * shuts down cleanly, letting atexit(ndL_exit) run outside the signal context. */
static volatile sig_atomic_t ndL_stop;

static void ndL_sig_exit(__attribute__((unused)) int sig)
{
    ndL_stop = 1;
}

#ifdef __linux__
/* Self-contained /etc/passwd / /etc/group lookups — avoids libnss so the static
 * binary drops onto any Linux distro (musl or glibc) without runtime deps. */

static bool ndL_all_digits(const char *s)
{
    if (!*s)
        return false;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9')
            return false;
    return true;
}

/* Return field N (0-indexed) of a colon-separated line, or NULL if not present.
 * Writes into out (must be at least out_size bytes). */
static bool ndL_split_field(const char *line, int n, char *out, size_t out_size)
{
    const char *start = line;
    for (int i = 0; i < n; i++) {
        start = strchr(start, ':');
        if (!start)
            return false;
        start++;
    }
    const char *end = strchr(start, ':');
    if (!end)
        end = start + strlen(start);
    size_t len = (size_t)(end - start);
    while (len > 0 && (start[len - 1] == '\n' || start[len - 1] == '\r'))
        len--;
    if (len >= out_size)
        return false;
    memcpy(out, start, len);
    out[len] = '\0';
    return true;
}

static bool ndL_lookup_user(const char *name, uid_t *uid_out, gid_t *gid_out)
{
    FILE *fp = fopen("/etc/passwd", "r");
    if (!fp) {
        nd_log_error("Failed to open /etc/passwd: %s", strerror(errno));
        return false;
    }

    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        char field[128];
        if (!ndL_split_field(line, 0, field, sizeof(field)))
            continue;
        if (strcmp(field, name) != 0)
            continue;

        char uid_str[32], gid_str[32];
        if (!ndL_split_field(line, 2, uid_str, sizeof(uid_str)) ||
            !ndL_split_field(line, 3, gid_str, sizeof(gid_str)))
            break;

        if (!ndL_all_digits(uid_str) || !ndL_all_digits(gid_str))
            break;

        *uid_out = (uid_t)strtoul(uid_str, NULL, 10);
        *gid_out = (gid_t)strtoul(gid_str, NULL, 10);
        found = true;
        break;
    }

    fclose(fp);
    if (!found)
        nd_log_error("User \"%s\" not found in /etc/passwd", name);
    return found;
}

static bool ndL_lookup_group(const char *name, gid_t *gid_out)
{
    FILE *fp = fopen("/etc/group", "r");
    if (!fp) {
        nd_log_error("Failed to open /etc/group: %s", strerror(errno));
        return false;
    }

    char line[512];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        char field[128];
        if (!ndL_split_field(line, 0, field, sizeof(field)))
            continue;
        if (strcmp(field, name) != 0)
            continue;

        char gid_str[32];
        if (!ndL_split_field(line, 2, gid_str, sizeof(gid_str)))
            break;
        if (!ndL_all_digits(gid_str))
            break;

        *gid_out = (gid_t)strtoul(gid_str, NULL, 10);
        found = true;
        break;
    }

    fclose(fp);
    if (!found)
        nd_log_error("Group \"%s\" not found in /etc/group", name);
    return found;
}

/* Convert a decimal string to an unsigned long, rejecting overflow and negatives.
 * Caller has already verified the string is all-digits (so no sign / whitespace). */
static bool ndL_parse_ulong(const char *s, unsigned long max, unsigned long *out)
{
    errno = 0;
    char *end;
    unsigned long v = strtoul(s, &end, 10);
    if (*end != '\0' || (v == ULONG_MAX && errno == ERANGE) || v > max) {
        nd_log_error("Numeric ID \"%s\" out of range (max %lu)", s, max);
        return false;
    }
    *out = v;
    return true;
}

/* Parse "user[:group]" where each part may be numeric or a name.
 * - "65534"           → uid=65534, gid=65534
 * - "65534:100"       → uid=65534, gid=100
 * - "nobody"          → looked up in /etc/passwd (uid + primary gid)
 * - "nobody:nogroup"  → uid from /etc/passwd, gid from /etc/group
 * - "nobody:100"      → uid from /etc/passwd, gid=100 (numeric override)
 * - "65534:nogroup"   → uid=65534, gid from /etc/group
 */
static bool ndL_parse_userspec(const char *spec, uid_t *uid_out, gid_t *gid_out)
{
    if (!spec[0]) {
        nd_log_error("Empty --user spec");
        return false;
    }

    char user_part[128];
    const char *colon = strchr(spec, ':');
    const char *group_part = NULL;

    if (colon) {
        /* Reject a second colon: "nobody:nogroup:extra" is a config typo, not a fallback. */
        if (strchr(colon + 1, ':')) {
            nd_log_error("Invalid --user spec \"%s\": more than one ':' separator", spec);
            return false;
        }
        size_t n = (size_t)(colon - spec);
        if (n == 0) {
            nd_log_error("Invalid --user spec \"%s\": empty user before ':'", spec);
            return false;
        }
        if (n >= sizeof(user_part)) {
            nd_log_error("--user name too long: \"%s\"", spec);
            return false;
        }
        memcpy(user_part, spec, n);
        user_part[n] = '\0';
        group_part = colon + 1;
        if (!*group_part) {
            nd_log_error("Invalid --user spec \"%s\": empty group after ':'", spec);
            return false;
        }
    } else {
        size_t n = strlen(spec);
        if (n >= sizeof(user_part)) {
            nd_log_error("--user name too long: \"%s\"", spec);
            return false;
        }
        memcpy(user_part, spec, n + 1);
    }

    /* uid_t / gid_t are typically 32-bit unsigned on Linux. */
    const unsigned long id_max = 0xFFFFFFFEUL;

    /* Resolve user (uid + fallback gid if only name given). */
    uid_t uid;
    gid_t gid;
    if (ndL_all_digits(user_part)) {
        unsigned long v;
        if (!ndL_parse_ulong(user_part, id_max, &v))
            return false;
        uid = (uid_t)v;
        gid = (gid_t)v; /* fallback if no explicit group */
    } else {
        if (!ndL_lookup_user(user_part, &uid, &gid))
            return false;
    }

    /* Resolve explicit group if provided. */
    if (group_part) {
        if (ndL_all_digits(group_part)) {
            unsigned long v;
            if (!ndL_parse_ulong(group_part, id_max, &v))
                return false;
            gid = (gid_t)v;
        } else {
            if (!ndL_lookup_group(group_part, &gid))
                return false;
        }
    }

    *uid_out = uid;
    *gid_out = gid;
    return true;
}

/* Drop from root to an unprivileged uid/gid while retaining CAP_NET_RAW (opening new
 * AF_PACKET sockets when interfaces come and go) and CAP_NET_ADMIN (route insert/remove
 * via netlink).  Limits blast radius from any future packet-parsing bug — a compromised
 * process no longer yields full root. */
static bool ndL_drop_privileges(const char *userspec)
{
    uid_t uid;
    gid_t gid;

    if (!ndL_parse_userspec(userspec, &uid, &gid))
        return false;

    if (uid == 0) {
        nd_log_error("Refusing to drop privileges to uid 0");
        return false;
    }

    /* PR_SET_KEEPCAPS keeps the permitted set alive across setresuid — without it,
     * the kernel drops all capabilities the moment we leave uid 0. */
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
        nd_log_error("prctl(PR_SET_KEEPCAPS): %s", strerror(errno));
        return false;
    }

    if (setgroups(1, &gid) < 0) {
        nd_log_error("setgroups: %s", strerror(errno));
        return false;
    }

    if (setresgid(gid, gid, gid) < 0) {
        nd_log_error("setresgid: %s", strerror(errno));
        return false;
    }

    if (setresuid(uid, uid, uid) < 0) {
        nd_log_error("setresuid: %s", strerror(errno));
        return false;
    }

    /* Restrict the capability set to what we still need.  Anything else — including
     * CAP_SYS_ADMIN (netns) that we may have used earlier — is permanently dropped. */
    struct __user_cap_header_struct hdr = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct data[2] = { { 0 } };
    uint32_t mask = (1U << CAP_NET_RAW) | (1U << CAP_NET_ADMIN);
    data[0].effective = mask;
    data[0].permitted = mask;
    data[0].inheritable = 0;

    if (syscall(SYS_capset, &hdr, data) < 0) {
        nd_log_error("capset: %s", strerror(errno));
        return false;
    }

    nd_log_info("Dropped to uid=%u gid=%u with CAP_NET_RAW+CAP_NET_ADMIN",
                (unsigned)uid, (unsigned)gid);
    return true;
}

__attribute__((unused)) static bool ndL_netns(const char *name)
{
    char net_path[128];
    snprintf(net_path, sizeof(net_path), "/var/run/netns/%s", name);

    int fd = open(net_path, O_RDONLY | O_CLOEXEC);

    if (fd < 0) {
        nd_log_error("Cannot open network namespace \"%s\": %s\n", name, strerror(errno));
        return false;
    }

    if (setns(fd, CLONE_NEWNET) < 0) {
        nd_log_error("Could not set network namespace \"%s\": %s\n", name, strerror(errno));
        close(fd);
        return false;
    }

    close(fd);
    return true;
}
#endif

int main(int argc, char *argv[])
{
    atexit(ndL_exit);
    signal(SIGINT, ndL_sig_exit);
    signal(SIGTERM, ndL_sig_exit);
    /* SIGPIPE would default-terminate the daemon if a write ever hits a closed
     * socket.  Ignore it — write() then returns EPIPE which our error paths log. */
    signal(SIGPIPE, SIG_IGN);

#ifdef __linux__
    char *netns = NULL;
#endif

    static struct option long_options[] = {
        { "config", 1, 0, 'c' },  //
        { "daemon", 0, 0, 'd' },  //
        { "verbose", 0, 0, 'v' }, //
        { "syslog", 0, 0, 1 },    //
        { "pidfile", 1, 0, 'p' }, //
        { "user", 1, 0, 'u' },    //
#ifdef __linux__
        { "netns", 1, 0, 2 },
#endif
        { NULL, 0, 0, 0 },
    };

    for (int ch; (ch = getopt_long(argc, argv, "c:dp:u:v", long_options, NULL)) != -1;) {
        switch (ch) {
        case 'c':
            nd_opt_config_path = nd_strdup(optarg);
            break;

        case 'd':
            nd_opt_daemonize = true;
            break;

        case 'v':
            if (nd_opt_verbosity < ND_LOG_TRACE)
                nd_opt_verbosity++;
            break;

        case 'p':
            nd_opt_pidfile_path = nd_strdup(optarg);
            break;

        case 'u':
            nd_opt_user = nd_strdup(optarg);
            break;

        case 1:
            nd_opt_syslog = true;
            break;

#ifdef __linux__
        case 2:
            if (netns) {
                fprintf(stderr, "--netns can only be specified once");
                return EXIT_FAILURE;
            }
            netns = nd_strdup(optarg);
            break;
#endif

        default:
            break;
        }
    }

    struct timeval t1;
    gettimeofday(&t1, 0);
    nd_current_time = t1.tv_sec * 1000 + t1.tv_usec / 1000;

    nd_log_info("unidoc-ndppd " NDPPD_VERSION);

    if (nd_opt_pidfile_path && !ndL_check_pidfile()) {
        nd_log_error("Failed to lock pidfile. Is ndppd already running?");
        return EXIT_FAILURE;
    }

    if (nd_opt_config_path == NULL)
        nd_opt_config_path = NDPPD_CONFIG_PATH;

    nd_log_info("Loading configuration \"%s\"...", nd_opt_config_path);

    if (!nd_conf_load(nd_opt_config_path))
        return EXIT_FAILURE;

#ifdef __linux__
    if (netns && !ndL_netns(netns))
        return EXIT_FAILURE;
#endif

    if (!nd_iface_startup())
        return EXIT_FAILURE;

    if (!nd_proxy_startup())
        return EXIT_FAILURE;

    if (!nd_rt_open())
        return EXIT_FAILURE;

#ifdef __linux__
    /* Drop privileges AFTER opening sockets that need root, BEFORE daemonize (so the
     * pidfile gets ownership by the target user).  Anything we do later — dynamic
     * nd_iface_open on new interfaces, route insert/remove — is covered by the
     * retained CAP_NET_RAW+CAP_NET_ADMIN. */
    if (nd_opt_user && !ndL_drop_privileges(nd_opt_user))
        return EXIT_FAILURE;
#else
    if (nd_opt_user) {
        nd_log_error("--user is only supported on Linux; use jails / capsicum on FreeBSD");
        return EXIT_FAILURE;
    }
#endif

    if (nd_opt_daemonize && !ndL_daemonize())
        return EXIT_FAILURE;

    nd_rt_query_routes();
    bool querying_routes = true;

    long last_session_update = 0;
    long last_iface_check = 0;
    int exit_code = EXIT_SUCCESS;

    for (;;) {
        if (ndL_stop) {
            nd_log_info("Received termination signal, shutting down");
            break;
        }

        if (nd_current_time >= nd_rt_dump_timeout)
            nd_rt_dump_timeout = 0;

        if (querying_routes && !nd_rt_dump_timeout) {
            querying_routes = false;
            nd_rt_remove_owned_routes();
            nd_rt_query_addresses();
        }

        if (nd_current_time - last_session_update > 100) {
            nd_session_update_all();
            last_session_update = nd_current_time;
        }

        /* Safety-net periodic rebind. Netlink RTM_NEWLINK/DELLINK events
         * are the primary trigger (see rt.c ndL_io_handler), but netlink
         * can drop messages under load and there are races between socket
         * bind and interface recreate. Polling every 5 s guarantees the
         * daemon reconverges to reality within one interval, which is the
         * "must not fail silently" property that this whole rebind path
         * exists to enforce. Cheap: O(#proxied ifaces × 2 syscalls). */
        if (nd_current_time - last_iface_check > 5000) {
            nd_iface_rebind_all();
            last_iface_check = nd_current_time;
        }

        if (!nd_io_poll()) {
            nd_log_error("Event loop failed, exiting");
            exit_code = EXIT_FAILURE;
            break;
        }

        gettimeofday(&t1, 0);
        nd_current_time = t1.tv_sec * 1000 + t1.tv_usec / 1000;
    }

    return exit_code;
}
