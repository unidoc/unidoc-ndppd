/* Session-layer test, built and asserted by `make test`.
 *
 * Links the REAL session.c / proxy.c / rule.c / addr.c / alloc.c / log.c and
 * stubs only the kernel-facing layer (iface send/open/close, rt route/address
 * table). Drives the session state machine on a fake clock exactly as the
 * main loop does (nd_session_update_all() every 100 ms) and feeds NS through
 * the real nd_proxy_handle_ns().
 *
 * The send_ns stub COUNTS calls with iface == NULL instead of crashing; the
 * real nd_iface_send_ns() dereferences iface->lladdr on its first line, so
 * any non-zero "ns_null" is a SIGSEGV in the daemon.
 *
 * Not modelled: packet I/O, netlink, the 5 s startup window before
 * nd_rt_query_addresses() fills the address table.
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "ndppd.h"

/* Globals owned by ndppd.c / conf.c in the real binary (conf.c defaults). */
bool nd_daemonized;
long nd_current_time;
int nd_conf_invalid_ttl = 10000;
int nd_conf_valid_ttl = 30000;
int nd_conf_stale_ttl = 30000;
int nd_conf_renew = 5000;
int nd_conf_retrans_limit = 3;
int nd_conf_retrans_time = 1000;
bool nd_conf_keepalive = false;

/* ---- stubs ---- */
static int ns_null, ns_sent, na_sent;
static bool local_addr_present = true;
static nd_addr_t local_addr;
static unsigned local_ifindex;

ssize_t nd_iface_send_ns(nd_iface_t *iface, const nd_addr_t *tgt)
{
    (void)tgt;
    if (!iface) {
        ns_null++; /* real code: NULL deref -> SIGSEGV */
        return -1;
    }
    ns_sent++;
    return 0;
}

ssize_t nd_iface_send_na(nd_iface_t *iface, const nd_addr_t *dst, const nd_lladdr_t *dst_ll, const nd_addr_t *tgt,
                         const nd_lladdr_t *tgt_ll, bool router)
{
    (void)iface, (void)dst, (void)dst_ll, (void)tgt, (void)tgt_ll, (void)router;
    na_sent++;
    return 0;
}

nd_iface_t *nd_iface_open(const char *n, unsigned i, bool p)
{
    (void)n, (void)i, (void)p;
    return NULL;
}
void nd_iface_close(nd_iface_t *iface) { iface->refcount--; }
nd_rt_route_t *nd_rt_find_route(const nd_addr_t *a, unsigned t)
{
    (void)a, (void)t;
    return NULL;
}
bool nd_rt_add_route(nd_addr_t *d, unsigned p, unsigned o, unsigned t)
{
    (void)d, (void)p, (void)o, (void)t;
    return true;
}
bool nd_rt_remove_route(nd_addr_t *d, unsigned p, unsigned t)
{
    (void)d, (void)p, (void)t;
    return true;
}
bool nd_rt_is_local_addr(unsigned index, const nd_addr_t *addr)
{
    return local_addr_present && index == local_ifindex && nd_addr_eq(addr, &local_addr);
}

/* ---- helpers ---- */
static nd_addr_t A(const char *s)
{
    nd_addr_t a;
    inet_pton(AF_INET6, s, &a);
    return a;
}

static nd_iface_t *fake_iface(const char *name, unsigned index, bool up)
{
    nd_iface_t *i = ND_NEW(nd_iface_t);
    *i = (nd_iface_t){ .refcount = 1, .index = index, .up = up };
    strcpy(i->name, name);
    return i;
}

static nd_rule_t *mkrule(nd_proxy_t *proxy, const char *pfx, int pflen, nd_mode_t mode, nd_iface_t *iface)
{
    nd_rule_t *r = nd_rule_create(proxy);
    r->addr = A(pfx);
    r->prefix = pflen;
    r->mode = mode;
    r->iface = iface;
    r->table = 254;
    return r;
}

static const nd_addr_t router = { .u8 = { 0xfe, 0x80, [15] = 0x99 } };
static const nd_lladdr_t router_ll = { .u8 = { 0x02, 0, 0, 0, 0, 0x99 } };

/* Advance the clock to `until`, ticking sessions every 100 ms like main(). */
static void run_until(long until)
{
    while (nd_current_time < until) {
        nd_current_time += 100;
        nd_session_update_all();
    }
}

/* Upstream router sends an NS for tgt; returns true if an NA went out. */
static bool router_ns(nd_proxy_t *proxy, const nd_addr_t *tgt)
{
    int before = na_sent;
    nd_proxy_handle_ns(proxy, &router, tgt, tgt, &router_ll);
    return na_sent > before;
}

/* ---- scenarios: each prints one joined outcome string ---- */

/* F1: rule `iface br0`, target = br0's own address, router re-solicits every 5 s. */
static void own_addr(bool remove_at_15s)
{
    nd_proxy_t *p = nd_proxy_create("up0");
    p->iface = fake_iface("up0", 2, true);
    nd_iface_t *br0 = fake_iface("br0", 7, true);
    mkrule(p, "2001:db8::", 64, ND_MODE_IFACE, br0);

    local_addr = A("2001:db8::1");
    local_ifindex = 7;
    nd_current_time = 100000;

    bool first = router_ns(p, &local_addr);
    bool last = false;
    for (long t = 105000; t <= 160000; t += 5000) {
        run_until(t);
        if (remove_at_15s && t == 115000)
            local_addr_present = false;
        last = router_ns(p, &local_addr);
    }
    run_until(161000);
    nd_session_t *s = nd_session_find(&local_addr, p);
    printf("answered_first=%s | answered_at_60s=%s | ns_on_null_iface=%d | state_at_60s=%d\n", first ? "yes" : "no",
           last ? "yes" : "no", ns_null, s ? (int)s->state : -1);
}

/* Pre-existing check: `static` rule, same NS cadence. */
static void static_rule(void)
{
    nd_proxy_t *p = nd_proxy_create("up0");
    p->iface = fake_iface("up0", 2, true);
    mkrule(p, "2001:db8::", 64, ND_MODE_STATIC, NULL);
    nd_addr_t tgt = A("2001:db8::42");
    nd_current_time = 100000;

    bool first = router_ns(p, &tgt);
    for (long t = 105000; t <= 160000; t += 5000) {
        run_until(t);
        router_ns(p, &tgt);
    }
    printf("answered_first=%s | ns_on_null_iface=%d\n", first ? "yes" : "no", ns_null);
}

/* F2: rule A's iface is absent (waiting); 4096 distinct targets solicited
 * (e.g. a scan of the proxied /64). 60 s later, can proxy B still create a session? */
static void cap_starvation(void)
{
    nd_proxy_t *pa = nd_proxy_create("upA");
    pa->iface = fake_iface("upA", 2, true);
    mkrule(pa, "2001:db8:a::", 64, ND_MODE_IFACE, fake_iface("gone0", 0, false));

    nd_proxy_t *pb = nd_proxy_create("upB");
    pb->iface = fake_iface("upB", 3, true);
    mkrule(pb, "2001:db8:b::", 64, ND_MODE_IFACE, fake_iface("br1", 8, true));

    nd_current_time = 100000;
    nd_addr_t base = A("2001:db8:a::");
    for (int i = 0; i < ND_SESSION_MAX; i++) {
        nd_addr_t t = base;
        t.u8[14] = (uint8_t)(i >> 8);
        t.u8[15] = (uint8_t)i;
        nd_proxy_handle_ns(pa, &router, &t, &t, &router_ll);
    }
    run_until(160000);

    int live = 0;
    for (int i = 0; i < ND_SESSION_MAX; i++) {
        nd_addr_t t = base;
        t.u8[14] = (uint8_t)(i >> 8);
        t.u8[15] = (uint8_t)i;
        live += nd_session_find(&t, pa) != NULL;
    }
    nd_addr_t tb = A("2001:db8:b::5");
    nd_proxy_handle_ns(pb, &router, &tb, &tb, &router_ll);
    printf("ruleA_live_sessions_at_60s=%d | proxyB_session_created=%s\n", live,
           nd_session_find(&tb, pb) ? "yes" : "no");
}

static void run(const char *name, void (*fn)(void))
{
    fflush(stdout);
    pid_t pid = fork();
    if (pid == 0) {
        printf("%-28s ", name);
        fn();
        fflush(stdout);
        _exit(0);
    }
    int st;
    waitpid(pid, &st, 0);
}

static void own_addr_keep(void) { own_addr(false); }
static void own_addr_removed(void) { own_addr(true); }

int main(void)
{
    nd_opt_verbosity = ND_LOG_ERROR;
    run("F1 own-address", own_addr_keep);
    run("F1 own-address removed@15s", own_addr_removed);
    run("static rule (pre-existing)", static_rule);
    run("F2 waiting-iface cap", cap_starvation);
    return 0;
}
