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
#include <string.h>

#include "ndppd.h"

extern int nd_conf_invalid_ttl;
extern int nd_conf_valid_ttl;
extern int nd_conf_stale_ttl;
extern int nd_conf_renew;
extern int nd_conf_retrans_limit;
extern int nd_conf_retrans_time;
extern bool nd_conf_keepalive;

#ifndef NDPPD_SESSION_BUCKETS
#    define NDPPD_SESSION_BUCKETS 64
#endif

#define NDL_BUCKET(a) (nd_addr_hash(a) % NDPPD_SESSION_BUCKETS)

static nd_session_t *ndL_sessions[NDPPD_SESSION_BUCKETS];
static nd_session_t *ndL_sessions_r[NDPPD_SESSION_BUCKETS];
static int ndL_session_count;

static void ndL_up(nd_session_t *session)
{
    if (session->iface && !session->autowired && session->rule->autowire) {
        nd_rt_add_route(&session->tgt, 128, session->iface->index, session->rule->table);
        session->autowired = true;
    }
}

static void ndL_down(nd_session_t *session)
{
    if (session->iface && session->autowired) {
        nd_rt_remove_route(&session->tgt, 128, session->rule->table);
        session->autowired = false;
    }
}

void nd_session_handle_ns(nd_session_t *session, const nd_addr_t *src, const nd_lladdr_t *src_ll)
{
    session->ins_time = nd_current_time;

    if (session->state == ND_STATE_VALID) {
        nd_lladdr_t *tgt_ll = !nd_lladdr_is_unspecified(&session->rule->target) ? &session->rule->target : NULL;

        /* DAD (unspecified source) or unicast NS without SLLAO: respond to all-nodes multicast. */
        if (nd_addr_is_unspecified(src) || !src_ll) {
            static const nd_lladdr_t allnodes_ll = { .u8 = { 0x33, 0x33, [5] = 1 } };
            static const nd_addr_t allnodes = { .u8 = { 0xff, 0x02, [15] = 1 } };
            nd_iface_send_na(session->rule->proxy->iface, &allnodes, &allnodes_ll,
                             &session->tgt, tgt_ll, session->rule->proxy->router);
        } else {
            nd_iface_send_na(session->rule->proxy->iface, src, src_ll, &session->tgt, tgt_ll,
                             session->rule->proxy->router);
        }
        return;
    }

    /* INCOMPLETE, STALE, INVALID: cannot confirm reachability yet — queue the subscriber
     * and wait for a fresh NA from the target before responding with OVERRIDE. */
    if (!src_ll) {
        nd_log_debug("session %s %s: no src_ll (DAD/no SLLAO) and state=%d, drop NS",
                     session->rule->proxy->ifname, nd_ntoa(&session->tgt), session->state);
        return;
    }

    nd_sub_t *sub;
    ND_LL_SEARCH(session->subs, sub, next, nd_addr_eq(&sub->addr, src) && nd_lladdr_eq(&sub->lladdr, src_ll));

    if (!sub) {
        /* Cap subscriber list to bound memory under NS flood from spoofed (src, src_ll) pairs. */
        int sub_count = 0;
        ND_LL_COUNT(session->subs, sub_count, next);
        if (sub_count >= ND_SESSION_MAX_SUBS) {
            nd_log_debug("session %s %s: sub list full (%d), dropping NS from %s",
                         session->rule->proxy->ifname, nd_ntoa(&session->tgt), sub_count, nd_ntoa(src));
            return;
        }
        sub = ND_NEW(nd_sub_t);
        sub->addr = *src;
        sub->lladdr = *src_ll;
        ND_LL_PREPEND(session->subs, sub, next);
    }

    /* INVALID with no iface: route was missing at session creation. Re-check now — if the
     * container's route has appeared in the meantime, open the interface and start probing. */
    if (session->state == ND_STATE_INVALID && !session->iface) {
        nd_rule_t *rule = session->rule;
        if (rule->mode == ND_MODE_AUTO) {
            nd_rt_route_t *route = nd_rt_find_route(&session->tgt, rule->table);
            if (route && route->oif != rule->proxy->iface->index &&
                (session->iface = nd_iface_open(NULL, route->oif, false))) {
                session->state = ND_STATE_INCOMPLETE;
                session->state_time = nd_current_time;
                session->ons_count = 1;
                session->ons_time = nd_current_time;
                nd_iface_send_ns(session->iface, &session->tgt_r);
            }
        }
    }

    /* STALE: trigger a fresh NUD probe if not recently sent. */
    if (session->state == ND_STATE_STALE && session->iface &&
        nd_current_time - session->ons_time >= nd_conf_retrans_time) {
        if (!session->ons_count)
            session->ons_count = 1;
        session->ons_time = nd_current_time;
        nd_iface_send_ns(session->iface, &session->tgt_r);
    }
}

void nd_session_handle_na(nd_session_t *session)
{
    if (session->state == ND_STATE_VALID) {
        /* Gratuitous NA confirms the target is still alive — refresh the VALID timer. */
        session->state_time = nd_current_time;
        return;
    }

    nd_lladdr_t *tgt_ll = !nd_lladdr_is_unspecified(&session->rule->target) ? &session->rule->target : NULL;

    ND_LL_FOREACH_S (session->subs, sub, tmp, next) {
        nd_iface_send_na(session->rule->proxy->iface, &sub->addr, &sub->lladdr, //
                         &session->tgt, tgt_ll, session->rule->proxy->router);
        ND_DELETE(sub);
    }

    session->subs = NULL;

    if (session->state != ND_STATE_VALID) {
        nd_log_debug("Session [%s] %s -> VALID", session->rule->proxy->ifname, nd_ntoa(&session->tgt));

        ndL_up(session);
        session->state = ND_STATE_VALID;
        session->state_time = nd_current_time;
    }
}

nd_session_t *nd_session_create(nd_rule_t *rule, const nd_addr_t *tgt)
{
    /* Bound total memory: without this, an on-link host sending NS for many
     * distinct targets inside a wide proxied prefix can grow sessions
     * without limit until malloc() fails and nd_alloc() calls exit(). */
    if (ndL_session_count >= ND_SESSION_MAX) {
        nd_log_debug("proxy %s: session limit reached (%d), dropping NS for %s", //
                     rule->proxy->ifname, ND_SESSION_MAX, nd_ntoa(tgt));
        return NULL;
    }

    nd_session_t *session = ND_NEW(nd_session_t);
    ndL_session_count++;

    *session = (nd_session_t){
        .rule = rule,
        .state_time = nd_current_time,
        .tgt = *tgt,
    };

    nd_addr_combine(&rule->rewrite_tgt, tgt, rule->rewrite_pflen, &session->tgt_r);

    ND_LL_PREPEND(ndL_sessions[NDL_BUCKET(&session->tgt)], session, next);
    ND_LL_PREPEND(ndL_sessions_r[NDL_BUCKET(&session->tgt_r)], session, next_r);

    if (rule->mode == ND_MODE_AUTO) {
        nd_rt_route_t *route = nd_rt_find_route(tgt, rule->table);

        if (!route || route->oif == rule->proxy->iface->index || !(session->iface = nd_iface_open(NULL, route->oif, false))) {
            session->state = ND_STATE_INVALID;
            return session;
        }
    } else if ((session->iface = rule->iface)) {
        session->iface->refcount++;
    }

    if (session->iface) {
        session->state = ND_STATE_INCOMPLETE;
        session->ons_count = 1;
        session->ons_time = nd_current_time;
        nd_iface_send_ns(session->iface, &session->tgt_r);
    } else if (rule->mode == ND_MODE_STATIC) {
        session->state = ND_STATE_VALID;
    }

    return session;
}

void nd_session_update(nd_session_t *session)
{
    switch (session->state) {
    case ND_STATE_INCOMPLETE:
        if (nd_current_time - session->ons_time < nd_conf_retrans_time)
            break;

        if (++session->ons_count > nd_conf_retrans_limit) {
            session->state = ND_STATE_INVALID;
            session->state_time = nd_current_time;
            nd_log_debug("session [%s] %s INCOMPLETE -> INVALID", //
                         session->rule->proxy->ifname, nd_ntoa(&session->tgt));
            break;
        }

        nd_iface_send_ns(session->iface, &session->tgt_r);
        break;

    case ND_STATE_INVALID:
        if (nd_current_time - session->state_time < nd_conf_invalid_ttl)
            break;

        ndL_down(session);

        if (session->iface)
            nd_iface_close(session->iface);

        ND_LL_FOREACH_S (session->subs, sub, tmp, next)
            ND_DELETE(sub);

        ND_LL_DELETE(ndL_sessions[NDL_BUCKET(&session->tgt)], session, next);
        ND_LL_DELETE(ndL_sessions_r[NDL_BUCKET(&session->tgt_r)], session, next_r);
        ndL_session_count--;

        nd_log_debug("session [%s] %s INVALID -> (deleted)", //
                     session->rule->proxy->ifname, nd_ntoa(&session->tgt));

        ND_DELETE(session);
        break;

    case ND_STATE_VALID:
        if (nd_current_time - session->state_time < nd_conf_valid_ttl)
            break;

        session->state = ND_STATE_STALE;
        session->state_time = nd_current_time;
        session->ons_time = nd_current_time;

        nd_log_debug("session [%s] %s VALID -> STALE", //
                     session->rule->proxy->ifname, nd_ntoa(&session->tgt));

        if (nd_conf_keepalive || nd_current_time - session->ins_time < nd_conf_valid_ttl) {
            session->ons_count = 1;
            nd_iface_send_ns(session->iface, &session->tgt_r);
        } else {
            session->ons_count = 0;
        }

        break;

    case ND_STATE_STALE:
        if (nd_current_time - session->state_time >= nd_conf_stale_ttl) {
            session->state = ND_STATE_INVALID;
            session->state_time = nd_current_time;

            nd_log_debug("session [%s] %s STALE -> INVALID", //
                         session->rule->proxy->ifname, nd_ntoa(&session->tgt));
        } else {
            // We will only retransmit if nd_conf_keepalive is true, or if the last incoming NS
            // request was made less than nd_conf_valid_ttl milliseconds ago.

            if (!nd_conf_keepalive && nd_current_time - session->ins_time > nd_conf_valid_ttl)
                break;

            /* Cap shift low enough that ((long)retrans_time << shift) stays under LONG_MAX
             * for realistic retrans_time values (well under 2^31 ms per config validation). */
            int shift = session->ons_count / 3;
            if (shift > 16)
                shift = 16;
            long time = session->ons_count && nd_conf_retrans_limit > 0 &&
                                !(session->ons_count % nd_conf_retrans_limit)
                            ? ((long)nd_conf_retrans_time << shift)
                            : nd_conf_retrans_time;

            if (nd_current_time - session->ons_time < time)
                break;

            session->ons_count++;
            session->ons_time = nd_current_time;
            nd_iface_send_ns(session->iface, &session->tgt_r);
        }
        break;
    }
}

nd_session_t *nd_session_find(const nd_addr_t *tgt, const nd_proxy_t *proxy)
{
    nd_session_t *session;
    ND_LL_SEARCH(ndL_sessions[NDL_BUCKET(tgt)], session, next,
                 session->rule->proxy == proxy && nd_addr_eq(&session->tgt, tgt));
    return session;
}

nd_session_t *nd_session_find_r(const nd_addr_t *tgt, const nd_iface_t *iface)
{
    nd_session_t *session;
    ND_LL_SEARCH(ndL_sessions_r[NDL_BUCKET(tgt)], session, next_r,
                 session->iface == iface && nd_addr_eq(&session->tgt_r, tgt));
    return session;
}

void nd_session_update_all()
{
    for (int i = 0; i < NDPPD_SESSION_BUCKETS; i++) {
        ND_LL_FOREACH_S (ndL_sessions[i], session, tmp, next)
            nd_session_update(session);
    }
}
