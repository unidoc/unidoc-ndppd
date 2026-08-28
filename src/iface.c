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
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>

// Need to include netinet/in.h first on FreeBSD.
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>

#ifdef __linux__
#    include <linux/filter.h>
#    include <linux/if_packet.h>
#    include <net/ethernet.h>
#    ifndef ETH_P_IPV6
#        define ETH_P_IPV6 0x86DD
#    endif
#else
#    include <fcntl.h>
#    include <net/bpf.h>
#    include <net/ethernet.h>
#    include <net/if_dl.h>
#    include <sys/sysctl.h>
#endif

#include "ndppd.h"

#if defined(__clang__)
#    pragma clang diagnostic ignored "-Waddress-of-packed-member"
#elif defined(__GNUC__)
#    pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif

extern int nd_conf_invalid_ttl;
extern int nd_conf_valid_ttl;
extern int nd_conf_renew;
extern int nd_conf_retrans_limit;
extern int nd_conf_retrans_time;
extern bool nd_conf_keepalive;

static nd_iface_t *ndL_first_iface;
static nd_io_t *ndL_io;

//! Used when daemonizing to make sure the parent process does not restore these flags upon exit.
bool nd_iface_no_restore_flags;

typedef struct __attribute__((packed)) {
    struct ether_header eh;
    struct ip6_hdr ip6h;
} ndL_ip6_msg_t;

static void ndL_handle_ns(nd_iface_t *iface, struct ip6_hdr *ip6h, struct icmp6_hdr *ih, size_t len,
                          const nd_lladdr_t *eth_src)
{
    if (!iface->proxy) {
        nd_log_trace("%s: NS on non-proxy iface, drop", iface->name);
        return;
    }

    if (len < sizeof(struct nd_neighbor_solicit)) {
        nd_log_debug("%s: NS too short (%zu), drop", iface->name, len);
        return;
    }

    struct nd_neighbor_solicit *ns = (struct nd_neighbor_solicit *)ih;

    /* RFC 4861 §7.1.1: Target Address MUST NOT be a multicast address. */
    if (nd_addr_is_multicast((nd_addr_t *)&ns->nd_ns_target)) {
        nd_log_debug("%s: NS target is multicast, drop", iface->name);
        return;
    }

    nd_lladdr_t *src_ll = NULL;

    if (!nd_addr_is_unspecified((nd_addr_t *)&ip6h->ip6_src)) {
        /* RFC 4861 §4.6: MUST discard if any option has length zero.
         * Iterate all options to find SLLAO (RFC 4861 §4.3). */
        uint8_t *opts = (uint8_t *)ns + sizeof(struct nd_neighbor_solicit);
        size_t opts_len = len - sizeof(struct nd_neighbor_solicit);

        while (opts_len >= 8) {
            struct nd_opt_hdr *opt = (struct nd_opt_hdr *)opts;

            if (opt->nd_opt_len == 0)
                return; /* RFC 4861 §4.6: discard entire packet */

            size_t opt_bytes = (size_t)opt->nd_opt_len * 8;
            if (opt_bytes > opts_len)
                break; /* truncated option — stop parsing */

            if (opt->nd_opt_type == ND_OPT_SOURCE_LINKADDR && opt->nd_opt_len == 1)
                src_ll = (nd_lladdr_t *)(opts + 2);

            opts += opt_bytes;
            opts_len -= opt_bytes;
        }

        /* RFC 4861 §7.7.3: NUD unicast NS SHOULD omit SLLAO since the sender already knows the
         * link-layer address.  Fall back to the Ethernet source MAC so we can send a solicited NA
         * (SOLICITED=1) back to the probe sender — an unsolicited NA (SOLICITED=0) does not
         * satisfy a NUD PROBE transition per §7.3.5. */
        if (!src_ll)
            src_ll = (nd_lladdr_t *)eth_src;
    }

    nd_proxy_handle_ns(iface->proxy, (nd_addr_t *)&ip6h->ip6_src, (nd_addr_t *)&ip6h->ip6_dst,
                       (nd_addr_t *)&ns->nd_ns_target, src_ll);
}

static void ndL_handle_na(nd_iface_t *iface, struct icmp6_hdr *ih, size_t len)
{
    if (len < sizeof(struct nd_neighbor_advert))
        return;

    struct nd_neighbor_advert *na = (struct nd_neighbor_advert *)ih;

    nd_log_trace("Handle NA tgt=%s", nd_ntoa((nd_addr_t *)&na->nd_na_target));

    nd_session_t *session = nd_session_find_r((nd_addr_t *)&na->nd_na_target, iface);

    if (!session) {
        nd_log_trace("%s: NA for %s has no matching session, drop", iface->name, nd_ntoa((nd_addr_t *)&na->nd_na_target));
        return;
    }

    nd_session_handle_na(session);
}

static void ndL_handle_mlq(nd_iface_t *iface)
{
    (void)iface;
    nd_log_error("(mlq) in");
}

static void ndL_handle_mlr(nd_iface_t *iface)
{
    (void)iface;
    nd_log_error("(mlr) in");
}

static uint16_t ndL_calculate_checksum(uint32_t sum, const void *data, size_t length)
{
    const uint8_t *p = (const uint8_t *)data;

    for (size_t i = 0; i < length; i += 2) {
        if (i + 1 < length) {
            /* memcpy avoids unaligned uint16_t load on strict-align architectures
             * (older MIPS/SPARC). x86_64 and arm64 are unaffected but the compiler
             * emits identical code, so no cost on our target platforms. */
            uint16_t word;
            memcpy(&word, p, sizeof(word));
            sum += ntohs(word);
            p += 2;
        } else {
            sum += *p++;
        }

        if (sum > 0xffff)
            sum -= 0xffff;
    }

    return sum;
}

static uint16_t ndL_calculate_icmp6_checksum(struct ip6_hdr *ip6_hdr, struct icmp6_hdr *icmp6_hdr, size_t size)
{
    struct __attribute__((packed)) {
        struct in6_addr src;
        struct in6_addr dst;
        uint32_t len;
        uint8_t unused[3];
        uint8_t type;
        struct icmp6_hdr icmp6_hdr;
    } hdr = {
        .src = ip6_hdr->ip6_src,
        .dst = ip6_hdr->ip6_dst,
        .len = htonl(size),
        .type = IPPROTO_ICMPV6,
        .icmp6_hdr = *icmp6_hdr,
    };

    hdr.icmp6_hdr.icmp6_cksum = 0;

    uint16_t sum;
    sum = ndL_calculate_checksum(0xffff, &hdr, sizeof(hdr));
    sum = ndL_calculate_checksum(sum, icmp6_hdr + 1, size - sizeof(struct icmp6_hdr));

    return htons(~sum);
}

static void ndL_handle_msg(nd_iface_t *iface, ndL_ip6_msg_t *msg)
{
    size_t plen = ntohs(msg->ip6h.ip6_plen);
    size_t i = 0;

    if (msg->ip6h.ip6_nxt == IPPROTO_HOPOPTS) {
        struct ip6_hbh *hbh = (void *)(msg + 1) + i;

        if (plen - i < 8 || plen - i < 8U + (hbh->ip6h_len * 8U)) {
            nd_log_debug("%s: truncated hop-by-hop header, drop", iface->name);
            return;
        }

        i += 8 + 8 * hbh->ip6h_len;

        if (hbh->ip6h_nxt != IPPROTO_ICMPV6) {
            nd_log_trace("%s: hbh nxt=%d != ICMPv6, drop", iface->name, hbh->ip6h_nxt);
            return;
        }
    } else if (msg->ip6h.ip6_nxt != IPPROTO_ICMPV6) {
        nd_log_trace("%s: nxt=%d != ICMPv6, drop", iface->name, msg->ip6h.ip6_nxt);
        return;
    }

    if (plen - i < sizeof(struct icmp6_hdr)) {
        nd_log_debug("%s: ICMPv6 header truncated, drop", iface->name);
        return;
    }

    struct icmp6_hdr *ih = (struct icmp6_hdr *)((void *)(msg + 1) + i);
    uint16_t ilen = plen - i;

    if (ndL_calculate_icmp6_checksum(&msg->ip6h, ih, ilen) != ih->icmp6_cksum) {
        nd_log_debug("%s: ICMPv6 checksum mismatch (got %04x want %04x), drop",
                     iface->name, ntohs(ih->icmp6_cksum),
                     ntohs(ndL_calculate_icmp6_checksum(&msg->ip6h, ih, ilen)));
        return;
    }

    /* RFC 4861 §6.1.1: hop limit MUST be 255 — reject anything that may have been forwarded. */
    if (msg->ip6h.ip6_hops != 255) {
        nd_log_debug("%s: hop limit %d != 255, drop", iface->name, msg->ip6h.ip6_hops);
        return;
    }

    if (ih->icmp6_type == ND_NEIGHBOR_SOLICIT)
        ndL_handle_ns(iface, &msg->ip6h, ih, ilen, (nd_lladdr_t *)msg->eh.ether_shost);
    else if (ih->icmp6_type == ND_NEIGHBOR_ADVERT)
        ndL_handle_na(iface, ih, ilen);
    else if (ih->icmp6_type == MLD_LISTENER_QUERY)
        ndL_handle_mlq(iface);
    else if (ih->icmp6_type == MLD_LISTENER_REPORT)
        ndL_handle_mlr(iface);
}

#ifdef __linux__
static void ndL_io_handler(nd_io_t *io, __attribute__((unused)) int events)
{
    struct sockaddr_ll lladdr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IPV6),
    };

    /* IPv6 min MTU is 1280 B; NAs with several options can exceed 1024. Give ourselves headroom. */
    uint8_t buf[2048];

    for (;;) {
        ssize_t len = nd_io_recv(io, (struct sockaddr *)&lladdr, sizeof(lladdr), buf, sizeof(buf));

        if (len == 0)
            return;

        if (len < 0)
            return;

        nd_iface_t *iface;

        ND_LL_SEARCH(ndL_first_iface, iface, next, iface->index == (unsigned int)lladdr.sll_ifindex);

        if (!iface) {
            nd_log_trace("pkt on unknown ifindex %d, skip", lladdr.sll_ifindex);
            continue;
        }

        if ((size_t)len < sizeof(ndL_ip6_msg_t)) {
            nd_log_trace("pkt too short (%zd) on %s, skip", len, iface->name);
            continue;
        }

        ndL_ip6_msg_t *msg = (ndL_ip6_msg_t *)buf;

        if (msg->eh.ether_type != ntohs(ETHERTYPE_IPV6)) {
            nd_log_trace("non-IPv6 ethertype 0x%04x on %s, skip", ntohs(msg->eh.ether_type), iface->name);
            continue;
        }

        if (ntohs(msg->ip6h.ip6_plen) != len - sizeof(ndL_ip6_msg_t)) {
            nd_log_trace("plen mismatch on %s (plen=%u frame=%zd), skip",
                         iface->name, ntohs(msg->ip6h.ip6_plen), len - sizeof(ndL_ip6_msg_t));
            continue;
        }

        nd_log_trace("pkt len=%zd on %s pkttype=%d", len, iface->name, lladdr.sll_pkttype);
        ndL_handle_msg(iface, msg);
    }
}
#else
static void ndL_io_handler(nd_io_t *io, __attribute__((unused)) int events)
{
    __attribute__((aligned(BPF_ALIGNMENT))) uint8_t buf[4096]; /* Depends on BIOCGBLEN */

    for (;;) {
        ssize_t len = nd_io_read(io, buf, sizeof(buf));

        if (len <= 0) {
            if (len < 0 && errno != EAGAIN && errno != EINTR)
                nd_log_error("BPF read: %s", strerror(errno));
            return;
        }

        size_t ulen = (size_t)len;

        for (size_t i = 0; i < ulen;) {
            if (i + sizeof(struct bpf_hdr) > ulen)
                break;

            struct bpf_hdr *bpf_hdr = (struct bpf_hdr *)(buf + i);
            size_t pkt_offset = i + bpf_hdr->bh_hdrlen;
            size_t advance = BPF_WORDALIGN(bpf_hdr->bh_hdrlen + bpf_hdr->bh_caplen);

            /* Zero-advance would loop forever; treat as malformed record. */
            if (advance == 0)
                break;

            /* Whole record (header + captured bytes) must be inside the read buffer. */
            if (pkt_offset > ulen || bpf_hdr->bh_caplen > ulen - pkt_offset) {
                i += advance;
                continue;
            }

            i += advance;

            if (bpf_hdr->bh_caplen < sizeof(ndL_ip6_msg_t))
                continue;

            ndL_ip6_msg_t *msg = (ndL_ip6_msg_t *)(buf + pkt_offset);

            if (msg->eh.ether_type != ntohs(ETHERTYPE_IPV6))
                continue;

            if (ntohs(msg->ip6h.ip6_plen) != bpf_hdr->bh_caplen - sizeof(ndL_ip6_msg_t))
                continue;

            ndL_handle_msg((nd_iface_t *)io->data, msg);
        }
    }
}
#endif

static bool ndL_configure_filter(nd_io_t *io)
{
#ifndef __linux__
#    define sock_filter bpf_insn
#endif

    static struct sock_filter filter[] = {
        /* Load P->ether_type into A. */
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_header, ether_type)),
        /* Drop packet if A != ETHERTYPE_IPV6. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPV6, 0, 17),
        /* Load next header offset into X. */
        BPF_STMT(BPF_LDX + BPF_W + BPF_IMM, sizeof(struct ether_header) + sizeof(struct ip6_hdr)),
        /* Load P->ip6_nxt. */
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, sizeof(struct ether_header) + offsetof(struct ip6_hdr, ip6_nxt)),

        /* Hop-by-hop */

        /* Skip if A != IPPROTO_HOPOPTS. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_HOPOPTS, 0, 8),
        /* Load X->ip6h_nxt into A. */
        BPF_STMT(BPF_LD + BPF_B + BPF_IND, 0),
        /* Save A into [0(nxt)]. */
        BPF_STMT(BPF_ST, 0),
        /* Load ip6h_len into A. */
        BPF_STMT(BPF_LD + BPF_B + BPF_IND, 1),
        /* Multiply by 8. */
        BPF_STMT(BPF_ALU + BPF_MUL + BPF_K, 8),
        /* Add 6. */
        BPF_STMT(BPF_ALU + BPF_ADD + BPF_K, 8),
        /* Add X. */
        BPF_STMT(BPF_ALU + BPF_ADD + BPF_X, 0),
        /* Copy A to X. */
        BPF_STMT(BPF_MISC + BPF_TAX, 0),
        /* Load [0(nxt)] into A. */
        BPF_STMT(BPF_LD + BPF_MEM, 0),

        /* ICMPv6 */

        /* Fail if A != IPPROTO_ICMPV6. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0, 5),
        /* Load X->icmp6_type into A. */
        BPF_STMT(BPF_LD + BPF_B + BPF_IND, offsetof(struct icmp6_hdr, icmp6_type)),
        /* Succeed if A == ND_NEIGHBOR_SOLICIT. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_SOLICIT, 4, 0),
        /* Succeed if A == ND_NEIGHBOR_SOLICIT. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_ADVERT, 3, 0),
        /* Succeed if A == MLD_LISTENER_QUERY. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, MLD_LISTENER_QUERY, 2, 0),
        /* Succeed if A == MLD_LISTENER_REPORT. */
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, MLD_LISTENER_REPORT, 1, 0),
        /* Drop packet. */
        BPF_STMT(BPF_RET + BPF_K, 0),
        /* Keep packet. */
        BPF_STMT(BPF_RET + BPF_K, (u_int32_t)-1),
    };

#ifdef __linux__
    static struct sock_fprog fprog = {
        .len = sizeof(filter) / sizeof(filter[0]),
        .filter = filter,
    };

    if (setsockopt(io->fd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog)) == -1)
        return false;
#else
    static struct bpf_program fprog = {
        .bf_len = sizeof(filter) / sizeof(filter[0]),
        .bf_insns = filter,
    };

    if (ioctl(io->fd, BIOCSETF, &fprog) == -1)
        return false;
#endif

    return true;
}

nd_iface_t *nd_iface_open(const char *name, unsigned index, bool promiscuous)
{
    char tmp_name[IF_NAMESIZE];

    if (!name && !index)
        return NULL;

    /* Resolve name↔index in a single lookup pass: prior version made up to three
     * separate kernel calls, which are TOCTOU-vulnerable to interface rename
     * between calls. Root is required to rename, so this is defense-in-depth. */
    if (name) {
        unsigned resolved = if_nametoindex(name);
        if (!resolved) {
            nd_log_error("Failed to get index of interface %s: %s", name, strerror(errno));
            return NULL;
        }
        if (index && index != resolved) {
            nd_log_error("Expected interface %s to have index %u (got %u)", name, index, resolved);
            return NULL;
        }
        index = resolved;
    } else {
        if (!if_indextoname(index, tmp_name)) {
            nd_log_error("Failed to get name of interface index %u: %s", index, strerror(errno));
            return NULL;
        }
        name = tmp_name;
    }

    /* If the specified interface is already opened, just increase the reference count. */

    nd_iface_t *iface;
    ND_LL_SEARCH(ndL_first_iface, iface, next, iface->index == index);

    if (iface) {
        iface->refcount++;
        return iface;
    }

#ifdef __linux__
    /* Determine link-layer address. */

    struct ifreq ifr = { 0 };
    strcpy(ifr.ifr_name, name);

    if (ioctl(ndL_io->fd, SIOCGIFHWADDR, &ifr) < 0) {
        nd_log_error("Failed to determine link-layer address: %s", strerror(errno));
        return NULL;
    }

    nd_lladdr_t *lladdr = (nd_lladdr_t *)ifr.ifr_hwaddr.sa_data;

    /* Default is ALLMULTI (catches solicited-node multicast NS).  Optional PROMISC picks up
     * unicast NS addressed to a stale MAC — useful for container/veth churn scenarios but not
     * needed for stable-MAC VPS setups.  Selected per-proxy via `promiscuous yes` in ndppd.conf. */

    int mr_type = promiscuous ? PACKET_MR_PROMISC : PACKET_MR_ALLMULTI;
    const char *mr_name = promiscuous ? "PROMISC" : "ALLMULTI";
    struct packet_mreq mreq = { .mr_ifindex = (int)index, .mr_type = mr_type };

    if (setsockopt(ndL_io->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
        nd_log_error("Could not configure %s: %s", mr_name, strerror(errno));
        return NULL;
    }

#else
    nd_io_t *io = NULL;

    /* This requires a cloning bpf device, but I hope most sane systems got them. */
    if (!(io = nd_io_open("/dev/bpf", O_RDWR))) {
        nd_log_error("Failed to open /dev/bpf");
        return NULL;
    }

    io->handler = ndL_io_handler;

    /* Set buffer length. */

    unsigned len = 4096; /* TODO: Configure */
    if (ioctl(io->fd, BIOCSBLEN, &len) < 0) {
        nd_log_error("BIOCSBLEN: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    /* Bind to interface. */

    struct ifreq ifr;
    strcpy(ifr.ifr_name, name);
    if (ioctl(io->fd, BIOCSETIF, &ifr) < 0) {
        nd_log_error("Failed to bind to interface: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    /* BPF requires promisc to receive solicited-node multicast NS on FreeBSD — the kernel only
     * joins those groups on interfaces where the address is configured locally.  The `promiscuous`
     * flag is a Linux-only knob; on FreeBSD we always enable BIOCPROMISC regardless. */

    if (!promiscuous)
        nd_log_info("%s: `promiscuous no` is ignored on FreeBSD — BPF requires BIOCPROMISC", name);

    if (ioctl(io->fd, BIOCPROMISC, NULL) < 0) {
        nd_log_error("Failed to enable promiscuous mode: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    /* Immediate */

    uint32_t enable = 1;
    if (ioctl(io->fd, BIOCIMMEDIATE, &enable) < 0) {
        nd_log_error("BIOCIMMEDIATE: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    /* Determine link-layer address. */

    int mib[] = { CTL_NET, AF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, (int)index };
    uint8_t sysctl_buf[512];
    size_t sysctl_buflen = sizeof(sysctl_buf);

    if (sysctl(mib, 6, sysctl_buf, &sysctl_buflen, NULL, 0) == -1) {
        nd_log_error("Failed to determine link-layer address: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    /* Defense-in-depth: the kernel is trusted but a short return would let us read past the buffer. */
    if (sysctl_buflen < sizeof(struct if_msghdr) + offsetof(struct sockaddr_dl, sdl_data) + ETHER_ADDR_LEN) {
        nd_log_error("Link-layer sysctl reply too short (%zu bytes)", sysctl_buflen);
        nd_io_close(io);
        return NULL;
    }

    if (!ndL_configure_filter(io)) {
        nd_log_error("Could not configure filter: %s", strerror(errno));
        nd_io_close(io);
        return NULL;
    }

    nd_lladdr_t *lladdr = (nd_lladdr_t *)LLADDR((struct sockaddr_dl *)(sysctl_buf + sizeof(struct if_msghdr)));
#endif

    iface = ND_NEW(nd_iface_t);

    *iface = (nd_iface_t){
        .index = index,
        .refcount = 1,
        .lladdr = *lladdr,
        .promiscuous = promiscuous,
    };

    strcpy(iface->name, name);

    ND_LL_PREPEND(ndL_first_iface, iface, next);

#ifndef __linux__
    io->data = (uintptr_t)iface;
    iface->bpf_io = io;
#endif

    nd_log_info("New interface %s [%s]", iface->name, nd_ll_ntoa(lladdr));

    return iface;
}

void nd_iface_rebind_all(void)
{
#ifdef __linux__
    if (!ndL_io) {
        return;
    }

    ND_LL_FOREACH (ndL_first_iface, iface, next) {
        unsigned int cur = if_nametoindex(iface->name);
        if (cur == 0) {
            /* Interface currently absent (bridge in the middle of a
             * delete+recreate, veth gone). Leave state as-is; the next
             * poll or LINK event will retry when it reappears. Do NOT
             * tear anything down — a permanent removal is indistinguishable
             * from a transient one and the operator can always kill the
             * daemon to force cleanup. */
            continue;
        }

        /* Refresh link-layer address unconditionally. A bridge recreate
         * assigns a new MAC (kernel picks a random one from an attached
         * port), and if we advertise the OLD MAC in NAs, the upstream
         * router will forward return packets to a non-existent Ethernet
         * neighbor — silently dropped. This is the exact failure mode
         * that motivates this whole rebind path. */
        struct ifreq ifr = { 0 };
        strcpy(ifr.ifr_name, iface->name);
        bool lladdr_changed = false;
        if (ioctl(ndL_io->fd, SIOCGIFHWADDR, &ifr) == 0) {
            nd_lladdr_t *new_lladdr = (nd_lladdr_t *)ifr.ifr_hwaddr.sa_data;
            if (memcmp(&iface->lladdr, new_lladdr, sizeof(*new_lladdr)) != 0) {
                nd_log_info("%s: MAC changed %s → %s", iface->name,
                            nd_ll_ntoa(&iface->lladdr), nd_ll_ntoa(new_lladdr));
                iface->lladdr = *new_lladdr;
                lladdr_changed = true;
            }
        } else {
            nd_log_error("%s: SIOCGIFHWADDR: %s", iface->name, strerror(errno));
        }

        if (cur == iface->index) {
            /* Same ifindex — no membership rebind needed. lladdr refresh
             * above is enough. */
            if (lladdr_changed) {
                nd_log_debug("%s: lladdr refreshed, ifindex unchanged", iface->name);
            }
            continue;
        }

        /* ifindex changed — rebind PACKET_ADD_MEMBERSHIP so multicast NS
         * frames delivered on the NEW ifindex reach our socket, and stop
         * receiving on the (probably-dead) old one. */
        unsigned int old_index = iface->index;
        nd_log_info("%s: ifindex changed %u → %u, rebinding multicast", iface->name, old_index, cur);

        int mr_type = iface->promiscuous ? PACKET_MR_PROMISC : PACKET_MR_ALLMULTI;

        /* Try ADD first: if it fails, we haven't lost anything (still
         * bound to old ifindex, however useless that may be). Only after
         * a successful ADD do we DROP the old and commit iface->index —
         * a straightforward "no half-transitions" ordering. */
        struct packet_mreq add_mreq = { .mr_ifindex = (int)cur, .mr_type = mr_type };
        if (setsockopt(ndL_io->fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &add_mreq, sizeof(add_mreq)) == -1) {
            nd_log_error("%s: ADD_MEMBERSHIP on new ifindex %u: %s — retry on next poll",
                         iface->name, cur, strerror(errno));
            continue; /* iface->index unchanged; the 5 s poll will retry. */
        }

        /* Drop old membership. Kernel usually cleaned it up when the
         * interface disappeared; ENODEV is expected and benign. Failure
         * here doesn't break the new binding — just a stale kernel MR
         * entry until socket close. */
        struct packet_mreq drop_mreq = { .mr_ifindex = (int)old_index, .mr_type = mr_type };
        if (setsockopt(ndL_io->fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &drop_mreq, sizeof(drop_mreq)) == -1
            && errno != ENODEV) {
            nd_log_error("%s: DROP_MEMBERSHIP on old ifindex %u: %s (non-fatal)",
                         iface->name, old_index, strerror(errno));
        }

        iface->index = cur;
    }
#else
    /* BSD: each iface owns its own /dev/bpf handle bound at open time.
     * BIOCSETIF ties the handle to a specific kernel interface object;
     * if that object is destroyed (bridge recreate, veth churn) the
     * handle becomes a black hole even though the fd stays open.
     * Close + reopen the bpf device, rebind by name, refresh lladdr.
     *
     * The ioctl sequence below intentionally mirrors nd_iface_open's
     * BSD branch line-for-line. Keeping them parallel — rather than
     * extracting a shared helper — leaves the proven open path
     * unchanged; a helper refactor can happen once both have soaked. */
    ND_LL_FOREACH (ndL_first_iface, iface, next) {
        unsigned int cur = if_nametoindex(iface->name);
        if (cur == 0) {
            /* Interface currently absent. Do NOT tear down bpf_io yet —
             * a transient flap and a permanent removal look identical
             * here, and destroying state prematurely means we'd miss
             * NS packets in the brief reappear-before-reopen window. */
            continue;
        }

        /* Refresh lladdr via sysctl regardless of ifindex change: some
         * BSDs preserve ifindex across a recreate but rotate MAC. Stale
         * lladdr in NAs → upstream router forwards to a nonexistent
         * neighbor → silent black hole. */
        int mib[] = { CTL_NET, AF_ROUTE, 0, AF_LINK, NET_RT_IFLIST, (int)cur };
        uint8_t sysctl_buf[512];
        size_t sysctl_buflen = sizeof(sysctl_buf);
        if (sysctl(mib, 6, sysctl_buf, &sysctl_buflen, NULL, 0) == -1) {
            nd_log_error("%s: sysctl NET_RT_IFLIST: %s", iface->name, strerror(errno));
            continue;
        }
        if (sysctl_buflen < sizeof(struct if_msghdr) + offsetof(struct sockaddr_dl, sdl_data) + ETHER_ADDR_LEN) {
            nd_log_error("%s: NET_RT_IFLIST reply too short (%zu)", iface->name, sysctl_buflen);
            continue;
        }
        nd_lladdr_t *new_lladdr = (nd_lladdr_t *)LLADDR((struct sockaddr_dl *)(sysctl_buf + sizeof(struct if_msghdr)));
        bool lladdr_changed = memcmp(&iface->lladdr, new_lladdr, sizeof(*new_lladdr)) != 0;
        bool index_changed = cur != iface->index;

        if (!lladdr_changed && !index_changed && iface->bpf_io != NULL) {
            continue;
        }

        nd_log_info("%s: link changed (ifindex %u→%u, lladdr %s→%s), reopening BPF",
                    iface->name, iface->index, cur,
                    nd_ll_ntoa(&iface->lladdr), nd_ll_ntoa(new_lladdr));

        /* Tear down the stale bpf handle. On BSD there's no equivalent
         * of DROP_MEMBERSHIP — the handle is either bound to a live
         * interface or it isn't. Close forces kernel to release. */
        if (iface->bpf_io) {
            nd_io_close(iface->bpf_io);
            iface->bpf_io = NULL;
        }

        /* --- begin: mirror of nd_iface_open BSD branch --- */
        nd_io_t *io = nd_io_open("/dev/bpf", O_RDWR);
        if (!io) {
            nd_log_error("%s: reopen /dev/bpf: %s — proxy degraded until next retry",
                         iface->name, strerror(errno));
            continue;
        }
        io->handler = ndL_io_handler;

        unsigned buflen_req = 4096;
        if (ioctl(io->fd, BIOCSBLEN, &buflen_req) < 0) {
            nd_log_error("%s: BIOCSBLEN: %s", iface->name, strerror(errno));
            nd_io_close(io);
            continue;
        }

        struct ifreq ifr;
        strcpy(ifr.ifr_name, iface->name);
        if (ioctl(io->fd, BIOCSETIF, &ifr) < 0) {
            nd_log_error("%s: BIOCSETIF: %s", iface->name, strerror(errno));
            nd_io_close(io);
            continue;
        }

        if (ioctl(io->fd, BIOCPROMISC, NULL) < 0) {
            nd_log_error("%s: BIOCPROMISC: %s", iface->name, strerror(errno));
            nd_io_close(io);
            continue;
        }

        uint32_t enable = 1;
        if (ioctl(io->fd, BIOCIMMEDIATE, &enable) < 0) {
            nd_log_error("%s: BIOCIMMEDIATE: %s", iface->name, strerror(errno));
            nd_io_close(io);
            continue;
        }

        if (!ndL_configure_filter(io)) {
            nd_log_error("%s: ndL_configure_filter: %s", iface->name, strerror(errno));
            nd_io_close(io);
            continue;
        }
        /* --- end: mirror of nd_iface_open BSD branch --- */

        io->data = (uintptr_t)iface;
        iface->bpf_io = io;
        iface->index = cur;
        iface->lladdr = *new_lladdr;
    }
#endif
}

void nd_iface_close(nd_iface_t *iface)
{
    if (--iface->refcount > 0)
        return;

#ifdef __linux__
    if (!nd_iface_no_restore_flags) {
        int mr_type = iface->promiscuous ? PACKET_MR_PROMISC : PACKET_MR_ALLMULTI;
        const char *mr_name = iface->promiscuous ? "PROMISC" : "ALLMULTI";
        struct packet_mreq mreq = { .mr_ifindex = (int)iface->index, .mr_type = mr_type };

        if (setsockopt(ndL_io->fd, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq)) == -1)
            nd_log_error("Could not disable %s: %s", mr_name, strerror(errno));
    }
#else
    nd_io_close(iface->bpf_io);
#endif

    ND_LL_DELETE(ndL_first_iface, iface, next);
    ND_DELETE(iface);
}

static void ndL_get_local_addr(nd_iface_t *iface, nd_addr_t *addr)
{
    uint8_t *p = iface->lladdr.u8;
    *addr = (nd_addr_t){ .u8 = { 0xfe, 0x80, [8] = p[0] ^ 0x02U, p[1], p[2], 0xff, 0xfe, p[3], p[4], p[5] } };
}

static ssize_t ndL_send_icmp6(nd_iface_t *iface, ndL_ip6_msg_t *msg, size_t size, const nd_lladdr_t *lladdr)
{
    msg->eh.ether_type = htons(ETHERTYPE_IPV6);
    memcpy(msg->eh.ether_shost, &iface->lladdr, ETHER_ADDR_LEN);
    memcpy(msg->eh.ether_dhost, lladdr, ETHER_ADDR_LEN);

    msg->ip6h.ip6_flow = htonl((6U << 28U) | (0U << 20U) | 0U);
    msg->ip6h.ip6_plen = htons(size - sizeof(ndL_ip6_msg_t));
    msg->ip6h.ip6_hops = 255;
    msg->ip6h.ip6_nxt = IPPROTO_ICMPV6;

    struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(msg + 1);
    uint16_t icmp6_len = size - sizeof(ndL_ip6_msg_t);
    icmp6_hdr->icmp6_cksum = ndL_calculate_icmp6_checksum(&msg->ip6h, icmp6_hdr, icmp6_len);

#ifdef __linux__
    struct sockaddr_ll ll = {
        .sll_family = AF_PACKET,
        .sll_ifindex = (int)iface->index,
    };

    return nd_io_send(ndL_io, (struct sockaddr *)&ll, sizeof(ll), msg, size);
#else
    return nd_io_write(iface->bpf_io, msg, size);
#endif
}

ssize_t nd_iface_send_na(nd_iface_t *iface, const nd_addr_t *dst, const nd_lladdr_t *dst_ll, //
                         const nd_addr_t *tgt, const nd_lladdr_t *tgt_ll, bool router)
{
    if (tgt_ll == NULL) {
        tgt_ll = &iface->lladdr;
    }

    struct __attribute__((packed)) {
        struct ether_header eh;
        struct ip6_hdr ip;
        struct nd_neighbor_advert na;
        struct nd_opt_hdr opt;
        struct ether_addr lladdr;
    } msg = {
        .ip.ip6_src = *(struct in6_addr *)tgt,
        .ip.ip6_dst = *(struct in6_addr *)dst,
        .na.nd_na_type = ND_NEIGHBOR_ADVERT,
        .na.nd_na_target = *(struct in6_addr *)tgt,
        .na.nd_na_flags_reserved = ND_NA_FLAG_OVERRIDE,
        .opt.nd_opt_type = ND_OPT_TARGET_LINKADDR,
        .opt.nd_opt_len = 1,
        .lladdr = *(struct ether_addr *)tgt_ll,
    };

    if (!nd_addr_is_multicast(dst))
        msg.na.nd_na_flags_reserved |= ND_NA_FLAG_SOLICITED;

    if (router)
        msg.na.nd_na_flags_reserved |= ND_NA_FLAG_ROUTER;

    nd_log_info("Write NA tgt=%s [%s], dst=%s [%s(%s)]", //
                nd_ntoa(tgt), nd_ll_ntoa(tgt_ll), nd_ntoa(dst), nd_ll_ntoa(dst_ll), iface->name);

    return ndL_send_icmp6(iface, (ndL_ip6_msg_t *)&msg, sizeof(msg), dst_ll);
}

ssize_t nd_iface_send_ns(nd_iface_t *iface, const nd_addr_t *tgt)
{
    struct __attribute__((packed)) {
        struct ether_header eh;
        struct ip6_hdr ip;
        struct nd_neighbor_solicit ns;
        struct nd_opt_hdr opt;
        struct ether_addr lladdr;
    } msg = {
        .ns.nd_ns_type = ND_NEIGHBOR_SOLICIT,
        .ns.nd_ns_target = *(struct in6_addr *)tgt,
        .opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR,
        .opt.nd_opt_len = 1,
        .lladdr = *(struct ether_addr *)&iface->lladdr,
    };

    ndL_get_local_addr(iface, (nd_addr_t *)&msg.ip.ip6_src);

    static const nd_addr_t multicast = { .u8 = { 0xff, 0x02, [11] = 0x01, 0xff, 0, 0, 0 } };
    *(nd_addr_t *)&msg.ip.ip6_dst = multicast;
    (*(nd_addr_t *)&msg.ip.ip6_dst).u8[13] = tgt->u8[13];
    (*(nd_addr_t *)&msg.ip.ip6_dst).u8[14] = tgt->u8[14];
    (*(nd_addr_t *)&msg.ip.ip6_dst).u8[15] = tgt->u8[15];

    nd_lladdr_t ll_mcast = { 0x33, 0x33, 0xff, tgt->u8[13], tgt->u8[14], tgt->u8[15] };

    nd_log_trace("Write NS iface=%s, tgt=%s, src=%s", iface->name, nd_ntoa(tgt), nd_ntoa((nd_addr_t *)&msg.ip.ip6_src));

    return ndL_send_icmp6(iface, (ndL_ip6_msg_t *)&msg, sizeof(msg), &ll_mcast);
}

bool nd_iface_startup()
{
#ifdef __linux__
    /* Open with protocol=0 first so the socket receives nothing.  Only after
     * SO_ATTACH_FILTER is applied do we bind to ETH_P_IPV6 — this eliminates
     * the brief window where unfiltered IPv6 frames could queue in the socket
     * buffer between socket() and setsockopt(). */
    if (!(ndL_io = nd_io_socket(AF_PACKET, SOCK_RAW, 0)))
        return false;

    if (!ndL_configure_filter(ndL_io)) {
        nd_log_error("Failed to configure BPF: %s", strerror(errno));
        nd_io_close(ndL_io);
        ndL_io = NULL;
        return false;
    }

    struct sockaddr_ll sll = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IPV6),
    };

    if (!nd_io_bind(ndL_io, (struct sockaddr *)&sll, sizeof(sll))) {
        nd_log_error("Failed to bind AF_PACKET socket: %s", strerror(errno));
        nd_io_close(ndL_io);
        ndL_io = NULL;
        return false;
    }

    ndL_io->handler = ndL_io_handler;
#endif

    return true;
}

void nd_iface_cleanup()
{
    ND_LL_FOREACH_S (ndL_first_iface, iface, tmp, next) {
        iface->refcount = 1;
        nd_iface_close(iface);
    }

    if (ndL_io)
        nd_io_close(ndL_io);
}
