# unidoc-ndppd — NDP Proxy Daemon

**unidoc-ndppd** proxies IPv6 Neighbor Discovery between interfaces so delegated
prefixes are reachable across a gateway. Ground-up C99 rewrite with a
corrected session state machine, configurable packet capture mode, and
strict RFC 4861 compliance.

[UniDoc](https://unidoc.io) fork of [totoCZ/ndppd][totocz], itself a
rewrite of [Daniel Adolfsson's ndppd][upstream]. Maintained for our own
IPv6 edge infrastructure.

[upstream]: https://github.com/DanielAdolfsson/ndppd
[totocz]: https://github.com/totoCZ/ndppd

---

## Why not the kernel or the original ndppd?

|  | Kernel `proxy_ndp` | Original ndppd | This fork |
|---|---|---|---|
| Prefix rules | per-address only | yes | yes |
| Probes before replying | replies blindly | yes | yes |
| Sees unicast NUD probes | multicast only | all-multicast socket | configurable (`promiscuous yes` for full capture) |
| Routing table integration | no | Netlink / AF_ROUTE | yes |
| RFC 4861 compliant | partial | DAD/STALE bugs | yes |

**The unicast NUD problem**: once a neighbor entry is established, NUD
refreshes it with unicast NS. In multi-bridge / veth scenarios these
frames can be addressed to a MAC that isn't the proxy's — so a
non-promiscuous socket never sees them, and the neighbor cache decays
to `FAILED` every 20-30 minutes under sustained traffic. On Linux this
fork defaults to `PACKET_MR_ALLMULTI` (catches solicited-node NS
without full promiscuous mode); set `promiscuous yes` per proxy when
you need every frame on the wire (container churn, bridged
deployments). On FreeBSD, BPF requires promiscuous mode as a kernel
constraint, so the flag is a no-op there.

---

## Fork status

This fork of `totoCZ/ndppd` adds:

- **Configurable capture mode.** Per-proxy `promiscuous yes/no` flag.
  Linux default `no` uses `PACKET_MR_ALLMULTI` — less invasive, still
  catches all solicited-node NS. `yes` uses `PACKET_MR_PROMISC` for
  scenarios that need every frame (unicast NS to stale MACs, bridge
  snoop). FreeBSD BPF always sets promisc (kernel requirement);
  setting `no` there emits an info-log and continues.
- **Static binary build by default.** `make` produces a fully static,
  non-PIE binary via `-static -no-pie -fstack-protector-strong
  -fno-strict-aliasing -Wformat=2`. One binary drops onto any Linux
  distro (musl or glibc) or FreeBSD of matching arch. No runtime
  dependencies beyond the kernel ABI.
- **Privilege drop.** `-u uid[:gid]` on Linux drops from root while
  retaining `CAP_NET_RAW` + `CAP_NET_ADMIN` via `capset(2)`. Any
  future parse-bug in the packet handlers no longer yields root.
- **Hardened packet handling.** BPF/PF_ROUTE read paths now
  bounds-check every record header before dereferencing; zero-advance
  records are rejected instead of hung on. Solicited-node NS receive
  buffer bumped to 2 KB so large NAs with multiple options are no
  longer silently dropped. Sub-list per session capped to bound memory
  under spoofed-NS floods. Hash seed randomized from `/dev/urandom`.
- **Clean shutdown.** Signal handlers set a flag polled by the main
  loop instead of calling `exit()` from async-signal context, so
  cleanup runs deterministically outside the signal frame.
- **musl compat.** Header includes and integer types cleaned up so the
  build is clean on Alpine (musl) as well as glibc.
- **Cleaner tree.** Removed CMake stub, asciidoctor manpage
  scaffolding, and upstream test scripts. `Makefile` is the single
  source of truth for builds.

---

## Build

Requires a C99 compiler (`gcc` or `clang`), `make`, and a static libc
available on the build host.

```sh
make            # builds bin/unidoc-ndppd (statically linked, stripped)
make clean      # removes bin/
make install    # copies bin/unidoc-ndppd to $PREFIX/sbin (default /usr/local/sbin)
```

**Build matrix.** Native build on each target; there is no cross-build
support in the Makefile (use `podman --platform` or a chroot if you
need cross-arch on one host).

| Target | Build host | Toolchain |
|---|---|---|
| Linux amd64 | Alpine amd64 | `apk add gcc musl-dev linux-headers make` |
| Linux arm64 | Alpine arm64 | `apk add gcc musl-dev linux-headers make` |
| FreeBSD amd64 | FreeBSD 13+ amd64 | `pkg install gmake` (invoke `gmake`) |
| FreeBSD arm64 | FreeBSD 13+ arm64 | `pkg install gmake` (invoke `gmake`) |

**Verify the binary is fully static:**

```sh
file bin/unidoc-ndppd    # "statically linked" (not "static-pie linked")
readelf -l bin/unidoc-ndppd | grep INTERP    # no output
```

An Alpine-built binary runs unmodified on Debian, Ubuntu, RHEL, and any
other glibc Linux of the same arch — no `/lib/ld-musl-*.so.1`
dependency, no runtime libc requirement.

---

## Usage

```sh
unidoc-ndppd -c /etc/unidoc-ndppd.conf [-dv] [-p pidfile] [--syslog] [--netns <name>]
```

| Flag | Description |
|---|---|
| `-c /path` | Config file (default `/opt/unidoc/etc/unidoc-ndppd.conf`) |
| `-d` | Daemonize |
| `-p /path` | Pidfile, flock-locked to prevent duplicates |
| `-u user[:group]` | *(Linux)* Drop from root to `user` (name or uid) and `group` (name or gid), retain CAP_NET_RAW + CAP_NET_ADMIN |
| `--syslog` | Force syslog in the foreground |
| `-v` / `-vv` | Debug / trace logging |
| `--netns <name>` | *(Linux)* Enter named netns before starting |

**Privilege drop** (`-u`) is recommended for production. The daemon reads
`/etc/passwd` and `/etc/group` directly (no libnss / dlopen) so the static
binary works identically on musl and glibc systems.

```sh
unidoc-ndppd -u nobody              # → uid + primary gid from /etc/passwd
unidoc-ndppd -u nobody:nogroup      # → uid from passwd, gid from group
unidoc-ndppd -u 65534               # → uid=gid=65534
unidoc-ndppd -u 65534:65534         # → uid=65534, gid=65534
unidoc-ndppd -u nobody:100          # → uid from passwd, gid=100 (numeric override)
```

---

## Configuration

Block syntax. Comments: `#` or `/* */`.

```nginx
# /etc/unidoc-ndppd.conf

valid-ttl   30000   # ms to keep a VALID session after last NA from target
invalid-ttl 10000   # ms to cache a failed session (absorbs NS floods)
retrans-time  1000  # ms between outgoing NS probes
retrans-limit    3  # probes before giving up
keepalive      no   # yes = keep probing STALE sessions without upstream NS

proxy eth0 {
    router no          # set Router flag in NAs (yes if targets are routers)
    promiscuous no     # yes = PACKET_MR_PROMISC on Linux; ignored on FreeBSD
    target <mac>       # override advertised MAC for all rules (optional)

    rule 2001:db8::/48 {
        auto           # resolve via routing table (or: iface <if>, or: static)
        table 254      # routing table to use (Linux only)
        autowire       # add /128 host route on VALID, remove on expiry (iface only)
        target <mac>          # per-rule MAC override (optional)
        rewrite fd00::/48     # rewrite target before forwarding (optional)
    }
}
```

Each rule requires exactly one of `auto`, `iface <if>`, or `static`.

See `contrib/unidoc-ndppd.conf-dist` for a minimal starting config.

---

## Session state machine

One session per (target, proxy) pair. STALE timeout is hardcoded at 30 s.

```
 [new NS] ──────────────────► INCOMPLETE ──── NA received ───► VALID
                                   │                              │
                          retrans_limit                       valid-ttl
                           exceeded  │                            │
                                     ▼                            ▼
                                  INVALID ◄──── 30 s ────── STALE
                                     │
                               invalid-ttl
                                     │
                                     ▼
                                 (deleted)
```

- **INCOMPLETE** — probing downstream; retransmits every `retrans-time`
  up to `retrans-limit` times.
- **VALID** — upstream NS answered immediately with a solicited NA.
- **STALE** — re-probes on fresh upstream NS; retransmit interval
  doubles every `retrans-limit` probes (capped at 2²⁰ × `retrans-time`).
- **INVALID** — keeps queued subscribers; a late NA still satisfies
  them all. In `auto` mode, re-checks the routing table on each
  incoming NS so a route appearing after initial failure is picked up
  automatically.

---

## Examples

### Delegated prefix to a LAN

```nginx
proxy wan0 {
    rule 2001:db8:1234:5600::/56 {
        auto
    }
}
```

### Containers with per-host route injection

```nginx
proxy eth0 {
    promiscuous yes    # veth churn — need all frames
    rule 2001:db8::/48 {
        iface br0
        autowire
        table 100
    }
}
```

### Public-to-internal prefix rewrite

NS for `2001:db8:a::1` probes `fd00::1` on `eth1`; the public address
is advertised upstream.

```nginx
proxy eth0 {
    rule 2001:db8:a::/48 {
        iface eth1
        rewrite fd00::/48
    }
}
```

---

## License and credits

GNU General Public License v3 or later.

- Copyright (C) 2011-2019 Daniel Adolfsson — original ndppd
- Copyright (C) 2020-2024 totoCZ — C99 rewrite
- UniDoc — this fork
