#!/bin/sh
# Integration test: a configured interface that is absent at startup, or
# deleted/recreated at runtime, must never kill the daemon, and must be
# (re)bound with its new ifindex. Needs root (or CAP_NET_ADMIN+CAP_NET_RAW)
# and `ip`; runs inside a throwaway network namespace. Skips (exit 77)
# otherwise.
set -u
BIN=${BIN:-./bin/unidoc-ndppd}
[ -x "$BIN" ] || { echo "build first (make)"; exit 1; }
command -v ip >/dev/null || { echo "SKIP: no ip"; exit 77; }

if [ -z "${IN_NETNS:-}" ]; then
    unshare -n true 2>/dev/null || { echo "SKIP: cannot unshare netns (need root)"; exit 77; }
    exec env IN_NETNS=1 unshare -n sh "$0" "$@"
fi

T=$(mktemp -d); trap 'kill $P 2>/dev/null; rm -rf "$T"' EXIT
cat > "$T/c.conf" <<CONF
proxy dummy0 {
    router yes
    rule 2001:db8::/64 {
        static
    }
}
CONF
fail=0
check() { # desc, cmd...
    d=$1; shift
    if "$@"; then echo "ok   - $d"; else echo "FAIL - $d"; fail=1; fi
}
alive() { kill -0 "$P" 2>/dev/null; }
logs()  { grep -q "$1" "$T/log"; }
waitlog() { n=0; while ! logs "$1" && [ $n -lt 80 ]; do sleep 0.1; n=$((n+1)); done; logs "$1"; }

ip link set lo up
# Any link type will do; dummy needs a kernel module that not every host has.
mklink() { # name
    ip link add "$1" type dummy 2>/dev/null && return 0
    ip link add "$1" type bridge 2>/dev/null && return 0
    ip link add "$1" type veth peer name "${1}p" 2>/dev/null
}
mklink probe0 || { echo "SKIP: kernel supports none of dummy/bridge/veth"; exit 77; }
ip link del probe0
"$BIN" -c "$T/c.conf" -v >"$T/log" 2>&1 & P=$!

# 1. interface absent at startup
sleep 1
check "daemon survives a missing interface at startup" alive
check "logs waiting state" logs "waiting for it to appear"

# 2. appears -> bound (rebind_all runs on netlink event / 5 s poll)
mklink dummy0; ip link set dummy0 up
check "binds when the interface appears" waitlog "interface appeared"
check "still alive" alive

# 3. disappears
ip link del dummy0
check "notices disappearance" waitlog "interface disappeared"
check "survives deletion" alive

# 4. recreated (occupy the old ifindex so the new one differs)
mklink pad0
mklink dummy0; ip link set dummy0 up
check "rebinds on recreate" waitlog "interface reappeared"
check "survives recreate" alive

exit $fail
