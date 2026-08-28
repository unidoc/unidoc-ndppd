ifdef DEBUG
CFLAGS  ?= -g -DDEBUG
else
CFLAGS  ?= -Os
LDFLAGS ?= -s -w
endif

CC      ?= gcc
PREFIX  ?= /usr/local
SBINDIR ?= ${DESTDIR}${PREFIX}/sbin

# This project's own version, baked into the binary (NDPPD_VERSION in
# ndppd.h) via CPPFLAGS below - never hand-edited in source. Auto-detected
# from git for local/dev builds; CI passes the exact pushed tag explicitly
# (VERSION=v1.0.0 make), which always wins over the git-describe guess.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
CPPFLAGS += -DNDPPD_VERSION=\"${VERSION}\"

CFLAGS := ${CFLAGS} -Werror -Wall -Wextra -Wno-missing-braces -Wno-missing-field-initializers

# Defensive compile flags:
#   -fno-strict-aliasing   packet code casts between struct in6_addr / nd_addr_t / uint16_t
#                          without may_alias; disabling strict aliasing removes miscompilation risk.
#   -fstack-protector-strong   canary on non-trivial stack frames — cheap defense-in-depth
#                              against buffer overflows in packet parsers.
#   -Wformat=2 -Wformat-security   ensures format-string arguments stay literal.
CFLAGS  += -fno-strict-aliasing -fstack-protector-strong -Wformat=2 -Wformat-security

# Always link statically: one binary drops onto any Linux distro (musl or
# glibc) or FreeBSD of the same arch. unidoc-ndppd calls no NSS routines
# (no getaddrinfo/getpwnam/etc.), so static glibc is safe here.
# -no-pie avoids static-PIE: static-PIE keeps an INTERP header pointing at
# the musl loader, which makes the binary fail to exec on glibc distros
# that don't have /lib/ld-musl-*.so.1. Non-PIE static has no interp.
LDFLAGS += -static -no-pie
CFLAGS  += -fno-pie

SRCS = $(wildcard src/*.c)
OBJS = $(patsubst src/%.c,bin/%.o,$(SRCS))
DEPS = $(OBJS:.o=.d)
BIN  = bin/unidoc-ndppd

# -MMD writes bin/<obj>.d with the header dependencies discovered during the
# compile.  -MP adds dummy targets for each header so deleting a header doesn't
# stop the build with a "no rule to make target" error.  Both flags cost nothing
# at compile time.
DEPFLAGS = -MMD -MP

all: ${BIN}

${BIN}: ${OBJS}
	${CC} -o $@ ${LDFLAGS} ${OBJS} ${LIBS}

bin/%.o: src/%.c | bin
	${CC} -c ${CPPFLAGS} ${CFLAGS} ${DEPFLAGS} -o $@ $<

bin:
	mkdir -p bin

install: ${BIN}
	mkdir -p ${SBINDIR}
	cp ${BIN} ${SBINDIR}
	chmod +x ${SBINDIR}/unidoc-ndppd

clean:
	rm -rf bin

# Pull in generated per-object header dependencies (created by -MMD).
# Missing on first build; the `-include` silently ignores that.
-include ${DEPS}

.PHONY: all install clean
