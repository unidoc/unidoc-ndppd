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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if !defined(__linux__) && !defined(NDPPD_NO_USE_EPOLL)
#    define NDPPD_NO_USE_EPOLL
#endif

#ifndef NDPPD_NO_USE_EPOLL
#    include <sys/epoll.h>
#else
#    include <poll.h>
#    include <stdlib.h>
#    ifdef EPOLLIN
#        undef EPOLLIN
#    endif
#    define EPOLLIN POLLIN
#endif

#include "ndppd.h"

static nd_io_t *ndL_first_io;

#ifndef NDPPD_NO_USE_EPOLL
static int ndL_epoll_fd;
#else
#    ifndef NDPPD_STATIC_POLLFDS_SIZE
#        define NDPPD_STATIC_POLLFDS_SIZE 8
#    endif

static struct pollfd ndL_static_pollfds[NDPPD_STATIC_POLLFDS_SIZE];
static struct pollfd *ndL_pollfds = ndL_static_pollfds;
static int ndL_pollfds_size = NDPPD_STATIC_POLLFDS_SIZE;
static int ndL_pollfds_count = 0;
static bool ndL_dirty;

static void ndL_refresh_pollfds()
{
    int count;

    ND_LL_COUNT(ndL_first_io, count, next);

    if (count > ndL_pollfds_size) {
        int new_pollfds_size = count * 2;

        struct pollfd *new_pollfds = (struct pollfd *)realloc(
            ndL_pollfds == ndL_static_pollfds ? NULL : ndL_pollfds, new_pollfds_size * sizeof(struct pollfd));

        if (!new_pollfds) {
            nd_log_error("realloc() failed growing pollfds to %d entries — out of memory", new_pollfds_size);
            exit(EXIT_FAILURE);
        }

        ndL_pollfds = new_pollfds;
        ndL_pollfds_size = new_pollfds_size;
    }

    int index = 0;

    ND_LL_FOREACH (ndL_first_io, io, next) {
        ndL_pollfds[index++] = (struct pollfd){ .fd = io->fd, .events = POLLIN };
    }

    ndL_pollfds_count = index;
}
#endif

static nd_io_t *ndL_create(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags == -1) {
        nd_log_error("Could not read flags: %s", strerror(errno));
        close(fd);
        return NULL;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        nd_log_error("Could not set flags: %s", strerror(errno));
        close(fd);
        return NULL;
    }

    nd_io_t *io = ND_NEW(nd_io_t);

    *io = (nd_io_t){ .fd = fd };

    ND_LL_PREPEND(ndL_first_io, io, next);

#ifndef NDPPD_NO_USE_EPOLL
    if (ndL_epoll_fd <= 0 && (ndL_epoll_fd = epoll_create(1)) < 0) {
        nd_log_error("epoll_create() failed: %s", strerror(errno));
        goto fail;
    }

    struct epoll_event event = { .events = EPOLLIN, .data.ptr = io };

    if (epoll_ctl(ndL_epoll_fd, EPOLL_CTL_ADD, io->fd, &event) < 0) {
        nd_log_error("epoll_ctl() failed: %s", strerror(errno));
        goto fail;
    }
#else
    /* Make sure our pollfd array is updated. */
    ndL_dirty = true;
#endif

    return io;

#ifndef NDPPD_NO_USE_EPOLL
fail:
    ND_LL_DELETE(ndL_first_io, io, next);
    close(io->fd);
    ND_DELETE(io);
    return NULL;
#endif
}

nd_io_t *nd_io_socket(int domain, int type, int protocol)
{
    int fd = socket(domain, type, protocol);

    if (fd == -1) {
        nd_log_error("nd_io_socket(): Could not create socket: %s", strerror(errno));
        return NULL;
    }

    return ndL_create(fd);
}

nd_io_t *nd_io_open(const char *file, int oflag)
{
    int fd = open(file, oflag);

    if (fd == -1)
        return NULL;

    return ndL_create(fd);
}

void nd_io_close(nd_io_t *io)
{
    /* NULL-tolerant: callers in the rebind path (iface.c) can end up
     * with a NULL bpf_io after a failed reopen, and downstream teardown
     * shouldn't have to know that. Defensive close is free. */
    if (!io) {
        return;
    }

    close(io->fd);

#ifdef NDPPD_NO_USE_EPOLL
    ndL_dirty = true;
#endif

    ND_LL_DELETE(ndL_first_io, io, next);
    ND_DELETE(io);
}

ssize_t nd_io_send(nd_io_t *io, const struct sockaddr *addr, size_t addrlen, const void *msg, size_t msglen)
{
    struct iovec iov = {
        .iov_len = msglen,
        .iov_base = (caddr_t)msg,
    };

    struct msghdr mhdr = {
        .msg_name = (caddr_t)addr,
        .msg_namelen = addrlen,
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    ssize_t len;

    if ((len = sendmsg(io->fd, &mhdr, 0)) < 0) {
        nd_log_error("nd_sio_send() failed: %s", strerror(errno));
        return -1;
    }

    return len;
}

ssize_t nd_io_recv(nd_io_t *io, struct sockaddr *addr, size_t addrlen, void *msg, size_t msglen)
{
    struct iovec iov = {
        .iov_len = msglen,
        .iov_base = (caddr_t)msg,
    };

    struct msghdr mhdr = {
        .msg_name = (caddr_t)addr,
        .msg_namelen = addrlen,
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    ssize_t len;

    do {
        len = recvmsg(io->fd, &mhdr, 0);
    } while (len < 0 && errno == EINTR);

    if (len < 0) {
        if (errno != EAGAIN)
            nd_log_error("nd_sio_recv() failed: %s", strerror(errno));

        return -1;
    }

    return len;
}

ssize_t nd_io_read(nd_io_t *io, void *buf, size_t count)
{
    ssize_t len;
    do {
        len = read(io->fd, buf, count);
    } while (len < 0 && errno == EINTR);
    return len;
}

ssize_t nd_io_write(nd_io_t *io, void *buf, size_t count)
{
    ssize_t len = write(io->fd, buf, count);

    if (len < 0)
        nd_log_error("err: %s", strerror(errno));

    return len;
}

bool nd_io_bind(nd_io_t *io, const struct sockaddr *addr, size_t addrlen)
{
    return bind(io->fd, addr, addrlen) == 0;
}

bool nd_io_poll()
{
#ifndef NDPPD_NO_USE_EPOLL
    struct epoll_event events[8];

    int count;
    do {
        count = epoll_wait(ndL_epoll_fd, events, 8, 250);
    } while (count < 0 && errno == EINTR);

    if (count < 0) {
        nd_log_error("epoll() failed: %s", strerror(errno));
        return false;
    }

    for (int i = 0; i < count; i++) {
        nd_io_t *io = (nd_io_t *)events[i].data.ptr;

        if (io->handler)
            io->handler(io, events[i].events);
    }
#else
    if (ndL_dirty) {
        ndL_refresh_pollfds();
        ndL_dirty = false;
    }

    int len;
    do {
        len = poll(ndL_pollfds, ndL_pollfds_count, 250);
    } while (len < 0 && errno == EINTR);

    if (len < 0) {
        nd_log_error("poll() failed: %s", strerror(errno));
        return false;
    }

    if (len == 0)
        return true;

    for (int i = 0; i < ndL_pollfds_count; i++) {
        if (ndL_pollfds[i].revents == 0)
            continue;

        ND_LL_FOREACH (ndL_first_io, io, next) {
            if (io->fd == ndL_pollfds[i].fd) {
                if (io->handler != NULL)
                    io->handler(io, ndL_pollfds[i].revents);

                break;
            }
        }
    }
#endif

    return true;
}

void nd_io_cleanup()
{
    ND_LL_FOREACH_S (ndL_first_io, sio, tmp, next)
        nd_io_close(sio);

#ifndef NDPPD_NO_USE_EPOLL
    if (ndL_epoll_fd > 0) {
        close(ndL_epoll_fd);
        ndL_epoll_fd = 0;
    }
#endif
}
