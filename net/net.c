/*
 * net.c
 * Copyright (c) 2020 Sergei Kosivchenko <archichief@gmail.com>
 *
 * smart-snmp is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smart-snmp is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <netinet/in.h>
#include <sys/poll.h>
#include <errno.h>

#include "net.h"
#include "../progam_config.h"
#include "net_udp.h"
#include "net_tcp.h"
#include "../log/log.h"

static int sock_fd_udp;
static int sock_fd_tcp;

int network_init() {
    socklen_t socklen;
    union {
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;
    } sockaddr_in;

    int sin_family = g_socket_type();
    int port = g_port();
    const struct in_addr inaddr_any = {INADDR_ANY};
    const struct sockaddr *sockaddr = (struct sockaddr *) (&sockaddr_in);
    int domain;

    memset(&sockaddr_in, 0, sizeof(sockaddr_in));

    if (AF_INET == g_socket_type()) {
        sockaddr_in.sa.sin_family = sin_family;
        sockaddr_in.sa.sin_port = htons(port);
        sockaddr_in.sa.sin_addr = inaddr_any;
        domain = PF_INET;
        socklen = sizeof(sockaddr_in.sa);
    } else {
        sockaddr_in.sa6.sin6_family = sin_family;
        sockaddr_in.sa6.sin6_port = htons(port);
        sockaddr_in.sa6.sin6_addr = in6addr_any;
        socklen = sizeof(sockaddr_in.sa6);
        domain = PF_INET6;
    }

    if (!(sock_fd_udp = init_udp(sockaddr, socklen, domain)) || !(sock_fd_tcp = init_tcp(sockaddr, socklen, domain))) {
        return -1;
    }

    log_info("Listening on port %d for UDP and TCP", port);
    return 0;
}

typedef enum {
    POLL_UDP = 0,
    POLL_TCP = 1,
    POLL_TOTAL
} pollfd_index_t;

#define POLL_TIMEOUT  5 * 1000 // in milliseconds

int network_listen(const bool *stop) {
    int poll_ret;
    int err;
    struct pollfd pollfds[POLL_TOTAL] = {
            {.fd = sock_fd_udp, .events = POLLIN, .revents = 0 },
            {.fd = sock_fd_tcp, .events = POLLIN, .revents = 0}
    };

    while (!*stop) {
        log_debug("Start polling");
        poll_ret = poll(pollfds, POLL_TOTAL, POLL_TIMEOUT);
        switch (poll_ret) {
            case 0: // timedout
                log_debug("Polling is timed out");
                continue;
            case -1:
                err = errno;
                switch (err) {
                    case EAGAIN:
                        log_warn("The allocation of internal data structures failed during polling for incoming "
                                 "connections, but a subsequent request may succeed");
                        break;
                    case EINTR:
                        log_warn("A signal was caught during polling for incoming connections");
                        continue;
                    case EINVAL:
                        log_err("Polling for incoming connections fails: %s", strerror(errno));
                        return -1;
                }
                break;
            default:
                log_debug("Polling succeeded. Event occurred for %d fds.", poll_ret);
                break;
        }

        if (*stop) {
            break;
        }

        if (pollfds[POLL_UDP].revents & POLLIN) {

        } else if (pollfds[POLL_TCP].revents & POLLIN) {

        }
    }

    log_info("Waiting for incoming connections finished.");
    return 0;
}
