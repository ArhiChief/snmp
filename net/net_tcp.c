/*
 * net_tcp.c
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

#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "net_tcp.h"
#include "../log/log.h"
#include "../progam_config.h"

static int sock_fd = -1;

int init_tcp(const struct sockaddr *sockaddr, socklen_t socklen, int domain) {
    int opt_val = 1;

    sock_fd = socket(domain, SOCK_STREAM, 0);
    if (-1 == sock_fd) {
        return -1;
    }

    if (-1 == setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val))) {
        log_warn("Failed to set SO_REUSEADDR for TCP socket: %s", strerror(errno));
        goto err;
    }

    if (-1 == bind(sock_fd, sockaddr, socklen)) {
        log_crit("Failed to bind TCP socket to port: %s", strerror(errno));
        goto err;
    }

    if (-1 == listen(sock_fd, g_max_connections())) {
        log_crit("Failed to start listening for incoming TCP connections: %s", strerror(errno));
        goto err;
    }

    return sock_fd;

err:
    close(sock_fd);
    return -1;
}

int release_tcp() {
    if (-1 != sock_fd) {
        close(sock_fd);
    }

    return 0;
}
