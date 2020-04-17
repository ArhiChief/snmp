/*
 * net_udp.c
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

#include "net_udp.h"
#include "../log/log.h"
#include "../progam_config.h"

static int sock_fd = -1;

int init_udp(const struct sockaddr *sockaddr, socklen_t socklen, int domain) {
    sock_fd = socket(domain, SOCK_DGRAM, 0);
    if (-1 == sock_fd) {
        log_crit("Failed to open UDP socket: %s", strerror(errno));
        return -1;
    }

    if (-1 == bind(sock_fd, sockaddr, socklen)) {
        log_crit("Failed to bind UDP socket to port: %s", strerror(errno));
        goto err;
    }

    return sock_fd;

err:
    close(sock_fd);
    return -1;
}

int release_upd() {
    if (-1 != sock_fd) {
        close(sock_fd);
    }

    return 0;
}
