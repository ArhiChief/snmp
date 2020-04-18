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
#include <stdlib.h>
#include <arpa/inet.h>

#include "net_tcp.h"
#include "../log/log.h"
#include "../progam_config.h"

static struct {
    int sock_fd;
    int domain;
} tcp_info = { .sock_fd = -1, .domain = -1 };


int init_tcp(const struct sockaddr *sockaddr, socklen_t socklen, int domain) {
    int opt_val = 1;

    tcp_info.sock_fd = socket(domain, SOCK_STREAM, 0);
    if (-1 == tcp_info.sock_fd) {
        return -1;
    }

    if (-1 == setsockopt(tcp_info.sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val))) {
        log_warn("Failed to set SO_REUSEADDR for TCP socket: %s", strerror(errno));
        goto err;
    }

    if (-1 == bind(tcp_info.sock_fd, sockaddr, socklen)) {
        log_crit("Failed to bind TCP socket to port: %s", strerror(errno));
        goto err;
    }

    if (-1 == listen(tcp_info.sock_fd, g_max_connections())) {
        log_crit("Failed to start listening for incoming TCP connections: %s", strerror(errno));
        goto err;
    }

    tcp_info.domain = domain;
    return tcp_info.sock_fd;

err:
    close(tcp_info.sock_fd);
    tcp_info.sock_fd = -1;
    return -1;
}

#define ADDR_STR_LEN 20

tcp_clien_t *accept_tcp_connection() {
    union {
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;
    } sockaddr = { 0 };
    socklen_t socklen = 0;
    char addr_str[ADDR_STR_LEN] = {'\0'};
    int receiver_fd;
    tcp_clien_t *client;

    receiver_fd = accept(tcp_info.sock_fd, (struct sockaddr *)&sockaddr, &socklen);
    if (-1 == receiver_fd) {
        log_err("Failed to accept incoming TCP connection: %s", strerror(errno));
        return NULL;
    }

    client = malloc(sizeof(*client));
    client->fd = receiver_fd;
    memmove(&client->addr, &sockaddr, sizeof(client->addr));

    inet_ntop(tcp_info.domain, &sockaddr, addr_str, sizeof(addr_str));
    log_info("Connected TCP client: %s:%d", addr_str, sockaddr.sa.sin_port);

    return client;
}

#define READ_LENGTH 512

ssize_t read_tcp(tcp_clien_t *client, uint8_t **buffer) {
    size_t shift = 0, siz = 0;
    ssize_t br;
    uint8_t *tmp;

    *buffer = NULL;

    do {
        if (shift + READ_LENGTH >= siz) {
            // try to reallocate as less times as possible
            tmp = realloc(*buffer, siz + READ_LENGTH * 2 * sizeof(uint8_t));
            if (!tmp) {
                log_err("Failed to allocate buffer: %s", strerror(errno));
                goto err;
            }
            siz += READ_LENGTH * 2;
            *buffer = tmp;
        }

        br = read(client->fd, *buffer + shift, READ_LENGTH * sizeof(uint8_t));
        shift += br;
    } while (READ_LENGTH == br);

    if (br < 0) {
        log_err("Failed to read incoming TCP: %s", strerror(errno));
        goto err;
    }

    // set buffer capacity to be equal to amount of read bytes to decrease memory lost if needed
    if (shift != siz) {
        tmp = realloc(*buffer, shift * sizeof(uint8_t));
        if (!tmp) {
            log_warn("Failed to set buffer capacity to amount of read bytes: %s", strerror(errno));
        }
        *buffer = tmp;
    }

    return siz;

err:
    free(*buffer);
    close (client->fd);
    client->fd = -1;
    return -1;
}

int release_tcp() {
    if (-1 != tcp_info.sock_fd) {
        close(tcp_info.sock_fd);
    }

    return 0;
}
