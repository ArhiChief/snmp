/*
 * net_tcp.h
 * Defines routines to work with TCP connections
 *
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

#ifndef SNMP_NET_TCP_H
#define SNMP_NET_TCP_H

#include <netinet/in.h>

typedef struct {
    int fd;
    union {
        struct sockaddr_in sa;
        struct sockaddr_in6 sa6;
    } addr;
} tcp_clien_t;

int init_tcp(const struct sockaddr *sockaddr, socklen_t socklen, int domain);
tcp_clien_t *accept_tcp_connection();

ssize_t read_tcp(const tcp_clien_t *client, uint8_t **buffer);
ssize_t write_tcp(const tcp_clien_t *client, const uint8_t *buffer, size_t buf_siz);
int release_tcp_client(tcp_clien_t *client);

int release_tcp();



#endif //SNMP_NET_TCP_H
