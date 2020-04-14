/*
 * main.c
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

#include <stdint.h>
#include <memory.h>
#include <errno.h>
#include <stdbool.h>
#include <unitypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>


#include "processor.h"
#include "mib.h"

typedef struct snmp_client {
    time_t          timestamp;
    int             sockfd;
    struct in_addr  addr;
    in_port_t       port;
    uint8_t         packet[BUFSIZ];
    size_t          size;
} snmp_client_t;


static snmp_client_t client;


static int sockfd;

static volatile int finish;

static int configure_socket() {
    const char *hostname = "0.0.0.0";
    const char *portname = "1993";
    struct addrinfo addr_hint;
    struct addrinfo *addr = NULL;
    int ret;

    /* Configure sockets listen address, port and type*/
    memset(&addr_hint, 0, sizeof(addr_hint));
    addr_hint.ai_family = AF_UNSPEC;
    addr_hint.ai_socktype = SOCK_DGRAM;
    addr_hint.ai_protocol = 0;
    addr_hint.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;

    if (0 != (ret = getaddrinfo(hostname, portname, &addr_hint, &addr))) {
//        log_critical("Can't obtain addrinfo for %s:%s: %s", hostname, portname, gai_strerror(ret));
        return ret;
    }

    /* Open UDP socket and bind it to machine address and SNMP port */
    if (-1 == (sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol))) {
//        log_critical("Failed to open UDP socket: %s", strerror(errno));
        ret = errno;
        goto end;
    }

    if (bind(sockfd, addr->ai_addr, addr->ai_addrlen) == -1) {
        ret = errno;
//        log_critical("Can't bind UDP socket to %s:%d: %s", hostname, ntohs(((struct sockaddr_in *)addr->ai_addr)->sin_port),
//                     strerror(errno));
        goto end;
    }

    end:
    freeaddrinfo(addr);
    return ret;
}

static void handle_incoming_datagram() {
    ssize_t rv;
    char straddr[INET_ADDRSTRLEN] = { '\0' };
    socklen_t socklen;
    struct sockaddr_in sockaddr;

    uint8_t *resp;
    ssize_t resp_size;


    /* Read whole UDP packet from socket */
    socklen = sizeof(sockaddr);
    rv = recvfrom(sockfd, client.packet, sizeof(client.packet), 0, (struct sockaddr *)&sockaddr, &socklen);

    if (rv == -1) {
//        log_error("Failde to receive UDP packet with SNMP request: %s", strerror(errno));
        return;
    }

    client.timestamp = time(NULL);
    client.sockfd = sockfd;
    client.addr = sockaddr.sin_addr;
    client.port = sockaddr.sin_port;
    client.size = rv;

    /* Call SNMP processor what will analyse request and prepare response packet */
    inet_ntop(AF_INET, &sockaddr.sin_addr, straddr, sizeof(straddr));

    resp_size = process_request(client.packet, client.size, &resp);


    rv = sendto(sockfd, resp, resp_size, MSG_DONTWAIT, (struct sockaddr *)&sockaddr, socklen);
    inet_ntop(AF_INET, &sockaddr.sin_addr, straddr, sizeof(straddr));
    if (rv == -1) {
        // Log warning
    } else if (rv != resp_size) {
        // Log warning
    }

    free(resp);
}


static int snmp_start() {
    fd_set rfds;
    struct timeval tv_timeout = { .tv_sec = 2, .tv_usec = 0 };
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);

    if (sockfd < 0) return 1;

    if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1) {
//        log_critical("Can't obtain information about SNMP service socket: %s", strerror(errno));
        return -1;
    }

//    log_info("Start listen for incomming UDP SNMP requests on 0.0.0.0:%d", ntohs(sin.sin_port));

    while (!finish) {
        FD_ZERO(&rfds);
        FD_SET(sockfd, &rfds);

        if (select(sockfd + 1, &rfds, NULL, NULL, &tv_timeout) == -1) {
            if (finish) break;

            //TODO: Maybe EINT must be handled
            return errno;
        }

        // handle UDP packets
        if (FD_ISSET(sockfd, &rfds)) handle_incoming_datagram();

        tv_timeout.tv_sec = 2;
        tv_timeout.tv_usec = 0;
    }

    return 0;
}







int get_device_type(void **value, size_t *size, bool *is_allocated) {
    static const oid_t oid = {.subids = { 1, 3, 6, 1, 2, 1, 25, 3, 1, 5 }, .subids_cnt = 10};

    *value = (void *)&oid;
    *size = sizeof(oid);
    *is_allocated = false;

    return 0;
}
int get_device_model(void **value, size_t *size, bool *is_allocated) {
    static const char str[] = "MyQ Virtual Device";

    *value = (void *)&str;
    *size = sizeof(str);
    *is_allocated = false;

    return 0;
}
int get_device_hw_addr(void **value, size_t *size, bool *is_allocated) {
    static const uint8_t hw_addr[] = { 0x18, 0xdb, 0xf2, 0x3d, 0xde, 0x50, 0x00 };

    *value = (void *)&hw_addr;
    *size = sizeof(hw_addr);
    *is_allocated = false;

    return 0;
}
int get_device_sn(void **value, size_t *size, bool *is_allocated) {
    static const char str[] = "SN2W443554";

    *value = (void *)&str;
    *size = sizeof(str);
    *is_allocated = false;

    return 0;
}

int get_c1(void **value, size_t *size, bool *is_allocated) {
    static const int cnt = 200;

    *value = (void *)&cnt;
    *size = sizeof(cnt);
    *is_allocated = false;

    return 0;
}

int get_c2(void **value, size_t *size, bool *is_allocated) {
    static const int cnt = 200;

    *value = (void *)&cnt;
    *size = sizeof(cnt);
    *is_allocated = false;

    return 0;
}

int get_c3(void **value, size_t *size, bool *is_allocated) {
    static const int cnt = 50;

    *value = (void *)&cnt;
    *size = sizeof(cnt);
    *is_allocated = false;

    return 0;
}

int get_c4(void **value, size_t *size, bool *is_allocated) {
    static const int cnt = 100;

    *value = (void *)&cnt;
    *size = sizeof(cnt);
    *is_allocated = false;

    return 0;
}



int main() {
    oid_t hw_info = {
            .subids = { 1, 3, 6, 1, 2, 1, 25, 3, 2, 1, 2, 2 },
            .subids_cnt = 12
    }, model = {
            .subids = { 1, 3, 6, 1, 2, 1, 25, 3, 2, 1, 3, 1 } ,
            .subids_cnt = 12
    }, hw_addr = {
            .subids = { 1, 3, 6, 1, 2, 1, 2, 2, 1, 6, 1 },
            .subids_cnt = 11
    }, sn = {
            .subids = { 1, 3, 6, 1, 2, 1, 43,   5,  1, 1,  17, 1},
            .subids_cnt = 12
    }, c1_1 = {
            .subids = { 1, 3, 6, 1, 4, 1, 11, 2, 3, 9, 4, 2, 1, 1, 16, 1, 44, 1, 2 },
            .subids_cnt = 19
    }, c1_2 = {
            .subids = { 1, 3, 6, 1, 4, 1, 11, 2, 3, 9, 4, 2, 1, 1, 16, 1, 44, 2, 1 },
            .subids_cnt = 17
    }, c1_3 = {
            .subids = { 1, 3, 6, 1, 4, 1, 11, 2, 3, 9, 4, 2, 1, 1, 16, 1, 44, 2, 2 },
            .subids_cnt = 19
    }, c1_4 = {
            .subids = { 1, 3, 6, 1, 4, 1, 11, 2, 3, 9, 4, 2, 1, 1, 16, 1, 44, 1, 3 },
            .subids_cnt = 19
    }, c2_1 = {
            .subids = { 1, 3, 6, 1, 4, 1, 11, 2, 3, 9, 4, 2, 1, 2, 2, 1, 62 },
            .subids_cnt = 17
    }, c3_1 = {
            .subids = { 1, 3, 6, 1, 2, 1, 43, 11,1, 1, 9, 1, 1 },
            .subids_cnt = 13
    }, c3_2 = {
            .subids = { 1, 3, 6, 1, 2, 1, 43, 11,1, 1, 9, 1, 2 },
            .subids_cnt = 13
    }, c3_3 = {
            .subids = { 1, 3, 6, 1, 2, 1, 43, 11,1, 1, 9, 1, 3 },
            .subids_cnt = 13
    }, c3_4 = {
            .subids = { 1, 3, 6, 1, 2, 1, 43, 11,1, 1, 9, 1, 4 },
            .subids_cnt = 13
    }, c4_1 = {
            .subids = { 1, 3, 6, 1, 2, 1, 43, 11,1, 1, 8, 1, 1 },
            .subids_cnt = 13
    }, c4_2 = {
            .subids = { 1, 3, 6, 1, 2, 1, 43, 11,1, 1, 8, 1, 2 },
            .subids_cnt = 13
    }, c4_3 = {
            .subids = { 1, 3, 6, 1, 2, 1, 43, 11,1, 1, 8, 1 ,3 },
            .subids_cnt = 13
    }, c4_4 = {
            .subids = { 1, 3, 6, 1, 2, 1, 43, 11,1, 1, 8, 1, 4 },
            .subids_cnt = 13
    };


    mib_add_entry(&hw_info, OBJECT_TYPE_OID, get_device_type, NULL);
    mib_add_entry(&model, OBJECT_TYPE_OCTET_STRING, get_device_model, NULL);
    mib_add_entry(&hw_addr, OBJECT_TYPE_OCTET_STRING, get_device_hw_addr, NULL);
    mib_add_entry(&sn, OBJECT_TYPE_OCTET_STRING, get_device_sn, NULL);

    mib_add_entry(&c1_1, OBJECT_TYPE_INTEGER, get_c1, NULL);
    mib_add_entry(&c1_2, OBJECT_TYPE_INTEGER, get_c1, NULL);
    mib_add_entry(&c1_3, OBJECT_TYPE_INTEGER, get_c1, NULL);
    mib_add_entry(&c1_4, OBJECT_TYPE_INTEGER, get_c1, NULL);

    mib_add_entry(&c2_1, OBJECT_TYPE_INTEGER, get_c2, NULL);

    mib_add_entry(&c3_1, OBJECT_TYPE_INTEGER, get_c3, NULL);
    mib_add_entry(&c3_2, OBJECT_TYPE_INTEGER, get_c3, NULL);
    mib_add_entry(&c3_3, OBJECT_TYPE_INTEGER, get_c3, NULL);
    mib_add_entry(&c3_4, OBJECT_TYPE_INTEGER, get_c3, NULL);

    mib_add_entry(&c4_1, OBJECT_TYPE_INTEGER, get_c4, NULL);
    mib_add_entry(&c4_2, OBJECT_TYPE_INTEGER, get_c4, NULL);
    mib_add_entry(&c4_3, OBJECT_TYPE_INTEGER, get_c4, NULL);
    mib_add_entry(&c4_4, OBJECT_TYPE_INTEGER, get_c4, NULL);

    if (!configure_socket()) {
        snmp_start();
    }


    mib_free();

    return 0;
}
