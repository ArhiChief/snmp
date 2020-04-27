/*
 * request_processor.c
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

#include "request_processor.h"
#include "../progam_config.h"
#include "../log/log.h"
#include "../ber/ber.h"
#include "../utilities.h"
#include "snmp_v1.h"

static bool is_version_supported(snmp_version_t v) {
    supported_snmp_version_t supportedVersions = g_snmp_version();

    switch (v) {
        case SNMP_VERSION_1:
            return supportedVersions & SNMP_V1;
        default:
            return false;
    }
}

static bool is_community_supported(const char *request_community, int len) {
    return memcmp(g_community_name(), request_community, len);
}

static int test_non_v3_snmp_request(const asn1_node_t *request) {
    const asn1_node_t *item;
    char *community = NULL;
    size_t community_string_len;

    int res = 0;

    // second element is SNMP Community String
    item = request->content.c.items[1];
    if (OBJECT_TYPE_OCTET_STRING != item->type ||
        (community_string_len = ber_decode_octet_string(item->content.p.data, item->content.p.size, &community)) < 1 ||
        !is_community_supported(community, community_string_len)) {
        res = -1;
    }

    free(community);
    return res;
}

static snmp_version_t test_snmp_request(const asn1_node_t *request) {
    const asn1_node_t *item;
    snmp_version_t version;

    // root must be SEQUENCE with 3 elements
    if (request->type != OBJECT_TYPE_SEQUENCE || request->content.c.items_num != 3) {
        return -1;
    }

    // first element is SNMP Version (1 byte length)
    item = request->content.c.items[0];
    if (OBJECT_TYPE_INTEGER != item->type ||
        item->content.p.size != 1 ||
        ber_decode_integer(item->content.p.data, item->content.p.size, (int *) &version) != 1 ||
        !is_version_supported(version)) {
        return -1;
    }

    if (version != SNMP_VERSION_3) {
        return test_non_v3_snmp_request(request) ? (snmp_version_t) -1 : version;
    } else {
        // snmp v3 looks different from v1 and v2c because can use authentication
        return -1;
    }
}

int queue_request_process(void *client, read_func_t read_func, write_func_t write_func, release_func_t release_func) {
    uint8_t *request_packet = NULL;
    uint8_t *response_packet = NULL;
    ssize_t requset_packet_size;
    size_t response_packet_size;
    ssize_t bytes_decoded;

    asn1_node_t request;
    asn1_node_t respone;

    memset(&request, 0, sizeof(request));
    memset(&respone, 0, sizeof(request));

    snmp_version_t version;

    if(0 >= (requset_packet_size = read_func(client, &request_packet))) {
        goto err;
    }

    if (0 > (bytes_decoded = ber_decode_asn1_tree(request_packet, requset_packet_size, &request)) || bytes_decoded != requset_packet_size) {
        return -1;
    }

    if (-1 == (int)(version = test_snmp_request(&request))) {
    }

    switch (version) {
        case SNMP_VERSION_1:
            process_snmp_v1(&request, &respone);
            break;
        default:
            exit(1);
    }

    if (write_func) {
        response_packet_size = ber_encode_asn1_tree(&respone, &response_packet);
        write_func(client, response_packet, response_packet_size);
    }
    return 0;

err:
    if (release_func) release_func(client);
    release_asn1_tree(&request);
    free(request_packet);

    return -1;
}
