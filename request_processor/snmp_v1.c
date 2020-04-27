/*
 * snmp_v1.c
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

#include "snmp_v1.h"
#include "../ber/ber.h"

enum snmp_v1_request {
    SNMP_V1_GET              = 0xA0,
    SNMP_V1_GETNEXT          = 0xA1,
    SNMP_V1_SET              = 0xA3,
    SNMP_V1_TRAP             = 0xA4,
};

static int process_get(asn1_node_t *request, asn1_node_t *response);
static int process_get_next(asn1_node_t *request, asn1_node_t *response);
static int process_set(asn1_node_t *request, asn1_node_t *response);
static int process_trap(asn1_node_t *request, asn1_node_t *response);

int process_snmp_v1(asn1_node_t *request, asn1_node_t *response) {
    const asn1_node_t *pdu = request->content.c.items[2];

    switch (pdu->type) {
        case SNMP_V1_GET:
            process_get(request, response);
            break;
        case SNMP_V1_GETNEXT:
            process_get_next(request, response);
            break;
        case SNMP_V1_SET:
            process_set(request, response);
            break;
        case SNMP_V1_TRAP:
            process_trap(request, response);
            break;
    }

    return 0;
}

static int process_get(asn1_node_t *request, asn1_node_t *response) {
    size_t i;
    oid_t oid;
    const asn1_node_t *pdu = request->content.c.items[2];
    size_t vbs_cnt = pdu->content.c.items[3]->content.c.items_num;
    asn1_node_t **req_vbs = pdu->content.c.items[3]->content.c.items,
            *resp_pdu = NULL, *resp_vb = NULL, *resp_vb_list;
    const asn1_node_t *req_vb_key, *pdu_root = pdu->root;

    const mib_entry_t *mib_entry;

    size_t encoded_val_size;
    void *encoded_val;

    resp_vb_list = create_asn1_node(NULL, OBJECT_TYPE_SEQUENCE, NULL, 0, false);

    for (i = 0; i < vbs_cnt; i++) {
        req_vb_key = req_vbs[i]->content.c.items[0];

        resp_vb = create_asn1_node(resp_vb_list, OBJECT_TYPE_SEQUENCE, NULL, 0, false);

        ber_decode_oid(req_vb_key->content.p.data, req_vb_key->content.p.size, &oid);

        encoded_val_size = req_vb_key->content.p.size;
        encoded_val = malloc(encoded_val_size);
        memmove(encoded_val, req_vb_key->content.p.data, encoded_val_size);

        create_asn1_node(resp_vb, req_vb_key->type, encoded_val, encoded_val_size, true);

        if (NULL == (mib_entry = search(&oid))) {

        } else {
            encode_data(mib_entry, &encoded_val, &encoded_val_size);
            create_asn1_node(resp_vb, mib_entry->type, encoded_val, encoded_val_size, true);
        }
    }

    resp->type = OBJECT_TYPE_SEQUENCE;
    add_asn1_node(resp, copy_primitive_asn1_node(pdu_root->content.c.items[0]));
    add_asn1_node(resp, copy_primitive_asn1_node(pdu_root->content.c.items[1]));

    resp_pdu = create_asn1_node(resp, REQUEST_TYPE_GETRESPONSE, NULL, 0, false);

    add_asn1_node(resp_pdu, copy_primitive_asn1_node(pdu->content.c.items[0]));
    add_asn1_node(resp_pdu, copy_primitive_asn1_node(pdu->content.c.items[1]));
    add_asn1_node(resp_pdu, copy_primitive_asn1_node(pdu->content.c.items[2]));
    add_asn1_node(resp_pdu, resp_vb_list);

    return true;
}

static int process_get_next(asn1_node_t *request, asn1_node_t *response) {
    if (request == NULL) exit(0);
    if (response == NULL) exit(0);

    return 0;
}

static int process_set(asn1_node_t *request, asn1_node_t *response) {
    if (request == NULL) exit(0);
    if (response == NULL) exit(0);

    return 0;
}

static int process_trap(asn1_node_t *request, asn1_node_t *response) {
    if (request == NULL) exit(0);
    if (response == NULL) exit(0);

    return 0;
}
