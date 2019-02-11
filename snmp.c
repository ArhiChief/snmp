//
// Created by arhichief on 2/8/19.
//

#include <memory.h>
#include <errno.h>
#include "snmp.h"
#include "ber.h"
#include "snmp_types.h"
#include "transcoder.h"
#include "snmp_mib.h"


typedef bool (*check_strategy_t)(const asn1_tree_node_t *req);

static bool is_version_supported(snmp_version_t ver) {
    return SNMP_VERSION_3 != ver; // version 3 doesn't support
}

static bool is_community_supported(const char *comunity) {
    return 0 == strcmp(comunity, "public");
}

// check GetRequest, GetNextRequest, GetResponse, SetRequest
static bool check_non_trap_request(const asn1_tree_node_t *pdu) {
    const asn1_tree_node_t *item, *varbind;
    int i, val = 0;

    // PDU contains should contain 4 elements
    if (pdu->content.c.items_num != 4) return false;

    // first element of PDU is Request ID
    item = pdu->content.c.items[0];
    if (SNMP_OBJECT_TYPE_INTEGER != item->type ||
        decode_int(item->content.p.data, item->content.p.size, &val) < 1 ||
        val < 0) {
        return false;
    }

    // next 2 elements are Error Status and Error Index
    for (i = 1; i < 3; i++) {
        item = pdu->content.c.items[i];

        if (SNMP_OBJECT_TYPE_INTEGER != item->type ||
            decode_int(item->content.p.data, item->content.p.size, &val) != 1 ||
            val > 0) {
            return false;
        }
    }

    // last element is varbind list
    item = pdu->content.c.items[3];
    if (SNMP_OBJECT_TYPE_SEQUENCE == item->type && item->content.c.items_num > 0) {
        for (i = 0; i < item->content.c.items_num; i++) {
            varbind = item->content.c.items[i];

            // varbind must be SEQUENCE with 2 primitive elements and first element must be OID
            if (SNMP_OBJECT_TYPE_SEQUENCE != varbind->type || 2 != varbind->content.c.items_num ||
                SNMP_OBJECT_TYPE_OID != varbind->content.c.items[0]->type ||
                is_constructed(varbind->content.c.items[1]->type)) {
                return false;
            }
        }
    } else
        return false;

    return true;
}

// only Get and GetNext requests are supported
static check_strategy_t is_request_type_supported(snmp_request_type_t type) {
    switch (type) {
        case SNMP_OBJECT_TYPE_GETREQUEST:
        case SNMP_OBJECT_TYPE_GETNEXTREQUEST:
            return check_non_trap_request;
        default:
            return NULL;
    }
}

static const asn1_tree_node_t *check_snmp_request(const asn1_tree_node_t *req) {
    const asn1_tree_node_t *item, *pdu = NULL;
    snmp_version_t version;
    char *community = NULL;
    check_strategy_t strategy;

    // root must be SEQUENCE with 3 elements
    if (req->type != SNMP_OBJECT_TYPE_SEQUENCE || req->content.c.items_num != 3) {
        goto end;
    }

    // first element is SNMP Version (1 byte length)
    item = req->content.c.items[0];
    if (SNMP_OBJECT_TYPE_INTEGER != item->type                                          ||
        item->content.p.size != 1                                                       ||
        decode_int(item->content.p.data, item->content.p.size, (int *)&version) != 1    ||
        !is_version_supported(version)) {
        goto end;
    }

    // second element is SNMP Community String
    item = req->content.c.items[1];
    if (SNMP_OBJECT_TYPE_OCTET_STRING != item->type                                     ||
        decode_string(item->content.p.data, item->content.p.size, &community) < 1       ||
        !is_community_supported(community)) {
        goto end;
    }

    // third element is SNMP PDU
    item = req->content.c.items[2];
    if (NULL == (strategy = is_request_type_supported(item->type)) || !strategy(item)) {
        goto end;
    }

    pdu = item;

    end:
    free(community);
    return pdu;
}

typedef const mib_entry_t *(*search_func_t)(const snmp_oid_t *oid);


static bool encode_data(const mib_entry_t *mib_entry, void **val, size_t *val_size) {

    void *mib_val = NULL;
    size_t mib_val_size;
    bool mib_is_allocated;

    mib_entry->get(&mib_val, &mib_val_size, &mib_is_allocated);

    switch (mib_entry->type) {
        case SNMP_OBJECT_TYPE_INTEGER:
            *val_size = calc_encoded_int_len((const int *)mib_val);
            *val = malloc(*val_size);
            encode_int((const int *)mib_val, *val);
            break;
        case SNMP_OBJECT_TYPE_OCTET_STRING:
            *val_size = calc_encoded_string_len((const char *)mib_val);
            *val = malloc(*val_size);
            encode_string((const char *)mib_val, *val);
            break;
        case SNMP_OBJECT_TYPE_OID:
            *val_size = calc_encoded_oid_len((const snmp_oid_t *)mib_val);
            *val = malloc(*val_size);
            encode_oid((const snmp_oid_t *)mib_val, *val);
            break;
    }

    if (mib_is_allocated) free(mib_val);

    return true;
}

static bool handle_get_request(const asn1_tree_node_t *pdu, asn1_tree_node_t *resp, search_func_t search) {
    int i;
    snmp_oid_t oid;
    size_t vbs_cnt = pdu->content.c.items[3]->content.c.items_num;
    asn1_tree_node_t **req_vbs = pdu->content.c.items[3]->content.c.items,
            *resp_pdu = NULL, *resp_vb = NULL, *resp_vb_list;
    const asn1_tree_node_t *req_vb_key, *pdu_root = pdu->root;
    const mib_entry_t *mib_entry;

    size_t encoded_val_size;
    void *encoded_val;

    resp_vb_list = create_node(NULL, SNMP_OBJECT_TYPE_SEQUENCE, NULL, 0, false);

    for (i = 0; i < vbs_cnt; i++) {
        req_vb_key = req_vbs[i]->content.c.items[0];

        resp_vb = create_node(resp_vb_list, SNMP_OBJECT_TYPE_SEQUENCE, NULL, 0, false);

        decode_oid(req_vb_key->content.p.data, req_vb_key->content.p.size, &oid);

        encoded_val_size = req_vb_key->content.p.size;
        encoded_val = malloc(encoded_val_size);
        memmove(encoded_val, req_vb_key->content.p.data, encoded_val_size);

        create_node(resp_vb, req_vb_key->type, encoded_val, encoded_val_size, true);

        if(NULL == (mib_entry = search(&oid))) {
            // todo: handle not found
            goto fail;
        }

        encode_data(mib_entry, &encoded_val, &encoded_val_size);
        create_node(resp_vb, mib_entry->type, encoded_val, encoded_val_size, true);
    }

    resp->type = SNMP_OBJECT_TYPE_SEQUENCE;
    add_node(resp, copy_primitive(pdu_root->content.c.items[0]));
    add_node(resp, copy_primitive(pdu_root->content.c.items[1]));

    resp_pdu = create_node(resp, SNMP_OBJECT_TYPE_GETRESPONSE, NULL, 0, false);

    add_node(resp_pdu, copy_primitive(pdu->content.c.items[0]));
    add_node(resp_pdu, copy_primitive(pdu->content.c.items[1]));
    add_node(resp_pdu, copy_primitive(pdu->content.c.items[2]));
    add_node(resp_pdu, resp_vb_list);

    return true;

fail:
    return false;
}


ssize_t process_snmp(const uint8_t *req_packet, size_t req_size, uint8_t **resp_packet) {
    asn1_tree_node_t request, response = { 0 };
    const asn1_tree_node_t *pdu;
    *resp_packet = NULL;
    bool res;

    if (decode_ber(req_packet, req_size, &request) != req_size)
        return -1;

    if (NULL == (pdu = check_snmp_request(&request))) {
        return -1;
    }

    switch (pdu->type) {
        case SNMP_OBJECT_TYPE_GETREQUEST:
            res = handle_get_request(pdu, &response, find_mib_entry);
            break;
        case SNMP_OBJECT_TYPE_GETNEXTREQUEST:
            res = handle_get_request(pdu, &response, findnext_mib_entry);
            break;
        default:
            return -1;
    }

    if (res) {
        return encode_ber(&response, resp_packet);
    }

    return -1;
}