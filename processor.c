#include <memory.h>
#include <errno.h>

#include "processor.h"
#include "ber.h"
#include "mib.h"
#include "utilities.h"
#include "asn1.h"

typedef bool (*check_strategy_t)(const asn1_tree_node_t *req);
typedef const mib_entry_t *(*search_func_t)(const oid_t *oid);

static bool is_version_supported(snmp_version_t ver) {
    return SNMP_VERSION_3 != ver; // version 3 doesn't support
}

static bool is_community_supported(const char *comunity) {
    return 0 == strcmp(comunity, "public");
}

// check GetRequest, GetNextRequest, GetResponse, SetRequest
static bool check_non_trap_request(const asn1_tree_node_t *pdu) {
    const asn1_tree_node_t *item, *varbind;
    size_t i;
    int val = 0;

    // PDU contains should contain 4 elements
    if (pdu->content.c.items_num != 4) return false;

    // first element of PDU is Request ID
    item = pdu->content.c.items[0];
    if (OBJECT_TYPE_INTEGER != item->type ||
            ber_decode_integer(item->content.p.data, item->content.p.size, &val) < 1 ||
        val < 0) {
        return false;
    }

    // next 2 elements are Error Status and Error Index
    for (i = 1; i < 3; i++) {
        item = pdu->content.c.items[i];

        if (OBJECT_TYPE_INTEGER != item->type ||
                ber_decode_integer(item->content.p.data, item->content.p.size, &val) != 1 ||
            val > 0) {
            return false;
        }
    }

    // last element is varbind list
    item = pdu->content.c.items[3];
    if (OBJECT_TYPE_SEQUENCE == item->type && item->content.c.items_num > 0) {
        for (i = 0; i < item->content.c.items_num; i++) {
            varbind = item->content.c.items[i];

            // varbind must be SEQUENCE with 2 primitive elements and first element must be OID
            if (OBJECT_TYPE_SEQUENCE != varbind->type || 2 != varbind->content.c.items_num ||
                OBJECT_TYPE_OID != varbind->content.c.items[0]->type ||
                    ber_is_constructed_type(varbind->content.c.items[1]->type)) {
                return false;
            }
        }
    } else
        return false;

    return true;
}

// only Get and GetNext requests are supported
static check_strategy_t is_request_type_supported(request_type_t type) {
    switch (type) {
        case REQUEST_TYPE_GET:
        case REQUEST_TYPE_GETNEXT:
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
    if (req->type != OBJECT_TYPE_SEQUENCE || req->content.c.items_num != 3) {
        goto end;
    }

    // first element is SNMP Version (1 byte length)
    item = req->content.c.items[0];
    if (OBJECT_TYPE_INTEGER != item->type                                          ||
        item->content.p.size != 1                                                       ||
            ber_decode_integer(item->content.p.data, item->content.p.size, (int *) &version) != 1    ||
        !is_version_supported(version)) {
        goto end;
    }

    // second element is SNMP Community String
    item = req->content.c.items[1];
    if (OBJECT_TYPE_OCTET_STRING != item->type                                     ||
            ber_decode_octet_string(item->content.p.data, item->content.p.size, &community) < 1       ||
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

static bool encode_data(const mib_entry_t *mib_entry, void **val, size_t *val_size) {
    void *mib_val = NULL;
    size_t mib_val_size;
    bool mib_is_allocated;

    mib_entry->get(&mib_val, &mib_val_size, &mib_is_allocated);

    switch (mib_entry->type) {
        case OBJECT_TYPE_INTEGER:
            *val_size = ber_calc_encoded_integer_len((const int *) mib_val);
            *val = malloc(*val_size);
            ber_encode_integer((const int *) mib_val, *val);
            break;
        case OBJECT_TYPE_OCTET_STRING:
            *val_size = ber_calc_encoded_octet_string_len((const char *) mib_val);
            *val = malloc(*val_size);
            ber_encode_octet_string((const char *) mib_val, *val);
            break;
        case OBJECT_TYPE_OID:
            *val_size = ber_calc_encoded_oid_len((const oid_t *) mib_val);
            *val = malloc(*val_size);
            ber_encode_oid((const oid_t *) mib_val, *val);
            break;
        default:
            if (mib_is_allocated) free(mib_val);
            return false;
    }

    if (mib_is_allocated) free(mib_val);

    return true;
}

static bool handle_get_request(const asn1_tree_node_t *pdu, asn1_tree_node_t *resp, search_func_t search) {
    size_t i;
    oid_t oid;
    size_t vbs_cnt = pdu->content.c.items[3]->content.c.items_num;
    asn1_tree_node_t **req_vbs = pdu->content.c.items[3]->content.c.items,
            *resp_pdu = NULL, *resp_vb = NULL, *resp_vb_list;
    const asn1_tree_node_t *req_vb_key, *pdu_root = pdu->root;
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

        if(NULL == (mib_entry = search(&oid))) {

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

ssize_t process_request(const uint8_t *req_packet, size_t req_size, uint8_t **resp_packet) {
    asn1_tree_node_t request, response = { 0 };
    const asn1_tree_node_t *pdu;
    *resp_packet = NULL;
    bool res;
    ssize_t resp_size = -1, bytes_decoded;

    if ((bytes_decoded = ber_decode_asn1_tree(req_packet, req_size, &request)) < 0 || (size_t)bytes_decoded != req_size)
        return -1;

    if (NULL == (pdu = check_snmp_request(&request))) {
        return -1;
    }

    switch (pdu->type) {
        case REQUEST_TYPE_GET:
            res = handle_get_request(pdu, &response, mib_find);
            break;
        case REQUEST_TYPE_GETNEXT:
            res = handle_get_request(pdu, &response, mib_findnext);
            break;
        default:
            return -1;
    }

    if (res) {
        resp_size = ber_encode_asn1_tree(&response, resp_packet);
    }

    release_asn1_tree(&request);
    release_asn1_tree(&response);

    return resp_size;
}
