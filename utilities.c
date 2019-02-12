#include <memory.h>
#include <errno.h>

#include "utilities.h"

static const char *type_to_string(int type) {
    switch (type) {
        case OBJECT_TYPE_SEQUENCE:
            return "SEQUENCE";
        case OBJECT_TYPE_NULL:
            return "NULL";
        case OBJECT_TYPE_INTEGER:
            return "INTEGER";
        case OBJECT_TYPE_OCTET_STRING:
            return "OCTET STRING";
        case OBJECT_TYPE_OID:
            return "OBJECT IDENTIFIER";
        case OBJECT_TYPE_IPADDRESS:
            return "IP ADDRESS";
        case REQUEST_TYPE_GET:
            return "GET REQUEST";
        case REQUEST_TYPE_GETRESPONSE:
            return "GET RESPONSE";
        case REQUEST_TYPE_GETNEXT:
            return "GETNEXT REQUEST";
        case REQUEST_TYPE_SET:
            return "SET REQUEST";
        default:
            return "UNKNOWN";
    }
}

static char *value_to_string(const asn1_tree_node_t *node) {
    char *str = malloc(1024 * sizeof(char));
    char *s;
    int res;
    oid_t oid;

    if (ber_is_constructed_type(node->type)) {
        snprintf(str, 100 * sizeof(char), "{ 'full_size': %zu, 'intems_num': %zu", node->full_size, node->content.c.items_num);
    } else {
        switch (node->type) {
            case OBJECT_TYPE_NULL:
                snprintf(str, 100 * sizeof(char), "{'value': NULL, 'size': %zu, 'full_size': %zu}", node->content.p.size, node->full_size);
                break;
            case OBJECT_TYPE_INTEGER:
                ber_decode_integer(node->content.p.data, node->content.p.size, &res);
                snprintf(str, 100 * sizeof(char), "{'value': %d, 'size': %zu, 'full_size': %zu}", res, node->content.p.size, node->full_size);
                break;
            case OBJECT_TYPE_OCTET_STRING:
                ber_decode_octet_string(node->content.p.data, node->content.p.size, &s);
                snprintf(str, 100 * sizeof(char), "{'value': '%s', 'size': %zu, 'full_size': %zu}", s, node->content.p.size, node->full_size);
                break;
            case OBJECT_TYPE_OID:
                ber_decode_oid(node->content.p.data, node->content.p.size, &oid);
                s = oid_to_string(&oid);
                snprintf(str, 100 * sizeof(char), "{'value': '%s', 'size': %zu, 'full_size': %zu}", s, node->content.p.size, node->full_size);
                break;
            default:
                snprintf(str, 100 * sizeof(char), "SOME OID");
                break;
        }
    }

    return str;
}

void print_asn1_tree(const asn1_tree_node_t *root, size_t spaces, const char *prefix) {
    char line[200] = { 0 };
    char *val = value_to_string(root);
    size_t i = 0;

    memset(line, '\t', spaces * sizeof(*line));
    snprintf(line + spaces, sizeof(line)/sizeof(*line) - spaces, "%s %s - %s", prefix, type_to_string(root->type), val);
    puts(line);
    free(val);

    if (ber_is_constructed_type(root->type)) {
        char pref[10];

        for (i = 0; i < root->content.c.items_num; i++) {
            sprintf(pref, "[%zu] ", i);
            print_asn1_tree(root->content.c.items[i], spaces + 1, pref);
        }
    }
}

void string_to_oid(const char *val, oid_t *res) {
    char *end;
    int32_t subid = 1;

    memset(res, 0, sizeof(*res));

    // OIDs can start with '.'
    if ('.' == *val) {
        val++;
    }

    while (1) {
        if ((subid = (int32_t )strtol(val, &end, 10)) == 0) break;
        val = end + 1;
        res->subids[res->subids_cnt++] = subid;
    }
}

char *oid_to_string(const oid_t *oid) {
    size_t i;
    char res[100];
    char *res_tmp = res;

    for (i = 0; i < oid->subids_cnt; i++) {
        res_tmp += snprintf(res_tmp, (sizeof(res) - (res_tmp - res) * sizeof(*res)), ".%d", oid->subids[i]);
    }

    return strdup(res);
}
