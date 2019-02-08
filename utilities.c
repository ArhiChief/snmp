//
// Created by arhichief on 2/8/19.
//

#include <memory.h>
#include "utilities.h"
#include "snmp_types.h"
#include "transcoder.h"


static const char *type_to_string(int type) {
    switch (type) {
        case SNMP_OBJECT_TYPE_SEQUENCE:
            return "SEQUENCE";
        case SNMP_OBJECT_TYPE_NULL:
            return "NULL";
        case SNMP_OBJECT_TYPE_INTEGER:
            return "INTEGER";
        case SNMP_OBJECT_TYPE_OCTET_STRING:
            return "OCTET STRING";
        case SNMP_OBJECT_TYPE_OID:
            return "OBJECT IDENTIFIER";
        case SNMP_OBJECT_TYPE_IPADDRESS:
            return "IP ADDRESS";
        case SNMP_OBJECT_TYPE_GETREQUEST:
            return "GET REQUEST";
        case SNMP_OBJECT_TYPE_GETRESPONSE:
            return "GET RESPONSE";
        case SNMP_OBJECT_TYPE_GETNEXTREQUEST:
            return "GETNEXT REQUEST";
        case SNMP_OBJECT_TYPE_SETREQUEST:
            return "SET REQUEST";
        default:
            return "UNKNOWN";
    }
}

static char *value_to_string(const asn1_tree_node_t *node) {
    char *str = malloc(1024 * sizeof(char));
    char *s;
    int res;
    snmp_oid_t oid;

    if (is_constructed(node->type)) {
        snprintf(str, 100 * sizeof(char), "{ 'full_size': %d, 'intems_num': %d, 'root': %d}",
                node->full_size, node->content.c.items_num, (node->root == NULL ? 0 : node->root->id));
    } else {
        switch (node->type) {
            case SNMP_OBJECT_TYPE_NULL:
                snprintf(str, 100 * sizeof(char), "{'value': NULL, 'size': %d, 'full_size': %d, 'root': %d}", node->content.p.size, node->full_size, (node->root == NULL ? 0 : node->root->id));
                break;
            case SNMP_OBJECT_TYPE_INTEGER:
                decode_int(node->content.p.data, node->content.p.size, &res);
                snprintf(str, 100 * sizeof(char), "{'value': %d, 'size': %d, 'full_size': %d, 'root': %d}", res, node->content.p.size, node->full_size, (node->root == NULL ? 0 : node->root->id));
                break;
            case SNMP_OBJECT_TYPE_OCTET_STRING:
                decode_string(node->content.p.data, node->content.p.size, &s);
                snprintf(str, 100 * sizeof(char), "{'value': '%s', 'size': %d, 'full_size': %d, 'root': %d}", s, node->content.p.size, node->full_size, (node->root == NULL ? 0 : node->root->id));
                break;
            case SNMP_OBJECT_TYPE_OID:
                decode_oid(node->content.p.data, node->content.p.size, &oid);
                s = oid_to_string(&oid);
                snprintf(str, 100 * sizeof(char), "{'value': '%s', 'size': %d, 'full_size': %d, 'root': %d}", s, node->content.p.size, node->full_size, (node->root == NULL ? 0 : node->root->id));
                break;
            default:
                snprintf(str, 100 * sizeof(char), "SOME OID");
                break;
        }
    }

    return str;
}

void print_tree(const asn1_tree_node_t *root, size_t spaces, const char *prefix) {
    char string[200] = { 0 };
    int i = 0;

    memset(string, '\t', spaces * sizeof(*string));

    snprintf(string + spaces, sizeof(string)/ sizeof(*string) - spaces, "%s(%d) %s - %s", prefix, root->id, type_to_string(root->type),
             value_to_string(root));

    puts(string);

    if (is_constructed(root->type)) {
        char pref[10];

        for (i = 0; i < root->content.c.items_num; i++) {
            sprintf(pref, "[%d] ", i);
            print_tree(root->content.c.items[i], spaces + 1, pref);
        }
    }
}