#ifndef SNMP_UTILITIES_H
#define SNMP_UTILITIES_H

#include "ber.h"

void print_asn1_tree(const asn1_tree_node_t *root, size_t spaces, const char *prefix);

void string_to_oid(const char *val, oid_t *res);
char *oid_to_string(const oid_t *oid);

#endif //SNMP_UTILITIES_H