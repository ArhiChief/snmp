/*
 * asn1.h
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

#ifndef SNMP_ASN1_H
#define SNMP_ASN1_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct asn1_node asn1_node_t;
typedef int (*asn1_tree_traverse_clbk_t)(void *user_data, asn1_node_t *node);

struct asn1_node {
    asn1_node_t *root;                     // pointer to root element
    int type;                                   // node type
    size_t full_size;                           // size of node in bytes include tag, length and content octets after encoding

    union {
        struct {
            size_t items_num;                   // number of items in constructed type
            asn1_node_t **items;           // items
        } c;                                    // constructed type
        struct {
            size_t size;                        // size of data in bytes
            const void *data;                   // pointer to data
            bool is_allocated;                  // data was allocated on heap
        } p;                                    // primitive data
    } content;                                  // content of node
};

int traverse_asn1_tree(asn1_node_t *root, void *user_data, asn1_tree_traverse_clbk_t clbk);

asn1_node_t *create_asn1_node(asn1_node_t *root, int type, const void *data, size_t size, bool is_allocated);

int add_asn1_node(asn1_node_t *root, asn1_node_t *node);

asn1_node_t *copy_primitive_asn1_node(const asn1_node_t *base);

void release_asn1_tree(asn1_node_t *root);

#endif //SNMP_ASN1_H
