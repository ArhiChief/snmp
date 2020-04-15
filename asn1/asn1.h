/*
 * asn1.h
 * Declarations of structure and basic functions to work with ASN.1 encoded objects.
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

#ifndef SNMP_ASN1_H
#define SNMP_ASN1_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct asn1_node asn1_node_t;

/*
 * Definition for callback called for each node during traversing ASN.1 encoded object
 *
 * user_data:   pointer to object what passed as user_data parameter in traverse_asn1_tree
 * node:        current ASN1 tree node
 *
 * returns:
 *              0 on success. Other values will be interpreted as error with stopping on traversing
 */
typedef int (*asn1_tree_traverse_clbk_t)(void *user_data, asn1_node_t *node);

/*
 * Represent ASN.1 encoded object
 */
struct asn1_node {
    asn1_node_t *root;              /* pointer to root element */
    int type;                       /* type of object */
    size_t full_size;               /* size of node in bytes include tag, length and content octets after encoding */
    union {
        struct {
            size_t items_num;       /* number of items in constructed type */
            asn1_node_t **items;    /* items */
        } c;                        /* constructed type */
        struct {
            size_t size;            /* size of data in bytes */
            const void *data;       /* pointer to data */
            bool is_allocated;      /* data was allocated on heap */
        } p;                        /* primitive data */
    } content;                      /* content of node */
};

/*
 * Makes traversing of ASN.1 encoded object. Stops traversing on first occurred non-0 result of clbk.
 *
 * root:        pointer to element what will be traversed
 * user_data:   pointer to user defined object what will be passed to callback on each traversed node
 * clbk:        pointer to callback function what execute action on each traversed node
 *
 * returns:
 *              0 in success, otherwise, value returned by firs non-0 result of clbk
 */
int traverse_asn1_tree(asn1_node_t *root, void *user_data, asn1_tree_traverse_clbk_t clbk);

/*
 * Creates new ASN.1 encoded object and adding it as content to root object.
 *
 * root:            pointer to root element where sub element will be created
 * type:            type of object what will be created
 * data:            pointer to data what object will contain in case of primitive type
 * size:            size of object pointed by data
 * is_allocated:    true if object pointed by data should be freed than node is released
 *
 * return:
 *                  pointer to created sub-element or NULL in case of error and set errno
 *
 */
asn1_node_t *create_asn1_node(asn1_node_t *root, int type, const void *data, size_t size, bool is_allocated);

/*
 *  Adding node to root node
 *
 *  root:       root node
 *  node:       node to be attached as child for root
 *
 *  returns:
 *              0 if success, otherwise non-0 and set errno
 */
int add_asn1_node(asn1_node_t *root, asn1_node_t *node);

/*
 *  Makes copy of primitive ASN.1 node
 *
 *  base:       object to be copied
 *
 *  returns:    pointer to copy, otherwise NULL and set errno
 */
asn1_node_t *copy_primitive_asn1_node(const asn1_node_t *base);

/*
 * Release allocated in memory ASN.1 encoded object.
 *
 * root:    pointer to releasing ASN.1 encoded object
 */
void release_asn1_tree(asn1_node_t *root);

#endif //SNMP_ASN1_H
