//
// Created by arhichief on 2/6/19.
//

#ifndef SNMP_BER_H
#define SNMP_BER_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "snmp_types.h"

typedef struct asn1_tree_node asn1_tree_node_t;

static inline bool is_constructed(int type) { return (bool)(type & 0x20); }

struct asn1_tree_node {

    int id;


    asn1_tree_node_t *root;             // pointer to root element
    int type;                           // node type
    uint16_t full_size;                 // size of node in bytes include tag, length and content octets after encoding

    union {
        struct {
            size_t items_num;           // number of items in constructed type
            asn1_tree_node_t **items;   // items
        } c;                            // constructed typr
        struct {
            uint16_t size;              // size of data in bytes
            const void *data;           // pointer to data
            bool is_allocated;          // data was allocated on heap
        } p;                            // primitive data
    } content;                          // content of node
};

ssize_t decode_ber(const uint8_t *data, size_t data_size, asn1_tree_node_t *root);
ssize_t encode_ber(asn1_tree_node_t *root, uint8_t **buffer);

int traverse_tree(asn1_tree_node_t *root, void *user_data, int (*clbk)(void *user_data, asn1_tree_node_t *node));
void free_asn1_tree(asn1_tree_node_t *root);

#endif //SNMP_BER_H
