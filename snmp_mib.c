//
// Created by arhichief on 2/8/19.
//

#include <stdbool.h>
#include <memory.h>
#include "snmp_mib.h"

typedef struct mib_tree_node mib_tree_node_t;

struct mib_tree_node {
    int32_t subid;

    int childs_cnt;
    mib_tree_node_t **childs;

    mib_entry_t entry;
};

static mib_tree_node_t mib = {
        .subid = 1,
        .childs_cnt = 0,
        .childs = NULL,
        .entry = { 0 }
};

static int mib_tree_node_cmp(const void *a, const void *b) {
    return (*((const mib_tree_node_t **)a))->subid - (*((const mib_tree_node_t **)b))->subid;
}

int add_mib_entry(const snmp_oid_t *oid, snmp_object_type_t type, getter_t getter, setter_t setter) {
    mib_tree_node_t *node = &mib, *subnode, key, *key_ptr;
    int i;
    bool found = true;

    key_ptr = &key;

    for (i = 1; i < oid->subids_cnt; i++) {
        key.subid = oid->subids[i];

        if (NULL == (subnode = bsearch(&key_ptr, node->childs, node->childs_cnt, sizeof(void *), mib_tree_node_cmp))) {
            found = false;
            break;
        }

        node = *(mib_tree_node_t **)subnode;
    }

    if (!found) {
        for (i; i < oid->subids_cnt; i++) {

            subnode = malloc(sizeof(*subnode));

            node->childs = realloc(node->childs, (node->childs_cnt + 1) * sizeof(*node->childs));
            node->childs[node->childs_cnt++] = subnode;

            subnode->subid = oid->subids[i];

            qsort(node->childs, node->childs_cnt, sizeof(*node->childs), mib_tree_node_cmp);

            node = subnode;
        }

        node->entry.type = type;
        node->entry.get = getter;
        node->entry.set = setter;
        memmove(&node->entry.oid, oid, sizeof(node->entry.oid));
    }

    return found;
}

const mib_entry_t *find_mib_entry(const snmp_oid_t *oid) {
    mib_tree_node_t *node = &mib, *subnode, key, *key_ptr;
    int i;

    key_ptr = &key;

    for (i = 1; i < oid->subids_cnt; i++) {
        key.subid = oid->subids[i];

        if (NULL == (subnode = bsearch(&key_ptr, node->childs, node->childs_cnt, sizeof(void *), mib_tree_node_cmp))) {
            return NULL;
        }

        node = *(mib_tree_node_t **)subnode;
    }

    return node->childs_cnt ? NULL : &node->entry;
}

// TODO: need to be tested!!!
const mib_entry_t *findnext_mib_entry(const snmp_oid_t *oid) {
    mib_tree_node_t *node = &mib, *subnode, key, *key_ptr;
    int i, j;
    key_ptr = &key;

    for (i = 1; i < oid->subids_cnt; i++) {
        key.subid = oid->subids[i];

        if (NULL == (subnode = bsearch(&key_ptr, node->childs, node->childs_cnt, sizeof(void *), mib_tree_node_cmp))) {
            break;
        }

        node = *(mib_tree_node_t **)subnode;
    }

    if (i < oid->subids_cnt) {
        for (int i = 0; i < node->childs_cnt; i++) {
            if (key.subid <= node->childs[i]->subid) {
                return &node->childs[i]->entry;
            }
        }

        return NULL;
    }

    return &node->entry;
}