/*
 * mib.c
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

#include <stdbool.h>
#include <memory.h>
#include <stdio.h>

#include "mib.h"
#include "utilities.h"

typedef struct mib_tree_node mib_tree_node_t;

struct mib_tree_node {
    int32_t subid;

    size_t childs_cnt;
    mib_tree_node_t **childs;

    mib_entry_t entry;
};

static mib_tree_node_t mib = {
        .subid = 1,
};

static int comparator(const void *a, const void *b) {
    return (*((const mib_tree_node_t **)a))->subid - (*((const mib_tree_node_t **)b))->subid;
}

int mib_add_entry(const oid_t *oid, object_type_t type, mib_getter_t getter,
                  mib_setter_t setter) {
    mib_tree_node_t *node = &mib, *subnode, key, *key_ptr;
    size_t i;
    bool found = true;

    key_ptr = &key;

    for (i = 1; i < oid->subids_cnt; i++) {
        key.subid = oid->subids[i];

        if (NULL == (subnode = bsearch(&key_ptr, node->childs, node->childs_cnt, sizeof(*node->childs), comparator))) {
            found = false;
            break;
        }

        node = *(mib_tree_node_t **)subnode;
    }

    if (!found) {
        for (; i < oid->subids_cnt; i++) {

            subnode = malloc(sizeof(*subnode));

            node->childs = realloc(node->childs, (node->childs_cnt + 1) * sizeof(*node->childs));
            node->childs[node->childs_cnt++] = subnode;

            subnode->subid = oid->subids[i];

            qsort(node->childs, node->childs_cnt, sizeof(*node->childs), comparator);

            node = subnode;
        }

        node->entry.type = type;
        node->entry.get = getter;
        node->entry.set = setter;
        memmove(&node->entry.oid, oid, sizeof(node->entry.oid));
    }

    return found;
}

const mib_entry_t *mib_find(const oid_t *oid) {
    mib_tree_node_t *node = &mib, *subnode, key, *key_ptr;
    size_t i;

    key_ptr = &key;

    for (i = 1; i < oid->subids_cnt; i++) {
        key.subid = oid->subids[i];

        if (NULL == (subnode = bsearch(&key_ptr, node->childs, node->childs_cnt, sizeof(*node->childs), comparator))) {
            return NULL;
        }

        node = *(mib_tree_node_t **)subnode;
    }

    return node->childs_cnt ? NULL : &node->entry;
}

const mib_entry_t *mib_findnext(const oid_t *oid) {
    mib_tree_node_t *node = &mib, *subnode, key, *key_ptr;
    size_t i;
    key_ptr = &key;

    for (i = 1; i < oid->subids_cnt; i++) {
        key.subid = oid->subids[i];

        if (NULL == (subnode = bsearch(&key_ptr, node->childs, node->childs_cnt, sizeof(void *), comparator))) {
            break;
        }

        node = *(mib_tree_node_t **)subnode;
    }

    while (node->childs_cnt) {
        node = *node->childs;
    }

    return &node->entry;
}

static void free_mib_node(mib_tree_node_t *node) {
    size_t i;
    for (i = 0; i < node->childs_cnt; i++) {
        free_mib_node(node->childs[i]);
        free(node->childs);
    }

    free(node);
}

void mib_free() {
    size_t i;
    for (i = 0; i < mib.childs_cnt; i++) {
        free_mib_node(mib.childs[i]);
    }

    free(mib.childs);
}