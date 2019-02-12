#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "asn1.h"
#include "ber.h"

asn1_tree_node_t *create_asn1_node(asn1_tree_node_t *root, int type, const void *data, size_t size, bool is_allocated) {
    asn1_tree_node_t *result;
    asn1_tree_node_t **items;

    if (NULL == (result = calloc(1, sizeof(*result)))) {
        errno = ENOMEM;
        return NULL;
    }

    if (NULL != root) {
        if (ber_is_constructed_type(root->type)) {
            items = realloc(root->content.c.items, (root->content.c.items_num + 1) * sizeof(*root->content.c.items));

            if (NULL == items) {
                errno = ENOMEM;
                goto fail;
            }

            items[root->content.c.items_num++] = result;
            root->content.c.items = items;
        } else {
            errno = EINVAL;
            goto fail;
        }
    }

    if (!ber_is_constructed_type(type)) {
        result->content.p.size = size;
        result->content.p.data = data;
        result->content.p.is_allocated = is_allocated;
    }

    result->type = type;
    result->root = root;

    return result;

fail:
    free(result);
    return NULL;
}

int add_asn1_node(asn1_tree_node_t *root, asn1_tree_node_t *node) {
    asn1_tree_node_t **items;

    if (NULL == root || !ber_is_constructed_type(root->type) || NULL == node) {
        errno = EINVAL;
        return -1;
    }

    items = realloc(root->content.c.items, (root->content.c.items_num + 1) * sizeof(*root->content.c.items));

    if (NULL == items) {
        errno = ENOMEM;
        return -1;
    }

    items[root->content.c.items_num++] = node;
    node->root = root;

    root->content.c.items = items;

    return 0;
}

asn1_tree_node_t *copy_primitive_asn1_node(const asn1_tree_node_t *base) {
    asn1_tree_node_t *result;
    size_t data_size = base->content.p.size;

    if (ber_is_constructed_type(base->type)){
        errno = EINVAL;
        return NULL;
    }

    if (NULL == (result = calloc(1, sizeof(*result)))) {
        errno = ENOMEM;
        return NULL;
    }

    result->type = base->type;
    result->content.p.size = data_size;

    if (NULL == (result->content.p.data = malloc(data_size))) {
        free(result);
        errno = ENOMEM;
        return NULL;
    }

    result->content.p.is_allocated = true;
    memmove((void *)result->content.p.data, base->content.p.data, data_size);

    return result;
}

int traverse_asn1_tree(asn1_tree_node_t *root, void *user_data, asn1_tree_traverse_clbk_t clbk) {
    int res = 0;
    size_t i = 0;
    asn1_tree_node_t *node = NULL;

    if (0 != (res = clbk(user_data, root))) return res;

    if (ber_is_constructed_type(root->type)) {
        for (i = 0; i < root->content.c.items_num; ++i) {
            node = root->content.c.items[i];
            if (0 != (res = traverse_asn1_tree(node, user_data, clbk))) return res;
        }
    }


    return 0;
}

void release_asn1_tree(asn1_tree_node_t *root) {
    size_t i;
    asn1_tree_node_t *node;

    if (ber_is_constructed_type(root->type)) {
        for (i = 0; i < root->content.c.items_num; ++i) {
            node = root->content.c.items[i];
            release_asn1_tree(node);

            free(node);
        }

        free(root->content.c.items);
    } else if (root->content.p.is_allocated) {
        free((void *)root->content.p.data);
    }
}