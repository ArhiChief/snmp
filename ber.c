//
// Created by arhichief on 2/6/19.
//

#include <stdio.h>
#include <errno.h>
#include <memory.h>
#include "transcoder.h"
#include "ber.h"

#include "utilities.h"


static  int id;

static ssize_t decode(const uint8_t *data, size_t size, asn1_tree_node_t *root);

int traverse_tree(asn1_tree_node_t *root, void *user_data, int (*clbk)(void *user_data, asn1_tree_node_t *node)) {
    int res = 0;
    size_t i = 0;
    asn1_tree_node_t *node = NULL;

    if (res = clbk(user_data, root)) return res;

    if (is_constructed(root->type)) {
        for (i = 0; i < root->content.c.items_num; ++i) {
            node = root->content.c.items[i];
            if (res = traverse_tree(node, user_data, clbk)) return res;
        }
    }


    return 0;
}

ssize_t decode_ber(const uint8_t *data, size_t size, asn1_tree_node_t *root) {
    id = 1;
    decode(data, size, root);
}

void free_asn1_tree(asn1_tree_node_t *root) {
    int i;
    asn1_tree_node_t *node;

    if (is_constructed(root->type)) {
        for (i = 0; i < root->content.c.items_num; ++i) {
            node = root->content.c.items[i];
            free_asn1_tree(node);
        }

        free(root->content.c.items);
    } else if (root->content.p.is_allocated) {
        free((void *)root->content.p.data);
    }
}

static ssize_t decode(const uint8_t *data, size_t size, asn1_tree_node_t *root) {
    asn1_tree_node_t **elems = NULL, *node = NULL;
    uint16_t content_size = 0;
    ssize_t bytes_read = 0;
    const uint8_t *tmp_data = data;

    if (NULL == data) {
        errno = EINVAL;
        return -1;
    }

    if (0 >= size) return 0;

    memset(root, 0, sizeof(*root));

    root->id = id++;

    root->type = *tmp_data++;

    if ((bytes_read = decode_content_length(tmp_data, &content_size)) < 1) {
        errno = EINVAL;
        return -1;
    }

    tmp_data += bytes_read;
    root->full_size = 1 + bytes_read + content_size; // +1 byte for TAG

    if (is_constructed(root->type)) {
        elems = root->content.c.items;
        while (content_size > 0) {
            elems = realloc(elems, (root->content.c.items_num + 1) * sizeof(*elems));

            if(NULL == elems) {
                return -1;
            }

            node = malloc(sizeof(*node));

            elems[root->content.c.items_num] = node;

            if ((bytes_read = decode(tmp_data, content_size, node)) < 0) {
                return -1;
            }

            tmp_data += bytes_read;
            content_size -= bytes_read;

            node->root = root;
            root->content.c.items_num++;
        }

        root->content.c.items = elems;

    } else {
        root->content.p.is_allocated = false;
        root->content.p.size = content_size;
        root->content.p.data = tmp_data;
    }

    return tmp_data - data + content_size;
}

typedef struct encoding_data {
    uint8_t *buffer;
    size_t shift;
} encoding_data_t;

static int encode_node(void *user_data, asn1_tree_node_t *node) {
    encoding_data_t *ed = (encoding_data_t *)user_data;
    uint8_t *buf = ed->buffer;
    ssize_t bytes_wrote;
    size_t shift = ed->shift;
    uint16_t content_length;

    buf[shift++] = (uint8_t)node->type;

    if (node->full_size < 127)
        content_length = node->full_size - 2; // TAG + 1 byte of content length
    else if (node->full_size < 255)
        content_length = node->full_size - 3; // TAG + 0x81 + 1 byte of content length
    else if (node->full_size < 512)
        content_length = node->full_size - 4; // TAG + 0x82 + 2 bytes of content length

    if ((bytes_wrote = encode_content_length(content_length, buf + shift)) < 0)
        return -1;
    shift += bytes_wrote;

    if (!is_constructed(node->type)) {
        memmove(buf + shift, node->content.p.data, node->content.p.size);
        shift += node->content.p.size;
    }

    ed->shift = shift;

    return 0;
}

// TODO: remove in prod
static int set_zero_full_size(void *_, asn1_tree_node_t *node) {
    node->full_size = 0;
    return 0;
}

static uint16_t calc_full_sizes(asn1_tree_node_t *node) {
    int i;
    uint16_t full_size = 0;

    if (is_constructed(node->type)) {
        for (i = 0; i < node->content.c.items_num; i++) {
            full_size += calc_full_sizes(node->content.c.items[i]);
        }
    } else {
        full_size = node->content.p.size;
    }

    full_size = 1 + calc_encoded_content_length(full_size) + full_size;
    node->full_size = full_size;

    return full_size;
}

ssize_t encode_ber(asn1_tree_node_t *root, uint8_t **buffer) {
    encoding_data_t ed;

    traverse_tree(root, NULL, set_zero_full_size);

    calc_full_sizes(root);

    *buffer = malloc(root->full_size);
    if (NULL == *buffer) {
        errno = ENOMEM;
        return -1;
    }

    ed.buffer = *buffer;
    ed.shift = 0;

    if (traverse_tree(root, &ed, encode_node)) return -1;

    return ed.shift;
}


int add_primitive_child(asn1_tree_node_t *root, int type, void *data, size_t size, bool is_allocated) {
    asn1_tree_node_t **items;
    asn1_tree_node_t *new_child;

    if (NULL == root || is_constructed(type) || !is_constructed(root->type)) {
        errno = EINVAL;
        return -1;
    }

    items = root->content.c.items;
    items = realloc(items, (root->content.c.items_num + 1) * sizeof(*items));
    if (NULL == items) {
        errno = ENOMEM;
        return -1;
    }

    new_child = calloc(1, sizeof(*new_child));
    if (NULL == new_child) {
        errno = ENOMEM;
        return -1;
    }

    items[root->content.c.items_num++] = new_child;
    root->content.c.items = items;

    new_child->root = root;
    new_child->type = type;
    new_child->content.p.is_allocated = is_allocated;
    new_child->content.p.data = data;
    new_child->content.p.size = size;

    return 0;
}