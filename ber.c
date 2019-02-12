#include <stdio.h>
#include <errno.h>
#include <memory.h>

#include "ber.h"
#include "utilities.h"



typedef struct encoding_data {
    uint8_t *buffer;
    size_t shift;
} encoding_data_t;


static int encode_node(void *user_data, asn1_tree_node_t *node) {
    encoding_data_t *ed = (encoding_data_t *)user_data;
    uint8_t *buf = ed->buffer;
    ssize_t bytes_wrote;
    size_t shift = ed->shift;
    size_t content_length;

    buf[shift++] = (uint8_t)node->type;

    if (node->full_size < 127)
        content_length = node->full_size - 2; // TAG + 1 byte of content length
    else if (node->full_size < 255)
        content_length = node->full_size - 3; // TAG + 0x81 + 1 byte of content length
    else if (node->full_size < 512)
        content_length = node->full_size - 4; // TAG + 0x82 + 2 bytes of content length

    if ((bytes_wrote = ber_encode_length(&content_length, buf + shift)) < 0)
        return -1;
    shift += (size_t)bytes_wrote;

    if (!ber_is_constructed_type(node->type)) {
        memmove(buf + shift, node->content.p.data, node->content.p.size);
        shift += node->content.p.size;
    }

    ed->shift = shift;

    return 0;
}

static int set_zero_full_size(__attribute__((unused)) void *_, asn1_tree_node_t *node) {
    node->full_size = 0;
    return 0;
}

static size_t calc_full_sizes(asn1_tree_node_t *node) {
    size_t i;
    size_t full_size = 0;

    if (ber_is_constructed_type(node->type)) {
        for (i = 0; i < node->content.c.items_num; i++) {
            full_size += calc_full_sizes(node->content.c.items[i]);
        }
    } else {
        full_size = node->content.p.size;
    }

    full_size = 1 + ber_calc_encoded_length_len(&full_size) + full_size;
    node->full_size = full_size;

    return full_size;
}

ssize_t ber_decode_asn1_tree(const uint8_t *data, size_t data_size, asn1_tree_node_t *root) {
    asn1_tree_node_t **elems = NULL, *node = NULL;
    size_t content_size = 0;
    ssize_t bytes_read = 0;
    const uint8_t *tmp_data = data;

    if (NULL == data) {
        errno = EINVAL;
        return -1;
    }

    if (0 >= data_size) return 0;

    memset(root, 0, sizeof(*root));

    root->type = *tmp_data++;

    if ((bytes_read = ber_decode_length(tmp_data, &content_size)) < 1) {
        errno = EINVAL;
        return -1;
    }

    tmp_data += bytes_read;
    root->full_size = 1 + bytes_read + content_size; // +1 byte for TAG

    if (ber_is_constructed_type(root->type)) {
        elems = root->content.c.items;
        while (content_size > 0) {
            elems = realloc(elems, (root->content.c.items_num + 1) * sizeof(*elems));

            if(NULL == elems) {
                return -1;
            }

            node = malloc(sizeof(*node));

            elems[root->content.c.items_num] = node;

            if ((bytes_read = ber_decode_asn1_tree(tmp_data, content_size, node)) < 0) {
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

ssize_t ber_encode_asn1_tree(asn1_tree_node_t *root, uint8_t **buffer) {
    encoding_data_t ed;

    traverse_asn1_tree(root, NULL, set_zero_full_size);

    calc_full_sizes(root);

    *buffer = malloc(root->full_size);
    if (NULL == *buffer) {
        errno = ENOMEM;
        return -1;
    }

    ed.buffer = *buffer;
    ed.shift = 0;

    if (0 != traverse_asn1_tree(root, &ed, encode_node)) return -1;

    return ed.shift;
}

ssize_t ber_decode_oid(const uint8_t *data, size_t size, oid_t *res) {
    int *tmp_val = res->subids;
    const uint8_t *tmp_data;
    memset(res, 0, sizeof(*res));

    tmp_data = data;

    *tmp_val++ = *tmp_data / 40;
    *tmp_val++ = *tmp_data % 40;
    size--;
    tmp_data++;

    while (size) {
        *tmp_val = 0;
        while (size--) {
            *tmp_val = (*tmp_val << 7) + (*tmp_data & 0x7F);
            if (*tmp_data & 0x80) {
                tmp_data++;
            } else {
                tmp_data++;
                break;
            }

        }
        tmp_val++;
    }

    res->subids_cnt = tmp_val - res->subids;
    return tmp_data - data;
}

ssize_t ber_decode_octet_string(const uint8_t *data, size_t size, char **res) {
    size_t decoded_size = size + sizeof(char);

    *res = malloc(decoded_size);
    if (NULL == *res) {
        errno = ENOMEM;
        return -1;
    }

    memmove(*res, data, size);
    (*res)[size] = '\0';

    return decoded_size;
}

ssize_t ber_decode_integer(const uint8_t *data, size_t size, int *res) {
    const uint8_t *tmp_data = data;
    *res = 0;

    if (!size || size > sizeof(*res)) {
        errno = EINVAL;
        return -1;
    }

    while (size--) {
        *res = (*res << 8) + *tmp_data++;
    }

    return tmp_data - data;
}

ssize_t ber_decode_length(const uint8_t *data, size_t *res) {
    const uint8_t *tmp_data = data;
    ssize_t bytes_read;

    /*
     * Length of data can be stored in short (primitive) or long (constructed) form.
     *
     * In the short form, the length octets shall consist of a single octet in which bit 7 is zero and bits 6 to 0
     * encode the number of octets in the contents octets (which may be zero), as an unsigned binary integer with bit 6
     * as the most significant bit
     *
     * In the long form, the length octets shall consist of an initial octet and one or more subsequent octets.
     * The initial octet shall be encoded as follows:
     *      a) bit 7 shall be one;
     *      b) bits 6 to 8 shall encode the number of subsequent octets in the length octets, as an unsigned binary
     *         integer with bit 6 as the most significant bit;
     *      c) the value 0b11111111 shall not be used.
     *
     * Bits 7 to 0 of the first subsequent octet, followed by bits 7 to 0 of the second subsequent octet, followed in
     * turn by bits 7 to 0 of each further octet up to and including the last subsequent octet, shall be the encoding
     * of an unsigned binary integer equal to the number of octets in the contents octets, with bit 7 of the first
     * subsequent octet as the most significant bit.
     */
    if (*tmp_data & 0x80) {
        // we can't handle so big values or empty lengths. probably where was an error in packet transmission
        if ((bytes_read = *tmp_data++ & 0x7F) > sizeof(*res) || bytes_read == 0) {
            errno = EINVAL;
            return -1;
        }

        tmp_data += ber_decode_integer(tmp_data, (size_t)bytes_read, (int *) res);
    } else {
        *res = (size_t)(*tmp_data++) & 0x7F;
    }

    return tmp_data - data;
}

ssize_t ber_encode_oid(const oid_t *data, uint8_t *res) {
    size_t i;
    size_t len;
    uint8_t *res_tmp = res;

    *res_tmp++ = (uint8_t)(data->subids[0] * 40 + data->subids[1]);

    for (i = 2; i < data->subids_cnt; i++) {
        if (data->subids[i] >= (1 << 28))
            len = 5;
        else if (data->subids[i] >= (1 << 21))
            len = 4;
        else if (data->subids[i] >= (1 << 14))
            len = 3;
        else if (data->subids[i] >= (1 << 7))
            len = 2;
        else
            len = 1;

        while (len--) {
            if (len)
                *res_tmp++ = ((data->subids[i] >> (7 * len)) & 0x7F) | 0x80;
            else
                *res_tmp++ = (data->subids[i] >> (7 * len)) & 0x7F;
        }
    }

    return res_tmp - res;
}

ssize_t ber_encode_octet_string(const char *data, uint8_t *res) {
    size_t size = strlen(data) * sizeof(*data);
    memmove(res, data, size);
    return size;
}

ssize_t ber_encode_integer(const int *data, uint8_t *res) {
    const int val = *data;
    uint8_t *res_tmp = res;
    size_t len = ber_calc_encoded_integer_len(data);

    while (len--) {
        *res_tmp++ = (uint8_t)((val >> (8 * len)) & 0xFF);
    }

    return res_tmp - res;
}

ssize_t ber_encode_length(const size_t *data, uint8_t *res) {
    size_t len = ber_calc_encoded_length_len(data);
    uint8_t *res_tmp = res;

    if (len > 1) {
        len--;
        *res_tmp++ = (uint8_t)(0x80 + len);
        while (len--) {
            *res_tmp++ = (uint8_t)((*data >> (8 * len)) & 0xFF);
        }
    } else {
        *res_tmp++ = (uint8_t)*data;
    }

    return res_tmp - res;
}

size_t ber_calc_encoded_oid_len(const oid_t *data) {
    size_t i;
    size_t len = 1;

    for (i = 2; i < data->subids_cnt; ++i) {
        if (data->subids[i] >= (1 << 28))
            len += 5;
        else if (data->subids[i] >= (1 << 21))
            len += 4;
        else if (data->subids[i] >= (1 << 14))
            len += 3;
        else if (data->subids[i] >= (1 << 7))
            len += 2;
        else
            len += 1;
    }

    return len;
}

size_t ber_calc_encoded_octet_string_len(const char *data) { return strlen(data) * sizeof(char); }

size_t ber_calc_encoded_integer_len(const int *data) {
    if (*data & (0xFF << 24))
        return 4;
    else if (*data & (0xFF << 16))
        return 3;
    else if (*data & (0xFF << 8))
        return 2;
    else
        return 1;
}

size_t ber_calc_encoded_length_len(const size_t *data) {
    return (*data > 127)
        ? ber_calc_encoded_integer_len((const int *) data) + 1
        : 1;
}