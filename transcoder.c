//
// Created by arhichief on 2/7/19.
//

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include "transcoder.h"


ssize_t decode_oid(const uint8_t *data, size_t size, snmp_oid_t *res) {
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

ssize_t decode_string(const uint8_t *data, size_t size, char **res) {
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

ssize_t decode_int(const uint8_t *data, size_t size, int *res) {
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

ssize_t decode_content_length(const uint8_t *data, uint16_t *res) {
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

        tmp_data += decode_int(tmp_data, bytes_read, (int *)res);
    } else {
        *res = (uint16_t)((*tmp_data++) & 0x7F);
    }

    return tmp_data - data;
}



ssize_t encode_oid(const snmp_oid_t *data, uint8_t *res) {
    int i;
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

ssize_t encode_string(const char *data, size_t size, uint8_t *res) {
    memmove(res, data, size);
    return size;
}

ssize_t encode_int(int data, uint8_t *res) {
    uint8_t *res_tmp = res;
    size_t len = calc_encoded_int_len(data);

    while (len--) {
        *res_tmp++ = (uint8_t)((data >> (8 * len)) & 0xFF);
    }

    return res_tmp - res;
}

ssize_t encode_content_length(size_t data, uint8_t *res) {
    size_t len = calc_encoded_content_length(data);
    uint8_t *res_tmp = res;

    if (len > 1) {
        len--;
        *res_tmp++ = 0x80 + len;
        while (len--) {
            *res_tmp++ = (data >> (8 * len)) & 0xFF;
        }
    } else {
        *res_tmp++ = (uint8_t)data;
    }

    return res_tmp - res;
}





uint16_t calc_encoded_oid_len(const snmp_oid_t *data) {
    int i;
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

uint16_t calc_encoded_string_len(const char *data) {
    return strlen(data) * sizeof(char);
}

uint16_t calc_encoded_int_len(int data) {
    return (data & (0xFF << 24)) ? 4
        : (data & (0xFF << 16)) ? 3
        : (data & (0xFF << 8)) ? 2
        : 1;
}

uint16_t calc_encoded_content_length(uint16_t data) {
    return data > 127
        ? calc_encoded_int_len(data) + 1
        : 1;
}


void string_to_oid(const char *val, snmp_oid_t *res) {
    char *end;
    int32_t subid = 1;

    memset(res, 0, sizeof(*res));

    // OIDs can start with '.'
    if ('.' == *val) {
        val++;
    }

    while (1) {
        if ((subid = (int32_t )strtol(val, &end, 10)) == 0) break;
        val = end + 1;
        res->subids[res->subids_cnt++] = subid;
    }
}

char *oid_to_string(const snmp_oid_t *oid) {
    int i;
    char res[100];
    char *res_tmp = res;

    for (i = 0; i < oid->subids_cnt; i++) {
        res_tmp += snprintf(res_tmp, (sizeof(res) - (res_tmp - res) * sizeof(*res)), ".%d", oid->subids[i]);
    }

    return strdup(res);
}