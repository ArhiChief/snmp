/*
 * ber.h
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

#ifndef SNMP_BER_H
#define SNMP_BER_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "asn1/asn1.h"

#ifndef SNMP_OID_LEN
#define SNMP_OID_LEN 40
#endif

typedef struct oid {
    int32_t subids[SNMP_OID_LEN];
    size_t subids_cnt;
} oid_t;

typedef enum object_type {
    OBJECT_TYPE_INTEGER           = 0x02,
    OBJECT_TYPE_OCTET_STRING      = 0x04,
    OBJECT_TYPE_NULL              = 0x05,
    OBJECT_TYPE_OID               = 0x06,
    OBJECT_TYPE_SEQUENCE          = 0x30,
    OBJECT_TYPE_IPADDRESS         = 0x40,
    OBJECT_TYPE_COUNTER           = 0x41,
    OBJECT_TYPE_GAUGE             = 0x42,
    OBJECT_TYPE_TIMETICKS         = 0x43,
    OBJECT_TYPE_OPAQUE            = 0x44,
    OBJECT_TYPE_NSAPADDRESS       = 0x45,

    OBJECT_TYPE_NO_OBJECT         = 0x80,
    OBJECT_TYPE_NO_INSTANCE       = 0x81,
    OBJECT_TYPE_END_OF_VIEW       = 0x82
} object_type_t;

typedef enum request_type {
    REQUEST_TYPE_GET              = 0xA0,
    REQUEST_TYPE_GETNEXT          = 0xA1,
    REQUEST_TYPE_GETRESPONSE      = 0xA2,
    REQUEST_TYPE_SET              = 0xA3,
    REQUEST_TYPE_TRAP             = 0xA4,
} request_type_t;

typedef enum snmp_version {
    SNMP_VERSION_1                = 0,
    SNMP_VERSION_2C               = 1,
    SNMP_VERSION_3                = 3
} snmp_version_t;

static inline bool ber_is_constructed_type(int type) { return (bool)(type & 0x20); }

ssize_t ber_decode_asn1_tree(const uint8_t *data, size_t data_size, asn1_node_t *root);
ssize_t ber_encode_asn1_tree(asn1_node_t *root, uint8_t **buffer);

ssize_t ber_decode_oid(const uint8_t *data, size_t size, oid_t *res);
ssize_t ber_decode_octet_string(const uint8_t *data, size_t size, char **res);
ssize_t ber_decode_integer(const uint8_t *data, size_t size, int *res);
ssize_t ber_decode_length(const uint8_t *data, size_t *res);

ssize_t ber_encode_oid(const oid_t *data, uint8_t *res);
ssize_t ber_encode_octet_string(const char *data, uint8_t *res);
ssize_t ber_encode_integer(const int *data, uint8_t *res);
ssize_t ber_encode_length(const size_t *data, uint8_t *res);

size_t ber_calc_encoded_oid_len(const oid_t *data);
size_t ber_calc_encoded_octet_string_len(const char *data);
size_t ber_calc_encoded_integer_len(const int *data);
size_t ber_calc_encoded_length_len(const size_t *data);

#endif //SNMP_BER_H
