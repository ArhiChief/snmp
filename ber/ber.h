/*
 * ber.h
 * Defines function to encode and decode binary stream into ASN.1 object using X.609 encoding rules
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

#ifndef SNMP_BER_H
#define SNMP_BER_H

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "../asn1/asn1.h"

#ifndef SNMP_OID_LEN
#define SNMP_OID_LEN 40
#endif

/*
 * Structure to represent OID object type
 */
typedef struct oid {
    int32_t subids[SNMP_OID_LEN];   /* List of sub ids of OID */
    size_t subids_cnt;              /* Amount of sub ids */
} oid_t;

/*
 * Enum to determine binary encoded ASN.1 object type
 */
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

/*
 * Binary encoded types of SNMP requests
 */
typedef enum request_type {
    REQUEST_TYPE_GET              = 0xA0,
    REQUEST_TYPE_GETNEXT          = 0xA1,
    REQUEST_TYPE_GETRESPONSE      = 0xA2,
    REQUEST_TYPE_SET              = 0xA3,
    REQUEST_TYPE_TRAP             = 0xA4,
} request_type_t;

/*
 * Binary encoded versions of SNMP
 */
typedef enum snmp_version {
    SNMP_VERSION_1                = 0,
    SNMP_VERSION_2C               = 1,
    SNMP_VERSION_3                = 3
} snmp_version_t;

/*
 * Determine if type of ASN.1 encoded object is constructed type
 *
 * type:    type to be tested
 *
 * return:
 *          true if type is constructed or false in other cases
 */
static inline bool is_constructed_type(int type) { return (bool)(type & 0x20); }

/*
 * Decode binary encoded ASN.1 object
 *
 * data:        pointer to binary array what stores encoded object
 * size:        size of array pointed by data
 * root:        root element used to hold decoded object
 *
 * returns:
 *              -1 if decoding fails and set errno
 *              amount of successfully decoded bytes
 */
ssize_t ber_decode_asn1_tree(const uint8_t *data, size_t size, asn1_node_t *root);
/*
 * Decode binary encoded OID object
 *
 * data:        pointer to binary array what stores encoded object
 * size:        size of array pointed by data
 * res:         element used to hold decoded object
 *
 * returns:
 *              -1 if decoding fails and set errno
 *              amount of successfully decoded bytes
 */
ssize_t ber_decode_oid(const uint8_t *data, size_t size, oid_t *res);
/*
 * Decode binary encoded null-terminated octet string object
 *
 * data:        pointer to binary array what stores encoded object
 * size:        size of array pointed by data
 * res:         element used to hold decoded object
 *
 * returns:
 *              -1 if decoding fails and set errno
 *              amount of successfully decoded bytes
 */
ssize_t ber_decode_octet_string(const uint8_t *data, size_t size, char **res);
/*
 * Decode binary encoded integer
 *
 * data:        pointer to binary array what stores encoded object
 * size:        size of array pointed by data
 * res:         element used to hold decoded object
 *
 * returns:
 *              -1 if decoding fails and set errno
 *              amount of successfully decoded bytes
 */
ssize_t ber_decode_integer(const uint8_t *data, size_t size, int *res);
/*
 * Decode binary encoded length
 *
 * data:        pointer to binary array what stores encoded object
 * size:        size of array pointed by data
 * res:         element used to hold decoded object
 *
 * returns:
 *              -1 if decoding fails and set errno
 *              amount of successfully decoded bytes
 */
ssize_t ber_decode_length(const uint8_t *data, size_t *res);

/*
 * Encode ASN.1 object to binary array
 *
 * root:        pointer to object what will be encoded
 * buffer:      pointer to pointer to buffer where encoded object will be stored
 *
 * returns:
 *              -1 in error and set errno
 *              size of allocated buffer what stores encoded object
 */
ssize_t ber_encode_asn1_tree(asn1_node_t *root, uint8_t **buffer);
/*
 * Encode OID object to binary array
 *
 * root:        pointer to object what will be encoded
 * buffer:      pointer to pointer to buffer where encoded object will be stored
 *
 * returns:
 *              -1 in error and set errno
 *              size of allocated buffer what stores encoded object
 */
ssize_t ber_encode_oid(const oid_t *data, uint8_t *res);
/*
 * Encode null-terminated octet string object to binary array
 *
 * root:        pointer to object what will be encoded
 * buffer:      pointer to pointer to buffer where encoded object will be stored
 *
 * returns:
 *              -1 in error and set errno
 *              size of allocated buffer what stores encoded object
 */
ssize_t ber_encode_octet_string(const char *data, uint8_t *res);
/*
 * Encode integer to binary array
 *
 * root:        pointer to object what will be encoded
 * buffer:      pointer to pointer to buffer where encoded object will be stored
 *
 * returns:
 *              -1 in error and set errno
 *              size of allocated buffer what stores encoded object
 */
ssize_t ber_encode_integer(const int *data, uint8_t *res);
/*
 * Encode length to binary array
 *
 * root:        pointer to object what will be encoded
 * buffer:      pointer to pointer to buffer where encoded object will be stored
 *
 * returns:
 *              -1 in error and set errno
 *              size of allocated buffer what stores encoded object
 */
ssize_t ber_encode_length(const size_t *data, uint8_t *res);

/*
 * Calculates amount of bytes needed to encode OID object
 *
 * data:        pointer to object which encoded size should be calculated
 *
 * returns:
 *              minimum number of bytes required to encode object
 *
 */
size_t ber_calc_encoded_oid_len(const oid_t *data);
/*
 * Calculates amount of bytes needed to encode null-terminated octet string
 *
 * data:        pointer to object which encoded size should be calculated
 *
 * returns:
 *              minimum number of bytes required to encode object
 */
size_t ber_calc_encoded_octet_string_len(const char *data);
/*
 * Calculates amount of bytes needed to encode integer
 *
 * data:        pointer to object which encoded size should be calculated
 *
 * returns:
 *              minimum number of bytes required to encode object
 */
size_t ber_calc_encoded_integer_len(const int *data);
/*
 * Calculates amount of bytes needed to encode length
 *
 * data:        pointer to object which encoded size should be calculated
 *
 * returns:
 *              minimum number of bytes required to encode object
 */
size_t ber_calc_encoded_length_len(const size_t *data);

#endif //SNMP_BER_H
