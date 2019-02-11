//
// Created by arhichief on 2/7/19.
//

#ifndef SNMP_TRANSCODER_H
#define SNMP_TRANSCODER_H

#include <stdlib.h>
#include <stdint.h>

#include "snmp_types.h"


ssize_t decode_oid(const uint8_t *data, size_t size, snmp_oid_t *res);
ssize_t decode_string(const uint8_t *data, size_t size, char **res);
ssize_t decode_int(const uint8_t *data, size_t size, int *res);
ssize_t decode_content_length(const uint8_t *data, uint16_t *res);


ssize_t encode_oid(const snmp_oid_t *data, uint8_t *res);
ssize_t encode_string(const char *data, uint8_t *res);
ssize_t encode_int(const int *data, uint8_t *res);
ssize_t encode_content_length(const uint16_t *data, uint8_t *res);

uint16_t calc_encoded_oid_len(const snmp_oid_t *data);
uint16_t calc_encoded_string_len(const char *data);
uint16_t calc_encoded_int_len(const int *data);

uint16_t calc_encoded_content_length(const uint16_t *data);

void string_to_oid(const char *val, snmp_oid_t *res);
char *oid_to_string(const snmp_oid_t *oid);

#endif //SNMP_TRANSCODER_H
