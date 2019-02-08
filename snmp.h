//
// Created by arhichief on 2/8/19.
//

#ifndef SNMP_SNMP_H
#define SNMP_SNMP_H

#include <stdlib.h>
#include <stdint.h>

ssize_t process_snmp(const uint8_t *request, size_t req_size, uint8_t **response);

#endif //SNMP_SNMP_H
