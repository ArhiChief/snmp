//
// Created by arhichief on 2/8/19.
//

#ifndef SNMP_SNMP_MIB_H
#define SNMP_SNMP_MIB_H

#include <stdlib.h>
#include "snmp_types.h"

typedef int (*getter_t)(void **res, size_t *size);
typedef int (*setter_t)(const void *res, size_t size);

typedef struct mib_entry {
    snmp_oid_t oid;
    snmp_object_type_t type;
    getter_t get;
    setter_t set;
} mib_entry_t;


int add_mib_entry(const snmp_oid_t *oid, snmp_object_type_t type, getter_t getter, setter_t setter);

const mib_entry_t *find_mib_entry(const snmp_oid_t *oid);
const mib_entry_t *findnext_mib_entry(const snmp_oid_t *oid);



#endif //SNMP_SNMP_MIB_H
