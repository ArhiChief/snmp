#ifndef SNMP_SNMP_MIB_H
#define SNMP_SNMP_MIB_H

#include <stdlib.h>
#include "ber.h"

typedef int (*mib_getter_t)(void **value, size_t *size, bool *is_allocated);
typedef int (*mib_setter_t)(const void *res, size_t size);

typedef struct mib_entry {
    oid_t oid;
    object_type_t type;
    mib_getter_t get;
    mib_setter_t set;
} mib_entry_t;


int mib_add_entry(const oid_t *oid, object_type_t type, mib_getter_t getter, mib_setter_t setter);

const mib_entry_t *mib_find(const oid_t *oid);
const mib_entry_t *mib_findnext(const oid_t *oid);

void mib_free();

#endif //SNMP_SNMP_MIB_H