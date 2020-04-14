/*
 * mib.h
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