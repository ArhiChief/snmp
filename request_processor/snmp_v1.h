/*
 * snmp_v1.h
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

#ifndef SNMP_SNMP_V1_H
#define SNMP_SNMP_V1_H

#include "../asn1/asn1.h"

int process_snmp_v1(asn1_node_t *request, asn1_node_t *response);

#endif //SNMP_SNMP_V1_H
