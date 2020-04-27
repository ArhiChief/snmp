/*
 * program_config.h
 * Defines getters to global program configuration variables
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

#ifndef SNMP_PROGAM_CONFIG_H
#define SNMP_PROGAM_CONFIG_H

#include <stdbool.h>

typedef enum {
    SNMP_V1 = 0x1,
    SNMP_V2C = 0x1 << 1,
    SNMP_V3 = 0x1 << 2
} supported_snmp_version_t;

const char *g_program_name();
int g_socket_type();
bool g_use_auth();
const char *g_community_name();
int g_max_connections();
int g_port();
bool g_use_syslog();
supported_snmp_version_t g_snmp_version();
char * const *g_handler_paths();


#endif //SNMP_PROGAM_CONFIG_H
