/*
 * request_processor.c
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

#ifndef SNMP_REQUEST_PROCESSOR_H
#define SNMP_REQUEST_PROCESSOR_H

#endif //SNMP_REQUEST_PROCESSOR_H

#include <stdlib.h>
#include <stdint.h>

typedef ssize_t (*read_data_t)(void *client, uint8_t **buffer);
typedef ssize_t (*write_data_t)(void *client, uint8_t **buffer, size_t buf_siz);
typedef int (*release_client_t)(void *client);

int process_request(void *client, read_data_t read, write_data_t write, release_client_t release);
