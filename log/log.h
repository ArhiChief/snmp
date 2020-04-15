/*
 * log.c
 * Define logging routines.
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

#ifndef SNMP_LOG_H
#define SNMP_LOG_H

#include <stdarg.h>
#include <syslog.h>


#define log_alert(fmt, ...) do { log_msg(LOG_ALERT, fmt, ##__VA_ARGS__); } while(0)
#define log_alertv(fmt, args) do { log_msgv(LOG_ALERT, fmt, args)} while(0)

#define log_crit(fmt, ...) do { log_msg(LOG_CRIT, fmt, ##__VA_ARGS__); } while(0)
#define log_critv(fmt, args) do { log_msgv(LOG_CRIT, fmt, args)} while(0)

#define log_err(fmt, ...) do { log_msg(LOG_ERR, fmt, ##__VA_ARGS__); } while(0)
#define log_errv(fmt, args) do { log_msgv(LOG_ERR, fmt, args)} while(0)

#define log_warn(fmt, ...) do { log_msg(LOG_WARNING, fmt, ##__VA_ARGS__); } while(0)
#define log_warnv(fmt, args) do { log_msgv(LOG_WARNING, fmt, args)} while(0)

#define log_notice(fmt, ...) do { log_msg(LOG_NOTICE, fmt, ##__VA_ARGS__); } while(0)
#define log_noticev(fmt, args) do { log_msgv(LOG_NOTICE, fmt, args)} while(0)

#define log_info(fmt, ...) do { log_msg(LOG_INFO, fmt, ##__VA_ARGS__); } while(0)
#define log_infov(fmt, args) do { log_msgv(LOG_INFO, fmt, args)} while(0)

#define log_debug(fmt, ...) do { log_msg(LOG_DEBUG, fmt, ##__VA_ARGS__); } while(0)
#define log_debugv(fmt, args) do { log_msgv(LOG_DEBUG, fmt, args)} while(0)

/*
 * Initialize logging subsystem.
 *
 * returns:
 *          0 if success, -1 otherwise and set errno
 */
int log_init();

/*
 * Release logging subsystem and flush logs.
 *
 * returns:
 *          0 if success, -1 otherwise and set errno
 */
int log_release();

/*
 * Log message
 *
 * lvl:     log level of message
 * fmt:     pointer to message format string
 * ...:     list of argument what will be formatted
 */
void log_msg(int lvl, const char *fmt, ...);
/*
 * Log message
 *
 * lvl:     log level of message
 * fmt:     pointer to message format string
 * args:    list of argument what will be formatted
 */
void log_msgv(int lvl, const char *fmt, va_list args);

#endif //SNMP_LOG_H
