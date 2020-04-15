/*
 * log.c
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

#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../progam_config.h"
#include "log.h"

static void (*log)(int lvl, const char *fmt, va_list args);

/*
* Message format is the follow: TIMESTAMP [LEVEL]: MESSAGE
*/
static void log_stdout(int lvl, const char *fmt, va_list args) {
    const char *lvl_msg;
    size_t msg_fmt_siz = strlen(fmt) * sizeof(*fmt) + sizeof("dd.mm.yyyy hh:mm:ss [EMG]: %s\n");
    time_t t = time(NULL);
    struct tm tmp;
    struct tm tm = *localtime_r(&t, &tmp);

    char *msg_fmt = malloc(msg_fmt_siz);

    switch (lvl) {
        case LOG_EMERG:
            lvl_msg = "EMG";
            break;
        case LOG_ALERT:
            lvl_msg = "ALR";
            break;
        case LOG_CRIT:
            lvl_msg = "CRT";
            break;
        case LOG_ERR:
            lvl_msg = "ERR";
            break;
        case LOG_WARNING:
            lvl_msg = "WRN";
            break;
        case LOG_NOTICE:
            lvl_msg = "NOT";
            break;
        case LOG_INFO:
            lvl_msg = "INF";
            break;
        case LOG_DEBUG:
            lvl_msg = "DBG";
            break;
        default:
            lvl_msg = "OTH";
            break;
    }

    snprintf(msg_fmt, msg_fmt_siz, "%02d.%02d.%04d %02d:%02d:%02d [%s]: %s\n", tm.tm_mday, tm.tm_mon + 1,
            tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, lvl_msg, fmt);

    vfprintf(stdout, msg_fmt, args);
}

static void log_syslog(int lvl, const char *fmt, va_list args) {
    vsyslog(lvl, fmt, args);
}

int log_init() {
    if (g_use_syslog()) {
        setlogmask(LOG_UPTO(LOG_DEBUG));
        openlog(g_program_name(), LOG_CONS | LOG_NDELAY, LOG_USER);
        log = log_syslog;
    } else {
        log = log_stdout;
    }

    return 0;
}

int log_release() {
    if (g_use_syslog()) {
        closelog();
    } else {
        fflush(stdout);
        fflush(stderr);
    }

    return 0;
}

void log_msg(int lvl, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_end(ap);

    log_msgv(lvl, fmt, ap);
}

void log_msgv(int lvl, const char *fmt, va_list args) {
    log(lvl, fmt, args);
}
