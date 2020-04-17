/*
 * main.c
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

#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <errno.h>

#include "progam_config.h"
#include "log/log.h"
#include "net/net.h"

/* global program parameters and their getters */
static const char *program_name = "smart-snmp";
const char *g_program_name() { return program_name; }

static int socket_type = AF_INET;
int g_socket_type() { return socket_type; }

static bool use_auth = false;
bool g_use_auth() { return use_auth; }

static const char *community_name = "public";
const char *g_community_name() { return community_name; }

static int max_connections;
int g_max_connections() { return max_connections; }

static int port = 10161;
int g_port() { return port; }

static bool use_syslog;
bool g_use_syslog() { return use_syslog; }

static snmp_version_t snmp_version = V2C;
snmp_version_t g_snmp_version() { return snmp_version; }

static char **handler_paths = NULL;
char * const *g_handler_paths() { return handler_paths; }
/*---------------------------------------------*/


_Noreturn static void show_usage() {
    const char *msg = "Usage: %s [options]\n"
                        "\t-4, --use-ipv4\n"
                        "\t\tUse IPv4, default\n"
                        "\t-6, --use-ipv5\n"
                        "\t\tUse IPv6\n"
                        "\t-a, --auth\n"
                        "\t\tRequire client authentication, thus SNMP version 2c and higher, default is off\n"
                        "\t-c, --community\n"
                        "\t\tSNMP version 2c authentication, or community, string, default is \"public\"\n"
                        "\t\tRemember to also enable --auth to activate authentication\n"
                        "\t-h, --help\n"
                        "\t\tShow summary of command line options and exit\n"
                        "\t-m, --max-connections NUMBER\n"
                        "\t\tAmount of connections concurrently handled by program, default is 10\n"
                        "\t-p, --port PORT\n"
                        "\t\tPort to listen to for incoming connections, default is 161\n"
                        "\t-s, --syslog\n"
                        "\t\tUse syslog for logging\n"
                        "\t-v, --version\n"
                        "\t\tShow program version and exit\n"
                        "\t-x --handlers PATH\n"
                        "\t\tPath to SNMP requests handlers";

    fprintf(stdout, msg, g_program_name());
    exit(EXIT_SUCCESS);
}

_Noreturn static void show_version() {
    const char *msg = "%s version 0.01";

    fprintf(stdout, msg, g_program_name());
    exit(EXIT_SUCCESS);
}

static const char *progname(const char *arg0) {
    const char *nm;

    nm = strrchr(arg0, '/');
    if (nm)
        nm++;
    else
        nm = arg0;

    return nm;
}

static int parse_handlers_paths(char *paths) {
    int paths_cnt = 1;
    char *path;
    char *rest;
    char **tmp;

    while ((path = strtok_r(paths, ",", &rest))) {
        tmp = realloc(handler_paths, (paths_cnt) * sizeof(*handler_paths));
        if (tmp) {
            handler_paths = tmp;
            handler_paths[paths_cnt - 1] = path;
        } else {
            errno = ENOMEM;
            return -1;
        }

        paths_cnt++;
    }

    tmp = realloc(handler_paths, paths_cnt * sizeof(*handler_paths));
    if (tmp) {
        handler_paths = tmp;
        handler_paths[paths_cnt - 1] = NULL;
    } else {
        errno = ENOMEM;
        return -1;
    }

    return 0;
}

_Noreturn static void show_unrecognized_option(const char arg) {
    const char *msg = "Unrecognized option '%c'. Use %s -h to get help.";

    fprintf(stdout, msg, arg, g_program_name());
    exit(EXIT_FAILURE);
}

static int parse_args(int argc, char **argv) {
    static const char *short_options = "ac:hm:p:P:svV:h:";
    static const struct option long_options[] = {
            {"use-ipv4", no_argument, NULL, '4'},
            {"use-ipv6", no_argument, NULL, '6'},
            {"auth", no_argument, NULL, 'a'},
            {"community", required_argument, NULL, 'c'},
            {"help", no_argument, NULL, 'h'},
            {"max-connections", required_argument, NULL, 'm'},
            {"port", required_argument, NULL, 'p'},
            {"syslog", no_argument, NULL, 's'},
            {"version", no_argument, NULL, 'v'},
            {"snmp-version", required_argument, NULL, 'V'},
            {"handlers", required_argument, NULL, 'x'}
    };

    int opt = 1;
    int opt_index;
    char *e;

    program_name = progname(argv[0]);

    while((opt = getopt_long(argc, argv, short_options, long_options, &opt_index)) > 0) {
        // TODO: add parsing checks for 'm', 'p', 'P', 'V' options
        switch (opt) {
            case '4':
                socket_type = AF_INET;
                break;
            case '6':
                socket_type = AF_INET6;
                break;
            case 'a':
                use_auth = true;
                break;
            case 'c':
                community_name = optarg;
                break;
            case 'h':
            case '?':
                show_usage();
            case 'm':
                e = NULL;
                max_connections = strtol(optarg, &e, 10);
                break;
            case 'p':
                e = NULL;
                port = strtol(optarg, &e, 10);
                break;
            case 's':
                use_syslog = true;
                break;
            case 'v':
                show_version();
            case 'V':
                e = NULL;
                snmp_version = strtol(optarg, &e, 10);
                break;
            case 'x':
                if (!parse_handlers_paths(optarg)) return -1;
                break;
            default:
                show_unrecognized_option(opt);
        }
    }

    return 0;
}

int main(int argc, char **argv) {
    if (parse_args(argc, argv)) {
        fprintf(stderr, "Failed to parse command line arguments: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    if (log_init()) {
        fprintf(stderr, "Failed to initialize logging: %s", strerror(errno));
        return EXIT_FAILURE;
    }

    log_info("Application started: %s", "OK");

    if (network_init()) {
        return EXIT_FAILURE;
    }

    bool stop = false;

    network_listen(&stop);

    log_release();

    return EXIT_SUCCESS;
}

