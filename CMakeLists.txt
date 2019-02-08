cmake_minimum_required(VERSION 3.13)
project(snmp C)

set(CMAKE_C_STANDARD 11)

add_executable(snmp main.c ber.c ber.h transcoder.c transcoder.h snmp_types.h utilities.c utilities.h snmp_mib.c snmp_mib.h snmp.c snmp.h)