cmake_minimum_required(VERSION 3.13)
project(snmp C)

set(CMAKE_C_STANDARD 11)

add_executable(snmp
        main.c
        ber/ber.c
        ber/ber.h
        utilities.c
        utilities.h
        mib.c
        mib.h
        processor.c
        processor.h
        asn1/asn1.c
        asn1/asn1.h progam_config.h log/log.c log/log.h net/net.c net/net.h net/net_tcp.c net/net_tcp.h net/net_udp.c net/net_udp.h request_processor/request_processor.c request_processor/request_processor.h request_processor/snmp_v1_processor.c request_processor/snmp_v1_processor.h)

target_compile_options(snmp PRIVATE -Wall -Wextra -pedantic -Werror)