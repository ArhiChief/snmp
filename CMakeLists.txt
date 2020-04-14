cmake_minimum_required(VERSION 3.13)
project(snmp C)

set(CMAKE_C_STANDARD 11)

add_executable(snmp
        main.c
        ber.c
        ber.h
        utilities.c
        utilities.h
        mib.c
        mib.h
        processor.c
        processor.h
        asn1/asn1.c
        asn1/asn1.h)

target_compile_options(snmp PRIVATE -Wall -Wextra -pedantic -Werror)