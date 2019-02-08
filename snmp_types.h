//
// Created by arhichief on 2/7/19.
//

#ifndef SNMP_SNMP_TYPES_H
#define SNMP_SNMP_TYPES_H

#define OID_LEN 40

typedef struct snmp_oid {
    int32_t subids[OID_LEN];
    int subids_cnt;
} snmp_oid_t;

typedef enum snmp_object_type {
    SNMP_OBJECT_TYPE_INTEGER           = 0x02,
    SNMP_OBJECT_TYPE_OCTET_STRING      = 0x04,
    SNMP_OBJECT_TYPE_NULL              = 0x05,
    SNMP_OBJECT_TYPE_OID               = 0x06,
    SNMP_OBJECT_TYPE_SEQUENCE          = 0x30,
    SNMP_OBJECT_TYPE_IPADDRESS         = 0x40,
    SNMP_OBJECT_TYPE_COUNTER           = 0x41,
    SNMP_OBJECT_TYPE_GAUGE             = 0x42,
    SNMP_OBJECT_TYPE_TIMETICKS         = 0x43,
    SNMP_OBJECT_TYPE_OPAQUE            = 0x44,
    SNMP_OBJECT_TYPE_NSAPADDRESS       = 0x45,
    SNMP_OBJECT_TYPE_GETREQUEST        = 0xA0,

    SNMP_OBJECT_TYPE_NO_OBJECT         = 0x80,
    SNMP_OBJECT_TYPE_NO_INSTANCE       = 0x81,
    SNMP_OBJECT_TYPE_END_OF_VIEW       = 0x82
} snmp_object_type_t;

typedef enum snmp_request_type {
    SNMP_OBJECT_TYPE_GETNEXTREQUEST    = 0xA1,
    SNMP_OBJECT_TYPE_GETRESPONSE       = 0xA2,
    SNMP_OBJECT_TYPE_SETREQUEST        = 0xA3,
    SNMP_OBJECT_TYPE_TRAPREQUEST       = 0xA4,
} snmp_request_type_t;

typedef enum snmp_version {
    SNMP_VERSION_1                  = 0,
    SNMP_VERSION_2C                 = 1,
    SNMP_VERSION_3                  = 3

} snmp_version_t;


#endif //SNMP_SNMP_TYPES_H
