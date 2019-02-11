#include <stdint.h>
#include <memory.h>
#include <errno.h>
#include <stdbool.h>
#include <unitypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


uint8_t request_message[] = {
        0x30, 0x33, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x26, 0x02, 0x04,
        0x7f, 0x50, 0x1a, 0xff, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x18, 0x30, 0x09, 0x06, 0x05, 0x2b,
        0x0e, 0x03, 0x04, 0x1a, 0x05, 0x00, 0x30, 0x0b, 0x06, 0x07, 0x2b, 0x0e, 0x82, 0x8c, 0x1e, 0x02, 0x1a,
        0x05, 0x00
};


#include "snmp.h"
#include "snmp_types.h"
#include "snmp_mib.h"


int get_string(void **res, size_t *size, bool *is_allocated) {
    *res = "hello world!!!";
    *size = sizeof("hello world!!!");
    *is_allocated = false;
}

int get_int(void **res, size_t *size, bool *is_allocated) {
    static const int val = 19922;
    *res = (void *)&val;
    *size = sizeof(val);
    *is_allocated = false;
}


int main() {
    ssize_t resp_size;
    snmp_oid_t oid1 = {
            .subids = { 1, 3, 14, 3, 4, 26 },
            .subids_cnt = 6
    }, oid2 = {
            .subids = { 1, 3, 14, 34334, 2, 26 },
            .subids_cnt = 6
    };

    add_mib_entry(&oid1, SNMP_OBJECT_TYPE_OCTET_STRING, get_string, NULL);
    add_mib_entry(&oid2, SNMP_OBJECT_TYPE_INTEGER, get_int, NULL);

    uint8_t *response;
    resp_size = process_snmp(request_message, sizeof(request_message), &response);
}

