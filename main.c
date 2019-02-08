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


int get_string(void **res, size_t *size) {
    *res = strdup("hello world!!!");
    *size = sizeof("hello world!!!");
}

int get_int(void **res, size_t *size) {
    static const int val = 19922;
    *res = &val;
    *size = sizeof(val);
}


int main() {
    uint8_t *response;

    process_snmp(request_message, sizeof(request_message), &response);
}
