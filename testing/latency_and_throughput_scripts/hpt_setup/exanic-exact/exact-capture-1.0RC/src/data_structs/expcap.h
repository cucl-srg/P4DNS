/*
 * expcap.h
 *
 *  Created on: 5 Mar. 2018
 *      Author: mattg
 */

#ifndef SRC_DATA_STRUCTS_EXPCAP_H_
#define SRC_DATA_STRUCTS_EXPCAP_H_

#include <stdint.h>

enum {
    EXPCAP_FLAG_NONE    = 0x00, //No flags
    EXPCAP_FLAG_HASCRC  = 0x01, //New CRC included
    EXPCAP_FLAG_ABRT    = 0x02, //Frame aborted
    EXPCAP_FLAG_CRPT    = 0x04, //Frame corrupt
    EXPCAP_FLAG_TRNC    = 0x08, //Frame truncated
    EXPCAP_FLAG_SWOVFL  = 0x10, //A software overflow happened
    EXPCAP_FLAG_HWOVFL  = 0x20, //A hardware overflow happened
} expcap_flags;


typedef struct expcap_pktftr  {
    uint64_t ts_secs : 32; /* 32bit seconds = max 136 years */
    uint64_t ts_psecs :40; /* 40bit picos   = max 1.09 seconds */
    uint8_t flags;
    uint8_t dev_id;
    uint8_t port_id;
    union {
        struct{
            uint16_t dropped;
            uint16_t _reserved;
        } extra;
        uint32_t new_fcs;
    } foot;
} __attribute__((packed)) expcap_pktftr_t;


#endif /* SRC_DATA_STRUCTS_EXPCAP_H_ */
