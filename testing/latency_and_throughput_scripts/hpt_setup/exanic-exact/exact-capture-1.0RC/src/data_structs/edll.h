/*
 * edll.h
 *
 *  Created on: 11 Jul 2017
 *      Author: mattg
 */

#ifndef SRC_DATA_STRUCTS_EDLL_H_
#define SRC_DATA_STRUCTS_EDLL_H_

/* This structure define the Exablaze link layer "protocol". This pseudo
 * protocol packages up metadata about packets
 */

#include "../data_structs/timespecps.h"

enum {
    EDLL_FLAG_NONE    = 0x00, //No flags
    EDDL_FLAG_ABRT    = 0x01, //Frame aborted
    EDDL_FLAG_CRPT    = 0x02, //Frame corrupt
    EDDL_FLAG_TRNC    = 0x04, //Frame truncated
    EDDL_FLAG_SWOVFL  = 0x08, //A software overflow happened
    EDDL_FLAG_HWOVFL  = 0x10, //A hardware overflow happened
} exadll_flags;


typedef struct exadll_hdr {
    //Header
    int32_t hdr_magic;
    int32_t hdr_ver;

    uint64_t flags;  //A flag from the exadll_flags enum
    int64_t frags;   //Number of fragments (from exanic)

    //Timestamp in picoseconds
    int64_t hw_rx; //Hardware seconds timestamp
    int64_t sw_rx; //Software seconds timestamp

    uint64_t packet_id;
    uint64_t packet_bytes;

    int64_t l_ostream_spins;
    int64_t l_istream_spins;

    int64_t l_start_rx;
    int64_t l_ostream_acq;
    int64_t l_istream_acq;
    int64_t l_istream_rel;
    int64_t l_ostream_tx;
    int64_t l_ostream_rel;


    int64_t w_ostream_spins;
    int64_t w_istream_spins;

    int64_t w_start_rx;
    int64_t w_ostream_acq;
    int64_t w_istream_acq;
    int64_t w_istream_rel;
    int64_t w_ostream_tx;
    int64_t w_ostream_rel;


} exadll_hdr_t;


#endif /* SRC_DATA_STRUCTS_EDLL_H_ */
