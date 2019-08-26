/*
 * timespecps.h
 *
 *  Created on: 13 Jul 2017
 *      Author: mattg
 */

#ifndef SRC_DATA_STRUCTS_TIMESPECPS_H_
#define SRC_DATA_STRUCTS_TIMESPECPS_H_

#include <stdint.h>

typedef struct timespecps {
    uint64_t tv_sec;
    uint64_t tv_psec;
} __attribute__((packed)) timespecps_t;


#endif /* SRC_DATA_STRUCTS_TIMESPECPS_H_ */
