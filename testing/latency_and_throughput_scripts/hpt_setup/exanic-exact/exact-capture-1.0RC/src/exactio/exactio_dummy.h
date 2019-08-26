/*
 * Copyright (c) 2017, All rights reserved.
 * See LICENSE.txt for full details. 
 * 
 *  Created:   19 Jun 2017
 *  File name: exactio_file.h
 *  Description:
 *  <INSERT DESCRIPTION HERE> 
 */
#ifndef EXACTIO_DUMMY_H_
#define EXACTIO_DUMMY_H_

#include "exactio_stream.h"


typedef enum
{
    DUMMY_MODE_NONE,   /* Reads as if there is one big empty buffer */
    DUMMY_MODE_EXPCAP, /* The buffer full of minimum sized expcap records */
    DUMMY_MODE_EXANIC, /* The buffer is full of minimum sized ExaNIC chunks */
} dummy_read_mode;

typedef struct  {
    uint64_t read_buff_size;
    uint64_t write_buff_size;
    dummy_read_mode rd_mode;
    uint64_t expcap_bytes;
    uint64_t exanic_pkt_bytes;
} dummy_args_t;


NEW_IOSTREAM_DECLARE(dummy, dummy_args_t);

#endif /* EXACTIO_DUMMY_H_ */
