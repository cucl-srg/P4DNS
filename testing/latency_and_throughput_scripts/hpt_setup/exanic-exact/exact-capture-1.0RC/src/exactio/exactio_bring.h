/*
 * Copyright (c) 2017, All rights reserved.
 * See LICENSE.txt for full details. 
 * 
 *  Created:   19 Jun 2017
 *  File name: exactio_file.h
 *  Description:
 *  <INSERT DESCRIPTION HERE> 
 */
#ifndef EXACTIO_BRING_H_
#define EXACTIO_BRING_H_

#include "exactio_stream.h"

typedef struct  {
    char* filename;
    uint64_t isserver;

    //These params only required if server
    uint64_t slot_size;
    uint64_t slot_count;
    uint64_t dontexpand;
} bring_args_t;

NEW_IOSTREAM_DECLARE(bring,bring_args_t);

#endif /* EXACTIO_BRING_H_ */
