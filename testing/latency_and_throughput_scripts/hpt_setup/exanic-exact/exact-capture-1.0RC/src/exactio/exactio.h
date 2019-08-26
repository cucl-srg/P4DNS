/*
 * Copyright (c) 2017, All rights reserved.
 * See LICENSE.txt for full details. 
 * 
 *  Created:   19 Jun 2017
 *  File name: io.h
 *  Description:
 *  <INSERT DESCRIPTION HERE> 
 */
#ifndef EXACTIO_IO_H_
#define EXACTIO_IO_H_

#include "exactio_bring.h"
#include "exactio_file.h"
#include "exactio_stream.h"
#include "exactio_dummy.h"
#include "exactio_exanic.h"

#include "../data_structs/timespecps.h"

typedef enum {
    EIO_DUMMY,
    EIO_FILE,
    EIO_EXA,
    EIO_BRING,
} exactio_stream_type_t;


typedef struct {
    exactio_stream_type_t type;
    union {
        exa_args_t exa;
        dummy_args_t dummy;
        file_args_t file;
        bring_args_t bring;
    } args;
} eio_args_t;


int eio_new(eio_args_t* args, eio_stream_t** result);
void eio_des(eio_stream_t* this);

////Read operations
//eio_error_t eio_rd_acq(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts );
//eio_error_t eio_rd_rel(eio_stream_t* this, int64_t* ts);
//
////Write operations
//eio_error_t eio_wr_acq(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts);
//eio_error_t eio_wr_rel(eio_stream_t* this, int64_t len, int64_t* ts);

//Read operations
static inline eio_error_t eio_rd_acq(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts )
{
    return this->vtable.read_acquire(this, buffer, len, ts);
}

static inline eio_error_t eio_rd_rel(eio_stream_t* this, int64_t* ts)
{
    return this->vtable.read_release(this, ts);
}

//Write operations
static inline eio_error_t eio_wr_acq(eio_stream_t* this, char** buffer, int64_t* len, int64_t* ts)
{
    return this->vtable.write_acquire(this, buffer, len, ts);
}


static inline eio_error_t eio_wr_rel(eio_stream_t* this, int64_t len, int64_t* ts)
{
    return this->vtable.write_release(this,len, ts);
}


#endif /* EXACTIO_IO_H_ */
