/*
 * Copyright (c) 2015, All rights reserved.
 * See LICENSE.txt for full details. 
 * 
 *  Created:    Jul 30, 2015
 *  File name:  debug.h
 *  Description:
 *  <INSERT DESCRIPTION HERE> 
 */
#ifndef DEBUG_H_
#define DEBUG_H_

#include "../types/types.h"

typedef enum {
    DBG,
    ERR,
    WARN
} ch_dbg_mode_e;


ch_word ch_debug_out_(
        ch_bool info,
        ch_dbg_mode_e mode,
        ch_word line_num,
        const char* filename,
        const char* function,
        const char* format, ... );
#define ERR( /*format, args*/...)  camio_err_helper(__VA_ARGS__, "")
#define camio_err_helper(format, ...) ch_debug_out_(true, ERR, __LINE__, __FILE__, __FUNCTION__, format, __VA_ARGS__ )
#define ERR2( /*format, args*/...)  camio_err_helper(__VA_ARGS__, "")
#define camio_err_helper2(format, ...) ch_debug_out_(false, ERR, __LINE__, __FILE__, __FUNCTION__, format, __VA_ARGS__ )



#ifndef NDEBUG
    //ch_word ch_debug_out_(ch_bool info, ch_word line_num, const char* filename, const char* function,  const char* format, ... );
    #define DBG( /*format, args*/...)  ch_debug_helper(__VA_ARGS__, "")
    #define ch_debug_helper(format, ...) ch_debug_out_(true,DBG,__LINE__, __FILE__, __FUNCTION__, format, __VA_ARGS__ )
    #define DBG2( /*format, args*/...)  ch_debug_helper2(__VA_ARGS__, "")
    #define ch_debug_helper2(format, ...) ch_debug_out_(false,DBG,__LINE__, __FILE__, __FUNCTION__, format, __VA_ARGS__ )
    #define WARN( /*format, args*/...)  ch_debug_helper3(__VA_ARGS__, "")
    #define ch_debug_helper3(format, ...) ch_debug_out_(true,WARN,__LINE__, __FILE__, __FUNCTION__, format, __VA_ARGS__ )
#else
    #define DBG( /*format, args*/...)
    #define DBG2( /*format, args*/...)
    #define WARN( /*format, args*/...)
#endif

void hexdump(const void *data, int size);


#endif /* DEBUG_H_ */
