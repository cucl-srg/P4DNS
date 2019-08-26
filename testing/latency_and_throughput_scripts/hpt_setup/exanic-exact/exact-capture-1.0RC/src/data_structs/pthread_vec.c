/*
 * pthread_vec.c
 *
 *  Created on: 7 Jul 2017
 *      Author: mattg
 */

#include <chaste/data_structs/vector/vector_typed_define_template.h>
#include "pthread_vec.h"

define_ch_vector(pthread,pthread_t)

define_ch_vector_cmp(pthread,pthread_t)
