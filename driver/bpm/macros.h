//
// Created by ubunto on 29/04/18.
//

#ifndef BPMTESTER_MACROS_H
#define BPMTESTER_MACROS_H

#include "../../driver_shared/driver_api.h"


#define _KILOBYTE 1024
#define MAX_ALLOCATION  (int)(128 * _KILOBYTE)

#ifndef _BOOL
#define _BOOL    int
#endif

#ifndef _TRUE
#define _TRUE    1
#endif

#ifndef _FALSE
#define _FALSE   0
#endif


#ifdef __KERNEL__




#include <stddef.h>
#include <asm/pgtable_types.h>
#include <linux/types.h>
#include <linux/limits.h>
#include <asm/atomic.h>
#include <linux/slab.h>
#include <asm/delay.h>
#include <linux/gfp.h>

void* __bpm_malloc(const unsigned long sz);

void* __bpm_cmalloc_alloc(const unsigned long sz);

void __bpm_free(void*ptr);

void __bpm_lock(void);


void __bpm_unlock(void);

#define MM_ALLOC(size)                  __bpm_malloc(size)
#define C_ALLOC(type, numOfElements)             (type *)__bpm_cmalloc_alloc(sizeof(type[numOfElements]))
#define ATOMIC_LONG_T
#define ATOMIC_LONG_NEW(name)           atomic_long_t name = ATOMIC_LONG_INIT(0)
#define ATOMIC_LONG_INC(ptr)            atomic_long_inc_return(ptr)

#define ATOMIC_T(name)            atomic_t name
#define ATOMIC_NEW(name)          atomic_t name = ATOMIC_INIT(0)
#define ATOMIC_GET(ptr)          atomic_read(ptr)
#define ATOMIC_SET(ptr, value)   atomic_set(ptr, value)
#define ATOMIC_INC(ptr)           atomic_inc_return(ptr)
#define ATOMIC_DEC(ptr)           atomic_dec_return(ptr)

#define FREE(ptr)                       __bpm_free(ptr)

#define LOCK_BPM()                __bpm_lock()
#define UNLOCK_BPM()                __bpm_unlock()
#define SLEEP(num)       udelay(num)

#include "../kcontroller_params.h"

#define LG_ERROR(str, ...) error("[bpm_engine2] " str, ##__VA_ARGS__)
#define LG_INFO(str, ...) info("[bpm_engine2] " str, ##__VA_ARGS__)
#define LG_DEBUG(str, ...) debug("[bpm_engine2] " str, ##__VA_ARGS__)


#ifndef ASSERT_MEMORY_ALLOCATION
#include <asm-generic/errno-base.h>
#include <linux/printk.h>
#define ASSERT_MEMORY_ALLOCATION(mem){\
  if(!mem){\
     LG_ERROR("memory allocation error in function  [ %s ]\n", __func__); \
     return (-ENOMEM);\
  }\
}


#endif
#else

// on user space we will not do any atomic or locking because the testing env is single thread

#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>


#define MM_ALLOC(size)                   malloc(size)
#define C_ALLOC(type, num)              (type *)calloc(num, sizeof(type))
// fake atomic operations. No need for atomics in the tester
#define ATOMIC_LONG_NEW(name)            long name = 0
#define ATOMIC_LONG_INC(ptr)  ++(*ptr)

#define ATOMIC_T(name)            int name
#define ATOMIC_NEW(name)          int name = 0
#define ATOMIC_GET(ptr)           *ptr
#define ATOMIC_SET(ptr, val)      *ptr = val
#define ATOMIC_INC(ptr)           ++(*ptr)
#define ATOMIC_DEC(ptr)           --(*ptr)
#define ATOMIC_INIT(num)          num

#define FREE(ptr)                       free(ptr)

#define LOCK_BPM()
#define UNLOCK_BPM()

#define SLEEP(num)                  sleep(num)

#define ASSERT_MEMORY_ALLOCATION(name)


void writeLog(const char* format, ...);

#define LG_DEBUG(...)    writeLog    ("[bpm] " __VA_ARGS__)
#define LG_INFO(...)     writeLog     ("[bpm] INFO: " __VA_ARGS__)
#define LG_ERROR(...)    writeLog    ("[bpm] ERROR: " __VA_ARGS__)

#endif



#endif //BPMTESTER_MACROS_H


