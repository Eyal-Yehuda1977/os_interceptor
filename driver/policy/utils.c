#include "macros.h"

#ifdef __KERNEL__


void* __bpm_malloc(const unsigned long sz)
{
    return vmalloc(sz);
}

void* __bpm_cmalloc_alloc(const unsigned long sz){
	void *ptr = __bpm_malloc(sz);
	if(!ptr) {
		error("allocation failed !!!!!!");
		return ptr;
	}
	memset(ptr, 0, sz);
//	unsigned char *castToChar = (unsigned char *)ptr;
//	if(*castToChar != 0 && *(castToChar + sz -1) != 0){
//		printk("memset error!!!!!");
//		__bpm_free(ptr);
//		return NULL;
//	}
	return ptr;
}

void __bpm_free(void*ptr){
	if(ptr)
		vfree(ptr);
	else error("Error free empty buffer");
}

static DEFINE_SPINLOCK(s_lock_mem_alloc_free);
static unsigned long flags_mem_alloc_free;

void __bpm_lock(void)
{
	spin_lock_irqsave(&s_lock_mem_alloc_free, flags_mem_alloc_free);
}


void __bpm_unlock(void)
{
	spin_unlock_irqrestore(&s_lock_mem_alloc_free, flags_mem_alloc_free);
}

#else
#include <zconf.h>
#include<stdarg.h>

void writeLog(const char* format, ...) {
	va_list argptr;
	va_start(argptr, format);
	vfprintf(stdout, format, argptr);
	fprintf(stdout, "\n");
	va_end(argptr);
}


#endif

