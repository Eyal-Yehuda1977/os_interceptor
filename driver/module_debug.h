#ifndef __MODULE_DEBUG_H_
#define __MODULE_DEBUG_H_

#include "os_interceptor_data_type.h"

#define DEBUG_MODULE  "debug_module"


#define DEFINE_TICK_COUNTER_JIFFIES(name) unsigned long volatile name ## _jiffies = jiffies;
#define DEFINE_TICK_COUNTER(name) unsigned long volatile name ## _jiffies=0;

#ifdef __STRESS_TEST__
#define DEFINE_TIME_COUNTERS(name_start, name_end)	\
	DEFINE_TICK_COUNTER_JIFFIES(name_start)		\
	DEFINE_TICK_COUNTER(name_end)
#else 
#define DEFINE_TIME_COUNTERS(name_start, name_end)
#endif

#define SET_TIME_COUNTER(name) name ## _jiffies = jiffies; 

#define GET_TIME_COUNTER(name) name ## _jiffies

static inline __attribute__((always_inline)) unsigned long
get_total_time_diff(unsigned long start,unsigned long end)
{ return ((end-start)/HZ); }



#ifdef __STRESS_TEST__
#define STOP_TIME_COUNTER(start,end)		\
        SET_TIME_COUNTER(end)						\
	error("[ %s ]  sec: [%lu]  ticks: [%lu] start: [%lu]  end: [%lu]", \
              DEBUG_MODULE,						\
	      get_total_time_diff( GET_TIME_COUNTER(start), GET_TIME_COUNTER(end)), \
	      (GET_TIME_COUNTER(end) -  GET_TIME_COUNTER(start) ),	\
	      GET_TIME_COUNTER(start), GET_TIME_COUNTER(end));
#else 
#define STOP_TIME_COUNTER(start,end)
#endif

#endif
