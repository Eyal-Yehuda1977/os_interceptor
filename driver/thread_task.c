#include "os_interceptor_data_type.h"


#define SET_INTERVAL_JIFFIES(interval)		\
	delay = interval*HZ;			\
	j0 = jiffies;				\
	j1 = j0 + delay;			\


static struct task_struct *cache_cleanup_thread  = NULL;
static const char *cache_cleanup_name            = "cache_cleanup_task";
static const short cache_cleanup_interval        = 2; // sec



int cache_clean_up_fn(void *p) {


	void delete_signed_nodes(void);
	unsigned long j0, j1;
	int delay = cache_cleanup_interval * HZ;

	while(1) {

		SET_INTERVAL_JIFFIES(cache_cleanup_interval)
		info("[ %s ] cache clean up start at: [ %lu ]", MODULE_NAME, jiffies);

		/*
		  thread stop
		*/
		if ( kthread_should_stop() ) {
			do_exit(0);
		}
 
		/* 
		   wait on timer 
		*/  
		while ( time_before(jiffies, j1) ) { 
			schedule();
			set_current_state(TASK_INTERRUPTIBLE);
		}

		delete_signed_nodes();

		info("[ %s ] cache clean up end at: [ %lu ]", MODULE_NAME, jiffies);
	}

	set_current_state(TASK_RUNNING);

	return 0;
}


int init_thread_task(void) {

	/*
	  initialize cache clean up thread 
	*/
	cache_cleanup_thread = kthread_create(cache_clean_up_fn, NULL, cache_cleanup_name);
	if ( (cache_cleanup_thread) ) {
		wake_up_process(cache_cleanup_thread);
	}

	return 0;
}



void destroy_thread_task(void) {

  int ret = 0;

  ret = kthread_stop(cache_cleanup_thread);
  if ( !ret )
	  info("[ %s ] %s stoped. ", MODULE_NAME, cache_cleanup_name);

}
