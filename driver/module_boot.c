#include "os_interceptor_data_type.h"


extern struct workqueue_struct* wq;
struct kmem_cache *cache_group = NULL;




int relay_channels_initialize(void) {


	if ( init_channel(RELAY_NAME_EVENTS, 5000, (MSG_LEN*10), events_relay) ) {

		pr_err("[ %s ] ERROR Relay channel initialization failure [ %s ]",
		       MODULE_NAME,
		       RELAY_NAME_EVENTS);
		return -EINVAL;
	}
  
	if ( logger_param() ) {

		if(init_channel(RELAY_NAME_LOGGER, 5000, (MSG_LEN*10),logger_relay)) {
			pr_err("[ %s ] ERROR Relay channel initialization failure [ %s ]", 
			       MODULE_NAME,
			       RELAY_NAME_LOGGER);
			return -EINVAL;
		}else 
		{
			info("[ %s ] successfully registered relay channels." \
			     "relay name [ %s ] on file cpu0. ",
			     MODULE_NAME,
			     RELAY_NAME_LOGGER);
		}   
	}

	info("[ %s ] successfully registered relay channels."	\
	     "relay name [ %s ] on file cpu0. ",
	     MODULE_NAME,
	     RELAY_NAME_EVENTS);

	
	return SUCCESS;  
}




int init_module_boot_process(void) {


	int init_user_app_communication(void);
	int bpm_engine_initialize(void);
	int init_crypto(void);
	int init_network(void);
	int init_process_scan(void);
	int init_thread_task(void);
	int init_patch_systcall_table(void);
	int ret = SUCCESS;
  
	
	cache_group = kmem_cache_create(KMEM_HASH, 
					sizeof(struct process_cache_node),
					__alignof__(struct process_cache_node),
					0,
					NULL);

	if (IS_ERR_OR_NULL(cache_group)) {

		error("[ %s ] error creating cache: [ %ld ], cache name: [ %s ]",
		      MODULE_NAME, 
		      PTR_ERR(cache_group), 
		      KMEM_HASH);

		return (-ENOMEM);
	}



	init_crypto();
	/*
	  memory barrier to protect process scan. 
	  lib crypto must be initialize before 
	*/ 
	smp_mb();

	init_process_scan();  
 
	wq =  create_workqueue(WQ_NAME);
	if (IS_ERR_OR_NULL(wq)) {
		error("[ %s ] error creating workqueue: [ %ld ]",
		      MODULE_NAME, 
		      PTR_ERR(wq) );

		return (-ENOMEM);
	}

	init_user_app_communication(); 
	
	bpm_engine_initialize();
	
	init_network();  

	init_thread_task();
	//ret = stop_machine(module_boot_process_stop_machine, NULL, 0);   

        smp_mb();

	ret = init_patch_systcall_table();

	
	return ret;
}


int destroy_module_boot_process(void) {


	int destroy_user_app_communication(void); 
	int bpm_engine_destroy(void);
	void destroy_crypto(void);
	void destroy_network(void);
	void destroy_thread_task(void);
	int destroy_patched_systcall_table(void);


	destroy_patched_systcall_table();

	/* 
	   hardware memory barrier to prevent instructions 
	   reordering with stop machine  
	*/
	smp_mb();
  
	/*
	  stop all module threads
	*/
	destroy_thread_task();

	smp_mb();

	/* 
	   cache destruction 
	*/
	destroy_process_cache();

	/* 
	   HP destroy
	*/ 
	bpm_engine_destroy();

	destroy_channel(events_relay);

	destroy_user_app_communication(); 

	/* 
	   clear & destroy workqueue 
	*/
	if (wq) {

		flush_workqueue(wq);
		destroy_workqueue(wq);

	}

	destroy_crypto(); 
	destroy_network();

    
	/*
	  hardware memory barrier to prevent logging after 
	  relay logger is down
	*/
	smp_mb(); 

	if (cache_group) {

		kmem_cache_destroy(cache_group);
	}

	info("[ %s ] driver unloaded success .", MODULE_NAME);

	if( logger_param() ) {
		destroy_channel(logger_relay);
	}
	

	return 0;
}






