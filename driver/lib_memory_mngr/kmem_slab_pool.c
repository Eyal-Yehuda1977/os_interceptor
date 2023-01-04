#include "../os_interceptor_data_type.h"





/* 
   slab kmem_group memory pools initialization  
*/
int init_memory_mngr(void) {

	int init_memory_hash(void);
	int ret = SUCCESS;

	init_memory_hash();

	info("[ %s ] kmem_cache initialized success.", MODULE_NAME);

	return ret;
}  


void destroy_memory_mngr(void) {

	void destroy_memory_hash(void);

	destroy_memory_hash();

	info("[ %s ] kmem_cache destroyed success.", MODULE_NAME);
}  
