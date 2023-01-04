#include "os_interceptor_data_type.h"





static inline __attribute__((always_inline)) 
void _init_syscall_current_data(struct event_t* evt) { 

	evt->user_id           = current_uid().val;
	evt->user_group_id     = current_gid().val;
	evt->caller_process_id = current->tgid;  
	evt->caller_thread_id  = current->pid;

}

static inline __attribute__((always_inline)) 
int _init_syscall_cache_data(struct event_t* evt) {


	int ret=SUCCESS;
	struct process_cache_node cache_node;
	struct timeval ktv; 
	unsigned long current_time_ms=0;
  
	memset(&cache_node, 0, sizeof(struct process_cache_node)); 
	memset(&ktv, 0, sizeof(struct timeval));
   
	if (get_process_cache_node(current->tgid, &cache_node) == SUCCESS) {
		
		//debug("[ %s ]  pid [ %d ] cache hit. ", MODULE_NAME, current->tgid);
		
		/* 
		   the actual process data 
		*/
		strncpy(evt->caller_path,  cache_node.data.path,   EVENT_MAX_PATH_LEN);
		strncpy(evt->caller_name,  cache_node.data.name,   EVENT_MAX_PATH_LEN);
		strncpy(evt->caller_cmd,   cache_node.data.cmdline,EVENT_MAX_PATH_LEN);

		/*file, tile related arguments*/
		evt->caller_created_at = 
			(uint64_t)(cache_node.data.created_at.tv_sec - (sys_tz.tz_minuteswest * 60));
		evt->caller_modified_at = 
			(uint64_t)(cache_node.data.modified_at.tv_sec - (sys_tz.tz_minuteswest * 60));
		evt->caller_last_accessed_at = 
			(uint64_t)(cache_node.data.last_accessed_at.tv_sec - (sys_tz.tz_minuteswest * 60));
		
		evt->caller_file_size = cache_node.data.file_size;
		
		evt->caller_start_at = 
			(uint64_t)(cache_node.data.task_start_time.tv_sec - (sys_tz.tz_minuteswest * 60));

		do_gettimeofday(&ktv);

		current_time_ms = (ktv.tv_sec - (sys_tz.tz_minuteswest * 60)); 
		evt->event_time_diff = (uint64_t)(current_time_ms - evt->caller_start_at);
		
		evt->caller_md5.is_valid = cache_node.data.identifier_valid;
		memcpy(evt->caller_md5.md5, cache_node.data.md5,MD5_LENGTH);


		/* parent process of this process */
		evt->parent_process_id =   cache_node.data.parent_pid;
		strncpy(evt->parent_path,  cache_node.data.parent_path,     EVENT_MAX_PATH_LEN);
		strncpy(evt->parent_name,  cache_node.data.parent_name,     EVENT_MAX_PATH_LEN);
		strncpy(evt->parent_cmd,   cache_node.data.parent_cmdline,  EVENT_MAX_PATH_LEN);    

		/*file, tile related arguments*/
		evt->parent_created_at = 
			(uint64_t)(cache_node.data.parent_created_at.tv_sec - (sys_tz.tz_minuteswest * 60));
		evt->parent_modified_at = 
			(uint64_t)(cache_node.data.parent_modified_at.tv_sec - (sys_tz.tz_minuteswest * 60));
		evt->parent_last_accessed_at = 
			(uint64_t)(cache_node.data.parent_last_accessed_at.tv_sec - (sys_tz.tz_minuteswest * 60));
		
		evt->parent_file_size = cache_node.data.parent_file_size;
		
		evt->parent_md5.is_valid = cache_node.data.parent_identifier_valid;
		memcpy(evt->parent_md5.md5, cache_node.data.parent_md5,MD5_LENGTH);
		
	} else
	{
		/* 
		   TODO sort out cache miss  
		*/
		ret = ERROR;
		//debug("[ %s ] ERROR  pid [ %d ] cache miss. ", MODULE_NAME,current->tgid);
		strncpy(evt->caller_name,  current->comm,   EVENT_MAX_PATH_LEN);
	}

	return ret;
}


int sys_process_execv(struct event_t* evt, struct bpm_result_t* res_t) {



	int ret = SUCCESS;
	struct process_cache_node *cache_node, *parent_cache_node;
	struct timeval ktv; 
	unsigned long current_time_ms = 0;
  

	cache_node = (struct process_cache_node*)vmalloc(sizeof(struct process_cache_node));
	ASSERT_MEMORY_ALLOCATION(cache_node)

	parent_cache_node = (struct process_cache_node*)vmalloc(sizeof(struct process_cache_node));
	ASSERT_MEMORY_ALLOCATION(parent_cache_node)

	memset(cache_node,0,sizeof(struct process_cache_node)); 
	memset(parent_cache_node,0,sizeof(struct process_cache_node)); 
	memset(&ktv,0,sizeof(struct timeval));

	_init_syscall_current_data(evt);

	evt->syscall = SC_EXECVE;

        if (get_process_cache_node(current->tgid, cache_node) == SUCCESS ) {
		
		info("[ %s ] sys_process_execv() process information ",MODULE_NAME);
		_dump_cache_node(cache_node);

		strncpy(evt->caller_path,  cache_node->data.parent_path,   EVENT_MAX_PATH_LEN);
		strncpy(evt->caller_name,  cache_node->data.parent_name,   EVENT_MAX_PATH_LEN);
		strncpy(evt->caller_cmd,   cache_node->data.parent_cmdline,EVENT_MAX_PATH_LEN);   

		/*
		  file, tile related arguments
		*/
		evt->caller_created_at = 
			(uint64_t)(cache_node->data.parent_created_at.tv_sec - (sys_tz.tz_minuteswest * 60));
		evt->caller_modified_at = 
			(uint64_t)(cache_node->data.parent_modified_at.tv_sec - (sys_tz.tz_minuteswest * 60));
		evt->caller_last_accessed_at = 
			(uint64_t)(cache_node->data.parent_last_accessed_at.tv_sec - (sys_tz.tz_minuteswest * 60));
		
		evt->caller_file_size = cache_node->data.parent_file_size;

		evt->caller_start_at = 
			(uint64_t)(cache_node->data.task_start_time.tv_sec - (sys_tz.tz_minuteswest * 60));
		
		do_gettimeofday(&ktv);

		current_time_ms = (ktv.tv_sec - (sys_tz.tz_minuteswest * 60)); 
		evt->event_time_diff = (uint64_t)(current_time_ms - evt->caller_start_at);

		evt->caller_md5.is_valid = cache_node->data.parent_identifier_valid;
		memcpy(evt->caller_md5.md5, cache_node->data.parent_md5,MD5_LENGTH);
		
		strncpy(evt->target.target_path,  cache_node->data.path,   EVENT_MAX_PATH_LEN);
		strncpy(evt->target.target_name,  cache_node->data.name,   EVENT_MAX_PATH_LEN);
		strncpy(evt->target.target_cmd,   cache_node->data.cmdline,EVENT_MAX_PATH_LEN);
		
		if (get_process_cache_node(cache_node->data.parent_pid, parent_cache_node) == SUCCESS) {	 

			info("[ %s ] sys_process_execv() parent process information ",MODULE_NAME);
			_dump_cache_node(parent_cache_node);

			evt->parent_process_id =   parent_cache_node->data.pid;
			strncpy(evt->parent_path,  parent_cache_node->data.path,     EVENT_MAX_PATH_LEN);
			strncpy(evt->parent_name,  parent_cache_node->data.name,     EVENT_MAX_PATH_LEN);
			strncpy(evt->parent_cmd,   parent_cache_node->data.cmdline,  EVENT_MAX_PATH_LEN);    
			
			/*
			  file, tile related arguments
			*/
			evt->parent_created_at = 
				(uint64_t)(parent_cache_node->data.created_at.tv_sec - (sys_tz.tz_minuteswest * 60));
			evt->parent_modified_at = 
				(uint64_t)(parent_cache_node->data.modified_at.tv_sec - (sys_tz.tz_minuteswest * 60));
			evt->parent_last_accessed_at = 
				(uint64_t)(parent_cache_node->data.last_accessed_at.tv_sec - (sys_tz.tz_minuteswest * 60));

			evt->parent_file_size = parent_cache_node->data.file_size;
			
			evt->parent_md5.is_valid = parent_cache_node->data.identifier_valid;
			memcpy(evt->parent_md5.md5, parent_cache_node->data.md5,MD5_LENGTH);
		}

	} else
	{
		/* 
		   TODO sort out cache miss  
		*/
		strncpy(evt->caller_name,  current->comm,   EVENT_MAX_PATH_LEN);
		info("[ %s ] sys_process_execv()  pid: %d not in cache", MODULE_NAME,current->tgid);
	}
       
	vfree(cache_node);    
	vfree(parent_cache_node);    
 
	ret = bpm_engine_process(evt, res_t);
 
	return ret;
}





int sys_process_read(char *path, struct event_t *evt, struct bpm_result_t *res_t) {



	int ret = SUCCESS;
	char *file_name = NULL;

	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);
  
	file_name = get_file_name_from_path(path);
	if (file_name) {
		strncpy(evt->target.target_name, file_name, EVENT_MAX_PATH_LEN);
		strncpy(evt->target.target_path, path, (file_name - path));
	}else
	{  
		strncpy(evt->target.target_name, path, EVENT_MAX_PATH_LEN);
		strncpy(evt->target.target_path, path, EVENT_MAX_PATH_LEN);
	}

	//debug("[ %s ] name: %s  path: %s  orig_path: %s "
	//	 ,MODULE_NAME , evt->target.target_name, evt->target.target_path , path);

	evt->syscall = SC_READ;   
	evt->target.file_access.flags = FILE_ACCESS_FLAG_READ;
 
	ret = bpm_engine_process(evt, res_t);

	return ret;
}


int sys_process_write(char *path, struct event_t *evt, struct bpm_result_t *res_t) {


	int ret = SUCCESS;
	char *file_name = NULL;

	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);

	file_name=get_file_name_from_path(path);
	if (file_name) {
		strncpy(evt->target.target_name, file_name, EVENT_MAX_PATH_LEN);
		strncpy(evt->target.target_path, path, (file_name - path));
	}else
	{
		strncpy(evt->target.target_name, path, EVENT_MAX_PATH_LEN);
		strncpy(evt->target.target_path, path, EVENT_MAX_PATH_LEN);
	}

	//debug("[ %s ] sys_process_write name: %s  path: %s  orig_path: %s "
	//    ,MODULE_NAME , evt->target.target_name, evt->target.target_path , path);

	evt->syscall = SC_WRITE;
	evt->target.file_access.flags = FILE_ACCESS_FLAG_WRITE;
	ret = bpm_engine_process(evt,res_t);
   
	return ret;
}


int sys_process_fork(struct event_t *evt, struct bpm_result_t *res_t) {


	int ret = SUCCESS;
 
	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);

	evt->syscall = SC_FORK;
    
	ret = bpm_engine_process(evt, res_t);

	return ret;
}


int sys_process_clone(struct event_t *evt, struct bpm_result_t *res_t) {



	int ret = SUCCESS;
 
	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);

	evt->syscall = SC_CLONE;
    
	ret = bpm_engine_process(evt, res_t);

	return ret;
}


int sys_process_socket_connect(const unsigned short dport, 
                               const uint32_t ipv4, 
                               struct event_t *evt,
                               struct bpm_result_t *res_t)
{



	int ret=SUCCESS;
 
	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);

	evt->syscall = SC_CONNECT;
	evt->network.target_port=dport;
	evt->network.ipv4=ipv4;
	ret = bpm_engine_process(evt, res_t);

	return ret;
}



int sys_process_open(char *path, int flags, struct event_t *evt, struct bpm_result_t *res_t) {



	int ret = SUCCESS;
	char *file_name = NULL;

	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);

	file_name = get_file_name_from_path(path);
	strncpy(evt->target.target_name, file_name, EVENT_MAX_PATH_LEN);
	strncpy(evt->target.target_path, path, (file_name - path));
	
	//debug("[ %s ] sys_process_open name: %s  path: %s  orig_path: %s "
	//      ,MODULE_NAME , evt->target.target_name, evt->target.target_path , path);

	evt->syscall = SC_OPEN;

	/* 
	   access mode and flagesd are checked 
	*/
	if ( ACC_MODE(flags) == MAY_READ )
		evt->target.file_access.flags |= FILE_ACCESS_FLAG_READ;

	if ( ACC_MODE(flags) == MAY_WRITE )
		evt->target.file_access.flags |= FILE_ACCESS_FLAG_WRITE;

	ret = bpm_engine_process(evt, res_t);

	return ret;
}


int sys_process_close(const char *path, struct event_t *evt, struct bpm_result_t *res_t) {


	int ret = SUCCESS;
 
	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);

	evt->syscall = SC_CLOSE;
	strncpy(evt->target.target_path, path, EVENT_MAX_PATH_LEN);    
	ret = bpm_engine_process(evt, res_t);
	
	return ret;

}


int sys_process_rename(const char *old_name, const char *new_name, 
		       struct event_t *evt, struct bpm_result_t *res_t) {


	int ret = SUCCESS;
 
	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);

	evt->syscall = SC_RENAME;
	strncpy(evt->target.target_path, old_name, EVENT_MAX_PATH_LEN);    
	evt->target.file_access.flags = FILE_ACCESS_FLAG_WRITE;
  
	ret = bpm_engine_process(evt, res_t);

	return ret;
}



int sys_process_unlink(const char *path_name ,struct event_t *evt, struct bpm_result_t *res_t) {


	int ret = SUCCESS;
 
	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);

	evt->syscall = SC_UNLINK;
	strncpy(evt->target.target_path, path_name, EVENT_MAX_PATH_LEN);    
	evt->target.file_access.flags = FILE_ACCESS_FLAG_WRITE;

	ret = bpm_engine_process(evt, res_t);

	return ret;
}


int sys_process_fchmodat(int dfd
                        ,const char *file_name
                        ,umode_t mode
                        ,struct event_t *evt
                        ,struct bpm_result_t *res_t)
{


	int ret=SUCCESS;
 
	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);
	
	evt->syscall = SC_FCHMODAT;
	strncpy(evt->target.target_path, file_name, EVENT_MAX_PATH_LEN);    
	evt->target.file_access.flags = FILE_ACCESS_FLAG_WRITE;
  
	ret = bpm_engine_process(evt, res_t);

	return ret;

}

int sys_process_truncate(char *pathname, struct event_t* evt, struct bpm_result_t* res_t) {


	int ret = SUCCESS;
	char *file_name = NULL;

	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);

	evt->syscall = SC_TRUNCATE;

	file_name = get_file_name_from_path(pathname);
	strncpy(evt->target.target_name, file_name, EVENT_MAX_PATH_LEN);
	strncpy(evt->target.target_path, pathname, (file_name - pathname));

	evt->target.file_access.flags = FILE_ACCESS_FLAG_WRITE;
   
	ret = bpm_engine_process(evt, res_t);   

	return ret;
}


int sys_process_ftruncate(char *pathname, struct event_t *evt, struct bpm_result_t *res_t) {


	int ret = SUCCESS;
	char *file_name = NULL;

	_init_syscall_current_data(evt);
	_init_syscall_cache_data(evt);

	evt->syscall = SC_FTRUNCATE;

	file_name = get_file_name_from_path(pathname);
	strncpy(evt->target.target_name, file_name, EVENT_MAX_PATH_LEN);
	strncpy(evt->target.target_path, pathname, (file_name - pathname));

	evt->target.file_access.flags = FILE_ACCESS_FLAG_WRITE;

	ret = bpm_engine_process(evt, res_t);   

	return ret;
}
