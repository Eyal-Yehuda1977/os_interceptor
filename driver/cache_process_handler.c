#include "kcontroller_data_type.h"


extern char* get_proc_path(struct task_struct* task, char *buf, int buflen);
extern void get_cmdline_args(struct task_struct* task,char* cmdline, int cmdlen);


static inline __attribute__((always_inline)) 
void gather_current_process_information(struct process_cache_node* process_info) {

	struct task_struct* task_parent = NULL;

	process_info->data.pid = current->tgid;
	
	if(current->parent)
		task_parent = current->parent;
	else
		task_parent = current->real_parent;

	process_info->data.parent_pid=task_parent->tgid; 
  
	/* get task runtime*/
	process_info->data.task_start_time = get_process_runtime(process_info->data.pid);
}

static inline __attribute__((always_inline))
int gather_process_parameters(struct process_cache_node* process_info,unsigned char mode) {


	int __kernel__file_info(const char* task_path, const unsigned char algo
				,struct file_info_t* f_inf, unsigned char* identifier_valid); 

	int ret = SUCCESS;    
	char* buffer = NULL, *path_ptr = NULL, *p = NULL;
	struct file_attr_t* attr = NULL;
	struct file_info_t* f_inf = NULL;

	memset(process_info, 0, sizeof(struct process_cache_node) * sizeof(char));   

	if ( ERROR == get_process_cache_node(current->tgid, process_info) ) { 
		
		gather_current_process_information(process_info);
    
		buffer = (char*)vmalloc(MAX_BUF_HALF_K * sizeof(char));
		ASSERT_MEMORY_ALLOCATION(buffer)

		memset(buffer, 0, (MAX_BUF_HALF_K * sizeof(char)));

		path_ptr = get_proc_path(current, buffer, EVENT_MAX_PATH_LEN);
		if ( !IS_ERR(path_ptr) ) {
			p = strnstr(path_ptr, current->comm, EVENT_MAX_PATH_LEN);
			if (p) {
				strncpy(process_info->data.path, path_ptr, (p-path_ptr));
				strncpy(process_info->data.name, p, EVENT_MAX_PATH_LEN);
			} else 
			{
				strncpy(process_info->data.path, path_ptr, EVENT_MAX_PATH_LEN);
				strncpy(process_info->data.name, current->comm, EVENT_MAX_PATH_LEN);
			}
		} else
			strncpy(process_info->data.name, current->comm, EVENT_MAX_PATH_LEN);

		memset(buffer, 0, (MAX_BUF_HALF_K * sizeof(char)));

		get_cmdline_args(current, buffer, EVENT_MAX_PATH_LEN);
		if( strlen(buffer) > 0 )
			strncpy(process_info->data.cmdline, buffer, EVENT_MAX_PATH_LEN);          

		attr = (struct file_attr_t*)vmalloc(sizeof(struct file_attr_t));
		ASSERT_MEMORY_ALLOCATION(attr)

		memset(attr, 0, sizeof(struct file_attr_t));
		memset(buffer, 0, (MAX_BUF_HALF_K *sizeof(char)));
		
		snprintf(buffer, EVENT_MAX_PATH_LEN, "%s%s", 
			 process_info->data.path,
			 process_info->data.name);

		get_file_attributes_from_path(buffer, attr);

		__memcpy_file_attr(process_info, (*(struct file_attr_t*)attr) )

		f_inf = vmalloc(sizeof(struct file_info_t));  
		ASSERT_MEMORY_ALLOCATION(f_inf)

		/* calculate md5 of process */  
		if ( ( strlen(process_info->data.path)>0 ) && (strlen(process_info->data.name)>0) ) {

			memset(f_inf, 0, sizeof(struct file_info_t));
			memset(buffer, 0, sizeof(char) * MAX_BUF_HALF_K);    
  
			snprintf(buffer, EVENT_MAX_PATH_LEN, "%s%s",
				 process_info->data.path,
				 process_info->data.name);

			if ( __kernel__file_info(buffer,
						 algo_md5,
						 f_inf,
						 &process_info->data.identifier_valid) == SUCCESS ) 
			{
				memcpy(process_info->data.md5, f_inf->md5, MD5_LENGTH); 
			}
       
			process_info->data.file_size = f_inf->file_size;
		}

		vfree(buffer);
		vfree(attr);
		vfree(f_inf);

		cache_rcu_process_item(process_info->data.pid, process_info, mode);

		info("[ %s ] gather_process_parameters() parent process information ",MODULE_NAME);
		_dump_cache_node(process_info);
		
	} else;
	// debug("[ %s ] read item not in cache pid [ %d ]", MODULE_NAME,current->tgid);

	return ret;
}

int gather_process_information_syscall_execve(char* target_file_path,
					      char* target_file_name, 
					      char* target_cmdline,
					      const char __user* filename)
{

	int __user__file_info(const char __user* filename, const unsigned char algo
			      ,struct file_info_t* f_inf, unsigned char* identifier_valid);

	int __kernel__file_info(const char* task_path, const unsigned char algo
				,struct file_info_t* f_inf, unsigned char* identifier_valid); 


	char buffer[EVENT_MAX_PATH_LEN];
	struct process_cache_node* process_info;
	struct file_info_t f_inf;
	struct file_attr_t* attr=NULL;
	
	int ret = SUCCESS;
	char *file_name = NULL;

	process_info = vmalloc(sizeof(struct process_cache_node));  
	ASSERT_MEMORY_ALLOCATION(process_info)

	memset(process_info, 0, sizeof(struct process_cache_node) * sizeof(char));   

	gather_current_process_information(process_info);


	if ( NULL != target_file_path ) {  
   
		memset(&f_inf, 0, sizeof(struct file_info_t));
		if(__user__file_info(filename ,
				     algo_md5, 
				     &f_inf,
				     &process_info->data.identifier_valid) == SUCCESS ) 
		{

			file_name = get_file_name_from_path(f_inf.path);
			strncpy(process_info->data.path, f_inf.path, (file_name-f_inf.path));
			//debug("[ %s ]  path: %s",MODULE_NAME, process_info->data.path);

			if(process_info->data.identifier_valid == 1) {
				memcpy(process_info->data.md5, f_inf.md5, MD5_LENGTH); 
			}

			process_info->data.file_size = f_inf.file_size;
		} else
			return ERROR;
	}

	if ( NULL != target_file_name ) {

		file_name = get_file_name_from_path(target_file_name);
		if ( file_name )
			strncpy(process_info->data.name, file_name, EVENT_MAX_PATH_LEN); 
		else
			strncpy(process_info->data.name, target_file_name, EVENT_MAX_PATH_LEN);      

		//debug("[ %s ]  name:  %s",MODULE_NAME,process_info->data.name);
	}   

	if ( NULL != target_cmdline ) {  
		strncpy(process_info->data.cmdline, target_cmdline, EVENT_MAX_PATH_LEN);
		//debug("[ %s ]  cmdline:     %s",MODULE_NAME,process_info->data.cmdline);
	}

	attr = (struct file_attr_t*)vmalloc(sizeof(struct file_attr_t));
	ASSERT_MEMORY_ALLOCATION(attr)

	memset(attr, 0, sizeof(struct file_attr_t));
	memset(buffer, 0, sizeof(buffer));

	snprintf(buffer, EVENT_MAX_PATH_LEN, "%s%s", process_info->data.path
		 ,process_info->data.name);
	
	get_file_attributes_from_path(buffer, attr);
	__memcpy_file_attr(process_info, (*(struct file_attr_t*)attr))

	vfree((void*)attr);
  
	smp_mb();
	cache_rcu_process_item(process_info->data.pid, process_info, GET_PARENT_CMDLINE);
  
  
	/* 
	   we need to calculate parent process md5 so we get from cache all parent info
	   including path for file lookup 
	*/

	memset(process_info, 0, sizeof(struct process_cache_node) * sizeof(char));   
	/* 
	   set current tid 
	*/
	gather_current_process_information(process_info);
	/* 
	   get node back from cache with parent info 
	*/
	get_process_cache_node(process_info->data.pid, process_info); 

	/* 
	   calculate md5 of parent process 
	*/

	if ( ( strlen(process_info->data.parent_path) > 0 ) && (strlen(process_info->data.parent_name) > 0 )
	     && (process_info->data.parent_identifier_valid == 0 ) )
	{

		memset(&f_inf, 0, sizeof(struct file_info_t));
		memset(buffer, 0, sizeof(char) * EVENT_MAX_PATH_LEN);    
  
		snprintf(buffer,EVENT_MAX_PATH_LEN,
			 "%s%s",
			 process_info->data.parent_path,
			 process_info->data.parent_name);


		if ( __kernel__file_info(buffer, algo_md5, &f_inf, 
					 &process_info->data.parent_identifier_valid) == SUCCESS ) {
			memcpy(process_info->data.parent_md5, f_inf.md5, MD5_LENGTH); 
		}
       
		process_info->data.parent_file_size = f_inf.file_size;
       
		smp_mb();
		cache_rcu_process_item(process_info->data.pid, process_info, NO_PARENT_CMDLINE);              
	}

	vfree(process_info);

	return ret;
}


int gather_process_information_syscall_read(void) {

	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret = gather_process_parameters(&process_info, NO_PARENT_CMDLINE);
    
	return ret;
}


int gather_process_information_syscall_write(void) {

	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret = gather_process_parameters(&process_info, NO_PARENT_CMDLINE);
    
	return ret;
}

int gather_process_information_syscall_fork(void) {

	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret = gather_process_parameters(&process_info,NO_PARENT_CMDLINE);
    
	return ret;
}


int gather_process_information_syscall_clone(void) {

	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret = gather_process_parameters(&process_info, NO_PARENT_CMDLINE);
    
	return ret;
}


int gather_process_information_syscall_connect(void) {

	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret = gather_process_parameters(&process_info, NO_PARENT_CMDLINE); 
    
	return ret;
}


int gather_process_information_syscall_open(void) {
	
	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret = gather_process_parameters(&process_info, NO_PARENT_CMDLINE); 
    
	return ret;
}


int gather_process_information_syscall_close(void) {

	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret = gather_process_parameters(&process_info, GET_PARENT_CMDLINE); 
    
	return ret;
}


int gather_process_information_syscall_rename(void) {

	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret=gather_process_parameters(&process_info, NO_PARENT_CMDLINE); 
    
	return ret;
}


int gather_process_information_syscall_unlink(void) {

	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret = gather_process_parameters(&process_info, NO_PARENT_CMDLINE); 
    
	return ret;
}

int gather_process_information_syscall_fchmodat(void) {

	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret = gather_process_parameters(&process_info, NO_PARENT_CMDLINE); 
    
	return ret;
}


int gather_process_information_syscall_group_exit(void) {

	int ret = SUCCESS;
	/* 
	   each closed proccess will get deleted from the cache 
	*/
	cache_rcu_process_item(current->tgid, NULL, NO_PARENT_CMDLINE);

	return ret;
}


int gather_process_information_syscall_truncate(void) {

	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret = gather_process_parameters(&process_info, NO_PARENT_CMDLINE); 
    
	return ret;
}


int gather_process_information_syscall_ftruncate(void)
{
	int ret = SUCCESS;
	struct process_cache_node process_info;  

	ret = gather_process_parameters(&process_info, NO_PARENT_CMDLINE); 
    
	return ret;
}




