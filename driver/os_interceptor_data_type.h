#ifndef __OS_INTERCEPTOR_DATA_TYPE_H_
#define __OS_INTERCEPTOR_DATA_TYPE_H_




#include "os_interceptor_params.h"


/*
  This file contains all data structures that are used in this driver "Os interceptor"
  created by Eyal Yehuda 
*/


/*
  stop mechine structure with 
  arguments and callback function 
*/

/*
struct stop_machine_work { 

	int (*fn)(struct gl_region[], size_t, void*); 
	struct gl_region *regions;
	size_t region_count; 
	void *args; 

}__attribute__((packed));
*/

/* 
   used for memory buffers 
*/
struct mem_page { 

	char *data; 
	struct list_head list; 
	rwlock_t data_lock; 

}; 


/* 
   work queue  
*/
struct w_kcontroller { 

	struct work_struct w; 
	int (*response_callback)(pid_t, const char*);
	pid_t pid;
	void *data;

};


/* 
   netlink 
*/
struct kmsg {

	struct sk_buff *skb;
	struct nlmsghdr *nlh;

};


/* 
   md5/sha1 datatype for file calculation 
*/
struct file_info_t {     

	char     path[EVENT_MAX_PATH_LEN]; 
	uint64_t file_size;

	union {

		unsigned char md5[MD5_LENGTH];
		unsigned char sha1[SHA1_LENGTH];

	}__attribute__((packed));

};


/* 
   file, time related parameters  
*/
struct file_attr_t {

	struct timespec created_at;
	struct timespec modified_at;
	struct timespec last_accessed_at;   

};


/*
  killed process data structure
*/
struct killed_process_id {

	struct hlist_node       list;
	struct rcu_head         rcu_h;

	struct {
		pid_t pid;
	} data;

};


/* 
   process cache data structure
*/
struct process_cache_node {

	struct hlist_node       list;
	struct rcu_head         rcu_h;
	struct rb_node          node;

	unsigned short          rec_status;

	struct { 

		pid_t pid;
		pid_t parent_pid;

		char path[EVENT_MAX_PATH_LEN];
		char name[EVENT_MAX_PATH_LEN];
		char cmdline[EVENT_MAX_PATH_LEN];

		struct timespec created_at;
		struct timespec modified_at;
		struct timespec last_accessed_at;
		uint64_t file_size;    
      
		struct timespec task_start_time;

		char parent_path[EVENT_MAX_PATH_LEN];
		char parent_name[EVENT_MAX_PATH_LEN];
		char parent_cmdline[EVENT_MAX_PATH_LEN];  

		struct timespec parent_created_at;
		struct timespec parent_modified_at;
		struct timespec parent_last_accessed_at;
		uint64_t parent_file_size;    
		
		unsigned char identifier_valid;

		union { 
        
			unsigned char md5[MD5_LENGTH];
			unsigned char sha1[SHA1_LENGTH];

		}__attribute__((packed));

		unsigned char parent_identifier_valid;

		union { 
        
			unsigned char parent_md5[MD5_LENGTH];
			unsigned char parent_sha1[SHA1_LENGTH];

		}__attribute__((packed));

	} data;  

}__attribute__((packed));


/* 
   casting types 
*/
#define CCHARP_CHARP    (char*)(const char*)
#define CUCHAR_UCHAR    (unsigned char)(const unsigned char)
#define CUINT_UINT      (unsigned int)(const unsigned int)
#define CVOIDPP_VOIDPP  (void**)(const void**)





static inline __attribute__((always_inline))  
void _memset_process_cache_node_data(struct process_cache_node *obj) {


	memset(&obj->list, 0, sizeof(struct hlist_node));
	memset(&obj->rcu_h, 0, sizeof(struct rcu_head));

	obj->rec_status = 0;

	memset(&(obj->data.pid), 0, sizeof(pid_t));
	memset(&(obj->data.parent_pid), 0, sizeof(pid_t));
	memset(obj->data.path, 0, sizeof(char) * EVENT_MAX_PATH_LEN);
	memset(obj->data.name, 0, sizeof(char) * EVENT_MAX_PATH_LEN);
	memset(obj->data.cmdline, 0, sizeof(char) * EVENT_MAX_PATH_LEN);

	memset(&obj->data.created_at, 0, sizeof(struct timespec));
	memset(&obj->data.modified_at, 0, sizeof(struct timespec));
	memset(&obj->data.last_accessed_at, 0, sizeof(struct timespec));

	obj->data.file_size = 0;    
	obj->data.identifier_valid = 0;
	memset(obj->data.sha1, 0, sizeof(char) * SHA1_LENGTH);

	memset(obj->data.parent_path, 0, sizeof(char) * EVENT_MAX_PATH_LEN);
	memset(obj->data.parent_name, 0, sizeof(char) * EVENT_MAX_PATH_LEN);
	memset(obj->data.parent_cmdline, 0, sizeof(char) * EVENT_MAX_PATH_LEN);

	memset(&obj->data.parent_created_at, 0, sizeof(struct timespec));
	memset(&obj->data.parent_modified_at, 0, sizeof(struct timespec));
	memset(&obj->data.parent_last_accessed_at, 0, sizeof(struct timespec));

	obj->data.parent_file_size = 0;    
	obj->data.parent_identifier_valid = 0;
	
	memset(obj->data.parent_sha1, 0, sizeof(char) * SHA1_LENGTH);
}



#define __memcpy_file_attr(p, a) {				\
		p->data.created_at = a.created_at;		\
		p->data.modified_at = a.modified_at;		\
		p->data.last_accessed_at = a.last_accessed_at;	\
	}

#define __memcpy_parent_file_attr(p, a) {				\
		p->data.parent_created_at = a.created_at;		\
		p->data.parent_modified_at = a.modified_at;		\
		p->data.parent_last_accessed_at = a.last_accessed_at;	\
}


#define __memset_bpm_message(evt, res_t) {			\
		memset(evt, 0, sizeof(struct event_t));		\
		memset(res_t, 0, sizeof(struct bpm_result_t));	\
}


void dump_event(struct event_t *evt);
void _dump_cache_node(const struct process_cache_node *cache_node);
int _file_info(const char *filename, struct file_info_t *f_inf);
struct timespec get_process_runtime(pid_t pid);
void get_file_attributes_from_path(const char *file_path, struct file_attr_t *attr);
char* get_pwd(struct task_struct *task, char *buf);
char* get_file_name_from_path(char *path);
int is_pid_permitted(pid_t pid);
int analize_bpm_response(unsigned int *rule_priority, unsigned short *spawn_log_in_relay, unsigned short *prevent_system_call);
unsigned short check_permissions(void);
int cache_rcu_process_item(pid_t pid, struct process_cache_node *process_info, unsigned char mode);
int get_process_cache_node(pid_t pid, struct process_cache_node *process_info);
void print_cache(void);
const struct md5_data_t* retrieve_hp_md5(void);
const struct md5_data_t* retrieve_bpm_md5(void);


#define _memory_free_on_error(_slab_error_, membuff, len)		\
	if (_slab_error_ == 1) memory_free_on_error(membuff, len);


#define user_authorized(action) {					\
		if ( check_permissions() ) {				\
									\
			error("[ %s ] ERROR the current user is not allowd to use this driver facility!" \
			      "Action asked is [ %s ]   user uid: [ %d ]: pid [ %d ] comm [ %s ]", \
			      MODULE_NAME,				\
			      action,current_uid().val,			\
			      current->pid,				\
			      current->comm);				\
			return (-EPERM);				\
		} else							\
		{						        \
			info("[ %s ] The current user allowd to use this driver facility!" \
			     "Action asked is [ %s ]  user uid: [ %d ]: pid [ %d ] comm [ %s ] " , \
			     MODULE_NAME,				\
			     action,					\
			     current_uid().val,				\
			     current->pid,				\
			     current->comm);				\
		}							\
}


#define __hook_pid_(pid, func, ...) {			\
		if (is_pid_permitted(pid) == 1) {	\
			return (func)(__VA_ARGS__);	\
		}					\
}

#define __prevent_syscall_(prevent_system_call)				\
	if (prevent_system_call == PRIORITY_PREVENT_SYSCALL) return (-EACCES);


#define __spawn_log_in_relay(msg, condition)				\
	if ((condition == SPAWN_LOG_IN_RELAY) || events_debug())	\
		write_to_chan_events((void*)msg, sizeof(struct bpm_message_t));

#define __spawn_event_log_debug(evt, condition)			\
	if( condition == SPAWN_LOG_IN_RELAY) dump_event(evt);

#endif //__OS_INTERCEPTOR_DATA_TYPE_H_
