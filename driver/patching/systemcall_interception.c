#include "../os_interceptor_data_type.h"
#include "systemcall_interception.h"
#include "../policy/policy.h"



/*
   system call patch handler to overrun systemcall table with our new system calls 
*/



extern int do_with_write_permissions(int (*fn)(struct gl_region[]),
				     struct gl_region regions[],
				     size_t region_count);

extern int lookup_sys_call_table_addr(unsigned long *sys_call_table_addr); 

extern int mem_patch_relative_call(unsigned long mem_addr,
				   size_t block_size,
				   unsigned long new_call_addr,
				   unsigned long *orig_call_addr);





extern asmlinkage long (*original_sys_execve_fn)(const char __user * filename,
						 const char __user * const __user * argv,
						 const char __user * const __user * envp);

extern asmlinkage long (*original_sys_read_fn)(unsigned int fd,
					       char __user *buf,
					       size_t count);

extern asmlinkage long (*original_sys_write_fn)(unsigned int fd, 
						const char __user *buf,
						size_t count);

extern asmlinkage long (*original_sys_fork_fn)(void);

extern asmlinkage long (*original_sys_clone_fn)(unsigned long chiled_stack,
						unsigned long flags,
						int __user *child_tidptr,
						int __user *parent_tidptr,
						int xxx);

extern asmlinkage long (*original_sys_connect_fn)(int fd,
						  struct sockaddr __user *uservaddr,
						  int addrlen);

extern asmlinkage long (*original_sys_open_fn)(const char __user *filename,
					       int flags,
					       umode_t mode);

extern asmlinkage long (*original_sys_close_fn)(struct files_struct *files ,unsigned fd);

extern asmlinkage long (*original_sys_rename_fn)(int olddfd, 
						 const char __user *oldname,
						 int newdfd,
						 const char __user *newname,
						 unsigned int flags);

extern asmlinkage long (*original_sys_unlink_fn)(int dfd, const char __user *pathname);

extern asmlinkage long (*original_sys_fchmodat_fn)(int dfd, 
						   const char __user *filename,
						   unsigned int lookup_flags,
						   struct path *path);

extern asmlinkage long (*original_sys_group_exit_fn)(int error_code);

extern asmlinkage long (*original_sys_truncate_fn)(const char __user *path, long length);

extern asmlinkage long (*original_sys_ftruncate_fn)(unsigned int fd, unsigned long length);

extern asmlinkage long (*original_sys_ptrace_fn)(long request, 
						 long pid, 
						 unsigned long addr,
						 unsigned long data);





extern asmlinkage long (*pfn_new_sys_execve)(const char __user * filename,
					     const char __user * const __user * argv,
					     const char __user * const __user * envp);

extern asmlinkage long (*pfn_new_sys_read)(unsigned int fd,
					   char __user* buf,
					   size_t count);

extern asmlinkage long (*pfn_new_sys_write)(unsigned int fd,
					    const char __user *buf,
					    size_t count);

extern asmlinkage long (*pfn_new_sys_connect)(int fd,
					      struct sockaddr __user* uservaddr,
					      int addrlen); 

extern asmlinkage long (*pfn_new_sys_open)(const char __user *filename,
					   int flags, 
					   umode_t mode);

extern asmlinkage long (*pfn_new_sys_close)(unsigned int fd);
extern asmlinkage long (*pfn_new_sys_rename)(const char __user *oldname,
					     const char __user *newname);

extern asmlinkage long (*pfn_new_sys_unlink)(const char __user *pathname);

extern asmlinkage long (*pfn_new_sys_fchmodat)(int dfd, 
					       const char __user *filename,
					       umode_t mode);

extern asmlinkage long (*pfn_new_sys_exit_group)(int error_code);

extern asmlinkage long (*pfn_new_sys_truncate)(const char __user *path,
					       long length);

extern asmlinkage long (*pfn_new_sys_ftruncate)(unsigned int fd,
						unsigned long length);

extern asmlinkage long (*pfn_new_sys_ptrace)(long request, 
					     long pid, 
					     unsigned long addr,
					     unsigned long data);

extern asmlinkage long (*pfn_new_sys_clone)(unsigned long chiled_stack, 
					    unsigned long flags,
					    int __user *child_tidptr,
					    int __user *parent_tidptr,
					    int xxx);

extern asmlinkage long (*pfn_new_sys_fork)(void);

extern asmlinkage long (*pfn_new_sys_ptrace)(long request, 
					     long pid, 
					     unsigned long addr,
					     unsigned long data);





static LIST_HEAD(sct_entry_list);
struct sct_entry* sct_entry_vector[ __NR_syscall_max ];
volatile unsigned char g_status = 0;


/*
   for each system call we patch we create an entry 
*/

static inline __attribute__((always_inline)) 
int create_patch_entry(const int syscall_num) {

	struct sct_entry *entry = NULL;

	entry = (struct sct_entry*)vmalloc(sizeof(struct sct_entry));
	if ( IS_ERR_OR_NULL(entry) ) {	

		error("memory allocation error. ");
		return (-ERROR);		
	}

	memset(entry, 0, sizeof(struct sct_entry));

	entry->s_lock = __SPIN_LOCK_UNLOCKED(entry->s_lock);
	entry->syscall_num = syscall_num;	
	list_add(&(entry->list), &sct_entry_list);
	sct_entry_vector[syscall_num] = entry;


	return (SUCCESS);
}


/*
  we wait here for all kernel control paths on a system call will terminate
 */
static inline __attribute__((always_inline)) 
void wait_on_patch_entry_counter(const int syscall_num) {

	struct sct_entry *entry = NULL;

	entry = sct_entry_vector[syscall_num];
	if (entry) {
		while (!__sync_bool_compare_and_swap(&(entry->syscall_counter), 0, 0));
        }
}


static int patch_syscall_table(struct gl_region regions[]) {


	int ret = SUCCESS;
	unsigned long *sys_call_table = NULL;
	unsigned long orig_stub_addr = 0, orig_call_addr = 0;

	if(!(regions[0].writeable)) { 
		return (-ERROR);
	}


	sys_call_table = regions[0].writeable;

/*
  For the range of kernel versions between 3.10 to 4.17 the folowing system calles :
  execve, fork and clone, have a stub inside their offset in system call table
  we need to address this with disassembler instead of overriting the entry 
  relative offset
*/

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0) && LINUX_VERSION_CODE <= KERNEL_VERSION(4,17,0))

	ret = create_patch_entry( __NR_execve );
	ASSERT_RETURN_VALUE(ret, (-ERROR))

	orig_stub_addr = sys_call_table[ __NR_execve ];

	ret = mem_patch_relative_call(orig_stub_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_execve, 
				      &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_execve_fn = (void*) orig_call_addr;
	}
        
	debug("[ %s ] syscall __NR_execve patched. orig address: [ %p ] "\
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_execve_fn,
	      (void*)pfn_new_sys_execve);

#if 0//eyal
	orig_stub_addr = 0;
	ret = create_patch_entry( __NR_fork );
	ASSERT_RETURN_VALUE(ret, (-ERROR))

	orig_stub_addr = sys_call_table[ __NR_fork ];

	ret = mem_patch_relative_call(orig_stub_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_fork, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
		original_sys_fork_fn = (void*) orig_call_addr;
	}


	debug("[ %s ] syscall __NR_fork patched. orig address: [ %p ] " \
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_fork_fn,
	      (void*)pfn_new_sys_fork);

	orig_stub_addr = 0;
	ret = create_patch_entry( __NR_clone );
	ASSERT_RETURN_VALUE(ret, (-ERROR))

	orig_stub_addr = sys_call_table[ __NR_clone ];

	ret = mem_patch_relative_call(orig_stub_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_clone, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
              original_sys_clone_fn = (void*) orig_call_addr;
	}

	debug("[ %s ] syscall __NR_clone patched. orig address: [ %p ] " \
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_clone_fn,
	      (void*)pfn_new_sys_clone);

#endif//eyal

#else


#endif 



#if 0//eyal
	ret = create_patch_entry( __NR_read );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_read_fn = (cast_read)sys_call_table[ __NR_read ];
	sys_call_table[ __NR_read ] = (long unsigned int) pfn_new_sys_read;
	debug("[ %s ] syscall __NR_read patched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_read_fn,
	      (void*)pfn_new_sys_read);

	ret = create_patch_entry( __NR_write );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_write_fn = (cast_write)sys_call_table[ __NR_write ];
	sys_call_table[ __NR_write ] = (long unsigned int) pfn_new_sys_write;
	debug("[ %s ] syscall __NR_write patched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_write_fn,
	      (void*)pfn_new_sys_write);



	ret = create_patch_entry( __NR_connect );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_connect_fn = (cast_connect)sys_call_table[ __NR_connect ];
	sys_call_table[ __NR_connect ] = (long unsigned int) pfn_new_sys_connect;
	debug("[ %s ] syscall __NR_connect patched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_connect_fn,
	      (void*)pfn_new_sys_connect);

	ret = create_patch_entry( __NR_open );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_open_fn = (cast_open)sys_call_table[ __NR_open ];
	sys_call_table[ __NR_open ] = (long unsigned int)pfn_new_sys_open;
	debug("[ %s ] syscall __NR_open patched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_open_fn,
	      (void*)pfn_new_sys_open);
#endif//eyal
#if 0//eyal
	ret = create_patch_entry( __NR_close );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_close_fn = (cast_close)sys_call_table[ __NR_close ];
	sys_call_table[ __NR_close ] = (long unsigned int)pfn_new_sys_close;
	debug("[ %s ] syscall __NR_close patched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_close_fn,
	      (void*)pfn_new_sys_close);


	ret = create_patch_entry( __NR_rename );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_rename_fn = (cast_rename)sys_call_table[ __NR_rename ];
	sys_call_table[ __NR_rename ] = (long unsigned int)pfn_new_sys_rename;
	debug("[ %s ] syscall __NR_rename patched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_rename_fn,
	      (void*)pfn_new_sys_rename);


	ret = create_patch_entry( __NR_unlink );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_unlink_fn = (cast_unlink)sys_call_table[ __NR_unlink ];
	sys_call_table[ __NR_unlink ] = (long unsigned int)pfn_new_sys_unlink;
	debug("[ %s ] syscall __NR_unlink patched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_unlink_fn,
	      (void*)pfn_new_sys_unlink);


	ret = create_patch_entry( __NR_fchmodat );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_fchmodat_fn = (cast_fchmodat)sys_call_table[ __NR_fchmodat ];
	sys_call_table[ __NR_fchmodat ] = (long unsigned int)pfn_new_sys_fchmodat;
	debug("[ %s ] syscall __NR_fchmodat patched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_fchmodat_fn,
	      (void*)pfn_new_sys_fchmodat);


	ret = create_patch_entry( __NR_exit_group );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_group_exit_fn = (cast_exit_group)sys_call_table[ __NR_exit_group ];
	sys_call_table[ __NR_exit_group ] = (long unsigned int)pfn_new_sys_exit_group;
	debug("[ %s ] syscall __NR_exit_group patched. orig address: [ %p ] "\
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_group_exit_fn,
	      (void*)pfn_new_sys_exit_group);


	ret = create_patch_entry( __NR_truncate );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_truncate_fn = (cast_truncate)sys_call_table[ __NR_truncate ];
	sys_call_table[ __NR_truncate ] = (long unsigned int)pfn_new_sys_truncate;
	debug("[ %s ] syscall __NR_truncate patched. orig address: [ %p ] "\
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_truncate_fn,
	      (void*)pfn_new_sys_truncate);



	ret = create_patch_entry( __NR_ftruncate );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_ftruncate_fn = (cast_ftruncate)sys_call_table[ __NR_ftruncate ];
	sys_call_table[ __NR_ftruncate ] = (long unsigned int)pfn_new_sys_ftruncate;
	debug("[ %s ] syscall __NR_ftruncate patched. orig address: [ %p ] "\
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_ftruncate_fn,
	      (void*)pfn_new_sys_ftruncate);



	ret = create_patch_entry( __NR_ptrace );
	ASSERT_RETURN_VALUE(ret, (-ERROR))
	original_sys_ptrace_fn = (cast_ptrace)sys_call_table[ __NR_ptrace ];
	sys_call_table[ __NR_ptrace ] = (long unsigned int)pfn_new_sys_ptrace;
	debug("[ %s ] syscall __NR_ptrace patched. orig address: [ %p ] "\
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_ptrace_fn,
	      (void*)pfn_new_sys_ptrace);


#endif//eyal


	info("[ %s ]  patched system call table . ", MODULE_NAME);

	return 0;
}


static int unpatch_syscall_table(struct gl_region regions[]) {


	unsigned long* sys_call_table = NULL;
	unsigned long orig_stub_addr = 0;

	if(!(regions[0].writeable)) {
		return (-ERROR);
	}

	sys_call_table = regions[0].writeable;


/*
  For the range of kernel versions between 3.10 to 4.17 the folowing system calles :
  execve, fork and clone, have a stub inside their offset in system call table
  we need to address this with disassembler instead of overriting the entry 
  relative offset
*/

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0) && LINUX_VERSION_CODE <= KERNEL_VERSION(4,17,0))

	
	
	debug("[ %s ] syscall __NR_execve unpatched. orig address: [ %p ] " \
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_execve ],
	      (void*)original_sys_execve_fn);

	wait_on_patch_entry_counter( __NR_execve );

	orig_stub_addr = sys_call_table[ __NR_execve ];

	mem_patch_relative_call(orig_stub_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_execve_fn, 
				NULL);


#if 0//eyal

	debug("[ %s ] syscall  __NR_fork unpatched. orig address: [ %p ] " \
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)((unsigned long*)(sys_call_table))[ __NR_fork ],
	      (void*)original_sys_fork_fn);



	orig_stub_addr = 0;
	wait_on_patch_entry_counter( __NR_fork );
	orig_stub_addr = sys_call_table[ __NR_fork ];

	mem_patch_relative_call(orig_stub_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_fork_fn, 
				NULL);


	debug("[ %s ] syscall  __NR_fork unpatched. orig address: [ %p ] " \
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_clone ],
	      (void*)original_sys_fork_fn);


	orig_stub_addr = 0;
	wait_on_patch_entry_counter( __NR_clone );
	orig_stub_addr = sys_call_table[ __NR_clone ];

	mem_patch_relative_call(orig_stub_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_clone_fn, 
				NULL);

#endif//eyal

#else


#endif


#if 0//eyal
	debug("[ %s ] syscall __NR_read unpatched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_read ],
	      (void*)original_sys_read_fn);
	
	wait_on_patch_entry_counter( __NR_read );
	sys_call_table[ __NR_read ] = (unsigned long int)original_sys_read_fn;


	debug("[ %s ] syscall __NR_write unpatched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_write ],
	      (void*)original_sys_write_fn);

	wait_on_patch_entry_counter( __NR_write );
	sys_call_table[ __NR_write ] = (unsigned long int)original_sys_write_fn; 

 

	debug("[ %s ] syscall __NR_connect unpatched. orig address: [ %p ] "\
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_connect ],
	      (void*)original_sys_connect_fn);

	wait_on_patch_entry_counter( __NR_connect );
	sys_call_table[ __NR_connect ] = (unsigned long int)original_sys_connect_fn;



	debug("[ %s ] syscall __NR_open unpatched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_open ],
	      (void*)original_sys_open_fn);

	wait_on_patch_entry_counter( __NR_open );
	sys_call_table[ __NR_open ] = (unsigned long int)original_sys_open_fn;
#endif//eyal
#if 0//eyal
	debug("[ %s ] syscall __NR_close unpatched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_close ],
	      (void*)original_sys_close_fn);

	wait_on_patch_entry_counter( __NR_close );
	sys_call_table[ __NR_close ] = (unsigned long int)original_sys_close_fn;


	debug("[ %s ] syscall __NR_rename unpatched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_rename ],
	      (void*)original_sys_rename_fn);

	wait_on_patch_entry_counter( __NR_rename );
	sys_call_table[ __NR_rename ] = (unsigned long int)original_sys_rename_fn;


	debug("[ %s ] syscall __NR_unlink unpatched. orig address: [ %p ] new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_unlink ],
	      (void*)original_sys_unlink_fn);

	wait_on_patch_entry_counter( __NR_unlink );
	sys_call_table[ __NR_unlink ] = (unsigned long int)original_sys_unlink_fn;



	debug("[ %s ] syscall __NR_fchmodat unpatched. orig address: [ %p ] "\
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_fchmodat ],
	      (void*)original_sys_fchmodat_fn);

	wait_on_patch_entry_counter( __NR_fchmodat );
	sys_call_table[ __NR_fchmodat ] = (unsigned long int)original_sys_fchmodat_fn;



	debug("[ %s ] syscall __NR_exit_group unpatched. orig address: [ %p ] "\
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_exit_group ],
	      (void*)original_sys_group_exit_fn);

	wait_on_patch_entry_counter( __NR_exit_group );
	sys_call_table[ __NR_exit_group ] = (unsigned long int)original_sys_group_exit_fn;



	debug("[ %s ] syscall __NR_truncate unpatched. orig address: [ %p ] "\
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_truncate ],
	      (void*)original_sys_truncate_fn);

	wait_on_patch_entry_counter( __NR_truncate );
	sys_call_table[ __NR_truncate ] = (unsigned long int)original_sys_truncate_fn;



	debug("[ %s ] syscall __NR_ftruncate unpatched. orig address: [ %p ] "\
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_ftruncate ],
	      (void*)original_sys_ftruncate_fn);

	wait_on_patch_entry_counter( __NR_ftruncate );
	sys_call_table[ __NR_ftruncate ] = (unsigned long int)original_sys_ftruncate_fn;



	debug("[ %s ] syscall __NR_ptrace unpatched. orig address: [ %p ] "\
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)sys_call_table[ __NR_ptrace ],
	      (void*)original_sys_ptrace_fn);

	wait_on_patch_entry_counter( __NR_ptrace );
	sys_call_table[ __NR_ptrace ] = (unsigned long int)original_sys_ptrace_fn;

#endif//eyal

	info("[ %s ]  unpach system call table success. ", MODULE_NAME);
        
        return (SUCCESS);
}



static void delete_patch_entry_list(void) {

	struct list_head *pos, *q;
	struct sct_entry *tmp;

	list_for_each_safe(pos, q, &sct_entry_list) {

		tmp = NULL;
		tmp = list_entry(pos, struct sct_entry, list);
		list_del(&tmp->list);
		vfree(tmp);

	}

	info("[ %s ]  %s()  sct_entry_list deleted.", MODULE_NAME, __func__);

}




int init_patch_systcall_table(void) {
 
	int ret = SUCCESS;
	unsigned long sys_call_table_addr = 0;
	struct gl_region sys_call_table_page;  


	ret = lookup_sys_call_table_addr(&sys_call_table_addr);
	if (SUCCESS != ret) {
		error("ERROR unable to find syscall table address "); 
		return ret;
	}

	memset(sct_entry_vector, 0, sizeof(struct sct_entry) * __NR_syscall_max);

	/* 
	   driver is up 
	*/
	__sync_bool_compare_and_swap(&g_status, g_status, 1);

	sys_call_table_page  = (struct gl_region) { 

		.source = (void*)sys_call_table_addr, 
		.length = 256 * sizeof(unsigned long) 

	};

	do_with_write_permissions(patch_syscall_table, &sys_call_table_page, 1);


	info("[ %s ] initilize patching for systcall table.", MODULE_NAME); 

	return ret;
}




int destroy_patched_systcall_table(void) {


	int ret = SUCCESS;
	unsigned long sys_call_table_addr = 0;
	struct gl_region sys_call_table_page;  

	ret = lookup_sys_call_table_addr(&sys_call_table_addr);
	if (SUCCESS != ret) {
		error("ERROR destroy_stub_systcall() unable to find syscall table address "); 
		return ret; 
	}

	/* 
	   driver is going down 
	*/
	__sync_bool_compare_and_swap(&g_status, g_status, 0);

	sys_call_table_page  = (struct gl_region) { 
		.source = (void*)sys_call_table_addr, 
		.length = 256 * sizeof(unsigned long) 
	};


	do_with_write_permissions(unpatch_syscall_table, &sys_call_table_page, 1);

	delete_patch_entry_list();

	info("[ %s ] destroy patched systcall table.", MODULE_NAME); 

	return ret;
}
