#include "../os_interceptor_data_type.h"
#include "systemcall_interceptor.h"
#include "../policy/policy.h"



/*
   system call patch handler to overrun systemcall table with our new system calls 
*/



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

extern asmlinkage long (*original_sys_open_fn)(int dfd,
					       const char __user *filename,
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





static LIST_HEAD(sct_entry_list);
struct sct_entry* sct_entry_vector[__NR_syscall_max];
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
  we wait here that all calls on a system call which are stack segments
  will terminate, once counter is zero we free to unpatch a system call   
 */
static inline __attribute__((always_inline)) 
void wait_on_patch_entry_counter(const int syscall_num) {

	struct sct_entry *entry = NULL;

	entry = sct_entry_vector[syscall_num];
	if (entry) {
		while (!__sync_bool_compare_and_swap(&(entry->syscall_counter), 0, 0));
        }
}



/*
  For the range of kernel versions between 3.10 to 4.17 the folowing system calles :
  execve, fork and clone, have a stub inside their offset in system call table
  we need to address this with disassembler instead of overriting the entry 
  relative offset
*/

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0) && LINUX_VERSION_CODE <= KERNEL_VERSION(4,17,0))

static int patch_sys_execve(unsigned long sys_call_table_addr) {

        int ret = SUCCESS;

	unsigned long orig_stub_execve_addr = 0, orig_call_addr = 0;

	ret = create_patch_entry( __NR_execve );
	ASSERT_RETURN_VALUE(ret, (-ERROR))

	orig_stub_execve_addr = ((unsigned long*)(sys_call_table_addr))[ __NR_execve ];

	ret = mem_patch_relative_call(orig_stub_execve_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_execve, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
		original_sys_execve_fn = (void*) orig_call_addr;
	}
        
	debug("[ %s ] syscall __NR_execve patched. orig address: [ %p ] " \
	      "new address: [ %p ]",
	      MODULE_NAME,
	      (void*)original_sys_execve_fn,
	      (void*)pfn_new_sys_execve);


	return ret;


}


#else  /*
	 all versions above 4.17, the system calles execve, fork and clone can be patched
	 by modifying the relative offsets directly
	*/





#endif

static int patch_sys_read(unsigned long sys_call_table_addr) {


        int ret = SUCCESS;
	unsigned long orig_stub_read_addr, orig_call_addr;

	orig_stub_read_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_read];

	ret = mem_patch_relative_call(orig_stub_read_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) pfn_new_sys_read, &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_read_fn = (void*) orig_call_addr;
	}


        debug("[ %s ]  system call table address __NR_read patched .", MODULE_NAME);


	return ret;
}


static int patch_sys_write(unsigned long sys_call_table_addr) {
    
        int ret = SUCCESS;
	unsigned long orig_stub_write_addr, orig_call_addr;

	orig_stub_write_addr = ((unsigned long *) (sys_call_table_addr))[__NR_write];

	ret = mem_patch_relative_call(orig_stub_write_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_write, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
		original_sys_write_fn = (void*) orig_call_addr;
	}

        debug("[ %s ]  system call table address __NR_write patched .", MODULE_NAME);


	return ret;
}


static int patch_sys_fork(unsigned long sys_call_table_addr) {


        int ret = SUCCESS;
	unsigned long orig_stub_fork_addr ,orig_call_addr;

	orig_stub_fork_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_fork];

	ret = mem_patch_relative_call(orig_stub_fork_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_fork, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
		original_sys_fork_fn = (void*) orig_call_addr;
	}

        debug("[ %s ]  system call table address __NR_fork patched .", MODULE_NAME);



	return ret;

}


static int patch_sys_clone(unsigned long sys_call_table_addr) {


        int ret = SUCCESS;
	unsigned long orig_stub_clone_addr, orig_call_addr;

	orig_stub_clone_addr = ((unsigned long *) (sys_call_table_addr))[__NR_clone];

	ret = mem_patch_relative_call(orig_stub_clone_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_clone, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
              original_sys_clone_fn = (void*) orig_call_addr;
	}

        debug("[ %s ]  system call table address __NR_clone patched .", MODULE_NAME);


	return ret;
}


static int patch_sys_connect(unsigned long sys_call_table_addr) {

        int ret = SUCCESS;
	unsigned long orig_stub_connect_addr, orig_call_addr;

	orig_stub_connect_addr = ((unsigned long *) (sys_call_table_addr))[__NR_connect];

	ret = mem_patch_relative_call(orig_stub_connect_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_connect, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
              original_sys_connect_fn = (void*) orig_call_addr;
	}

        debug("[ %s ]  system call table address __NR_connect patched .", MODULE_NAME);


	return ret;
}


static int patch_sys_open(unsigned long sys_call_table_addr) {


        int ret = SUCCESS;
	unsigned long orig_stub_open_addr, orig_call_addr;

	orig_stub_open_addr = ((unsigned long *) (sys_call_table_addr))[__NR_open];

	ret = mem_patch_relative_call(orig_stub_open_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_open, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
		original_sys_open_fn = (void*) orig_call_addr;
	}

        debug("[ %s ]  system call table address __NR_open patched .", MODULE_NAME);


	return ret;
}


static int patch_sys_close(unsigned long sys_call_table_addr) {


        int ret = SUCCESS;
	unsigned long orig_stub_close_addr, orig_call_addr;

	orig_stub_close_addr = ((unsigned long *) (sys_call_table_addr))[__NR_close];

	ret = mem_patch_relative_call(orig_stub_close_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_close, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
		original_sys_close_fn = (void*) orig_call_addr;
	}


        debug("[ %s ]  system call table address __NR_close patched .", MODULE_NAME);

	
	return ret;
}

static int patch_sys_rename(unsigned long sys_call_table_addr) {


        int ret = SUCCESS;
	unsigned long orig_stub_rename_addr, orig_call_addr;

	orig_stub_rename_addr = ((unsigned long *) (sys_call_table_addr))[__NR_rename];

	ret = mem_patch_relative_call(orig_stub_rename_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_rename, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
		original_sys_rename_fn = (void*) orig_call_addr;
	}

        debug("[ %s ]  system call table address __NR_rename patched .", MODULE_NAME);


	return ret;
}

static int patch_sys_unlink(unsigned long sys_call_table_addr) {

        int ret = SUCCESS;
	unsigned long orig_stub_unlink_addr, orig_call_addr;

	orig_stub_unlink_addr = ((unsigned long *) (sys_call_table_addr))[__NR_unlink];

	ret = mem_patch_relative_call(orig_stub_unlink_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_unlink, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
		original_sys_unlink_fn = (void*) orig_call_addr;
	}


        debug("[ %s ]  system call table address __NR_unlink patched .", MODULE_NAME);


	return ret;
}


static int patch_sys_fchmodat(unsigned long sys_call_table_addr) {

        int ret = SUCCESS;
	unsigned long orig_stub_fchmodat_addr, orig_call_addr;

	orig_stub_fchmodat_addr = ((unsigned long *) (sys_call_table_addr))[__NR_fchmodat];

	ret = mem_patch_relative_call(orig_stub_fchmodat_addr,
			              MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_fchmodat, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
		original_sys_fchmodat_fn = (void*) orig_call_addr;
	}


        debug("[ %s ]  system call table address __NR_fchmodat patched .", MODULE_NAME);


	return ret;
}


static int patch_sys_group_exit(unsigned long sys_call_table_addr) {


	int ret = SUCCESS;
	unsigned long orig_stub_group_exit_addr, orig_call_addr;
	
	orig_stub_group_exit_addr = ((unsigned long *) (sys_call_table_addr))[__NR_exit_group];

	ret = mem_patch_relative_call(orig_stub_group_exit_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_exit_group, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
		original_sys_group_exit_fn = (void*) orig_call_addr;
	}


	debug("[ %s ]  system call table address __NR_exit_group patched .", MODULE_NAME);


	return ret; 
}

static int patch_sys_truncate(unsigned long sys_call_table_addr) {

	int ret = SUCCESS;
	unsigned long orig_stub_truncate_addr, orig_call_addr;
	
	orig_stub_truncate_addr = ((unsigned long *) (sys_call_table_addr))[__NR_truncate];

	ret = mem_patch_relative_call(orig_stub_truncate_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_truncate, 
				      &orig_call_addr);

       if (ret == SUCCESS ) {
             original_sys_truncate_fn = (void*) orig_call_addr;
       }

       debug("[ %s ]  system call table address __NR_truncate patched .", MODULE_NAME);

       return ret; 
}

static int patch_sys_ftruncate(unsigned long sys_call_table_addr) {


	int ret = SUCCESS;
	unsigned long orig_stub_ftruncate_addr, orig_call_addr;

	orig_stub_ftruncate_addr = ((unsigned long *) (sys_call_table_addr))[__NR_ftruncate];

	ret = mem_patch_relative_call(orig_stub_ftruncate_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_ftruncate, 
				      &orig_call_addr);

	if (ret == SUCCESS ) {
		original_sys_ftruncate_fn = (void*) orig_call_addr;
	}


	debug("[ %s ]  system call table address __NR_ftruncate patched .", MODULE_NAME);


	return ret; 
}

/*################################################################################################*/
/* 
   unpatch systenm calles
*/

static void unpatch_sys_execve(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_execve_addr;

	orig_stub_execve_addr = ((unsigned long *) (sys_call_table_addr))[__NR_execve];

	mem_patch_relative_call(orig_stub_execve_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_execve_fn, 
				NULL);
	
        debug("[ %s ]  system call table address __NR_execve unpatched .", MODULE_NAME);
}


static void unpatch_sys_read(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_read_addr;

	orig_stub_read_addr = ((unsigned long *) (sys_call_table_addr))[__NR_read];

	mem_patch_relative_call(orig_stub_read_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_read_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_read unpatched .", MODULE_NAME);
}


static void unpatch_sys_write(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_write_addr;

	/* Get stub_execve address */
	orig_stub_write_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_write];

	mem_patch_relative_call(orig_stub_write_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_write_fn, NULL);
        debug("[ %s ]  system call table address __NR_write unpatched .", MODULE_NAME);
}


static void unpatch_sys_fork(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_fork_addr;

	orig_stub_fork_addr = ((unsigned long *) (sys_call_table_addr))[__NR_fork];

	mem_patch_relative_call(orig_stub_fork_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_fork_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_fork unpatched .", MODULE_NAME);
}

static void unpatch_sys_clone(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_clone_addr;

	orig_stub_clone_addr = ((unsigned long *) (sys_call_table_addr))[__NR_clone];

	mem_patch_relative_call(orig_stub_clone_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_clone_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_clone unpatched .", MODULE_NAME);
}


static void unpatch_sys_connect(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_connect_addr;

	orig_stub_connect_addr = ((unsigned long *) (sys_call_table_addr))[__NR_connect];

	mem_patch_relative_call(orig_stub_connect_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_connect_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_connect unpatched .", MODULE_NAME);
}


static void unpatch_sys_open(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_open_addr;

	orig_stub_open_addr = ((unsigned long *) (sys_call_table_addr))[__NR_open];

	mem_patch_relative_call(orig_stub_open_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_open_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_open unpatched .", MODULE_NAME);
}


static void unpatch_sys_close(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_close_addr;

	orig_stub_close_addr = ((unsigned long *) (sys_call_table_addr))[__NR_close];

	mem_patch_relative_call(orig_stub_close_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_close_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_close unpatched .", MODULE_NAME);
}


static void unpatch_sys_rename(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_rename_addr;

	orig_stub_rename_addr = ((unsigned long *) (sys_call_table_addr))[__NR_rename];

	mem_patch_relative_call(orig_stub_rename_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_rename_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_rename unpatched .", MODULE_NAME);
}


static void unpatch_sys_unlink(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_unlink_addr;

	orig_stub_unlink_addr = ((unsigned long *) (sys_call_table_addr))[__NR_unlink];

	mem_patch_relative_call(orig_stub_unlink_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_unlink_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_unlink unpatched .", MODULE_NAME);
}

static void unpatch_sys_fchmodat(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_fchmodat_addr;

	orig_stub_fchmodat_addr = ((unsigned long *) (sys_call_table_addr))[__NR_fchmodat];

	mem_patch_relative_call(orig_stub_fchmodat_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_fchmodat_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_fchmodat unpatched .", MODULE_NAME);
}


static void unpatch_sys_group_exit(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_exit_group_addr;

	orig_stub_exit_group_addr = ((unsigned long *) (sys_call_table_addr))[__NR_exit_group];

	mem_patch_relative_call(orig_stub_exit_group_addr,
				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_group_exit_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_exit_group unpatched .", MODULE_NAME);
}

static void unpatch_sys_truncate(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_truncate_addr;

	orig_stub_truncate_addr = ((unsigned long *) (sys_call_table_addr))[__NR_truncate];

	mem_patch_relative_call(orig_stub_truncate_addr,
 				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_truncate_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_truncate unpatched .", MODULE_NAME);
}


static void unpatch_sys_ftruncate(unsigned long sys_call_table_addr) {

	unsigned long orig_stub_ftruncate_addr;
	
	orig_stub_ftruncate_addr = ((unsigned long *) (sys_call_table_addr))[__NR_ftruncate];

	mem_patch_relative_call(orig_stub_ftruncate_addr,
 				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_ftruncate_fn, 
				NULL);

        debug("[ %s ]  system call table address __NR_ftruncate unpatched .", MODULE_NAME);
}









int init_patch_systcall_table(void) {
 
	int obtain_sys_call_table_addr(unsigned long *sys_call_table_addr);
	int ret = SUCCESS, call_rv;
	unsigned long sys_call_table_addr;


	call_rv = obtain_sys_call_table_addr(&sys_call_table_addr);
	if (SUCCESS != call_rv) {

		ret = call_rv;
		error("ERROR unable to find syscall table address "); 
		
		return ret;
	}


	patch_sys_group_exit(sys_call_table_addr);
	patch_sys_clone(sys_call_table_addr);
	patch_sys_execve(sys_call_table_addr);                                 
	patch_sys_close(sys_call_table_addr);  
	patch_sys_open(sys_call_table_addr);  
	patch_sys_read(sys_call_table_addr);  
	patch_sys_write(sys_call_table_addr);
	patch_sys_fork(sys_call_table_addr);
	patch_sys_connect(sys_call_table_addr);  
	patch_sys_rename(sys_call_table_addr);  
	patch_sys_unlink(sys_call_table_addr);
	patch_sys_fchmodat(sys_call_table_addr);
	patch_sys_truncate(sys_call_table_addr);
	patch_sys_ftruncate(sys_call_table_addr);

	info("[ %s ] initilize patching for systcall table.", MODULE_NAME); 

	return ret;
}




int destroy_patched_systcall_table(void) {


	int obtain_sys_call_table_addr(unsigned long *sys_call_table_addr);
	int ret = SUCCESS, call_rv;
	unsigned long sys_call_table_addr;


	call_rv = obtain_sys_call_table_addr(&sys_call_table_addr);
	if (SUCCESS != call_rv) {

		ret = call_rv;
		error("ERROR destroy_stub_systcall() unable to find syscall table address "); 
		return ret; 
	}


	unpatch_sys_group_exit(sys_call_table_addr);  
	unpatch_sys_clone(sys_call_table_addr);
	unpatch_sys_execve(sys_call_table_addr);
	unpatch_sys_close(sys_call_table_addr);
	unpatch_sys_open(sys_call_table_addr);
	unpatch_sys_read(sys_call_table_addr);
	unpatch_sys_write(sys_call_table_addr);
	unpatch_sys_fork(sys_call_table_addr);
	unpatch_sys_connect(sys_call_table_addr);  
	unpatch_sys_rename(sys_call_table_addr);
	unpatch_sys_unlink(sys_call_table_addr);
	unpatch_sys_fchmodat(sys_call_table_addr);
	unpatch_sys_truncate(sys_call_table_addr);
	unpatch_sys_ftruncate(sys_call_table_addr);

	info("[ %s ] destroy patched systcall table.", MODULE_NAME); 



	return ret;
}
