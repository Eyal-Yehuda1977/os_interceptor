#include "../kcontroller_data_type.h"
/*
   AUTHOR : eyal yehuda 
   system call stub handler to overrun systemcall table with our new system calls 
   by parssing the stub region and searching for assembly instruction E8 "call"
   after that the memory get patched with our new system call   
*/

#include "../bpm/bpm.h"

extern int mem_patch_relative_call(unsigned long mem_addr, 
                                   size_t block_size, 
				   unsigned long new_call_addr, 
                                   unsigned long * orig_call_addr);

extern asmlinkage long (*orig_sys_execve_fn)(const char __user * filename,
  				             const char __user * const __user * argv,
  				             const char __user * const __user * envp);

extern asmlinkage long (*original_sys_read_fn)(unsigned int fd
                                              ,char __user* buf
                                              ,size_t count);

extern asmlinkage long (*original_sys_write_fn)(unsigned int fd
                                               ,const char __user *buf
                                               ,size_t count);

extern asmlinkage long (*original_sys_fork_fn)(void);

extern asmlinkage long (*original_sys_clone_fn)(unsigned long chiled_stack
                                               ,unsigned long flags
                                               ,int __user* child_tidptr
                                               ,int __user* parent_tidptr
                                               ,int xxx);

extern asmlinkage long (*original_sys_connect_fn)(int fd
                                                 ,struct sockaddr __user* uservaddr
                                                 ,int addrlen);

extern asmlinkage long (*original_sys_open_fn)(int dfd
                                              ,const char __user *filename
                                              ,int flags
                                              ,umode_t mode);

extern asmlinkage long (*original_sys_close_fn)(struct files_struct *files
                                               ,unsigned fd);

extern asmlinkage long (*original_sys_rename_fn)(int olddfd
                                                ,const char __user *oldname
                                                ,int newdfd
                                                ,const char __user *newname
                                                ,unsigned int flags);

extern asmlinkage long (*original_sys_unlink_fn)(int dfd
                                                ,const char __user *pathname);

extern asmlinkage long (*original_sys_fchmodat_fn)(int dfd
                                                  ,const char __user * filename
                                                  ,unsigned int lookup_flags
                                                  ,struct path* path);

extern asmlinkage long (*original_sys_group_exit_fn)(int error_code);

extern asmlinkage long (*original_sys_truncate_fn)(const char __user *path
                                                  ,long length);

extern asmlinkage long (*original_sys_ftruncate_fn)(unsigned int fd
                                                   ,unsigned long length);





/*################################################################################################*/
/* hook system calls  */

static int hook_sys_execve(unsigned long sys_call_table_addr) 
{
        extern asmlinkage long (*pfn_new_sys_execve)(const char __user * filename,
  				         const char __user * const __user * argv,
  				         const char __user * const __user * envp);
        int ret = SUCCESS;
	unsigned long orig_stub_execve_addr;
	unsigned long orig_call_addr;

	orig_stub_execve_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_execve];

	ret = mem_patch_relative_call(orig_stub_execve_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) pfn_new_sys_execve, &orig_call_addr);
	if (ret == SUCCESS ) {
              orig_sys_execve_fn = (void*) orig_call_addr;
	}
        
        debug("[ %s ]  system call table address __NR_execve hooked .", MODULE_NAME);
   return ret;
}


static int hook_sys_read(unsigned long sys_call_table_addr) 
{
        extern asmlinkage long (*pfn_new_sys_read)(unsigned int fd
                                                  ,char __user* buf
                                                  ,size_t count);

        int ret = SUCCESS;
	unsigned long orig_stub_read_addr;
	unsigned long orig_call_addr;

	orig_stub_read_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_read];

	ret = mem_patch_relative_call(orig_stub_read_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) pfn_new_sys_read, &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_read_fn = (void*) orig_call_addr;
	}
        debug("[ %s ]  system call table address __NR_read hooked .", MODULE_NAME);
   return ret;
}


static int hook_sys_write(unsigned long sys_call_table_addr) 
{
    
        extern asmlinkage long (*pfn_new_sys_write)(unsigned int fd
                                                   ,const char __user *buf
                                                   ,size_t count);

        int ret = SUCCESS;
	unsigned long orig_stub_write_addr;
	unsigned long orig_call_addr;

	orig_stub_write_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_write];

	ret = mem_patch_relative_call(orig_stub_write_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) pfn_new_sys_write, &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_write_fn = (void*) orig_call_addr;
	}
        debug("[ %s ]  system call table address __NR_write hooked .", MODULE_NAME);
   return ret;
}

static int hook_sys_fork(unsigned long sys_call_table_addr) 
{

        extern asmlinkage long (*pfn_new_sys_fork)(void);

        int ret = SUCCESS;
	unsigned long orig_stub_fork_addr;
	unsigned long orig_call_addr;

	orig_stub_fork_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_fork];

	ret = mem_patch_relative_call(orig_stub_fork_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) pfn_new_sys_fork, &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_fork_fn = (void*) orig_call_addr;
	}

        debug("[ %s ]  system call table address __NR_fork hooked .", MODULE_NAME);

   return ret;
}


static int hook_sys_clone(unsigned long sys_call_table_addr) 
{

        extern asmlinkage long (*pfn_new_sys_clone)(unsigned long chiled_stack, 
                                                    unsigned long flags,
                                                    int __user* child_tidptr,
                                                    int __user* parent_tidptr,
                                                    int xxx);

        int ret = SUCCESS;
	unsigned long orig_stub_clone_addr;
	unsigned long orig_call_addr;

	orig_stub_clone_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_clone];

	ret = mem_patch_relative_call(orig_stub_clone_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) pfn_new_sys_clone, &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_clone_fn = (void*) orig_call_addr;
	}

        debug("[ %s ]  system call table address __NR_clone hooked .", MODULE_NAME);

   return ret;
}


static int hook_sys_connect(unsigned long sys_call_table_addr) 
{

        extern asmlinkage long (*pfn_new_sys_connect)(int fd
                                                     ,struct sockaddr __user* uservaddr
                                                     ,int addrlen); 

        int ret = SUCCESS;
	unsigned long orig_stub_connect_addr;
	unsigned long orig_call_addr;

	orig_stub_connect_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_connect];

	ret = mem_patch_relative_call(orig_stub_connect_addr,
				      MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_connect, &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_connect_fn = (void*) orig_call_addr;
	}
        debug("[ %s ]  system call table address __NR_connect hooked .", MODULE_NAME);
   return ret;
}


static int hook_sys_open(unsigned long sys_call_table_addr) 
{

        extern asmlinkage long (*pfn_new_sys_open)(int dfd
                                                  ,const char __user *filename
                                                  ,int flags, umode_t mode);

        int ret = SUCCESS;
	unsigned long orig_stub_open_addr;
	unsigned long orig_call_addr;

	orig_stub_open_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_open];

	ret = mem_patch_relative_call(orig_stub_open_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) pfn_new_sys_open, &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_open_fn = (void*) orig_call_addr;
	}
        debug("[ %s ]  system call table address __NR_open hooked .", MODULE_NAME);

   return ret;
}


static int hook_sys_close(unsigned long sys_call_table_addr) 
{

        extern asmlinkage long (*pfn_new_sys_close)(struct files_struct *files
                                                    ,unsigned fd);

        int ret = SUCCESS;
	unsigned long orig_stub_close_addr;
	unsigned long orig_call_addr;

	orig_stub_close_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_close];

	ret = mem_patch_relative_call(orig_stub_close_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) pfn_new_sys_close, &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_close_fn = (void*) orig_call_addr;
	}
        debug("[ %s ]  system call table address __NR_close hooked .", MODULE_NAME);
   return ret;
}

static int hook_sys_rename(unsigned long sys_call_table_addr) 
{

        extern asmlinkage long (*pfn_new_sys_rename)(int olddfd 
                                                    ,const char __user *oldname
                                                    ,int newdfd
                                                    ,const char __user *newname
                                                    ,unsigned int flags);
        int ret = SUCCESS;
	unsigned long orig_stub_rename_addr;
	unsigned long orig_call_addr;

	orig_stub_rename_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_rename];

	ret = mem_patch_relative_call(orig_stub_rename_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) pfn_new_sys_rename, &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_rename_fn = (void*) orig_call_addr;
	}
        debug("[ %s ]  system call table address __NR_rename hooked .", MODULE_NAME);
   return ret;
}

static int hook_sys_unlink(unsigned long sys_call_table_addr) 
{

        extern asmlinkage long (*pfn_new_sys_unlink)(int dfd
                                                    ,const char __user *pathname);

        int ret = SUCCESS;
	unsigned long orig_stub_unlink_addr;
	unsigned long orig_call_addr;

	orig_stub_unlink_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_unlink];

	ret = mem_patch_relative_call(orig_stub_unlink_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) pfn_new_sys_unlink, &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_unlink_fn = (void*) orig_call_addr;
	}
        debug("[ %s ]  system call table address __NR_unlink hooked .", MODULE_NAME);
   return ret;
}

static int hook_sys_fchmodat(unsigned long sys_call_table_addr) 
{

        extern asmlinkage long (*pfn_new_sys_fchmodat)(int dfd
                                                      ,const char __user * filename
  				                      ,unsigned int lookup_flags
                                                      ,struct path* path);

        int ret = SUCCESS;
	unsigned long orig_stub_fchmodat_addr;
	unsigned long orig_call_addr;

	orig_stub_fchmodat_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_fchmodat];

	ret = mem_patch_relative_call(orig_stub_fchmodat_addr,
			              MAX_RELATIVE_CALL_OFFSET,
				      (unsigned long) pfn_new_sys_fchmodat, &orig_call_addr);
	if (ret == SUCCESS ) {
              original_sys_fchmodat_fn = (void*) orig_call_addr;
	}
        debug("[ %s ]  system call table address __NR_fchmodat hooked .", MODULE_NAME);
   return ret;
}


static int hook_sys_group_exit(unsigned long sys_call_table_addr)
{

       extern asmlinkage long (*pfn_new_sys_exit_group)(int error_code);

       int ret = SUCCESS;
       unsigned long orig_stub_group_exit_addr;
       unsigned long orig_call_addr;

       orig_stub_group_exit_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_exit_group];

       ret = mem_patch_relative_call(orig_stub_group_exit_addr,
				       MAX_RELATIVE_CALL_OFFSET,
				       (unsigned long) pfn_new_sys_exit_group, &orig_call_addr);
       if (ret == SUCCESS ) {
             original_sys_group_exit_fn = (void*) orig_call_addr;
       }
       debug("[ %s ]  system call table address __NR_exit_group hooked .", MODULE_NAME);

  return ret; 
}

static int hook_sys_truncate(unsigned long sys_call_table_addr)
{

       extern asmlinkage long (*pfn_new_sys_truncate)(const char __user *path
						     ,long length);

       int ret = SUCCESS;
       unsigned long orig_stub_truncate_addr;
       unsigned long orig_call_addr;

       orig_stub_truncate_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_truncate];

       ret = mem_patch_relative_call(orig_stub_truncate_addr,
				       MAX_RELATIVE_CALL_OFFSET,
				       (unsigned long) pfn_new_sys_truncate, &orig_call_addr);
       if (ret == SUCCESS ) {
             original_sys_truncate_fn = (void*) orig_call_addr;
       }
       debug("[ %s ]  system call table address __NR_truncate hooked .", MODULE_NAME);
  return ret; 
}

static int hook_sys_ftruncate(unsigned long sys_call_table_addr)
{

       extern asmlinkage long (*pfn_new_sys_ftruncate)(const char __user *path
						      ,long length);

       int ret = SUCCESS;
       unsigned long orig_stub_ftruncate_addr;
       unsigned long orig_call_addr;

       orig_stub_ftruncate_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_ftruncate];

       ret = mem_patch_relative_call(orig_stub_ftruncate_addr,
				     MAX_RELATIVE_CALL_OFFSET,
				     (unsigned long) pfn_new_sys_ftruncate, &orig_call_addr);
       if (ret == SUCCESS ) {
             original_sys_ftruncate_fn = (void*) orig_call_addr;
       }
       debug("[ %s ]  system call table address __NR_ftruncate hooked .", MODULE_NAME);

  return ret; 
}

/*################################################################################################*/
/* remove hooks  */

static void remove_hook_sys_execve(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_execve_addr;

	/* Get stub_execve address */
	orig_stub_execve_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_execve];

	mem_patch_relative_call(orig_stub_execve_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) orig_sys_execve_fn, NULL);
        debug("[ %s ]  system call table address __NR_execve restored .", MODULE_NAME);
}


static void remove_hook_sys_read(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_read_addr;

	/* Get stub_execve address */
	orig_stub_read_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_read];

	mem_patch_relative_call(orig_stub_read_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_read_fn, NULL);
        debug("[ %s ]  system call table address __NR_read restored .", MODULE_NAME);
}


static void remove_hook_sys_write(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_write_addr;

	/* Get stub_execve address */
	orig_stub_write_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_write];

	mem_patch_relative_call(orig_stub_write_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_write_fn, NULL);
        debug("[ %s ]  system call table address __NR_write restored .", MODULE_NAME);
}


static void remove_hook_sys_fork(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_fork_addr;

	/* Get stub_execve address */
	orig_stub_fork_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_fork];

	mem_patch_relative_call(orig_stub_fork_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_fork_fn, NULL);
        debug("[ %s ]  system call table address __NR_fork restored .", MODULE_NAME);
}

static void remove_hook_sys_clone(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_clone_addr;

	/* Get stub_execve address */
	orig_stub_clone_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_clone];

	mem_patch_relative_call(orig_stub_clone_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_clone_fn, NULL);
        debug("[ %s ]  system call table address __NR_clone restored .", MODULE_NAME);
}


static void remove_hook_sys_connect(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_connect_addr;

	/* Get stub_execve address */
	orig_stub_connect_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_connect];

	mem_patch_relative_call(orig_stub_connect_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_connect_fn, NULL);
        debug("[ %s ]  system call table address __NR_connect restored .", MODULE_NAME);
}


static void remove_hook_sys_open(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_open_addr;

	/* Get stub_execve address */
	orig_stub_open_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_open];

	mem_patch_relative_call(orig_stub_open_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_open_fn, NULL);
        debug("[ %s ]  system call table address __NR_open restored .", MODULE_NAME);
}


static void remove_hook_sys_close(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_close_addr;

	/* Get stub_execve address */
	orig_stub_close_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_close];

	mem_patch_relative_call(orig_stub_close_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_close_fn, NULL);
        debug("[ %s ]  system call table address __NR_close restored .", MODULE_NAME);
}


static void remove_hook_sys_rename(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_rename_addr;

	/* Get stub_execve address */
	orig_stub_rename_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_rename];

	mem_patch_relative_call(orig_stub_rename_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_rename_fn, NULL);
        debug("[ %s ]  system call table address __NR_rename restored .", MODULE_NAME);
}


static void remove_hook_sys_unlink(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_unlink_addr;

	/* Get stub_execve address */
	orig_stub_unlink_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_unlink];

	mem_patch_relative_call(orig_stub_unlink_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_unlink_fn, NULL);
        debug("[ %s ]  system call table address __NR_unlink restored .", MODULE_NAME);
}

static void remove_hook_sys_fchmodat(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_fchmodat_addr;

	/* Get stub_execve address */
	orig_stub_fchmodat_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_fchmodat];

	mem_patch_relative_call(orig_stub_fchmodat_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_fchmodat_fn, NULL);
        debug("[ %s ]  system call table address __NR_fchmodat restored .", MODULE_NAME);
}


static void remove_hook_sys_group_exit(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_exit_group_addr;

	/* Get stub_execve address */
	orig_stub_exit_group_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_exit_group];

	mem_patch_relative_call(orig_stub_exit_group_addr,
					MAX_RELATIVE_CALL_OFFSET,
					(unsigned long) original_sys_group_exit_fn, NULL);
        debug("[ %s ]  system call table address __NR_exit_group restored .", MODULE_NAME);
}

static void remove_hook_sys_truncate(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_truncate_addr;

	/* Get stub_execve address */
	orig_stub_truncate_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_truncate];

	mem_patch_relative_call(orig_stub_truncate_addr,
 				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_truncate_fn, NULL);
        debug("[ %s ]  system call table address __NR_truncate restored .", MODULE_NAME);
}

static void remove_hook_sys_ftruncate(unsigned long sys_call_table_addr) 
{
	unsigned long orig_stub_ftruncate_addr;

	/* Get stub_execve address */
	orig_stub_ftruncate_addr = ((unsigned long * ) (sys_call_table_addr))[__NR_ftruncate];

	mem_patch_relative_call(orig_stub_ftruncate_addr,
 				MAX_RELATIVE_CALL_OFFSET,
				(unsigned long) original_sys_ftruncate_fn, NULL);
        debug("[ %s ]  system call table address __NR_ftruncate restored .", MODULE_NAME);
}



/*################################################################################################*/

int init_stub_systcall(void)
{
 
  int obtain_sys_call_table_addr(unsigned long * sys_call_table_addr);
  int ret = SUCCESS, call_rv;
  unsigned long sys_call_table_addr;

  /* Obtain syscall table address */
  call_rv = obtain_sys_call_table_addr(&sys_call_table_addr);
  if (SUCCESS != call_rv) 
  {
     ret = call_rv;
     error("ERROR unable to find syscall table address "); 
    return ret;
  }


  hook_sys_group_exit(sys_call_table_addr);
  hook_sys_clone(sys_call_table_addr);
  hook_sys_execve(sys_call_table_addr);                                 
  hook_sys_close(sys_call_table_addr);  
  hook_sys_open(sys_call_table_addr);  
  hook_sys_read(sys_call_table_addr);  
  hook_sys_write(sys_call_table_addr);
  hook_sys_fork(sys_call_table_addr);
  hook_sys_connect(sys_call_table_addr);  
  hook_sys_rename(sys_call_table_addr);  
  hook_sys_unlink(sys_call_table_addr);
  hook_sys_fchmodat(sys_call_table_addr);
  hook_sys_truncate(sys_call_table_addr);
  hook_sys_ftruncate(sys_call_table_addr);

  info("[ %s ] initilize systcall hooks.", MODULE_NAME); 

 return ret;
}




int destroy_stub_systcall(void){

  int obtain_sys_call_table_addr(unsigned long * sys_call_table_addr);
  int ret = SUCCESS, call_rv;
  unsigned long sys_call_table_addr;

  /* Obtain syscall table address */
  call_rv = obtain_sys_call_table_addr(&sys_call_table_addr);
  if (SUCCESS != call_rv) 
  {
     ret = call_rv;
     error("ERROR destroy_stub_systcall() unable to find syscall table address "); 
    return ret; 
  }

  remove_hook_sys_group_exit(sys_call_table_addr);  
  remove_hook_sys_clone(sys_call_table_addr);
  remove_hook_sys_execve(sys_call_table_addr);
  remove_hook_sys_close(sys_call_table_addr);
  remove_hook_sys_open(sys_call_table_addr);
  remove_hook_sys_read(sys_call_table_addr);
  remove_hook_sys_write(sys_call_table_addr);
  remove_hook_sys_fork(sys_call_table_addr);
  remove_hook_sys_connect(sys_call_table_addr);  
  remove_hook_sys_rename(sys_call_table_addr);
  remove_hook_sys_unlink(sys_call_table_addr);
  remove_hook_sys_fchmodat(sys_call_table_addr);
  remove_hook_sys_truncate(sys_call_table_addr);
  remove_hook_sys_ftruncate(sys_call_table_addr);

  info("[ %s ] destroy systcall hooks.", MODULE_NAME); 

 return ret;
}
