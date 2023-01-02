#ifndef __CACHE_PROCESS_HANDLER__
#define __CACHE_PROCESS_HANDLER__





int gather_process_information_syscall_execve(char *target_file_path,
					      char *target_file_name, 
					      char *target_cmdline,
					      const char __user *filename);

int gather_process_information_syscall_read(void);
int gather_process_information_syscall_write(void);
int gather_process_information_syscall_fork(void);
int gather_process_information_syscall_clone(void);
int gather_process_information_syscall_connect(void);
int gather_process_information_syscall_open(void);
int gather_process_information_syscall_close(void);
int gather_process_information_syscall_rename(void);
int gather_process_information_syscall_unlink(void);
int gather_process_information_syscall_fchmodat(void);
int gather_process_information_syscall_group_exit(void);
int destroy_process_cache(void);
int gather_process_information_syscall_truncate(void);
int gather_process_information_syscall_ftruncate(void);


#endif
