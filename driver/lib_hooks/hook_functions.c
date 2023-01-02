#include "../kcontroller_data_type.h"
/*
   AUTHOR : eyal yehuda 
   system call stub handler to overrun systemcall table with our new system calls 
   by parssing the stub region and searching for assembly instruction E8 "call"
   after that the memory get patched with our new system call   
*/

#include "../bpm/bpm.h"

asmlinkage long (*orig_sys_execve_fn)(const char __user * filename,
  				      const char __user * const __user * argv,
				      const char __user * const __user * envp);

asmlinkage long (*original_sys_read_fn)(unsigned int fd, char __user* buf, size_t count);
asmlinkage long (*original_sys_write_fn)(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long (*original_sys_fork_fn)(void);
asmlinkage long (*original_sys_clone_fn)(unsigned long chiled_stack,
                                         unsigned long flags,
                                         int __user* child_tidptr,
                                         int __user* parent_tidptr, 
                                         int xxx);

asmlinkage long (*original_sys_connect_fn)(int fd, struct sockaddr __user* uservaddr, int addrlen);

asmlinkage long (*original_sys_open_fn)(int dfd,const char __user *filename,
                                        int flags, umode_t mode);

asmlinkage long (*original_sys_close_fn)(struct files_struct *files, unsigned fd);
asmlinkage long (*original_sys_rename_fn)(int olddfd, const char __user *oldname,
                                          int newdfd, const char __user *newname,
          			          unsigned int flags);

asmlinkage long (*original_sys_unlink_fn)(int dfd, const char __user *pathname);

asmlinkage long (*original_sys_fchmodat_fn)(int dfd, const char __user * filename
                                           ,unsigned int lookup_flags, struct path* path);

asmlinkage long (*original_sys_group_exit_fn)(int error_code);

asmlinkage long (*original_sys_truncate_fn)(const char __user *path
                                           ,long length);

asmlinkage long (*original_sys_ftruncate_fn)(unsigned int fd
                                            ,unsigned long length);



/*for debug only*/
#define NO_CACHE_BPM_USE
#undef  NO_CACHE_BPM_USE



static asmlinkage long new_sys_execve(const char __user * filename,
 			              const char __user * const __user * argv,
   			              const char __user * const __user * envp) 
{
	unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                       prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;
        size_t exec_line_size=0, continue_process=ERROR;
        char* executable_file_path=NULL, *execve_args_str=NULL
             ,*executable_file_name=NULL;
      	char** p_argv = (char **)argv;
        struct bpm_message_t* _msg = NULL;
        struct event_t* evt = NULL;
        struct bpm_result_t* res_t = NULL;


        DEFINE_TIME_COUNTERS(start,end)

        __hook_pid_(current->tgid,orig_sys_execve_fn,filename, argv, envp) 

        _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t));
	ASSERT_MEMORY_ALLOCATION(_msg)

        
        evt = &_msg->event;
        res_t = &_msg->result;                 
   
        __memset_bpm_message(evt,res_t)
        /* get total length in bytes of execve command line arguments */     	
	while (NULL != *p_argv) {
	     exec_line_size += (strlen(*p_argv) + 1);
	     (char **) p_argv++;	
	}	
      
        /* allocate memory to hold all function parameters in to one string for relay */
        execve_args_str = 
	  (char*)vmalloc(sizeof(unsigned char)*(exec_line_size+strlen(filename)+1));
	ASSERT_MEMORY_ALLOCATION(execve_args_str)

        memset(execve_args_str,0, (sizeof(unsigned char)*(exec_line_size+strlen(filename)+1)));

        /* copy command as it was run at the first place with all args */
        p_argv= (char**)argv;
        while(NULL!=*p_argv) {
	    snprintf(execve_args_str, (exec_line_size + (strlen(filename) + 1))
                         ,"%s %s", execve_args_str, *p_argv);
	    (char **) p_argv++; 
	}


        /* allocate space to hold the path to the executable that runs by execve */
        executable_file_path = (char*)vmalloc((strlen(filename) + 1) * sizeof(char)); 
        ASSERT_MEMORY_ALLOCATION(executable_file_path)
 
        memset(executable_file_path,0,(strlen(filename) + 1) * sizeof(char));

        /*  copy path of the executable name that runs by execve syscall */
        if(strncpy_from_user(executable_file_path, filename, 
             ((strlen(filename) + 1) * sizeof(char)) ) != (-EFAULT)) 
	     continue_process=SUCCESS;               
    
          /* if everything is ok then get the actual executable name */              	
        if(continue_process==SUCCESS) {  

            p_argv = (char **) argv; 

	    if(p_argv[0]!=NULL) {  
	      /* allocate space for executable name only */ 
              executable_file_name =(char*)vmalloc((strlen(p_argv[0]) + 1) * sizeof(char));  
              ASSERT_MEMORY_ALLOCATION(executable_file_name)
   	      
              memset(executable_file_name,0,( (strlen(p_argv[0]) + 1) * sizeof(char) ));

              /* copy executable name to kernel space memory */
              if(strncpy_from_user(executable_file_name, p_argv[0], 
     	                ((strlen(p_argv[0]) + 1) * sizeof(char)) ) != (-EFAULT))
	         continue_process=SUCCESS;
              else
	         continue_process=ERROR;
	    }
	}           
#ifndef NO_CACHE_BPM_USE
          /* go to cache */
        if( (continue_process==SUCCESS) &&
	  ( gather_process_information_syscall_execve(executable_file_path,
					              executable_file_name,
						      execve_args_str,
						      filename) == SUCCESS) )       
	{
  
           /* invoke BPM/HP query about this system call  */
           if(sys_process_execv(evt,res_t)==SUCCESS) {
              /* check BPM response */
              analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                                   &prevent_system_call);

              _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
			             prevent_system_call,res_t->priority)
              /* log to rellay */      
              __spawn_log_in_relay(_msg,spawn_log_in_relay)  
	    }
          
        }      
#endif

        vfree((void*)executable_file_name);  
        vfree((void*)executable_file_path); 
        vfree((void*)execve_args_str);

        __spawn_event_log_debug(evt,spawn_log_in_relay)  

        vfree((void*)_msg);

     STOP_TIME_COUNTER(start,end)

    /*prevent syscall from happening*/
    __prevent_syscall_(prevent_system_call);  

    return orig_sys_execve_fn(filename, argv, envp);
}


asmlinkage long (*pfn_new_sys_execve)(const char __user * filename,
 			      const char __user * const __user * argv,
			      const char __user * const __user * envp) = new_sys_execve;




static asmlinkage long new_sys_read(unsigned int fd, char __user* buf, size_t count)
{
  struct fd f;
  struct bpm_message_t* _msg = NULL;
  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;
  char name[EVENT_MAX_PATH_LEN], *path;   
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        


  DEFINE_TIME_COUNTERS(start,end)

   __hook_pid_(current->tgid,original_sys_read_fn,fd,buf,count)  

   f = fdget(fd);  
   if(!(f.file))
     return (-EBADF);

   memset(name,0,EVENT_MAX_PATH_LEN*sizeof(char));
   path = dentry_path_raw(f.file->f_path.dentry, name, EVENT_MAX_PATH_LEN);   
   fdput(f);  

   _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t)); 
   ASSERT_MEMORY_ALLOCATION(_msg)


   evt = &_msg->event;
   res_t = &_msg->result;        
   
   __memset_bpm_message(evt,res_t)

   if (!IS_ERR(path)) 
   {  

     
#ifndef NO_CACHE_BPM_USE
     gather_process_information_syscall_read();
     /* invoke BPM query about this system call  */
     if(sys_process_read(path,evt,res_t)==SUCCESS) {      
       /* check BPM response */
       analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                               &prevent_system_call);

       _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
				 prevent_system_call,res_t->priority)

       /* log to rellay */      
       __spawn_log_in_relay(_msg,spawn_log_in_relay)  

     }      
#endif
   }  

  __spawn_event_log_debug(evt,spawn_log_in_relay)    

   vfree((void*)_msg);
  
  STOP_TIME_COUNTER(start,end)
  /*prevent syscall from happening*/
  __prevent_syscall_(prevent_system_call)

  return original_sys_read_fn(fd,buf,count);
}

asmlinkage long (*pfn_new_sys_read)(unsigned int fd
                                   ,char __user* buf
                                   ,size_t count) = new_sys_read;



static asmlinkage long new_sys_write(unsigned int fd
                                    ,const char __user *buf
                                    ,size_t count)
{
  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;

  char name[EVENT_MAX_PATH_LEN]; 
  struct fd f;  
  char* path = NULL; 
  struct bpm_message_t* _msg;
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        

  DEFINE_TIME_COUNTERS(start,end)

  __hook_pid_(current->tgid,original_sys_write_fn,fd,buf,count)  

  f = fdget(fd);
  if(!(f.file))
      return (-EBADF);

  path = dentry_path_raw(f.file->f_path.dentry, name, EVENT_MAX_PATH_LEN);
  fdput(f);

  _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t));
  ASSERT_MEMORY_ALLOCATION(_msg)
  

  evt = &_msg->event;
  res_t = &_msg->result;        

    __memset_bpm_message(evt,res_t)

    if (!IS_ERR(path)) 
    { 
#ifndef NO_CACHE_BPM_USE
      gather_process_information_syscall_write();

      /* invoke BPM query about this system call */
      if(sys_process_write(path,evt,res_t)==SUCCESS) {
      
        /* check BPM response */
        analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                               &prevent_system_call);

        _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
				 prevent_system_call,res_t->priority)

        /* log to rellay */      
        __spawn_log_in_relay(_msg,spawn_log_in_relay)  

      }      
#endif
    }  

   __spawn_event_log_debug(evt,spawn_log_in_relay)    

    vfree((void*)_msg);

  __spawn_event_log_debug(evt,spawn_log_in_relay)  
 
  STOP_TIME_COUNTER(start,end)
  /*prevent syscall from happening*/
  __prevent_syscall_(prevent_system_call)
  return original_sys_write_fn(fd,buf,count);
}


asmlinkage long (*pfn_new_sys_write)(unsigned int fd
                                    ,const char __user *buf
		                    ,size_t count) = new_sys_write;



static asmlinkage long new_sys_fork(void)
{

  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;

  struct bpm_message_t* _msg = NULL;
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        
  
  __hook_pid_(current->tgid,original_sys_fork_fn)  
  DEFINE_TIME_COUNTERS(start,end)
  
  _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t));
  ASSERT_MEMORY_ALLOCATION(_msg)
  
  evt = &_msg->event;
  res_t = &_msg->result;          

  __memset_bpm_message(evt,res_t)

     
#ifndef NO_CACHE_BPM_USE
     gather_process_information_syscall_fork();
     /* invoke BPM query about this system call */
     if(sys_process_fork(evt,res_t)==SUCCESS) {    
       /* check BPM response */
       analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                               &prevent_system_call);

       _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
 			    prevent_system_call,res_t->priority)

       /* log to rellay */      
       __spawn_log_in_relay(_msg,spawn_log_in_relay)  

    }  
#endif

   __spawn_event_log_debug(evt,spawn_log_in_relay)    

     vfree((void*)_msg);

  __spawn_event_log_debug(evt,spawn_log_in_relay)  
 
  STOP_TIME_COUNTER(start,end)
  /*prevent syscall from happening*/
  __prevent_syscall_(prevent_system_call)  

  return original_sys_fork_fn();
}


asmlinkage long (*pfn_new_sys_fork)(void) = new_sys_fork;


static asmlinkage long new_sys_clone(unsigned long chiled_stack, 
                                     unsigned long flags,
                                     int __user* child_tidptr,
                                     int __user* parent_tidptr,
                                     int xxx)
{

  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;

  struct bpm_message_t* _msg = NULL;
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        

  DEFINE_TIME_COUNTERS(start,end)

  __hook_pid_(current->tgid,original_sys_clone_fn,
	                   chiled_stack,flags,
                           child_tidptr, 
                           parent_tidptr,xxx)  

  _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t));
  ASSERT_MEMORY_ALLOCATION(_msg)
  
 
  evt = &_msg->event;
  res_t = &_msg->result;        
 
  __memset_bpm_message(evt,res_t)

#ifndef NO_CACHE_BPM_USE
    gather_process_information_syscall_clone(); 
    /* invoke BPM query about this system call */
    if(sys_process_clone(evt,res_t)==SUCCESS) {    
      /* check BPM response */
      analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                               &prevent_system_call);

      _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
				 prevent_system_call,res_t->priority)
 
      /* log to rellay */      
      __spawn_log_in_relay(_msg,spawn_log_in_relay)  
      
    }  
#endif

   __spawn_event_log_debug(evt,spawn_log_in_relay)    

    vfree((void*)_msg);

   __spawn_event_log_debug(evt,spawn_log_in_relay)  

   STOP_TIME_COUNTER(start,end)
  /*prevent syscall from happening*/
  __prevent_syscall_(prevent_system_call)  

  return original_sys_clone_fn(chiled_stack
                              ,flags
                              ,child_tidptr
                              ,parent_tidptr
                              ,xxx);
}


asmlinkage long (*pfn_new_sys_clone)(unsigned long chiled_stack, 
                                     unsigned long flags,
                                     int __user* child_tidptr,
                                     int __user* parent_tidptr,
                                     int xxx) = new_sys_clone;



static asmlinkage long new_sys_connect(int fd
                                      ,struct sockaddr __user* uservaddr
                                      ,int addrlen) 
{
  int move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr_storage *kaddr);

  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;
  int res=0;
  struct sockaddr_storage address;
  __be16 port=0;
  unsigned char ip_buf[INET6_ADDRSTRLEN+1];
  struct bpm_message_t* _msg = NULL;
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        

  DEFINE_TIME_COUNTERS(start,end)

  __hook_pid_(current->tgid,original_sys_connect_fn,fd, uservaddr, addrlen)  

   _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t));
  ASSERT_MEMORY_ALLOCATION(_msg)

  evt = &_msg->event;
  res_t = &_msg->result;        
    
    __memset_bpm_message(evt,res_t)
  
    memset(ip_buf,0,(INET6_ADDRSTRLEN +1) * sizeof(unsigned char));
    res = move_addr_to_kernel(uservaddr, addrlen, &address);
    if(!(res < 0)) {

      if(address.ss_family == AF_INET) {

         port = ntohs(((struct sockaddr_in*)&address)->sin_port);
         sprintf(ip_buf,"%d:%d:%d:%d",NIPQUAD(((struct sockaddr_in*)&address)->sin_addr.s_addr));

      }else if (address.ss_family == AF_INET6)
      {
         port = ntohs(((struct sockaddr_in6*)&address)->sin6_port);
       // inet_ntop(AF_INET6, &(ss.sin6_addr), ip_buf, INET6_ADDRSTRLEN);
      }else
      {
	res=-1;
      }


#ifndef NO_CACHE_BPM_USE
      gather_process_information_syscall_connect();
      /* invoke BPM query about this system call  */
      if(sys_process_socket_connect(port,
         ((struct sockaddr_in*)&address)->sin_addr.s_addr,evt,res_t)==SUCCESS) {      
        /* check BPM response */
        analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                             &prevent_system_call);

        _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
				 prevent_system_call,res_t->priority)

       /* log to rellay */      
       __spawn_log_in_relay(_msg,spawn_log_in_relay)  

     } 
#endif
   } 

  __spawn_event_log_debug(evt,spawn_log_in_relay)    

  vfree((void*)_msg);

  STOP_TIME_COUNTER(start,end)
 /*prevent syscall from happening*/
 __prevent_syscall_(prevent_system_call)  

 return original_sys_connect_fn(fd, uservaddr, addrlen);
}


asmlinkage long (*pfn_new_sys_connect)(int fd
                                      ,struct sockaddr __user* uservaddr
 			              ,int addrlen) = new_sys_connect;




static asmlinkage long new_sys_open(int dfd
                                   ,const char __user *filename
                                   ,int flags
                                   ,umode_t mode)
{ 

  struct fd f;
  int fd=0;
  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;
  char name[EVENT_MAX_PATH_LEN], *path=NULL;
  struct bpm_message_t* _msg = NULL;
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        

  DEFINE_TIME_COUNTERS(start,end)

  __hook_pid_(current->tgid,original_sys_open_fn,dfd,filename,flags,mode)  

  /* let file get opened so we can get file descriptor to it , in addirion to derive 
     the appropriate file path */
  if (force_o_largefile()) flags |= O_LARGEFILE;
  fd = original_sys_open_fn(dfd,filename,flags,mode);
  if(fd < 0) return fd; 

  f = fdget(fd);  
  if(!(f.file)) 
      return (-EBADF);
  memset(name,0,EVENT_MAX_PATH_LEN*sizeof(char));
  path = dentry_path_raw(f.file->f_path.dentry, name, EVENT_MAX_PATH_LEN);
  fdput(f);
 
  if (!IS_ERR(path)) 
  {  

    _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t));
    ASSERT_MEMORY_ALLOCATION(_msg)
   
    evt = &_msg->event;
    res_t = &_msg->result;

      __memset_bpm_message(evt,res_t)        

#ifndef NO_CACHE_BPM_USE
      gather_process_information_syscall_open();    
  
      /* invoke BPM query about this system call  */
      if(sys_process_open(path,flags,evt,res_t)==SUCCESS) {      
         /* check BPM response */
         analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                             &prevent_system_call);

         _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
				prevent_system_call,res_t->priority)

         /* log to rellay */      
          __spawn_log_in_relay(_msg,spawn_log_in_relay)  

      }
#endif

      __spawn_event_log_debug(evt,spawn_log_in_relay)  

      vfree((void*)_msg);
   }

 if(prevent_system_call==PRIORITY_PREVENT_SYSCALL)
    original_sys_close_fn(current->files,fd);    

  STOP_TIME_COUNTER(start,end)
 /*prevent syscall from happening*/
 __prevent_syscall_(prevent_system_call)  

 return fd;

}


asmlinkage long (*pfn_new_sys_open)(int dfd
                                   ,const char __user *filename
                                   ,int flags
				   ,umode_t mode) = new_sys_open;


static asmlinkage long new_sys_close(struct files_struct *files
                                    ,unsigned fd)
{
  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;

  char *tmp, *pathname;
  struct file *file;
  struct path *path;
  struct bpm_message_t* _msg = NULL;
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        

  DEFINE_TIME_COUNTERS(start,end)

  __hook_pid_(current->tgid,original_sys_close_fn,files,fd)  

  _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t)); 
  ASSERT_MEMORY_ALLOCATION(_msg)
  
  evt = &_msg->event;
  res_t = &_msg->result; 

  __memset_bpm_message(evt,res_t)       

  spin_lock(&files->file_lock);
  file = fcheck_files(current->files, fd);
  if (!file) {
      spin_unlock(&files->file_lock);
      vfree((void*)_msg);
      return -ENOENT;
  }

    path = &file->f_path;
    path_get(path);
    spin_unlock(&files->file_lock);

    tmp = (char *)__get_free_page(GFP_KERNEL);

    if (!tmp) {
      path_put(path);
      vfree((void*)_msg);
      return -ENOMEM;
    }

    pathname = d_path(path, tmp, PAGE_SIZE);
    path_put(path);

    if (IS_ERR(pathname)) {
      free_page((unsigned long)tmp);
      vfree((void*)_msg);
      return PTR_ERR(pathname);
    }
#ifndef NO_CACHE_BPM_USE
    gather_process_information_syscall_close();

    /* invoke BPM query about this system call  */
    if(sys_process_close(pathname,evt,res_t)==SUCCESS) {       
      /* check BPM response */
      analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                             &prevent_system_call);

      _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
				 prevent_system_call,res_t->priority)
      /* log to rellay */      
      __spawn_log_in_relay(_msg,spawn_log_in_relay)  
  
    }               
#endif

  free_page((unsigned long)tmp); 

  __spawn_event_log_debug(evt,spawn_log_in_relay)  

  vfree((void*)_msg);

  STOP_TIME_COUNTER(start,end)
  /*prevent syscall from happening*/
  __prevent_syscall_(prevent_system_call)  

 return original_sys_close_fn(files,fd);
}


asmlinkage long (*pfn_new_sys_close)(struct files_struct *files
  		                    ,unsigned fd) = new_sys_close;


static asmlinkage long new_sys_rename(int olddfd
                                     ,const char __user *oldname
                                     ,int newdfd
                                     ,const char __user *newname
                                     ,unsigned int flags)
{

  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;

  char new_name[EVENT_MAX_PATH_LEN], old_name[EVENT_MAX_PATH_LEN];
  struct bpm_message_t* _msg = NULL;
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        

  DEFINE_TIME_COUNTERS(start,end)

  __hook_pid_(current->tgid,original_sys_rename_fn
             ,AT_FDCWD
             ,oldname
             ,AT_FDCWD
             ,newname
             ,flags)  

    _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t));
  ASSERT_MEMORY_ALLOCATION(_msg)
  

  evt = &_msg->event;
  res_t = &_msg->result;        

  __memset_bpm_message(evt,res_t)
 
    memset(new_name,0,EVENT_MAX_PATH_LEN*sizeof(char));
    memset(old_name,0,EVENT_MAX_PATH_LEN*sizeof(char));
 
    if(strncpy_from_user(new_name, newname, (EVENT_MAX_PATH_LEN -1)) != (-EFAULT)
    && strncpy_from_user(old_name, oldname, (EVENT_MAX_PATH_LEN -1)) != (-EFAULT)) 
    {
#ifndef NO_CACHE_BPM_USE
      gather_process_information_syscall_rename();

      /* invoke BPM query about this system call  */
      if(sys_process_rename(old_name, new_name,evt,res_t)==SUCCESS) {      
         /* check BPM response */
         analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                             &prevent_system_call);

         _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
				 prevent_system_call,res_t->priority)
         /* log to rellay */      
         __spawn_log_in_relay(_msg,spawn_log_in_relay)  

      }      
#endif  
    }  

  __spawn_event_log_debug(evt,spawn_log_in_relay)  

  vfree((void*)_msg);

  STOP_TIME_COUNTER(start,end)
  /*prevent syscall from happening*/
  __prevent_syscall_(prevent_system_call)  

  return original_sys_rename_fn(AT_FDCWD
                               ,oldname
                               ,AT_FDCWD
                               ,newname
                               ,flags);

}

asmlinkage long (*pfn_new_sys_rename)(int olddfd
                             ,const char __user *oldname
                             ,int newdfd
                             ,const char __user *newname
  		             ,unsigned int flags) =  new_sys_rename;






static asmlinkage long new_sys_unlink(int dfd
                                     ,const char __user *pathname)
{

  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;  

  char path_name[EVENT_MAX_PATH_LEN];
  struct bpm_message_t* _msg = NULL;
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        

  DEFINE_TIME_COUNTERS(start,end)

  __hook_pid_(current->tgid,original_sys_unlink_fn,AT_FDCWD, pathname)

    _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t));   
  ASSERT_MEMORY_ALLOCATION(_msg)
  

  evt = &_msg->event;
  res_t = &_msg->result;        

  __memset_bpm_message(evt,res_t)

    if(strncpy_from_user(path_name, pathname, (EVENT_MAX_PATH_LEN -1)) != (-EFAULT)) 
    {

#ifndef NO_CACHE_BPM_USE
      gather_process_information_syscall_unlink();

      /* invoke BPM query about this system call  */
      if(sys_process_unlink(path_name,evt,res_t)==SUCCESS) {      
         /* check BPM response */
         analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                             &prevent_system_call);

         _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
  			     prevent_system_call,res_t->priority)

         /* log to rellay */      
         __spawn_log_in_relay(_msg,spawn_log_in_relay)  
  
       }      
#endif
    }

  __spawn_event_log_debug(evt,spawn_log_in_relay)  

  vfree((void*)_msg);

  STOP_TIME_COUNTER(start,end)
  /*prevent syscall from happening*/
  __prevent_syscall_(prevent_system_call)

  return original_sys_unlink_fn(AT_FDCWD, pathname);
}



asmlinkage long (*pfn_new_sys_unlink)(int dfd
		                     ,const char __user *pathname) = new_sys_unlink;



static asmlinkage long new_sys_fchmodat(int dfd
                                       ,const char __user * filename
                                       ,unsigned int lookup_flags
                                       ,struct path* path)
{

  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;  

  char file_name[EVENT_MAX_PATH_LEN];
  umode_t mode=0;  // EYAL TODO this should be taken from register (EDX)  
  struct bpm_message_t* _msg = NULL;
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        

  DEFINE_TIME_COUNTERS(start,end)

  __hook_pid_(current->tgid,original_sys_fchmodat_fn,dfd,filename,lookup_flags,path)

    _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t));
  ASSERT_MEMORY_ALLOCATION(_msg)
  

  evt = &_msg->event;
  res_t = &_msg->result;        

     __memset_bpm_message(evt,res_t)

    memset(file_name,0,EVENT_MAX_PATH_LEN*sizeof(char));

    if(strncpy_from_user(file_name, filename, (EVENT_MAX_PATH_LEN -1)) != (-EFAULT)) {

#ifndef NO_CACHE_BPM_USE
      gather_process_information_syscall_fchmodat();
     
      /* invoke BPM query about this system call  */
      if(sys_process_fchmodat(dfd,file_name,mode,evt,res_t)==SUCCESS) {      
        /* check BPM response */
        analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                             &prevent_system_call);

        _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
   		              prevent_system_call,res_t->priority)

        /* log to rellay */      
        __spawn_log_in_relay(_msg,spawn_log_in_relay)  
         
      } 
#endif
    }

  __spawn_event_log_debug(evt,spawn_log_in_relay)  

  vfree((void*)_msg);

  STOP_TIME_COUNTER(start,end)
  /*prevent syscall from happening*/
  __prevent_syscall_(prevent_system_call)

  return original_sys_fchmodat_fn(dfd,filename,lookup_flags,path);
}


asmlinkage long (*pfn_new_sys_fchmodat)(int dfd
                                       ,const char __user * filename
                                       ,unsigned int lookup_flags
			               ,struct path* path) = new_sys_fchmodat;


static asmlinkage long new_sys_exit_group(int error_code)
{
  
  __hook_pid_(current->tgid,original_sys_group_exit_fn,((error_code & 0xff) << 8))
#ifndef NO_CACHE_BPM_USE
  gather_process_information_syscall_group_exit(); 
#endif  
  smp_mb();

  //info("[ %s ] new_sys_exit_group() pid: %d", MODULE_NAME,current->pid);

  original_sys_group_exit_fn(((error_code & 0xff) << 8));

  return SUCCESS;
}


asmlinkage long (*pfn_new_sys_exit_group)(int error_code) = new_sys_exit_group;



static asmlinkage long new_sys_truncate(const char __user *path
                                       ,long length)
{

  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;
  char pathname[EVENT_MAX_PATH_LEN], buf[EVENT_MAX_PATH_LEN],
       *pwd=NULL;
  struct bpm_message_t* _msg = NULL;  
  struct fd f;
  /*always open with root permissions*/
  umode_t mode = S_IFREG|0644; 
  int  fd=0, flags=O_RDONLY, ret=SUCCESS;
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        

  __hook_pid_(current->tgid,original_sys_ftruncate_fn,fd,length)  

  _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t)); 
  ASSERT_MEMORY_ALLOCATION(_msg)
  

  evt = &_msg->event;
  res_t = &_msg->result;        
   
    __memset_bpm_message(evt,res_t)

    if (force_o_largefile()) flags |= O_LARGEFILE;
    fd = original_sys_open_fn(AT_FDCWD,path,flags,mode);

    if(!(fd < 0)){

       f = fdget(fd);  
       if(!(f.file)) {
         vfree((void*)_msg);
         return (-EBADF);
       }

       memset(buf,0,EVENT_MAX_PATH_LEN*sizeof(char));
       pwd = dentry_path_raw(f.file->f_path.dentry, buf, EVENT_MAX_PATH_LEN);
       fdput(f);

       if (!IS_ERR(pwd)){

           memset(pathname,0,EVENT_MAX_PATH_LEN*sizeof(char)); 
           strncpy(pathname,pwd, EVENT_MAX_PATH_LEN);
       }else
         ret=ERROR;
     
      original_sys_close_fn(current->files,fd);    
    }else
      ret=ERROR;

    if(ret==ERROR)
       if(strncpy_from_user(pathname, path, (EVENT_MAX_PATH_LEN -1)) != (-EFAULT))
	 ret = SUCCESS;    

    if(ret == SUCCESS) {
#ifndef NO_CACHE_BPM_USE
      gather_process_information_syscall_close();

      /* invoke BPM query about this system call  */
      if(sys_process_truncate(pathname,evt,res_t)==SUCCESS) {       
      /* check BPM response */
        analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                             &prevent_system_call);

        _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
			       prevent_system_call,res_t->priority)
        /* log to rellay */      
        __spawn_log_in_relay(_msg,spawn_log_in_relay)  

      }               
#endif
    }

   __spawn_event_log_debug(evt,spawn_log_in_relay)  

    vfree((void*)_msg);

  /*prevent syscall from happening*/
  __prevent_syscall_(prevent_system_call)  

  return original_sys_truncate_fn(path,length);
}


asmlinkage long (*pfn_new_sys_truncate)(const char __user *path
				       ,long length) = new_sys_truncate;

static asmlinkage long new_sys_ftruncate(unsigned int fd
                                        ,unsigned long length)
{
  unsigned short spawn_log_in_relay=DO_NOT_SPAWN_LOG_IN_RELAY,
                 prevent_system_call=PRIORITY_ALLOW_SYSTEM_CALL;

  char* pathname, name[EVENT_MAX_PATH_LEN];
  struct bpm_message_t* _msg = NULL;
  struct fd f;  
  struct event_t* evt = NULL;
  struct bpm_result_t* res_t = NULL;        
 
  __hook_pid_(current->tgid,original_sys_ftruncate_fn,fd,length)  
  
  f = fdget(fd);
  if(!(f.file))
    return (-EBADF);

  memset(name,0,EVENT_MAX_PATH_LEN*sizeof(char));
  pathname = dentry_path_raw(f.file->f_path.dentry, name, EVENT_MAX_PATH_LEN);
  fdput(f);

  _msg = (struct bpm_message_t*)vmalloc(sizeof(struct bpm_message_t));
  ASSERT_MEMORY_ALLOCATION(_msg)


  evt = &_msg->event;
  res_t = &_msg->result;        

    __memset_bpm_message(evt,res_t)

    if (!IS_ERR(pathname)) 
    {  
#ifndef NO_CACHE_BPM_USE
      gather_process_information_syscall_close();

      /* invoke BPM query about this system call  */
      if(sys_process_ftruncate(pathname,evt,res_t)==SUCCESS) {       
      /* check BPM response */
        analize_bpm_response(&(res_t->priority), &spawn_log_in_relay, 
                             &prevent_system_call);

        _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,
			       prevent_system_call,res_t->priority)
        /* log to rellay */      
        __spawn_log_in_relay(_msg,spawn_log_in_relay)  

      }               
#endif
    }

    __spawn_event_log_debug(evt,spawn_log_in_relay)  


    vfree((void*)_msg);

  /*prevent syscall from happening*/
  __prevent_syscall_(prevent_system_call)  
 
  return original_sys_ftruncate_fn(fd,length);
}

asmlinkage long (*pfn_new_sys_ftruncate)(unsigned int fd
					,unsigned long length) = new_sys_ftruncate;
