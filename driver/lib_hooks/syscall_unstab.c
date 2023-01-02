//EYAL TO DO  system call table hooks will be implimented here !

/*
   AUTHOR : eyal yehuda 
   simple system call unstub handler to overrun systemcall table with our new system calls 

   /usr/src/kernels/3.10.0-693.11.1.el7.x86_64/arch/x86/include/generated/uapi/asm/unistd_64.h


   
*/
#include "kcontroller_data_type.h"


//done 
asmlinkage long (*original_connect)(int fd, struct sockaddr __user* uservaddr, int addrlen);
//done
asmlinkage long (*original_open)(const char __user *filename,int flags, umode_t mode);

asmlinkage long (*original_close)(unsigned int fd);
asmlinkage long (*original_rename)(const char __user *oldname,const char __user *newname);
asmlinkage long (*original_unlink)(const char __user *pathname);
asmlinkage long (*original_chmod)(const char __user *filename, umode_t mode);
asmlinkage long (*original_fchmodat)(int dfd, const char __user * filename,umode_t mode);


typedef long (*cast_connect)(int, struct sockaddr __user *, int);
typedef long (*cast_open)(const char __user*,int, umode_t);
typedef long (*cast_close)(unsigned int fd);
typedef long (*cast_rename)(const char __user *oldname,const char __user *newname);
typedef long (*cast_unlink)(const char __user *pathname);
typedef long (*cast_chmod)(const char __user *filename, umode_t mode);
typedef long (*cast_fchmodat)(int dfd, const char __user * filename,umode_t mode);








static asmlinkage long new_connect (int fd, struct sockaddr __user* uservaddr, int addrlen) 
{
  int move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr_storage *kaddr);
  int res=0;
  struct sockaddr_storage address;
  __be16 port=0;
  unsigned char ip_buf[INET6_ADDRSTRLEN+1];
  struct bpm_response bpmres;
  unsigned short spawn_log_in_relay, prevent_system_call;

  memset(ip_buf,0,(INET6_ADDRSTRLEN +1) * sizeof(unsigned char));
  res = move_addr_to_kernel(uservaddr, addrlen, &address);
  if(!(res < 0))
  {
      if(address.ss_family == AF_INET)
      {
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

      memset(&bpmres,0,sizeof(struct bpm_response));
      /* invoke BPM query about this system call  */
      if(!(sys_process_socket_connect(port,ip_buf,(void*)&bpmres)))
      {      
       /* check BPM response */
       analize_bpm_response(&(bpmres.rule_priority),
                            &spawn_log_in_relay, 
                            &prevent_system_call);
       /*
       debug("[ %s ] after analize_bpm_response() spawn_log_in_relay: [ %d ]" \
                 "prevent_system_call: [ %d ] priority [ %d ] ", MODULE_NAME
      	         ,spawn_log_in_relay,prevent_system_call
	         ,bpmres.rule_priority);
       */       
       /* log to rellay */      
       if(spawn_log_in_relay==SPAWN_LOG_IN_RELAY)
       {
          log_sys_socket_connect(port,ip_buf);
       }
  
       /*prevent syscall from happening*/
       if(prevent_system_call==PRIORITY_PREVENT_SYSCALL)
       {
          return -EINVAL;
       }      
     } 
  } 

  return original_connect(fd, uservaddr, addrlen);
}


static asmlinkage long new_open(const char __user *filename,int flags, umode_t mode)
{ 
  unsigned short spawn_log_in_relay, prevent_system_call;
  char name[EVENT_MAX_PATH_LEN];
  struct bpm_response bpmres;

  memset(name,0,EVENT_MAX_PATH_LEN*sizeof(char));
 
  if(strncpy_from_user(name, filename, (EVENT_MAX_PATH_LEN -1)) != (-EFAULT))
  {
    memset(&bpmres,0,sizeof(struct bpm_response));
    /* invoke BPM query about this system call  */
    if(!(sys_process_open(name,(void*)&bpmres)))
     {      
       /* check BPM response */
       analize_bpm_response(&(bpmres.rule_priority),
                            &spawn_log_in_relay, 
                            &prevent_system_call);
       /*
       debug("[ %s ] after analize_bpm_response() spawn_log_in_relay: [ %d ]" \
                 "prevent_system_call: [ %d ] priority [ %d ] ", MODULE_NAME
      	         ,spawn_log_in_relay,prevent_system_call
	         ,bpmres.rule_priority);
       */       
       /* log to rellay */      
       if(spawn_log_in_relay==SPAWN_LOG_IN_RELAY)
       {
	 log_sys_open(name);
       }
  
       /*prevent syscall from happening*/
       if(prevent_system_call==PRIORITY_PREVENT_SYSCALL)
       {
          return -EINVAL;
       }      
     }      
  }

 return original_open(filename,flags,mode);
}


static asmlinkage long new_close(unsigned int fd)
{
  unsigned short spawn_log_in_relay, prevent_system_call;
  struct bpm_response bpmres;
  char *tmp;
  char *pathname;
  struct file *file;
  struct path *path;

  //  spin_lock(&files->file_lock);
  file = fcheck_files(current->files, fd);
  if (!file) {
    //spin_unlock(&files->file_lock);
    return -ENOENT;
  }

  path = &file->f_path;
  path_get(path);
  //  spin_unlock(&files->file_lock);

  tmp = (char *)__get_free_page(GFP_KERNEL);

  if (!tmp) {
    path_put(path);
    return -ENOMEM;
  }

  pathname = d_path(path, tmp, PAGE_SIZE);
  path_put(path);

  if (IS_ERR(pathname)) {
    free_page((unsigned long)tmp);
    return PTR_ERR(pathname);
  }

  memset(&bpmres,0,sizeof(struct bpm_response));

  /* invoke BPM query about this system call  */
  if(!(sys_process_close(pathname,(void*)&bpmres)))
  {      
     /* check BPM response */
     analize_bpm_response(&(bpmres.rule_priority),
                          &spawn_log_in_relay, 
                          &prevent_system_call);
     /*
     debug("[ %s ] after analize_bpm_response() spawn_log_in_relay: [ %d ]" \
                 "prevent_system_call: [ %d ] priority [ %d ] ", MODULE_NAME
      	         ,spawn_log_in_relay,prevent_system_call
	         ,bpmres.rule_priority);
     */
     /* log to rellay */      
     if(spawn_log_in_relay==SPAWN_LOG_IN_RELAY)
     {
       log_sys_close(pathname);
     }
  
     /*prevent syscall from happening*/
     if(prevent_system_call==PRIORITY_PREVENT_SYSCALL)
     {
        return -EINVAL;
     }      
   }               

  free_page((unsigned long)tmp); 

  return original_close(fd);
}




static asmlinkage long new_rename(const char __user *oldname,const char __user *newname)
{

  unsigned short spawn_log_in_relay, prevent_system_call;
  char new_name[EVENT_MAX_PATH_LEN], old_name[EVENT_MAX_PATH_LEN];
  struct bpm_response bpmres;

  memset(new_name,0,EVENT_MAX_PATH_LEN*sizeof(char));
  memset(old_name,0,EVENT_MAX_PATH_LEN*sizeof(char));
 
  if(strncpy_from_user(new_name, newname, (EVENT_MAX_PATH_LEN -1)) != (-EFAULT)
  && strncpy_from_user(old_name, oldname, (EVENT_MAX_PATH_LEN -1)) != (-EFAULT))
  {
    memset(&bpmres,0,sizeof(struct bpm_response));
    /* invoke BPM query about this system call  */
    if(!(sys_process_rename(old_name, new_name, (void*)&bpmres)))
    {      
       /* check BPM response */
       analize_bpm_response(&(bpmres.rule_priority),
                            &spawn_log_in_relay, 
                            &prevent_system_call);
       /*
       debug("[ %s ] after analize_bpm_response() spawn_log_in_relay: [ %d ]" \
                 "prevent_system_call: [ %d ] priority [ %d ] ", MODULE_NAME
      	         ,spawn_log_in_relay,prevent_system_call
	         ,bpmres.rule_priority);
       */
       /* log to rellay */      
       if(spawn_log_in_relay==SPAWN_LOG_IN_RELAY)
       {
	 log_sys_rename(old_name,new_name);
       }
  
       /*prevent syscall from happening*/
       if(prevent_system_call==PRIORITY_PREVENT_SYSCALL)
       {
          return -EINVAL;
       }      
     }      
  }  

  return original_rename(oldname,newname);
}


static asmlinkage long new_unlink(const char __user *pathname)
{
  unsigned short spawn_log_in_relay, prevent_system_call;
  char path_name[EVENT_MAX_PATH_LEN];
  struct bpm_response bpmres;

  memset(path_name,0,EVENT_MAX_PATH_LEN*sizeof(char));
  if(strncpy_from_user(path_name, pathname, (EVENT_MAX_PATH_LEN -1)) != (-EFAULT))
  {
    memset(&bpmres,0,sizeof(struct bpm_response));
    /* invoke BPM query about this system call  */
    if(!(sys_process_unlink(path_name, (void*)&bpmres)))
    {      
       /* check BPM response */
       analize_bpm_response(&(bpmres.rule_priority),
                            &spawn_log_in_relay, 
                            &prevent_system_call);
       /*
       debug("[ %s ] after analize_bpm_response() spawn_log_in_relay: [ %d ]" \
                 "prevent_system_call: [ %d ] priority [ %d ] ", MODULE_NAME
      	         ,spawn_log_in_relay,prevent_system_call
	         ,bpmres.rule_priority);
       */
       /* log to rellay */      
       if(spawn_log_in_relay==SPAWN_LOG_IN_RELAY)
       {
	 log_sys_unlink(path_name);
       }
  
       /*prevent syscall from happening*/
       if(prevent_system_call==PRIORITY_PREVENT_SYSCALL)
       {
          return -EINVAL;
       }      
     }      
  }  

 return original_unlink(pathname);
}




static asmlinkage long new_chmod(const char __user *filename, umode_t mode)
{

  unsigned short spawn_log_in_relay, prevent_system_call;
  char file_name[EVENT_MAX_PATH_LEN];
  struct bpm_response bpmres;
  
  debug("[ %s ] new_chmod 1", MODULE_NAME);
  memset(file_name,0,EVENT_MAX_PATH_LEN*sizeof(char));
  if(strncpy_from_user(file_name, filename, (EVENT_MAX_PATH_LEN -1)) != (-EFAULT))
  {
    debug("[ %s ] new_chmod 2", MODULE_NAME);

    memset(&bpmres,0,sizeof(struct bpm_response));
    /* invoke BPM query about this system call  */
    if(!(sys_process_chmod(file_name,mode, (void*)&bpmres)))
    {      
       /* check BPM response */
       analize_bpm_response(&(bpmres.rule_priority),
                            &spawn_log_in_relay, 
                            &prevent_system_call);
       /*      
       debug("[ %s ] after analize_bpm_response() spawn_log_in_relay: [ %d ]" \
                 "prevent_system_call: [ %d ] priority [ %d ] ", MODULE_NAME
      	         ,spawn_log_in_relay,prevent_system_call
	         ,bpmres.rule_priority);*/
       
       /* log to rellay */      
       if(spawn_log_in_relay==SPAWN_LOG_IN_RELAY)
       {
	 log_sys_chmod(file_name,mode);
       }
  
       /*prevent syscall from happening*/
       if(prevent_system_call==PRIORITY_PREVENT_SYSCALL)
       {
          return -EINVAL;
       }      
     }      
  }  

  return original_chmod(filename, mode);
}


static asmlinkage long new_fchmodat(int dfd, const char __user * filename,umode_t mode)
{

  unsigned short spawn_log_in_relay, prevent_system_call;
  char file_name[EVENT_MAX_PATH_LEN];
  struct bpm_response bpmres;
  
  memset(file_name,0,EVENT_MAX_PATH_LEN*sizeof(char));
  if(strncpy_from_user(file_name, filename, (EVENT_MAX_PATH_LEN -1)) != (-EFAULT))
  {
    memset(&bpmres,0,sizeof(struct bpm_response));
    /* invoke BPM query about this system call  */
    if(!(sys_process_fchmodat(dfd,file_name,mode, (void*)&bpmres)))
    {      
       /* check BPM response */
       analize_bpm_response(&(bpmres.rule_priority),
                            &spawn_log_in_relay, 
                            &prevent_system_call);
       /*
       debug("[ %s ] after analize_bpm_response() spawn_log_in_relay: [ %d ]" \
                 "prevent_system_call: [ %d ] priority [ %d ] ", MODULE_NAME
      	         ,spawn_log_in_relay,prevent_system_call
	         ,bpmres.rule_priority);
       */
       /* log to rellay */      
       if(spawn_log_in_relay==SPAWN_LOG_IN_RELAY)
       {
	 log_sys_fchmodat(dfd,file_name,mode);
       }
  
       /*prevent syscall from happening*/
       if(prevent_system_call==PRIORITY_PREVENT_SYSCALL)
       {
          return -EINVAL;
       }      
     }      
  }  

  return original_fchmodat(dfd,filename, mode);
}



static int patch_syscall_table(struct gl_region regions[], size_t region_count, void* arg){
   
   unsigned long* sys_call_table = regions[0].writeable;

   original_connect =(cast_connect)sys_call_table[__NR_connect];
   debug("[ %s ]  system call table address __NR_connect %p"
        ,MODULE_NAME, original_connect);
   sys_call_table[__NR_connect] =(long unsigned int) new_connect;
   debug("[ %s ]  system call table address __NR_connect hooked with %p"
        ,MODULE_NAME, new_connect);

   original_open = (cast_open)sys_call_table[__NR_open];
   debug("[ %s ]  system call table address __NR_open %p"
        ,MODULE_NAME, original_open);    
   sys_call_table[__NR_open] =  (unsigned long int) new_open;
   debug("[ %s ]  system call table address __NR_open hooked with %p"
        ,MODULE_NAME, new_open);    
   
   original_close = (cast_close)sys_call_table[__NR_close];
   debug("[ %s ]  system call table address __NR_close %p"
        ,MODULE_NAME, original_close);    
   sys_call_table[__NR_close] = (unsigned long int) new_close;
   debug("[ %s ]  system call table address __NR_close hooked with %p"
        ,MODULE_NAME, new_close);    

   original_rename = (cast_rename)sys_call_table[__NR_rename];
   debug("[ %s ]  system call table address __NR_rename %p"
        ,MODULE_NAME, original_rename);    
   sys_call_table[__NR_rename] = (unsigned long int) new_rename;
   debug("[ %s ]  system call table address __NR_rename hooked with %p"
        ,MODULE_NAME, new_rename);   


   original_unlink = (cast_unlink)sys_call_table[__NR_unlink];
   debug("[ %s ]  system call table address __NR_unlink %p"
        ,MODULE_NAME, original_unlink);    
   sys_call_table[__NR_unlink] = (unsigned long int) new_unlink;
   debug("[ %s ]  system call table address __NR_unlink hooked with %p"
        ,MODULE_NAME, new_unlink);  
   
   
   original_chmod = (cast_chmod)sys_call_table[__NR_chmod];
   debug("[ %s ]  system call table address __NR_chmod %p"
       ,MODULE_NAME, original_chmod);      
   sys_call_table[__NR_chmod] = (unsigned long int)new_chmod;
   debug("[ %s ]  system call table address __NR_chmod hooked with %p"
       ,MODULE_NAME, new_chmod);  

   original_fchmodat = (cast_fchmodat)sys_call_table[__NR_fchmodat];
   debug("[ %s ]  system call table address __NR_fchmodat %p"
       ,MODULE_NAME, original_fchmodat);
   sys_call_table[__NR_fchmodat] = (unsigned long int)new_fchmodat;     
   debug("[ %s ]  system call table address __NR_fchmodat hooked with %p"
         ,MODULE_NAME, new_fchmodat);  

   info("[ %s ]  patch system call table for unstub . ", MODULE_NAME);

  return 0;
}


static int unpatch_syscall_table(struct gl_region regions[], size_t region_count, void* arg){

  unsigned long* sys_call_table = regions[0].writeable;


  sys_call_table[__NR_connect] = (unsigned long int)original_connect;
  debug("[ %s ]  system call table address __NR_connect restore %p"
        ,MODULE_NAME,original_connect);

  sys_call_table[__NR_open] = (unsigned long int)original_open;
  debug("[ %s ]  system call table address __NR_open restore %p"
        ,MODULE_NAME,original_open);    

  sys_call_table[__NR_close] = (unsigned long int)original_close;
  debug("[ %s ]  system call table address __NR_close restore %p"
        ,MODULE_NAME,original_close);    


  sys_call_table[__NR_rename]=(unsigned long int)original_rename;
  debug("[ %s ]  system call table address __NR_rename restore %p"
        ,MODULE_NAME,original_rename);


  sys_call_table[__NR_unlink]=(unsigned long int)original_unlink;
  debug("[ %s ]  system call table address __NR_unlink restore %p"
        ,MODULE_NAME,original_unlink);
    

  sys_call_table[__NR_chmod]=(unsigned long int)original_chmod;
  debug("[ %s ]  system call table address __NR_chmod restore %p"
        ,MODULE_NAME,original_chmod);  

  sys_call_table[__NR_fchmodat]=(unsigned long int)original_fchmodat;
  debug("[ %s ]  system call table address __NR_fchmodat restore %p"
       ,MODULE_NAME,original_fchmodat);  
   
  info("[ %s ]  unpach system call table unstub. ", MODULE_NAME);

  return 0;
}






int do_with_write_permissions(int (*fn)(struct gl_region[], size_t, void*)
                             ,struct gl_region regions[],size_t region_count,void* args)
{

  void* remap_with_write_permissions(void* region, size_t len);

  size_t i;
  int result = 0;
   
  if (!fn) return -EINVAL;  /* main function to pach system call table  */

  if (!regions || region_count == 0) return fn(NULL, 0, args); /* error in region  */

  for (i = 0; i < region_count; i++) 
  { 
    /* if remap memory to become writble failed then revert all remapping 
       to continues virtual address*/
    regions[i].writeable = remap_with_write_permissions(regions[i].source, regions[i].length);
    if (!regions[i].writeable) 
    {
      size_t j;
      for (j = 0; j < i; j++)
	vunmap(base_of_page(regions[j].writeable));

      return -ENOMEM;
    }
  }

  fn(regions, region_count, args); // call patch function

  /*revert all remapping to continues virtual address */
  for (i = 0; i < region_count; i++)  vunmap(base_of_page(regions[i].writeable));

  return result;
}



int init_unstub_systcall(void){

  struct gl_region sys_call_table;  
  unsigned long* locate_sys_call_table(void);

  sys_call_table  = (struct gl_region) 
  { 
    .source = locate_sys_call_table(), 
    .length = 256 * sizeof(unsigned long) 
  };

  do_with_write_permissions(patch_syscall_table, &sys_call_table, 1, NULL);
   
  debug("[ %s ] init unstub systcall module, initialized success.", MODULE_NAME); 

  return 0;
}



int destroy_unstub_systcall(void){  

  struct gl_region sys_call_table;
  unsigned long* locate_sys_call_table(void);

  sys_call_table  = (struct gl_region) 
  { 
    .source = locate_sys_call_table(), 
    .length = 256 * sizeof(unsigned long) 
  };

  do_with_write_permissions(unpatch_syscall_table, &sys_call_table, 1, NULL);

  debug("[ %s ]  destroy unstub systcall module, destroyed success.", MODULE_NAME); 

  return 0;
}
