#include "../kcontroller_data_type.h"

static DEFINE_HASHTABLE(h_process_cache,PRPCESS_CACHE_HASH_DISTRIBUTION);
static DEFINE_SPINLOCK(s_lock);

static atomic_long_t cache_node_count = ATOMIC_LONG_INIT(0);


#define M_BYTE (1024*1024)


static inline __attribute__((always_inline)) 
void dump_cache_node(const struct process_cache_node* cache_node); 


void _dump_cache_node(const struct process_cache_node* cache_node){
  dump_cache_node(cache_node);
} 


static inline __attribute__((always_inline)) 
void dump_cache_node(const struct process_cache_node* cache_node) 
{
  const unsigned short sz = 50;
  char atimebuffer[sz], mtimebuffer[sz], ctimebuffer[sz],
       p_atimebuffer[sz], p_mtimebuffer[sz], p_ctimebuffer[sz],
       task_start_at[sz], current_time[sz];

  struct rtc_time tm;
  unsigned long local_time;
  struct timeval ktv;

  memset(&ktv,0,sizeof(struct timeval));
  memset(atimebuffer,0,sz);
  memset(mtimebuffer,0,sz);
  memset(ctimebuffer,0,sz);

  memset(p_atimebuffer,0,sz);
  memset(p_mtimebuffer,0,sz);
  memset(p_ctimebuffer,0,sz);
  memset(task_start_at,0,sz);
  memset(current_time,0,sz);

  /* current time */
  do_gettimeofday(&ktv);

  local_time = (u32)(ktv.tv_sec - (sys_tz.tz_minuteswest * 60)); 
  rtc_time_to_tm(local_time, &tm);
  sprintf(current_time,"%04d-%02d-%02d %02d:%02d:%02d", 
         tm.tm_year + 1900, tm.tm_mon + 1, 
         tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

  /*  process time  */  
  local_time = (u32)(cache_node->data.created_at.tv_sec - (sys_tz.tz_minuteswest * 60));
  rtc_time_to_tm(local_time, &tm);
  sprintf(atimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
         tm.tm_year + 1900, tm.tm_mon + 1, 
         tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

  local_time = (u32)(cache_node->data.modified_at.tv_sec - (sys_tz.tz_minuteswest * 60));
  rtc_time_to_tm(local_time, &tm);
  sprintf(mtimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
         tm.tm_year + 1900, tm.tm_mon + 1, 
         tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  
  local_time = (u32)(cache_node->data.last_accessed_at.tv_sec - (sys_tz.tz_minuteswest * 60));
  rtc_time_to_tm(local_time, &tm);
  sprintf(ctimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
         tm.tm_year + 1900, tm.tm_mon + 1, 
         tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

  /* task start at */
  local_time = (u32)(cache_node->data.task_start_time.tv_sec - (sys_tz.tz_minuteswest * 60));
  rtc_time_to_tm(local_time, &tm);
  sprintf(task_start_at,"%04d-%02d-%02d %02d:%02d:%02d", 
         tm.tm_year + 1900, tm.tm_mon + 1, 
         tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

  /* parent  process time */   
  local_time = (u32)(cache_node->data.parent_created_at.tv_sec - (sys_tz.tz_minuteswest * 60));
  rtc_time_to_tm(local_time, &tm);
  sprintf(p_atimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
         tm.tm_year + 1900, tm.tm_mon + 1, 
         tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

  local_time = (u32)(cache_node->data.parent_modified_at.tv_sec - (sys_tz.tz_minuteswest * 60));
  rtc_time_to_tm(local_time, &tm);
  sprintf(p_mtimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
         tm.tm_year + 1900, tm.tm_mon + 1, 
         tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  
  local_time = (u32)(cache_node->data.parent_last_accessed_at.tv_sec 
                     - (sys_tz.tz_minuteswest * 60));
  rtc_time_to_tm(local_time, &tm);
  sprintf(p_ctimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
         tm.tm_year + 1900, tm.tm_mon + 1, 
         tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

  

       info("[ %s ]                        \n"\
	    "time                     [ %s ]\n"\
	    "pid                      [ %d ]\n"\
            "parent_pid               [ %d ]\n"\
            "path                     [ %s ]\n"\
            "name                     [ %s ]\n"\
            "cmdline                  [ %s ]\n"\
            "created_at               [ %s ]\n"\
            "modified_at              [ %s ]\n"\
            "last_accessed_at         [ %s ]\n"\
	    "file size                [ %llu Bytes ]\n"\
	    "start time               [ %s ]\n"\
            "parent_path              [ %s ]\n"\
            "parent_name              [ %s ]\n"\
            "parent_cmdline           [ %s ]\n"\
            "parent_created_at        [ %s ]\n"\
	    "parent_modified_at       [ %s ]\n"\
	    "parent_last_accessed_at  [ %s ]\n"\
    	    "parent_file_size         [ %llu Bytes ]\n"\
	    ,MODULE_NAME   
	    ,current_time
            ,cache_node->data.pid
	    ,cache_node->data.parent_pid
	    ,cache_node->data.path
	    ,cache_node->data.name
	    ,cache_node->data.cmdline
            ,atimebuffer
	    ,mtimebuffer
    	    ,ctimebuffer
	    ,cache_node->data.file_size
	    ,task_start_at
	    ,cache_node->data.parent_path
            ,cache_node->data.parent_name
            ,cache_node->data.parent_cmdline
            ,p_atimebuffer
	    ,p_mtimebuffer
    	    ,p_ctimebuffer 
	    ,cache_node->data.parent_file_size );


       if(cache_node->data.identifier_valid==1)     
       {
         info("md5                    \n");
         print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,\
	         16, 1,cache_node->data.md5, MD5_LENGTH, false);
       }else
         info("md5 not valid           \n");

       if(cache_node->data.parent_identifier_valid==1)     
       {
         info("parent md5              \n");
         print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,\
	          16, 1,cache_node->data.parent_md5, MD5_LENGTH, false);
       }else
         info("parent md5 not valid    \n");

       info("-----------------------\n");
}

void print_cache(void)
{
   int bkt;
   struct process_cache_node* cache_node=NULL;     
   
   rcu_read_lock();
   
   hash_for_each_rcu(h_process_cache,bkt,cache_node,list) {   
     dump_cache_node(cache_node);
   }
   
   rcu_read_unlock();
}


static void cache_rcu_free_node(struct rcu_head* head)
{
  void _mempool_free_hash(void* obj);

  int cache_size_in_bytes=0;
  struct process_cache_node* proc_cn=NULL;
  proc_cn=container_of(head,struct process_cache_node, rcu_h);

  atomic_long_dec(&cache_node_count);  

  cache_size_in_bytes = (atomic_long_read(&cache_node_count) * sizeof(struct process_cache_node));

  /*  debug("[ %s ] cache_rcu_free_node pid [ %d ] . parent_pid: [ %d ] comm: [ %s ]" \
        " count: [ %ld ]:[ %d ]",
        MODULE_NAME,proc_cn->data.pid, proc_cn->data.parent_pid,
        proc_cn->data.name, atomic_long_read(&cache_node_count)
        ,cache_size_in_bytes);*/

  _mempool_free_hash((void*)proc_cn);
}

#if 0 
static void cache_rcu_remove(pid_t pid)
{
  unsigned long key=0, flags;
  struct process_cache_node* node_del;
  
  memcpy(&key,&pid,sizeof(pid_t));

  spin_lock_irqsave(&s_lock,flags);  
  
  hash_for_each_possible_rcu(h_process_cache,node_del,list,key)
  {
    if(pid==node_del->data.pid)
    {
      hlist_del_init_rcu(&(node_del->list));
      spin_unlock_irqrestore(&s_lock,flags); 
      call_rcu(&(node_del->rcu_h),cache_rcu_free_node);
      //info("[ %s ] cache_rcu_remove()   pid: [ %d ]  removed ! ", MODULE_NAME, pid);
      return;
    }
  }

  spin_unlock_irqrestore(&s_lock,flags); 
}
#endif

void delete_signed_nodes(void)
{
  int bkt;
  unsigned long flags;
  struct process_cache_node* node_del;
  
  synchronize_rcu();

  spin_lock_irqsave(&s_lock,flags);  

  hash_for_each_rcu(h_process_cache,bkt,node_del,list)
  {
    if(node_del->rec_status == CACHE_NODE_DELETED)
    {
      hlist_del_init_rcu(&(node_del->list));
      info("[ %s ] delete_signed_nodes()   pid: [ %d ]  removed ! "
	   , MODULE_NAME, node_del->data.pid);
      call_rcu(&(node_del->rcu_h),cache_rcu_free_node);
    }
  }

  spin_unlock_irqrestore(&s_lock,flags); 
}


static void sign_node_status_delete(pid_t pid)
{
  unsigned long key=0, flags;
  struct process_cache_node* node_del;
  
  memcpy(&key,&pid,sizeof(pid_t));

  synchronize_rcu();

  rcu_read_lock();

  spin_lock_irqsave(&s_lock,flags);  
  
  hash_for_each_possible_rcu(h_process_cache,node_del,list,key)
  {
    if(pid==node_del->data.pid)
    {
      node_del->rec_status = CACHE_NODE_DELETED;
      spin_unlock_irqrestore(&s_lock,flags); 
      rcu_read_unlock();
      return;
    }
  }

  spin_unlock_irqrestore(&s_lock,flags); 

  rcu_read_unlock();
}


static void get_parent_process_information(struct process_cache_node* parent_node_ptr
				    ,unsigned char mode)
{
  extern int proc_pid_cmdline(struct task_struct *task, char * buffer);
  extern char* get_proc_path(struct task_struct* task, char *buf, int buflen);
  extern int __kernel__file_info(const char* task_path, const unsigned char algo
	          ,struct file_info_t* f_inf, unsigned char* identifier_valid); 

  struct task_struct* task_parent;
  char* buffer, *path_ptr=NULL, *p=NULL;
  struct file_attr_t attr;
  struct file_info_t f_inf;
  int res=0;
  /* case we do not have parent then pid 0 (init) will be the parent */
  if(current->parent)
      task_parent = current->parent;
  else
      task_parent = current->real_parent;
#if 0  
  /* check if the parent alive yet, 
     if not then init task (1) will be the real parent.
     for example: this comes to support GUI invoking an application and gnome-shell dies
     right after execve*/
  if((pid_task(find_get_pid(task_parent->pid), PIDTYPE_PID) == NULL)
      || (task_parent->state != TASK_RUNNING)) 
  {
     task_parent = pid_task(find_vpid(1), PIDTYPE_PID);
  }
#endif

  buffer = vmalloc(PAGE_SIZE*sizeof(char));
  if(IS_ERR_OR_NULL(buffer)){
     pr_err("memory allocation error in function  [ %s ]  file [ %s ]"\
            " line [ %d ]\n", __func__, __FILE__, __LINE__ ); \
     return;
  }

  memset(buffer,0,PAGE_SIZE*sizeof(char));

  if((mode == GET_PARENT_CMDLINE) && task_parent)
  { 
    if((res=proc_pid_cmdline(task_parent,buffer))>0)
    { 
      res = (res>EVENT_MAX_PATH_LEN)?(EVENT_MAX_PATH_LEN-1):res;
      strncpy(parent_node_ptr->data.parent_cmdline,buffer,res); 
    }
  }

  memset(buffer,0,PAGE_SIZE*sizeof(char));

  if(task_parent)
  { 
     path_ptr = get_proc_path(task_parent,buffer,EVENT_MAX_PATH_LEN);
     if(!IS_ERR(path_ptr))
     {
       p=get_file_name_from_path(path_ptr);
       if(p)
       {
        strncpy(parent_node_ptr->data.parent_path,path_ptr, (p-path_ptr));
        strncpy(parent_node_ptr->data.parent_name,p,EVENT_MAX_PATH_LEN);	
       }else
       {
         strncpy(parent_node_ptr->data.parent_path, path_ptr,EVENT_MAX_PATH_LEN);
         strncpy(parent_node_ptr->data.parent_name, task_parent->comm,EVENT_MAX_PATH_LEN);
       }       
    }    
  }
  
  /*take file time attributes */
  memset(buffer,0,(PAGE_SIZE*sizeof(char)));
  snprintf(buffer,EVENT_MAX_PATH_LEN,"%s%s",parent_node_ptr->data.parent_path
          ,parent_node_ptr->data.parent_name);

  get_file_attributes_from_path(buffer,&attr);

  __memcpy_parent_file_attr(parent_node_ptr,attr) 

  /* calculate md5 of parent process */
  if((strlen(parent_node_ptr->data.parent_path)>0)
  && (strlen(parent_node_ptr->data.parent_name)>0))
  {
    memset(&f_inf,0,sizeof(struct file_info_t));
    memset(buffer,0,PAGE_SIZE*sizeof(char));
  
    snprintf(buffer,EVENT_MAX_PATH_LEN,"%s%s"
            ,parent_node_ptr->data.parent_path
	    ,parent_node_ptr->data.parent_name);

    if( __kernel__file_info(buffer
			   ,algo_md5
			   ,&f_inf
			   ,&parent_node_ptr->data.parent_identifier_valid) == SUCCESS ) 
       memcpy(parent_node_ptr->data.parent_md5,f_inf.md5,MD5_LENGTH); 
       
    parent_node_ptr->data.parent_file_size = f_inf.file_size;              
  }
   
  vfree(buffer);  
}

static noinline 
int cache_rcu_add_node(struct process_cache_node* process_info,unsigned char mode)
{
  void* _mempool_alloc_hash(void);

  int ret=SUCCESS;
  int cache_size_in_bytes=0;
  unsigned long key=0, flags;
  struct process_cache_node* cache_node=NULL;  

  /* allocate new cache node item   */
  cache_node = (struct process_cache_node*)_mempool_alloc_hash();
  ASSERT_MEMORY_ALLOCATION(cache_node);
  _memset_process_cache_node_data(cache_node);
 
  /* used only by lib_process*/
  if(mode == NODE_FULL_INSERT)
  { 

    cache_node->data.pid = process_info->data.pid;
    cache_node->data.parent_pid = process_info->data.parent_pid;

    strncpy(cache_node->data.path, process_info->data.path
                 ,EVENT_MAX_PATH_LEN);

    strncpy(cache_node->data.name, process_info->data.name
                ,EVENT_MAX_PATH_LEN);

    strncpy(cache_node->data.cmdline, process_info->data.cmdline
                 ,EVENT_MAX_PATH_LEN);

    cache_node->data.created_at = process_info->data.created_at;
    cache_node->data.modified_at = process_info->data.modified_at;
    cache_node->data.last_accessed_at = process_info->data.last_accessed_at;
    
    cache_node->data.file_size= process_info->data.file_size;

    cache_node->data.task_start_time = process_info->data.task_start_time;

    strncpy(cache_node->data.parent_cmdline,process_info->data.parent_cmdline
                 ,EVENT_MAX_PATH_LEN);   
   
    strncpy(cache_node->data.parent_path,process_info->data.parent_path
                 ,EVENT_MAX_PATH_LEN);

    strncpy(cache_node->data.parent_name,process_info->data.parent_name
                 ,EVENT_MAX_PATH_LEN);
     
    cache_node->data.parent_created_at = process_info->data.parent_created_at;
    cache_node->data.parent_modified_at = process_info->data.parent_modified_at;
    cache_node->data.parent_last_accessed_at = process_info->data.parent_last_accessed_at; 
   
    cache_node->data.parent_file_size = process_info->data.parent_file_size;

    /* union then both will be copied into the same memory speace  */
    cache_node->data.identifier_valid=process_info->data.identifier_valid;
    if((cache_node->data.identifier_valid=1)) {
        memcpy(cache_node->data.sha1, process_info->data.sha1
              ,SHA1_LENGTH);          
    }

    /* union then both will be copied into the same memory speace  */
    cache_node->data.parent_identifier_valid=process_info->data.parent_identifier_valid;
    if((cache_node->data.parent_identifier_valid=1)) {
        memcpy(cache_node->data.parent_sha1, process_info->data.parent_sha1
              ,SHA1_LENGTH);          
    }

  }else
  {      /*  used from cache_process_handler.c when process not exist in cache*/
    /* copy data to new cache node item */

    //info("[ %s ] cache_rcu_add_node() start\n", MODULE_NAME);
    //dump_cache_node(process_info);

    cache_node->data.pid = process_info->data.pid;
    cache_node->data.parent_pid = process_info->data.parent_pid;       

    strncpy(cache_node->data.path, process_info->data.path
           ,EVENT_MAX_PATH_LEN);
    strncpy(cache_node->data.name, process_info->data.name
           ,EVENT_MAX_PATH_LEN);
    strncpy(cache_node->data.cmdline, process_info->data.cmdline
           ,EVENT_MAX_PATH_LEN);

    cache_node->data.created_at = process_info->data.created_at;
    cache_node->data.modified_at = process_info->data.modified_at;
    cache_node->data.last_accessed_at = process_info->data.last_accessed_at;

    cache_node->data.task_start_time = process_info->data.task_start_time;

    cache_node->data.parent_file_size = process_info->data.parent_file_size;

    /* union then both will be copied into the same memory speace  */
    cache_node->data.identifier_valid=process_info->data.identifier_valid;
    if((cache_node->data.identifier_valid=1)) {
        memcpy(cache_node->data.sha1, process_info->data.sha1
              ,SHA1_LENGTH);          
    }

    smp_mb();
    /* copy parent process information */
    get_parent_process_information(cache_node,mode);  

    //dump_cache_node(cache_node);
    //info("[ %s ] cache_rcu_add_node() end\n",MODULE_NAME);

  }
  /* build the key which is contained of pid  */  
  memcpy(&key,&(cache_node->data.pid),sizeof(pid_t)); 

  spin_lock_irqsave(&s_lock,flags);
  hash_add_rcu(h_process_cache,&(cache_node->list),key);
  atomic_long_inc(&cache_node_count);  
  cache_size_in_bytes = (atomic_long_read(&cache_node_count) * sizeof(struct process_cache_node));
  spin_unlock_irqrestore(&s_lock,flags);  

  debug("[ %s ] cache_rcu_add_node pid [ %d ] . parent_pid: [ %d ] comm: [ %s ]"\
       " count: [ %ld ]:[ %d ]",
       MODULE_NAME,cache_node->data.pid, cache_node->data.parent_pid,
       cache_node->data.name, atomic_long_read(&cache_node_count)
      ,cache_size_in_bytes);

 return ret;
}

static int cache_rcu_update(struct process_cache_node* process_info)
{
  unsigned long key=0, flags;
  struct process_cache_node* cache_node=NULL;  

  memcpy(&key,&process_info->data.pid,sizeof(pid_t));  

  synchronize_rcu();

  rcu_read_lock();

  hash_for_each_possible_rcu(h_process_cache,cache_node,list,key)
  { 
    if(cache_node->data.pid==process_info->data.pid)
    {
      spin_lock_irqsave(&s_lock,flags);

      //info("[ %s ] cache_rcu_update() start\n",MODULE_NAME);
      //dump_cache_node(process_info);
      //dump_cache_node(cache_node);
      
      if((strlen(process_info->data.path)>0) &&
          strncmp(cache_node->data.path, process_info->data.path
                ,EVENT_MAX_PATH_LEN) != 0)
      {
          strncpy(cache_node->data.path, process_info->data.path
                 ,EVENT_MAX_PATH_LEN);
      }

      if((strlen(process_info->data.name)>0) &&
          strncmp(cache_node->data.name, process_info->data.name
                ,EVENT_MAX_PATH_LEN)!=0)
      {
         strncpy(cache_node->data.name, process_info->data.name
                ,EVENT_MAX_PATH_LEN);
      }

      if((strlen(process_info->data.cmdline)>0) &&
          strncmp(cache_node->data.cmdline, process_info->data.cmdline
                ,EVENT_MAX_PATH_LEN)!=0)
      {
          strncpy(cache_node->data.cmdline, process_info->data.cmdline
                 ,EVENT_MAX_PATH_LEN);
      }

      cache_node->data.created_at = process_info->data.created_at;
      cache_node->data.modified_at = process_info->data.modified_at;
      cache_node->data.last_accessed_at = process_info->data.last_accessed_at;
      cache_node->data.file_size= process_info->data.file_size;
     
      cache_node->data.task_start_time = process_info->data.task_start_time;

      if((strlen(process_info->data.parent_name)>0) &&
          strncmp(cache_node->data.parent_name,process_info->data.parent_name
                ,EVENT_MAX_PATH_LEN)!=0)
      {
          strncpy(cache_node->data.parent_name,process_info->data.parent_name
                 ,EVENT_MAX_PATH_LEN);
      }

      if((strlen(process_info->data.parent_path)>0) &&
          strncmp(cache_node->data.parent_path,process_info->data.parent_path
                ,EVENT_MAX_PATH_LEN)!=0)
      {
          strncpy(cache_node->data.parent_path,process_info->data.parent_path
                 ,EVENT_MAX_PATH_LEN);

      }


      if((strlen(process_info->data.parent_cmdline)>0) && 
          strncmp(cache_node->data.parent_cmdline,process_info->data.parent_cmdline
                ,EVENT_MAX_PATH_LEN)!=0)
      {
          strncpy(cache_node->data.parent_cmdline,process_info->data.parent_cmdline
                 ,EVENT_MAX_PATH_LEN);   
   
      }


      if(cache_node->data.parent_created_at.tv_sec==0)
        cache_node->data.parent_created_at = process_info->data.parent_created_at;

      if(cache_node->data.parent_modified_at.tv_sec==0)
	cache_node->data.parent_modified_at = process_info->data.parent_modified_at;

      if(cache_node->data.parent_last_accessed_at.tv_sec==0)
	cache_node->data.parent_last_accessed_at = process_info->data.parent_last_accessed_at; 
   
      if(cache_node->data.parent_file_size==0)
	cache_node->data.parent_file_size = process_info->data.parent_file_size;

      /* union then both will be copied into the same memory speace  */
      if(process_info->data.identifier_valid==1) {
          memcpy(cache_node->data.sha1, process_info->data.sha1
                ,SHA1_LENGTH);
          cache_node->data.identifier_valid=1;
      }

      /* union then both will be copied into the same memory speace  */
      if(process_info->data.parent_identifier_valid==1) {
          memcpy(cache_node->data.parent_sha1, process_info->data.parent_sha1
                ,SHA1_LENGTH);
          cache_node->data.parent_identifier_valid=1;
      }
      
      //dump_cache_node(cache_node);
      //info("[ %s ] cache_rcu_update() end\n", MODULE_NAME);

      spin_unlock_irqrestore(&s_lock,flags);   
      rcu_read_unlock();

      smp_mb();

      return SUCCESS;
    }

  }

  rcu_read_unlock();

 return ERROR;
}


int get_process_cache_node(pid_t pid, struct process_cache_node* process_info)
{
  struct process_cache_node* p;
  unsigned long key=0; 


  memcpy(&key,&pid,sizeof(pid_t));  

  //  debug("[ CACHE ] get_process_cache_node  pid [ %d ]  key: %d", pid,key);

  rcu_read_lock();

  hash_for_each_possible_rcu(h_process_cache,p,list,key)
  { /*
     debug("[ CACHE ] get_process_cache_node  pid [ %d ] process_info->data.pid [ %d ]." \
     " key: %lu ", pid, process_info->data.pid, key);    */

    if(p->data.pid==pid)
    {
      /* special case to be protected from page fault
         so if node will be used out side for period of time, it would be better 
         to return a copy of it and not a pointer to memory address which may not be on virtual 
         address space of the ko */
      if(process_info!=NULL)
      {
         memcpy(process_info,p,sizeof(struct process_cache_node));
      }

      rcu_read_unlock();
      return SUCCESS;
    }
  }

  rcu_read_unlock();

 return ERROR;
}


int cache_rcu_process_item(pid_t pid, struct process_cache_node* process_info
                          ,unsigned char mode)
{
  int ret=SUCCESS;
  struct process_cache_node cache_node;     
  memset(&cache_node,0,sizeof(struct process_cache_node));
 
  smp_rmb();

  if(NULL != process_info)
  {
     ret=get_process_cache_node(pid,&cache_node);
     smp_rmb();

     if(SUCCESS==ret)
     { /* update existing item */
       cache_rcu_update(process_info);
     }else if(ERROR==ret)
     { /* add new cache node item */
       cache_rcu_add_node(process_info,mode); 
     }     
  }else if(SUCCESS==get_process_cache_node(pid,NULL))  
  {  /* delete item */    
     //cache_rcu_remove(pid);
    sign_node_status_delete(pid);
  }else
  {  
     ret=ERROR;
  }

 return ret;
}



static inline __attribute__((always_inline))  
void destroy_cache(void)
{
  int bkt, cache_size_in_bytes=0; 
  unsigned long flags;
  struct process_cache_node* cache_node=NULL;     
  

  spin_lock_irqsave(&s_lock,flags);  

  hash_for_each_rcu(h_process_cache,bkt,cache_node,list) 
  {
    hlist_del_init_rcu(&(cache_node->list));
    call_rcu(&(cache_node->rcu_h),cache_rcu_free_node);
  }    

  cache_size_in_bytes = (atomic_long_read(&cache_node_count) * sizeof(struct process_cache_node));

  if(0)
  info("[ %s ] destroy_cache count: [ %ld ]:[ %d ]",
       MODULE_NAME,atomic_long_read(&cache_node_count),cache_size_in_bytes);

  spin_unlock_irqrestore(&s_lock,flags); 

  rcu_barrier();
}


int init_process_cache(unsigned int size)
{
  atomic_long_set(&cache_node_count,0);
  return 0;
}


int destroy_process_cache(void)
{
  destroy_cache();
  info("[ %s ] cache is going down all memory is free. ", MODULE_NAME );
  return 0;
}




