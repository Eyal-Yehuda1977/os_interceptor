#include "../kcontroller_data_type.h"


extern char* get_proc_path(struct task_struct* task, char *buf, int buflen);
extern int proc_pid_cmdline(struct task_struct *task, char * buffer);

static void get_parent_process_info(struct process_cache_node* process_info
                                   ,struct task_struct* task
			           ,unsigned char* path_valid)
{
    struct task_struct* task_parent;
    char buffer[MAX_BUF_HALF_K], buff[MAX_BUF_HALF_K],*path_ptr=NULL,*p=NULL;
    int res=0;
    struct file_attr_t attr;

    /* case we do not have parent then pid 0 (init) will be the parent */
    if(task->parent)
      task_parent = task->parent;
    else
      task_parent = task->real_parent;

    process_info->data.parent_pid = task_parent->tgid;
    debug("[ %s ]  parent_pid:  %d",MODULE_NAME,process_info->data.parent_pid);    

    memset(buffer,0,MAX_BUF_HALF_K);    
    path_ptr = get_proc_path(task_parent,buffer,EVENT_MAX_PATH_LEN);
    
    if(!IS_ERR(path_ptr))
    {

      *path_valid=1;

      p=get_file_name_from_path(path_ptr);
      if(p)
      {
        strncpy(process_info->data.parent_path,path_ptr, (p-path_ptr));
        strncpy(process_info->data.parent_name,p,EVENT_MAX_PATH_LEN);
      }else
      {
        strncpy(process_info->data.parent_path,path_ptr, EVENT_MAX_PATH_LEN);
        strncpy(process_info->data.parent_name,task_parent->comm, EVENT_MAX_PATH_LEN);
      }
    }else
      strncpy(process_info->data.parent_name,task_parent->comm,EVENT_MAX_PATH_LEN);
    

    debug("[ %s ]  parent_name:  %s",MODULE_NAME,process_info->data.parent_name);        
    debug("[ %s ]  parent_path:  %s",MODULE_NAME,process_info->data.parent_path);        

    memset(buffer,0,MAX_BUF_HALF_K);    

    if((res = proc_pid_cmdline(task_parent,buffer))>0)
    {
      memset(buff,0,MAX_BUF_HALF_K);    
      snprintf(buff,res,"%s",buffer);
      strncpy(process_info->data.parent_cmdline,buff,EVENT_MAX_PATH_LEN);
      debug("[ %s ]  parent_cmdline:  %s",MODULE_NAME,process_info->data.parent_cmdline);        
    }

    /*take file time attributes */  
    memset(buffer,0,sizeof(buffer));
    snprintf(buffer,EVENT_MAX_PATH_LEN,"%s%s",process_info->data.parent_path
	     ,process_info->data.parent_name);
    get_file_attributes_from_path(buffer,&attr);
    __memcpy_parent_file_attr(process_info,attr)
} 


static void get_task_info(struct process_cache_node* process_info
                         ,struct task_struct* task
		         ,unsigned char* path_valid) 
{ 

    char buffer[MAX_BUF_HALF_K], buff[MAX_BUF_HALF_K],*path_ptr=NULL,*p=NULL;
    int res=0;
    struct file_attr_t attr;
    
    process_info->data.pid = task->tgid;
    debug("[ %s ]  pid:  %d",MODULE_NAME,process_info->data.pid);       

    memset(buffer,0,MAX_BUF_HALF_K);    
    path_ptr = get_proc_path(task,buffer,EVENT_MAX_PATH_LEN);
    
    if(!IS_ERR(path_ptr))
    {

      *path_valid=1;

      p=get_file_name_from_path(path_ptr);     
      if(p)
      {
        strncpy(process_info->data.path,path_ptr, (p-path_ptr));
        strncpy(process_info->data.name,p,EVENT_MAX_PATH_LEN);
      }else
      {
        strncpy(process_info->data.path,path_ptr, EVENT_MAX_PATH_LEN);
        strncpy(process_info->data.name,task->comm, EVENT_MAX_PATH_LEN);
      }

    }else
      strncpy(process_info->data.name,task->comm,EVENT_MAX_PATH_LEN);
      
    debug("[ %s ]  name:  %s",MODULE_NAME,process_info->data.name);    
    debug("[ %s ]  path:  %s",MODULE_NAME,process_info->data.path);    

    memset(buffer,0,MAX_BUF_HALF_K);    
    
    if((res = proc_pid_cmdline(task,buffer))>0) 
    {
      memset(buff,0,MAX_BUF_HALF_K);    
      snprintf(buff,res,"%s",buffer);
      strncpy(process_info->data.cmdline,buff,EVENT_MAX_PATH_LEN);
      debug("[ %s ]  cmdline:  %s",MODULE_NAME,process_info->data.cmdline);    
    }

    /*take file time attributes */ 
    memset(buffer,0,sizeof(buffer));
    snprintf(buffer,EVENT_MAX_PATH_LEN,"%s%s",process_info->data.path
	     ,process_info->data.name);
    get_file_attributes_from_path(buffer,&attr);
    __memcpy_file_attr(process_info,attr)

    /* get task runtime*/
    process_info->data.task_start_time = get_process_runtime(process_info->data.pid);
}



void get_parent_process_md5(struct process_cache_node* process_info)
{
  int __kernel__file_info(const char* task_path, const unsigned char algo
	          ,struct file_info_t* f_inf, unsigned char* identifier_valid); 

  char task_path[EVENT_MAX_PATH_LEN];
  struct file_info_t f_inf;

  memset(task_path,0,sizeof(char)*EVENT_MAX_PATH_LEN);
 
  snprintf(task_path,EVENT_MAX_PATH_LEN,"%s%s"
          ,process_info->data.parent_path,process_info->data.parent_name);       

  memset(&f_inf,0,sizeof(struct file_info_t));

  if( __kernel__file_info(task_path, algo_md5, &f_inf,
		  &process_info->data.parent_identifier_valid) == SUCCESS ) 
       memcpy(process_info->data.parent_md5,f_inf.md5,MD5_LENGTH);         
  
  process_info->data.parent_file_size = f_inf.file_size;
} 

  
void get_process_md5(struct process_cache_node* process_info)
{
  int __kernel__file_info(const char* task_path, const unsigned char algo
	          ,struct file_info_t* f_inf, unsigned char* identifier_valid); 

  char task_path[EVENT_MAX_PATH_LEN];
  struct file_info_t f_inf;

  memset(task_path,0,sizeof(char)*EVENT_MAX_PATH_LEN);

  snprintf(task_path,EVENT_MAX_PATH_LEN,"%s%s"
          ,process_info->data.path,process_info->data.name);       

  memset(&f_inf,0,sizeof(struct file_info_t));

  if( __kernel__file_info(task_path, algo_md5, &f_inf,
		  &process_info->data.identifier_valid) == SUCCESS ) 
       memcpy(process_info->data.md5,f_inf.md5,MD5_LENGTH);         
  
  process_info->data.file_size = f_inf.file_size;
} 



void process_list_itertor(void)
{
  
  struct task_struct* task;
  unsigned char path_valid=0;
  unsigned int proc_cnt=0;
  struct process_cache_node* process_info=NULL; 


  process_info = (struct process_cache_node*) vmalloc(sizeof(struct process_cache_node));

  rcu_read_lock();

  for_each_process(task)
  {     
   
    if(task->tgid == current->tgid) continue;
    
    if(task->state == TASK_STOPPED || task->state == TASK_TRACED) continue;
    
    path_valid=0;
    proc_cnt++;      

    debug("[ %s ]----------------------------------------------------------------------------"
	 ,MODULE_NAME);
  
    memset(process_info,0,sizeof(struct process_cache_node));

    get_task_info(process_info,task,&path_valid);
    if(path_valid==1)
      get_process_md5(process_info);

    path_valid=0;

    get_parent_process_info(process_info,task,&path_valid);         
    if(path_valid==1)
      get_parent_process_md5(process_info);


    cache_rcu_process_item(process_info->data.pid,
                           process_info,NODE_FULL_INSERT);

    debug("[ %s ]  after cache_rcu_process_item ",MODULE_NAME);        


  }
  rcu_read_unlock();

  vfree(process_info);

  info("[ %s ]  process scan found [ %u ] process."
         ,MODULE_NAME,proc_cnt);          

}


int init_process_scan(void)
{
  int ret = SUCCESS;

  info("[ %s ]  init_process_scan <begin>",MODULE_NAME);          

  process_list_itertor(); 

  //print_cache();

  info("[ %s ]  init_process_scan <end>",MODULE_NAME);          

  return ret;
}



