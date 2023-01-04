#include "os_interceptor_data_type.h"



void write_to_chan_format(unsigned char log_level, unsigned int relay_channel_idx
                         ,const char *fmt, ... )
{


	va_list args;
	struct relay_logger_t rl;
	struct timespec ts; 

	memset(&rl, 0, sizeof(struct relay_logger_t));  
	memset(&ts, 0, sizeof(struct timespec));

	va_start (args, fmt);
	vsnprintf(rl.data, DRIVER_LOG_MAX_SIZE, fmt, args);
	va_end (args);

	getnstimeofday(&ts);
	memcpy(rl.tstamp, &ts, sizeof(struct timespec));
	rl.log_level = log_level;

	write_to_chan((void*)&rl, sizeof(struct relay_logger_t), relay_channel_idx);
}

int move_addr_to_kernel(void __user *uaddr, int ulen, struct sockaddr_storage *kaddr) {

	if ( ulen < 0 || ulen > sizeof(struct sockaddr_storage))
		return -EINVAL;
	if  (ulen == 0 )
		return 0;
	if ( copy_from_user(kaddr, uaddr, ulen) )
		return -EFAULT;

        return 0;
}


int analize_bpm_response(unsigned int *rule_priority, unsigned short *spawn_log_in_relay
			 ,unsigned short *prevent_system_call)
{


	int res = 0;
  
	switch( (*rule_priority) ) {

		/* 
		   not in use.  allow system call to continue  
		*/
	case BPM_PRIORITY_UNINITILIZED:  //0
		(*spawn_log_in_relay)  = DO_NOT_SPAWN_LOG_IN_RELAY;   //3
		(*prevent_system_call) = PRIORITY_ALLOW_SYSTEM_CALL;  //1
		break;  
		/* 
		   allow, do not spawn log in relay 
		*/
	case BPM_PRIORITY_INTERNAL:    //1 
		(*spawn_log_in_relay)  = SPAWN_LOG_IN_RELAY;          //2
		(*prevent_system_call) = PRIORITY_ALLOW_SYSTEM_CALL;  //1
		break;       
		/* 
		   allow, and spawn log in relay 
		*/
	case BPM_PRIORITY_ALLOW:     //2
		(*spawn_log_in_relay)  = SPAWN_LOG_IN_RELAY;          //2
		(*prevent_system_call) = PRIORITY_ALLOW_SYSTEM_CALL;  //1
		break;
		/* 
		   allow, and spawn log in relay and agent should report it to server 
		*/       
	case BPM_PRIORITY_SERVER_NOTIFY: // BPM_PRIORITY_SUSPECT same priority value 3
		(*spawn_log_in_relay)  = SPAWN_LOG_IN_RELAY;          //2
		(*prevent_system_call) = PRIORITY_ALLOW_SYSTEM_CALL;  //1
		break;   
		/*
		  1. prevent system call from happening and spawn log in relay with prevent 
 		  2.  if BPM respond with prevent, but we are in no prevention mode then 
		      allow spawn log in relay with BPM_PRIORITY_DETECT
		*/
	case BPM_PRIORITY_PREVENT: //5
		(*spawn_log_in_relay)  = SPAWN_LOG_IN_RELAY;           //2
		(*prevent_system_call) = PRIORITY_PREVENT_SYSCALL;     //4
		break;
	default:  
		(*spawn_log_in_relay)  = DO_NOT_SPAWN_LOG_IN_RELAY;    //3
		(*prevent_system_call) = PRIORITY_ALLOW_SYSTEM_CALL;   //1
		error("[ %s ] undefined priority code: [ %u ]  ", MODULE_NAME, (*rule_priority));   
		break;     
	}


	return res;
}
 


unsigned short check_permissions(void) {  int ret=SUCCESS;  return ret; }

char* get_proc_path(struct task_struct* task, char *buf, int buflen) {


	struct file *exe_file = NULL;
	char *result = ERR_PTR(-ENOENT);
	struct mm_struct *mm = NULL;
  
	if (!task) {
		goto out;
	}	 

	mm = get_task_mm(task);
	if (!mm) {
		goto out;
	}
    
	down_read(&mm->mmap_sem);
	exe_file = mm->exe_file;
   
	if (exe_file) {
		get_file(exe_file);
		path_get(&exe_file->f_path);
	}
    
	up_read(&mm->mmap_sem);
	mmput(mm);

	if(exe_file) {
		result = d_path(&exe_file->f_path, buf, buflen);
		path_put(&exe_file->f_path);
		fput(exe_file);
	}
out:

	return result;
}


void get_cmdline_args(struct task_struct *task, char *cmdline, int cmdlen) {

	struct mm_struct* mm;
	int calc_cmd_len = 0;  

	if (!task) {
		goto out;
	}	 

	mm = get_task_mm(task);
	if (!mm) {
		goto out;
	}  

	down_read(&mm->mmap_sem);
  
	calc_cmd_len = mm->arg_end - mm->arg_start;  
 
	strncpy(cmdline, (char*)mm->arg_start, cmdlen);  
     
	up_read(&mm->mmap_sem);  
	mmput(mm);

out:

	return;
}


static int __access_remote_vm(struct task_struct *tsk, struct mm_struct *mm,
			      unsigned long addr, void *buf, int len, int write)
{


	struct vm_area_struct *vma;
	void *old_buf = buf;

	down_read(&mm->mmap_sem);
	/* 
	   ignore errors, just check how much was successfully transferred 
	*/
	while (len) {
		int bytes, ret, offset;
		void *maddr;
		struct page *page = NULL;

		ret = get_user_pages(tsk, mm, addr, 1,
				     write, 1, &page, &vma);
		if ( ret <= 0 ) {
		/*
		 * Check if this is a VM_IO | VM_PFNMAP VMA, which
		 * we can access using slightly different code.
		 */
#ifdef CONFIG_HAVE_IOREMAP_PROT
			vma = find_vma(mm, addr);
			if (!vma || vma->vm_start > addr)
				break;
			if (vma->vm_ops && vma->vm_ops->access)
				ret = vma->vm_ops->access(vma, addr, buf,
							  len, write);
			if (ret <= 0)
#endif
				break;
			bytes = ret;

		} else 
		{
			bytes = len;
			offset = addr & (PAGE_SIZE-1);
			if (bytes > PAGE_SIZE - offset)
				bytes = PAGE_SIZE-offset;
			
			maddr = kmap(page);
			if (write) {
				copy_to_user_page(vma, page, addr,
						  maddr + offset, buf, bytes);
				set_page_dirty_lock(page);
			} else {
				copy_from_user_page(vma, page, addr,
						    buf, maddr + offset, bytes);
			}
			kunmap(page);
			page_cache_release(page);
		}
		len -= bytes;
		buf += bytes;
		addr += bytes;
	}
	up_read(&mm->mmap_sem);

	return buf - old_buf;
}

int proc_pid_cmdline(struct task_struct *task, char *buffer) {


	int res = 0;
	unsigned int len;
	struct mm_struct *mm = get_task_mm(task);

	if (!mm)
		goto out;
	if (!mm->arg_end)
		goto out_mm;/* Shh! No looking before we're done */

	len = mm->arg_end - mm->arg_start;
 
	if (len > PAGE_SIZE)
		len = PAGE_SIZE;
 
	res = __access_remote_vm(task, mm, mm->arg_start, buffer, len, 0);

	// If the nul at the end of args has been overwritten, then
	// assume application is using setproctitle(3).
	if (res > 0 && buffer[res-1] != '\0' && len < PAGE_SIZE) {

		len = strnlen(buffer, res);
		if (len < res) {
			res = len;
		} else 
		{
			len = mm->env_end - mm->env_start;
			if (len > PAGE_SIZE - res)
				len = PAGE_SIZE - res;
			res += __access_remote_vm(task,mm, mm->env_start, buffer+res, len, 0);
			res = strnlen(buffer, res);
		}
	}

out_mm:
	mmput(mm);
out:
	return res;
}



void dump_event(struct event_t *evt) {



	const unsigned short sz = 50;
	struct rtc_time tm;
	char atimebuffer[sz], mtimebuffer[sz], ctimebuffer[sz],	p_atimebuffer[sz], 
		p_mtimebuffer[sz], p_ctimebuffer[sz], task_start_at[sz], current_time[sz]; 
    


	memset(atimebuffer, 0, sz);
	memset(mtimebuffer, 0, sz);
	memset(ctimebuffer,0, sz);
	memset(p_atimebuffer, 0, sz);
	memset(p_mtimebuffer, 0, sz);
	memset(p_ctimebuffer, 0, sz);
	memset(task_start_at, 0, sz);
	memset(current_time, 0, sz);

	rtc_time_to_tm(evt->caller_created_at, &tm);
	sprintf(atimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
		tm.tm_year + 1900, tm.tm_mon + 1, 
		tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	rtc_time_to_tm(evt->caller_modified_at, &tm);
	sprintf(mtimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
		tm.tm_year + 1900, tm.tm_mon + 1, 
		tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	rtc_time_to_tm(evt->caller_last_accessed_at, &tm);
	sprintf(ctimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
		tm.tm_year + 1900, tm.tm_mon + 1, 
		tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	rtc_time_to_tm(evt->caller_start_at, &tm);
	sprintf(task_start_at,"%04d-%02d-%02d %02d:%02d:%02d", 
		tm.tm_year + 1900, tm.tm_mon + 1, 
		tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	rtc_time_to_tm(evt->parent_created_at, &tm);
	sprintf(p_atimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
		tm.tm_year + 1900, tm.tm_mon + 1, 
		tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	
	rtc_time_to_tm(evt->parent_modified_at, &tm);
	sprintf(p_mtimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
		tm.tm_year + 1900, tm.tm_mon + 1, 
		tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	rtc_time_to_tm(evt->parent_last_accessed_at, &tm);
	sprintf(p_ctimebuffer,"%04d-%02d-%02d %02d:%02d:%02d", 
		tm.tm_year + 1900, tm.tm_mon + 1, 
		tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	info("[ %s ]\n"				\
	     "syscall                     [ %d ]\n"	\
	     "user_id                     [ %d ]\n"	\
	     "user_group_id               [ %d ]\n"	\
	     "caller_process_id           [ %d ]\n"	\
	     "caller_thread_id            [ %d ]\n"	\
	     "caller_path                 [ %s ]\n"	\
	     "caller_name                 [ %s ]\n"	\
	     "caller_cmd                  [ %s ]\n"	\
	     "caller_created_at           [ %s ]\n"	\
	     "caller_modified_at          [ %s ]\n"	\
	     "caller_last_accessed_at     [ %s ]\n"	\
	     "caller_file_size            [ %llu ]\n"	\
	     "task_start_at               [ %s ]\n"	\
	     "event_time_diff             [ %llu ]\n"	\
	     "parent_process_id           [ %d ]\n"	\
	     "parent_path                 [ %s ]\n"	\
	     "parent_name                 [ %s ]\n"	\
	     "parent_cmd                  [ %s ]\n"	\
	     "parent_created_at           [ %s ]\n"	\
	     "parent_modified_at          [ %s ]\n"	\
	     "parent_last_accessed_at     [ %s ]\n"	\
	     "parent_file_size            [ %llu ]\n"	\
	     "network.ipv4                [ %d ]\n"	\
	     "network.target_port         [ %d ]\n"	\
	     "target.target_path          [ %s ]\n"	\
	     "target.target_name          [ %s ]\n"	\
	     "target.target_cmd           [ %s ]\n"	\
	     ,MODULE_NAME
	     ,evt->syscall
	     ,evt->user_id
	     ,evt->user_group_id
	     ,evt->caller_process_id
	     ,evt->caller_process_id
	     ,evt->caller_path
	     ,evt->caller_name
	     ,evt->caller_cmd
	     ,atimebuffer
	     ,mtimebuffer
	     ,ctimebuffer
	     ,evt->caller_file_size
	     ,task_start_at
	     ,evt->event_time_diff
	     ,evt->parent_process_id
	     ,evt->parent_path
	     ,evt->parent_name
	     ,evt->parent_cmd
	     ,p_atimebuffer
	     ,p_mtimebuffer
	     ,p_ctimebuffer
	     ,evt->caller_file_size
	     ,evt->network.ipv4
	     ,evt->network.target_port
	     ,evt->target.target_path
	     ,evt->target.target_name
	     ,evt->target.target_cmd ); 
	
	if (evt->caller_md5.is_valid == 1) {
		info("\nmd5                    \n");
		print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,	\
			       16, 1,evt->caller_md5.md5, MD5_LENGTH, false);
	}else
		info("\nmd5 not valid           \n");
  
	if (evt->parent_md5.is_valid == 1) {
		info("\nparent md5              \n");
		print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,	\
			       16, 1,evt->parent_md5.md5, MD5_LENGTH, false);
	}else
		info("\nparent md5 not valid    \n");

	info("----------------------------------------------------------------------\n");
}



char* get_file_name_from_path(char *path) {


	int i = 0;
	for( i = strlen(path);  i >= 0; i-- ) {
		if (path[i] == '/') {
			return &path[i+1]; 
		}
	}

	return NULL;
}

/* get local directory for process */
char* get_pwd(struct task_struct *task, char *buf){


	struct path pwd;
	char *p =NULL;

	spin_lock(&task->fs->lock);
	pwd = task->fs->pwd;
	path_get(&pwd);
	spin_unlock(&task->fs->lock);

	memset(buf, 0, EVENT_MAX_PATH_LEN * sizeof(char));
	p = dentry_path_raw(pwd.dentry, buf, EVENT_MAX_PATH_LEN);
	path_put(&pwd);

	if ( !IS_ERR(p) ) return p;
	
	return NULL;
}


/*
 get file path, md5, file size
 this function should be used when we do not have the file full path but just 
 its name, example running command "cat" from any path 
 this function will get the original path of "cat" which is /usr/bin/cat . 
 the function use system call open read and close the same way as in user space. 
*/
int __user__file_info(const char __user *filename, const unsigned char algo
		     ,struct file_info_t *f_inf, unsigned char *identifier_valid)
{

	extern asmlinkage long (*original_sys_open_fn)(int dfd, const char __user *filename,
						       int flags, umode_t mode);

	extern asmlinkage long (*original_sys_close_fn)(struct files_struct *files
							,unsigned fd);

	/*
	  always open with root permissions
	*/
	umode_t mode = S_IFREG|0644; 
	struct fd f;
	int fd = 0, flags = O_RDONLY;
	char* pwd = NULL, *file_buffer = NULL;
	struct kstat stat;
	mm_segment_t fs;
	char md5sum[MD5_LENGTH], sha1sum[SHA1_LENGTH], name[EVENT_MAX_PATH_LEN];

	if ( force_o_largefile() ) flags |= O_LARGEFILE;
	fd = original_sys_open_fn(AT_FDCWD, filename, flags, mode); 
	if( !(fd < 0) ) {
		f = fdget(fd);  
		if (!(f.file))
			return (-EBADF);
       
		memset(name, 0, EVENT_MAX_PATH_LEN);
		memset(f_inf->path, 0, EVENT_MAX_PATH_LEN * sizeof(char));
		pwd = dentry_path_raw(f.file->f_path.dentry, name, EVENT_MAX_PATH_LEN);
 
		if ( !IS_ERR(pwd) )
			strncpy(f_inf->path, pwd, EVENT_MAX_PATH_LEN);
	
		debug("[ %s ] _file_info  path: %s", MODULE_NAME, f_inf->path);

		/* 
		   get file stat 
		*/
		vfs_fstat(fd, &stat);

		debug("[ %s ] _file_info  file size: %llu", MODULE_NAME, stat.size);

		file_buffer = vmalloc(stat.size * sizeof(char));
		ASSERT_MEMORY_ALLOCATION(file_buffer);
		memset(file_buffer, 0, stat.size * sizeof(char));

		f_inf->file_size = stat.size;


		/* 
		   Get current segment descriptor 
		*/
		fs = get_fs();
		/* 
		   Set segment descriptor associated to kernel space 
		*/
		set_fs(get_ds());
		/* 
		   Read the file 
		*/
		f.file->f_op->read(f.file, file_buffer, stat.size, &f.file->f_pos);
		/* 
		   Restore segment descriptor 
		*/
		set_fs(fs);

		fdput(f);

		original_sys_close_fn(current->files, fd);    
       
		switch(algo) {
		case algo_md5: 
			memset(md5sum,0,MD5_LENGTH);
			if( SUCCESS == __crypto_run_algorithem(algo, file_buffer, stat.size, md5sum)) { 
				memcpy(f_inf->md5,md5sum,MD5_LENGTH);  
				*identifier_valid=1;
			}
			break;
		case algo_sha1:
			memset(sha1sum,0,SHA1_LENGTH);
			if( SUCCESS == __crypto_run_algorithem(algo, file_buffer, stat.size, sha1sum)) { 
				memcpy(f_inf->sha1, sha1sum, SHA1_LENGTH);  
				*identifier_valid = 1;
			}
			break;
		default:
			error("[ %s ] unsupported algorithem. algo: %u", MODULE_CRYPTO, algo);
			*identifier_valid = 0;
			break;
		}       
       
		vfree(file_buffer);
	} else
		return ERROR;

	return SUCCESS;
}




/*
 get md5, file size
 this function should be used when we have the file full path. 
 example running command "/usr/bin/cat" from any path 
 this function uses file operation structure in addition to invoke open read and close 
*/
int __kernel__file_info(const char *task_path, const unsigned char algo
		       ,struct file_info_t *f_inf, unsigned char *identifier_valid) 
{


	char *file_buffer=NULL;
 
	mm_segment_t fs;
	struct kstat stat;
	struct file *_file;
	umode_t mode = S_IFREG|0644;
	int flags = O_RDONLY, ret = ERROR;     
	char file_identifyer[SHA1_LENGTH];    


	_file = NULL;
 
	debug("[ %s ]  task_path %s", MODULE_NAME, task_path); 

	if ( force_o_largefile() ) flags |= O_LARGEFILE;

	_file = filp_open(task_path, flags, mode);
    
	if ( !IS_ERR(_file) ) {             

		debug("[ %s ]  task_path %s  file open success", MODULE_NAME, task_path); 
		fs = get_fs();
		set_fs(get_ds());

		vfs_stat(task_path, &stat);
		debug("[ %s ]  task_path %s  file fstat success", MODULE_NAME, task_path);

		file_buffer = vmalloc(stat.size * sizeof(char));
		if (!file_buffer) {
			ret = ERROR;
			pr_err("memory allocation error in function  [ %s ]  file [ %s ]" \
			       " line [ %d ]\n", __func__, __FILE__, __LINE__ ); \
			filp_close(_file,NULL);
			set_fs(fs);
			return ret;
		}

		f_inf->file_size= stat.size;

		memset(file_buffer, 0, stat.size * sizeof(char));
		_file->f_op->read(_file, file_buffer, stat.size, &_file->f_pos);
		set_fs(fs);
		filp_close(_file,NULL);   

		memset(file_identifyer, 0, SHA1_LENGTH);

		switch(algo) {
		case algo_md5: 
			if( (ret = __crypto_run_algorithem(algo, file_buffer, stat.size,
							   file_identifyer)) == SUCCESS )
			{ 
				memcpy(f_inf->md5, file_identifyer, MD5_LENGTH);  
				*identifier_valid = 1;	       
			} else
				*identifier_valid = 0;
			break;
		case algo_sha1:
			if( (ret = __crypto_run_algorithem(algo, file_buffer, stat.size,
							   file_identifyer)) == SUCCESS ) 
			{ 
				memcpy(f_inf->sha1, file_identifyer, SHA1_LENGTH);  
				*identifier_valid = 1;
			}else
				*identifier_valid = 0;
			break;
		default:
			error("[ %s ] unsupported algorithem. algo: %u", MODULE_CRYPTO, algo);
			*identifier_valid = 0;
			break;
		}       
		
		vfree(file_buffer); 
	}
	

	return ret;
}



struct timespec get_process_runtime(pid_t pid) {


	char task_path[EVENT_MAX_PATH_LEN];
	struct kstat stat;    
	mm_segment_t fs;
	struct timespec ts;
  
	memset(&ts, 0, sizeof(struct timespec)); 
	memset(task_path, 0, EVENT_MAX_PATH_LEN);
	sprintf(task_path,"/proc/%d", pid);

	fs = get_fs();
	set_fs(get_ds());

	vfs_stat(task_path, &stat);   

	/*take start time*/
	ts=stat.atime;
	set_fs(fs); 

	return ts;
}


void get_file_attributes_from_path(const char *file_path, struct file_attr_t *attr) {



	struct kstat stat;    
	mm_segment_t fs;

	if( !(strlen(file_path) > 0) ) return;

	fs = get_fs();
	set_fs(get_ds());
	
	vfs_stat(file_path, &stat);   

	/*take file time attributes */
	attr->created_at=stat.ctime;
	attr->modified_at=stat.mtime;
	attr->last_accessed_at=stat.atime;

	set_fs(fs); 
}

 
