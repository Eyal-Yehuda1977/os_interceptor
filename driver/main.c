#include "kcontroller_data_type.h"





MODULE_LICENSE(DRIVER_LICENSE);
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESCRIPTION);
MODULE_VERSION(CURRENT_DRIVER_VERSION);


static short kernel_log_param=0; 
module_param(kernel_log_param,short,S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP );
MODULE_PARM_DESC(kernel_log_param,"define if kernel logs should go on relayfs channel," \
" and the log level.\n usage <0 default no relay ,1 error,2 info ,3 debug > ");
 
static short relayfs_events_debug=0; 
module_param(relayfs_events_debug,short,S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP );
MODULE_PARM_DESC(relayfs_events_debug,
"define if kernel should send all events to relayfs channel,"\
"regardless of hardening policy or BPM rules.\n  <1 yes,0 no , default 0 > ");


static unsigned short module_ref_count = 0;
static struct dentry *dfs;

/* HP file MD5*/
static struct md5_data_t hp_md5;
/* BPM file MD5*/
static struct md5_data_t bpm_md5;

struct workqueue_struct *wq;

static pid_t pid_permitted;
static atomic_long_t netlink_handshake_valid = ATOMIC_LONG_INIT(0);

// file operations for debugfs
long      kcontroller_ioctl(struct file *filp, unsigned int ioctl_num, unsigned long ioctl_param);
int       kcontroller_open(struct inode *inode, struct file *filp);
int       kcontroller_release(struct inode *inode, struct file *filep);
ssize_t   kcontroller_read(struct file *filp, char __user *buf, size_t count, loff_t *offp);
ssize_t   kcontroller_write(struct file *filp, const char __user *buf, size_t count, loff_t *offp);

void set_pid_permitted(pid_t pid) {
	pid_permitted = pid;
	atomic_long_set(&netlink_handshake_valid,1);
}

int is_pid_permitted(pid_t pid) {

	if(atomic_long_read(&netlink_handshake_valid) == 1)
		return (pid_permitted == pid);
	else
		return 0;
}


short logger_param(void) {
	return kernel_log_param;
}


short events_debug(void) {
	return relayfs_events_debug;
}

const struct md5_data_t* retrieve_hp_md5(void) {
	return (const struct md5_data_t*)(&hp_md5);
}


const struct md5_data_t* retrieve_bpm_md5(void) {
	return (const struct md5_data_t*)(&bpm_md5);
}


/*###############################################################################################*/
/* debugfs  */

static const struct file_operations fops = {
 
	.open           = kcontroller_open, 
	.release        = kcontroller_release, 
	.read           = kcontroller_read,
	.write          = kcontroller_write, 
	.unlocked_ioctl = kcontroller_ioctl 

};


long kcontroller_ioctl(struct file* filp, unsigned int ioctl_num, unsigned long ioctl_param) {


	user_authorized("kcontroller_ioctl")
   
	switch(ioctl_num)
	{
	case CMD_SHOW_CACHE: 
		print_cache();  
	break;
	case CMD_NOT_IN_USE: 
		info("[ %s ]  command not in use. (free to use)  ", MODULE_NAME);
	break;
	default: break;
	}    
  

	return 0;
}


int kcontroller_open(struct inode *inode, struct file *filp) {

	user_authorized("kcontroller_open")

	debug("[ %s ] kcontroller_open() device opened module_ref_count [ %u ]\n",
	      MODULE_NAME, 
	      module_ref_count++);

	//try_module_get(THIS_MODULE);      

	return 0;
}

int kcontroller_release(struct inode *inode, struct file *filep) {


	user_authorized("kcontroller_release")
      
	if (module_ref_count > 0) module_ref_count--;
    
	debug("[ %s ] kcontroller_release() device released module_ref_count [ %u ]\n", 
	      MODULE_NAME,  
	      module_ref_count);

	//module_put(THIS_MODULE);

	return 0;
}


ssize_t kcontroller_read(struct file *filp, char __user *buf, size_t count, loff_t *offp) {

	user_authorized("kcontroller_read")

	debug("[ %s ] kcontroller_read()  device read.  count: [ %zd ] offp: [ %lld ]\n",
	      MODULE_NAME, 
	      count, 
	      (*offp));
  

	return count;     
}


ssize_t kcontroller_write(struct file *filp, const char __user *buf, size_t count, loff_t *offp) {


	unsigned char *data = NULL, *p = NULL;
	struct data_write_t *data_write;   
	hp_rule_file_t *rule_cnt;
	hp_rule_t *hpr;
   
	user_authorized("kcontroller_write");

	smp_mb();

	info("[ %s ] kcontroller_write()  device write.  count: [ %zd ] offp: [ %lld ] \n",
	     MODULE_NAME, 
	     count, 
	     (*offp));

	/* 
	   memory allocation for all data size 
	*/   
	data = (unsigned char*)vmalloc((count*sizeof(unsigned char)) + 1);
	ASSERT_MEMORY_ALLOCATION(data)
        
	memset(data, 0, (count * sizeof(unsigned char)) + 1);

	if (copy_from_user(data, buf, count) != (-EFAULT)) {

		data_write = (struct data_write_t*)data;    
		info("[ %s ] is_valid: [ %d ]  md5: [ %s ] sizeof(struct data_write_t): [ %lu ] ",
		     MODULE_NAME ,
		     data_write->md5.is_valid,
		     data_write->md5.md5,
		     sizeof(struct data_write_t));

		rule_cnt = (hp_rule_file_t*)(data+sizeof(struct data_write_t));
		p = (data + sizeof(struct data_write_t) + sizeof(hp_rule_file_t));

		info("[ %s ] copy data from user .. data [ %p ] count [ %lu ] op [ %d ] rule_count [ %d ]",
		     MODULE_NAME,
		     data,
		     count,
		     data_write->op,
		     rule_cnt->rule_count);

		smp_mb();

		switch(data_write->op) {
		case HP_FILE:
			hpr = (hp_rule_t*)p;
			info("[ %s ] load hp to bpm engine", MODULE_NAME);

			bpm_engine_load_hardening_policy(rule_cnt, hpr);

			info("[ %s ] load hp to bpm engine done", MODULE_NAME);
		break;
		case BPM_FILE:
			info("[ %s ] BPM_FILE unhandled at the momnent", MODULE_NAME);
		break;
		default:
			error("[ %s ] ERROR unknown option : %d \n", MODULE_NAME, data_write->op);
		goto exit_1;
		break;
		}
         
	} else
	{ 
		error("[ %s ] ERROR unable to copy data from user.\n", MODULE_NAME);    
		return (-EFAULT);
	}

exit_1:
	vfree(data);    
  
	info("[ %s ] p: [ %p ]  data: [ %p ] count [ %lu ]  (p-data)==count --> %d ",
	     MODULE_NAME,p,data,count,((p-data)==count));
 

	return count;
}



static int __init kcontroller_init(void) {


	int init_module_boot_process(void);
	int relay_channels_initialize(void);
	int ret = 0;

	if (relay_channels_initialize()) return -EINVAL;

	info("[ %s ] driver is loading up .... .\n", MODULE_NAME);    
 
	dfs = debugfs_create_file(KCONTROLLER_DFS_NAME, 0644, NULL, NULL, &fops);
	if (!dfs) {
		error("[ %s ] error creating debugfs entry : [ %s ]\n", 
		      MODULE_NAME,
		      KCONTROLLER_DFS_NAME);

		return -EINVAL;
	} else
	{
		info("[ %s ]  debugfs file [ %s ] created for file operations\n" , 
		     MODULE_NAME,
		     KCONTROLLER_DFS_NAME);
	}

	smp_mb();

	ret = init_module_boot_process(); 

	info("[ %s ] driver loaded success .\n", MODULE_NAME);


	return ret;
}


static void __exit kcontroller_exit(void){
  
	int destroy_module_boot_process(void);

	info("[ %s ] driver going down .... .", MODULE_NAME);

	debugfs_remove(dfs);  

	destroy_module_boot_process();
}




module_init(kcontroller_init);
module_exit(kcontroller_exit);


