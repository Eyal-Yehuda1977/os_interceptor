#include "os_interceptor_data_type.h"



extern struct workqueue_struct* wq;
static struct sock* nl_sk = NULL;


static inline __attribute__((always_inline)) 
int cb_handshake_response(pid_t pid, const char *err);

static inline __attribute__((always_inline)) 
int cb_shutdown_response(pid_t pid, const char *err);

static inline __attribute__((always_inline)) 
int cb_quarantine_response(pid_t pid, const char *err);

static inline __attribute__((always_inline)) 
int cb_update_configuration_response(pid_t pid, const char *err);

static inline __attribute__((always_inline)) 
int cb_unknown_controll_message(pid_t pid, const char *err);


/* netlink */
static void nl_recv(struct sk_buff *skb_in);
static void nl_send(unsigned char *msg, const int pid);
static int  nl_logic(unsigned char *nl_msg, const struct nlmsghdr *nlh);


struct netlink_kernel_cfg nl_cfg = {
  .input = nl_recv,
};







static int nl_logic(unsigned char* nl_msg, const struct nlmsghdr* nlh) {



	void shutdown_process (struct work_struct *data);
	void quarantine_process(struct work_struct *data);
	void update_configuration_process(struct work_struct *data);
	void handshake_process(struct work_struct *data);
	void unknown_controll_message(struct work_struct *data);

	int ret;
    
	struct cmd_request_t *m = NULL;     
	struct w_kcontroller *w = NULL;

	if (!nl_msg) {
		error("[ %s ] nl_logic() error nl_msg is empy ", MODULE_NAME);
		return ERROR;
	}

	m = (struct cmd_request_t*)nl_msg;

	info("[ %s ] nl_logic()  got controll message: [ %d ] auth_key [ %s ] driver_version [ %s ]" \
	     "  from PID [ %d ] ",
	     MODULE_NAME,
	     m->cmd,
	     m->handshake.auth_key,
	     m->handshake.driver_version,
	     nlh->nlmsg_pid);

	switch (m->cmd) {
        case HANDSHAKE: 
	{       	  
		w = vmalloc(sizeof(struct w_kcontroller));
		INIT_WORK(&w->w, handshake_process);              
		w->response_callback = cb_handshake_response;
		w->pid = nlh->nlmsg_pid;
		w->data = (void*)nl_msg;
		queue_work(wq, &w->w);   
        }
        break;
        case SHUTDOWN_DRIVER: 
	{
		w = vmalloc(sizeof(struct w_kcontroller));
		INIT_WORK(&w->w, shutdown_process);              
		w->response_callback = cb_shutdown_response;
		w->pid = nlh->nlmsg_pid;
		w->data = (void*)nl_msg;
		queue_work(wq, &w->w);              
	}
        break;       
        case QUARANTINE:
        {
		w = vmalloc(sizeof(struct w_kcontroller));
		INIT_WORK(&w->w, quarantine_process);              
		w->response_callback = cb_quarantine_response;
		w->pid = nlh->nlmsg_pid;
		w->data = (void*)nl_msg;
		queue_work(wq, &w->w);              	  
	}
        break;
        case UPDATE_CONFIGURATION:
	{
		w = vmalloc(sizeof(struct w_kcontroller));
		INIT_WORK(&w->w, update_configuration_process);              
		w->response_callback = cb_update_configuration_response;
		w->pid = nlh->nlmsg_pid;
		w->data = (void*)nl_msg;
		queue_work(wq,&w->w);              	               
	}
        break;
        default:  
       	{
		w = vmalloc(sizeof(struct w_kcontroller));
		INIT_WORK(&w->w, unknown_controll_message);              
		w->response_callback = cb_unknown_controll_message;
		w->pid = nlh->nlmsg_pid;
		w->data = (void*)nl_msg;
		queue_work(wq, &w->w);              	               
		error("[ %s ] nl_logic() unknown controll message [ %d ]"
		      ,MODULE_NAME, m->cmd); 
	}
        break;
	}



	return ret;
}



/*------------------------------------------------------------------------------------------------*/
/* netlink call back functions */

static inline __attribute__((always_inline)) 
int cb_handshake_response(pid_t pid, const char *err) {


	struct cmd_response_t *res_t;
	int ret = SUCCESS;    
	unsigned char *buf = NULL;

	debug("[ %s ] allocating memory for message ", MODULE_NAME);
	buf = (unsigned char*)vmalloc(sizeof(struct cmd_response_t));
	ASSERT_MEMORY_ALLOCATION(buf)
	memset(buf, 0, sizeof(struct cmd_response_t));

	res_t               = (struct cmd_response_t*)buf;
	res_t->cmd          = HANDSHAKE;                    
     
	if (strlen(err) > 0) {
		res_t->error_number = INVALID_PARAMETRS;
		strncpy(res_t->error_message, err, CONTROL_BUFFER_DEFAULT_SIZE);
	}else
		res_t->error_number = NETLINK_PACKET_OK;

	snprintf(res_t->handshake.fops_file_path, CONTROL_BUFFER_DEFAULT_SIZE, "%s/%s",
		 DEBUGFS_DIR,
		 OS_INTERCEPTOR_DFS_NAME); 

	debug("[ %s ] nl_logic handshake response fops_file_path: [ %s ]", 
	      MODULE_NAME,
	      res_t->handshake.fops_file_path);

	snprintf(res_t->handshake.bpm_relay_file_path, CONTROL_BUFFER_DEFAULT_SIZE, "%s%s/%s",
		 DEBUGFS_DIR,
		 RELAY_NAME_EVENTS,
		 RELAY_FILE);                

	debug("[ %s ] nl_logic handshake response bpm_relay_file_path: [ %s ]",
	      MODULE_NAME,
	      res_t->handshake.bpm_relay_file_path);

	snprintf(res_t->handshake.log_relay_file_path,CONTROL_BUFFER_DEFAULT_SIZE, "%s%s/%s",
		 DEBUGFS_DIR,
		 RELAY_NAME_LOGGER,
		 RELAY_FILE);                

	debug("[ %s ] nl_logic handshake response log_relay_file_path: [ %s ]",
	      MODULE_NAME,
	      res_t->handshake.log_relay_file_path);

	memcpy(&(res_t->handshake.hp_md5), retrieve_hp_md5(), sizeof(struct md5_data_t)); 
	memcpy(&(res_t->handshake.bpm_md5), retrieve_bpm_md5(), sizeof(struct md5_data_t)); 
                
	nl_send(buf, pid);

	vfree(buf);

	return ret;
}



static inline __attribute__((always_inline)) 
int cb_shutdown_response(pid_t pid, const char *err) {



	struct cmd_response_t *res_t;
	unsigned char *buf;
	int ret = SUCCESS;

	buf = (unsigned char*)vmalloc(sizeof(struct cmd_response_t));
	ASSERT_MEMORY_ALLOCATION(buf)
	memset(buf, 0, sizeof(struct cmd_response_t));

	res_t               = (struct cmd_response_t*)buf;
	res_t->cmd          = SHUTDOWN_DRIVER;                    
  
	if (strlen(err) > 0) {
		res_t->error_number = SHOUTDOWN_PROCESS_ERROR;
		strncpy(res_t->error_message, err, CONTROL_BUFFER_DEFAULT_SIZE);
	}else
		res_t->error_number = NETLINK_PACKET_OK;

	nl_send(buf, pid);
	vfree(buf);

	return ret;
}

static inline __attribute__((always_inline)) 
int cb_quarantine_response(pid_t pid, const char* err) {

	
	struct cmd_response_t *res_t;
	unsigned char *buf;
	int ret = SUCCESS;

	buf = (unsigned char*)vmalloc(sizeof(struct cmd_response_t));
	ASSERT_MEMORY_ALLOCATION(buf)
	memset(buf, 0, sizeof(struct cmd_response_t));

	res_t               = (struct cmd_response_t*)buf;
	res_t->cmd          = QUARANTINE;                    
  
	if (strlen(err) > 0) {
		res_t->error_number = INVALID_PARAMETRS;
		strncpy(res_t->error_message, err, CONTROL_BUFFER_DEFAULT_SIZE);
	}else
		res_t->error_number = NETLINK_PACKET_OK;

	nl_send(buf, pid);
	vfree(buf);

	return ret;
}


static inline __attribute__((always_inline)) 
int cb_update_configuration_response(pid_t pid, const char *err) {


	struct cmd_response_t *res_t;
	unsigned char *buf;
	int ret = SUCCESS;

	buf = (unsigned char*)vmalloc(sizeof(struct cmd_response_t));
	ASSERT_MEMORY_ALLOCATION(buf)
	memset(buf, 0, sizeof(struct cmd_response_t));

	res_t               = (struct cmd_response_t*)buf;
	res_t->cmd          = UPDATE_CONFIGURATION;                    
  
	if (strlen(err) > 0) {
		res_t->error_number = INVALID_PARAMETRS;
		strncpy(res_t->error_message, err, CONTROL_BUFFER_DEFAULT_SIZE);
	}else
		res_t->error_number = NETLINK_PACKET_OK;

	nl_send(buf, pid);
	vfree(buf);

	return ret;
}



static inline __attribute__((always_inline)) 
int cb_unknown_controll_message(pid_t pid, const char *err) {


	struct cmd_response_t *res_t;
	unsigned char *buf;
	int ret = SUCCESS;

	buf = (unsigned char*)vmalloc(sizeof(struct cmd_response_t));
	ASSERT_MEMORY_ALLOCATION(buf)
	memset(buf, 0, sizeof(struct cmd_response_t));

	res_t               = (struct cmd_response_t*)buf;
	res_t->cmd          = UNKNOWN;                    
  
	if ( strlen(err) > 0 ) {
		res_t->error_number = INVALID_PARAMETRS;
		strncpy(res_t->error_message, err, CONTROL_BUFFER_DEFAULT_SIZE);
	} else
		res_t->error_number = NETLINK_PACKET_OK;

	nl_send(buf, pid);
	vfree(buf);


	return ret; 
}



/*----------------------------------------------------------------------------------------------*/
/*  netlink functions  */

static void nl_recv(struct sk_buff *skb_in) {

	struct nlmsghdr *nlh;
	unsigned char *nl_msg = NULL;

	nl_msg = (unsigned char*) vmalloc(sizeof(struct cmd_request_t));

	if (!nl_msg) {
		error("[ %s ] nl_recv() ERROR failed to allocate netlink message ", MODULE_NAME);
		return;
	}
	
	memset(nl_msg, 0, sizeof(struct cmd_request_t) * sizeof(unsigned char));

	nlh = (struct nlmsghdr*)skb_in->data;

	memcpy(nl_msg, (unsigned char*)nlmsg_data(nlh)
	       ,sizeof(struct cmd_request_t) * sizeof(unsigned char));

	nl_logic(nl_msg, nlh);
}



static inline __attribute__((always_inline)) 
struct kmsg make_msg(const unsigned char *msg, const int sz) {


	struct kmsg m;
	m.skb = nlmsg_new(sz, 0);

	if (m.skb) {

		m.nlh = nlmsg_put(m.skb, 0, 0, NLMSG_DONE, sz, 0);
		NETLINK_CB(m.skb).dst_group = 0;
		memcpy(nlmsg_data(m.nlh), msg, sz * sizeof(unsigned char));
	} else
	{
		error("[ %s ] error allocation SKB ", MODULE_NAME);
	}


	return m;
}

static void nl_send(unsigned char *msg, const int pid) {


	int res = 0;
	struct kmsg m;
	m = make_msg(msg, sizeof(struct cmd_response_t));
	res = nlmsg_unicast(nl_sk, m.skb, pid);

	if (res < 0) {
		error("[ %s ] nl_send() error sending message to user  pid [ %d ]", MODULE_NAME, pid);
	}else 
	{
		debug("[ %s ] nl_send() message sent to user pid [ %d ]", MODULE_NAME, pid);
	}
}



int init_user_app_communication(void) {

	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &nl_cfg);
	if (!nl_sk)
	{
		error("[ %s ] ERROR creating netlink socket ", MODULE_NAME); 
		return -ENOMEM;
	}

	info("[ %s ] init user app communication() success. ", MODULE_NAME);   
	
	return 0; 
}


int destroy_user_app_communication(void) {

	netlink_kernel_release(nl_sk);
	info("[ %s ] destroy user app communication() success", MODULE_NAME );

	return 0;
}

