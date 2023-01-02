#include "kcontroller_data_type.h"




#define ERR_NL_HANDSHAKE    "handshake error. given pid: [ %d ] for agent process is incorrect"
#define ERR_NL_UNKNOWN      "netlink error. unknown netlink request: [ %d ]"


void handshake_process(struct work_struct *data) {


	void set_pid_permitted(pid_t pid);

	struct cmd_request_t *m = NULL;     
	struct w_kcontroller *w = (struct w_kcontroller*)data;
	char err[CONTROL_BUFFER_DEFAULT_SIZE];
	memset(err, 0, CONTROL_BUFFER_DEFAULT_SIZE); 

	info("[ %s ] handshake process ", MODULE_NAME); 

	m = (struct cmd_request_t*)w->data;

	if ( !(w->pid > 1) || !(w->pid <= THREAD_MAX) ) 
		snprintf(err, CONTROL_BUFFER_DEFAULT_SIZE, ERR_NL_HANDSHAKE, w->pid);       
	else
		set_pid_permitted(w->pid);

	w->response_callback(w->pid, err);   

	vfree(w->data);  //free nl_msg
	vfree(data);   // free work
}



void shutdown_process(struct work_struct *data) {


	void shut_down_relay(void);
 
	struct cmd_request_t *m = NULL;     
	struct w_kcontroller *w = (struct w_kcontroller*)data;
	char err[CONTROL_BUFFER_DEFAULT_SIZE];
	memset(err, 0, CONTROL_BUFFER_DEFAULT_SIZE);

	info("[ %s ] shutdown process ", MODULE_NAME); 

	m = (struct cmd_request_t*)w->data;
	shut_down_relay();
 
	w->response_callback(w->pid, err);
   
	vfree(w->data);  //free nl_msg
	vfree(data);    // free work
}


void quarantine_process(struct work_struct *data) {


	struct cmd_request_t *m = NULL;     
	struct w_kcontroller *w = (struct w_kcontroller*)data;
	char err[CONTROL_BUFFER_DEFAULT_SIZE];
	memset(err, 0, CONTROL_BUFFER_DEFAULT_SIZE);

	info("[ %s ] quarantine process  ", MODULE_NAME); 

	m = (struct cmd_request_t*)w->data;

	if( __quarantine_mode() == 0 && 
	    (SUCCESS == set_quarantine_info(&m->update_configuration.daddr,
					   &m->update_configuration.saddr,
					   &m->update_configuration.port,
					   err)) ) 
	{
		__enable_quarantine();
	} else if ( __quarantine_mode() == 1 ) 
		__disable_quarantine();  

	w->response_callback(w->pid,err);
  
	vfree(w->data);  //free nl_msg
	vfree(data);    // free work
}


void update_configuration_process(struct work_struct *data)
{


	void set_pid_permitted(pid_t pid);

	struct cmd_request_t *m = NULL;     
	struct w_kcontroller *w = (struct w_kcontroller*)data;
	char err[CONTROL_BUFFER_DEFAULT_SIZE];
	memset(err, 0, CONTROL_BUFFER_DEFAULT_SIZE);
   
	info("[ %s ] update configuration process  ", MODULE_NAME);  

	m = (struct cmd_request_t*)w->data;
	w->response_callback(w->pid, err);

	vfree(w->data);  //free nl_msg
	vfree(data);     //free work
}


void unknown_controll_message(struct work_struct *data) {


	struct cmd_request_t *m = NULL;     
	struct w_kcontroller *w = (struct w_kcontroller*)data;
	char err[CONTROL_BUFFER_DEFAULT_SIZE];
	memset(err, 0, CONTROL_BUFFER_DEFAULT_SIZE);
   
	info("[ %s ] unknown controll message  ", MODULE_NAME);  
  
	m = (struct cmd_request_t*)w->data;
  
	snprintf(err, CONTROL_BUFFER_DEFAULT_SIZE, ERR_NL_UNKNOWN, m->cmd);       
	w->response_callback(w->pid, err);

	vfree(w->data);  //free nl_msg
	vfree(data);     //free work
}
