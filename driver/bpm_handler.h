#ifndef __BPM_HANDLER_H_
#define __BPM_HANDLER_H_

int sys_process_read(char* path
                    ,struct event_t* evt
                    ,struct bpm_result_t* res_t);

int sys_process_write(char* path
                     ,struct event_t* evt
                     ,struct bpm_result_t* res_t);

int sys_process_execv(struct event_t* evt
                     ,struct bpm_result_t* res_t);

int sys_process_fork(struct event_t* evt
                    ,struct bpm_result_t* res_t);

int sys_process_clone(struct event_t* evt
                     ,struct bpm_result_t* res_t);

int sys_process_socket_connect(const unsigned short dport, 
                               const uint32_t ipv4, 
                               struct event_t* evt,
                               struct bpm_result_t* res_t);

int sys_process_open(char* path                    
                    ,int flags
                    ,struct event_t* evt
		    ,struct bpm_result_t* res_t);

int sys_process_close(const char *path
                     ,struct event_t* evt
                     ,struct bpm_result_t* res_t);

int sys_process_rename(const char* old_name, 
                       const char* new_name, 
                       struct event_t* evt, 
                       struct bpm_result_t* res_t);

int sys_process_unlink(const char* path_name
                      ,struct event_t* evt
                      ,struct bpm_result_t* res_t);

int sys_process_fchmodat(int dfd, 
                         const char* file_name,
                         umode_t mode,
                         struct event_t* evt,
                         struct bpm_result_t* res_t);

int sys_process_chmod(const char* file_name
                     ,umode_t mode
                     ,void* p_res);

int sys_process_truncate(char* pathname
                        ,struct event_t* evt
                        ,struct bpm_result_t* res_t);

int sys_process_ftruncate(char* pathname
                         ,struct event_t* evt
                         ,struct bpm_result_t* res_t);

#endif
