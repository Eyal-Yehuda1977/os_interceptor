//
// Created by ubunto on 06/02/18.
//

#ifndef DRIVER_API_H
#define DRIVER_API_H


#define EVENT_MD5_LEN       16

#ifndef __KERNEL__

	#include <unistd.h>
	#include <linux/types.h>
	#include <sys/types.h>
	#include <netinet/in.h>

	#define enum_class enum class

	typedef unsigned short		umode_t;

#else
	#include <linux/inet.h>
	#define enum_class enum

#endif


/*###############################################################################################*/
/* Control Channel  NETLINK */



struct md5_data_t {
	// If zero, it means that the md5 is empty.
	char is_valid;
	uint8_t md5[EVENT_MD5_LEN];
};


#define NETLINK_USER                    31
#define CONTROL_BUFFER_DEFAULT_SIZE     256
#define CONTROL_CHECKSUM_LENGTH         32

enum cmd_request_type {
	UNKNOWN         = 0,
	HANDSHAKE       = 2,
	SHUTDOWN_DRIVER = 10,
	QUARANTINE      = 11,
	UPDATE_CONFIGURATION = 12,
};

enum netlink_error_type {
        NETLINK_PACKET_OK       =0,
        INVALID_PARAMETRS       =1,
        SHOUTDOWN_PROCESS_ERROR =2                
};


struct cmd_request_t {
	// general details
	// request type
	enum cmd_request_type cmd;

	// request details by type
	union {
		// Handshake details, TBD
		struct {
			// For example
			char auth_key[CONTROL_BUFFER_DEFAULT_SIZE];
			char driver_version[CONTROL_CHECKSUM_LENGTH + 1];
		} handshake;

		// TODO, decide with eyal on interface
		struct {
			char prevent_detection;
		        /* server address*/
		        uint32_t daddr;
		        /* client address*/
                        uint32_t saddr;
		        /* client port*/
		        unsigned short port; 
		} update_configuration;
               
	};
} __attribute__ ((packed));


struct cmd_response_t {
	// general response details

	enum cmd_request_type cmd;

	// 0 - is successful, negative number for errors
	int error_number;
	char error_message[CONTROL_BUFFER_DEFAULT_SIZE];

	/* response details by type */
	union {
		/* Handshake response TBD*/
		struct {
			/* path to file to write data to, This path will be used in debugfs
            read/write to transfer large buffers*/
			char fops_file_path[CONTROL_BUFFER_DEFAULT_SIZE];
			/* path to read events from BPM events will be sent to this file using relay,
           and read by the agent*/
			char bpm_relay_file_path[CONTROL_BUFFER_DEFAULT_SIZE];
			/* path to read log from Log buffers will be sent to this file using relay,
               and read by the agent*/
			char log_relay_file_path[CONTROL_BUFFER_DEFAULT_SIZE];
			/* Current hard-coded driver version (i.e.  0.0.1-patch2-231232312312)*/
			char driver_version[CONTROL_BUFFER_DEFAULT_SIZE];
			/* authentication token (TBD)*/
			char auth_token[CONTROL_BUFFER_DEFAULT_SIZE];
			/* file MD5, If no files have been loaded to driver, these fields will be empty strings
               when file is sent to driver, it is sent with MD5. This MD5 should be saved,
               and if agent restarts the driver will return those MD5 in the handshake response.
               In case driver files are out-dated, driver will follow by sending the updated 
               files to driver (via debug fs data channel)*/
			/* HP file MD5*/
			struct md5_data_t hp_md5;
			/* BPM file MD5*/
			struct md5_data_t bpm_md5;
		} handshake;
	};
} __attribute__ ((packed));


#define NETLINK_MAX_PAYLOAD sizeof(cmd_request_t)

/// END Control Channel

/// BPM Events



/// The type of the HP operation this rule applies to.
enum hp_rule_op_type_t {
	NONE,
	PROCESS,
	FILESYSTEM,
	NETWORK
};


/* system call identifyers corresponding to unistd_64.h  */
enum sys_caller_t {
   SC_NA         =-1,
   SC_READ       = 0,
   SC_WRITE      = 1,
   SC_OPEN       = 2,
   SC_CLOSE      = 3,
   SC_CONNECT    = 42,
   SC_CLONE      = 56,
   SC_FORK       = 57,
   SC_EXECVE     = 59,
   SC_TRUNCATE   = 76,
   SC_FTRUNCATE  = 77,
   SC_RENAME     = 82,
   SC_UNLINK     = 87,
   SC_CHMOD      = 90,
   SC_FCHMODAT   = 268
};

#define MAX_SYS_CALL    SC_FCHMODAT

/*###############################################################################################*/
/*  BPM response srturctures    */


#define EVENT_MAX_PATH_LEN  256

#define FILE_ACCESS_FLAG_READ  (1 << 0)
#define FILE_ACCESS_FLAG_WRITE (1 << 1)

struct event_t {
	// system call
	enum sys_caller_t syscall;

	// session information
	uid_t user_id;
	gid_t user_group_id;

	// caller information
	pid_t caller_process_id;
	pid_t caller_thread_id;

	char caller_path[EVENT_MAX_PATH_LEN]; // /bin/l
	char caller_name[EVENT_MAX_PATH_LEN]; // ls
	char caller_cmd[EVENT_MAX_PATH_LEN];  // ls -lthr  (how process is written)

	uint64_t caller_created_at;
	uint64_t caller_modified_at;
	uint64_t caller_last_accessed_at;
        uint64_t caller_file_size;
        uint64_t caller_start_at;
        uint64_t event_time_diff;

	// caller md5 hash
	struct md5_data_t caller_md5;

	// caller parent information
	pid_t parent_process_id;
	char parent_path[EVENT_MAX_PATH_LEN];
	char parent_name[EVENT_MAX_PATH_LEN];
	char parent_cmd[EVENT_MAX_PATH_LEN];

	uint64_t parent_created_at;
	uint64_t parent_modified_at;
	uint64_t parent_last_accessed_at;
        uint64_t parent_file_size;

	// parent md5 hash
	struct md5_data_t parent_md5;

	// target specific information
	union {
		struct {       /* make room for IPV6/IPV4 */
		        uint32_t ipv4;
			short target_port;
		} network;

		struct {
			// target common information
			char target_path[EVENT_MAX_PATH_LEN];
			char target_name[EVENT_MAX_PATH_LEN];
			char target_cmd[EVENT_MAX_PATH_LEN];

			struct {
				// SEE FILE_ACCESS_FLAG_READ/FILE_ACCESS_FLAG_WRITE
				int flags;
			} file_access;

		} target;

	};
} __attribute__((packed));

struct bpm_result_t {
	// unique bpm message id
	uint64_t id;

	// timestamp of event
	uint64_t time_seconds;
	int time_microseconds;

	// name of rule that caused the message/block
	char rule_name[EVENT_MAX_PATH_LEN];

	// action to be performed on sys call, 2 is allow, 3 is block, 4 match, 5 prevented
	unsigned int priority;
};

struct bpm_message_t {
	struct event_t event;
	struct bpm_result_t result;

} __attribute__((packed));


#define MSG_LEN sizeof(struct bpm_message_t)

/*#############################################################################################*/
// DEBUGFS OPERATIONS 
//1. write data to device . 

/// Event sent from the driver to the agent. EYAL TODO  this should be discussed with Ishai. 
typedef struct bpm_message_t bpm_event_t;

/// End BPM Events

/// Data Channel (File Read/Write)

enum data_write_option {
	BPM_FILE = 1,
	HP_FILE = 2,
};

struct data_write_t {
	enum data_write_option op;
	struct md5_data_t md5;
}__attribute__((packed));


// Hardening policy file. This struct is the file header, contains number of rules. file body will contain hp_rule_t array


typedef struct hp_rule_file {
	// how many rules in the file, rules will be sent starting right after this header struct
	unsigned int rule_count;
	// byte size of mini heap
	unsigned int mini_heap_size;
} __attribute__((packed)) hp_rule_file_t;

#define ARRAY_STRUCT(type) typedef struct type ## _array { \
	unsigned int array_size; \
	struct type *array_start; \
} type ## _array_t;

typedef struct hp_value_string {
	unsigned int size;
	char *string;
} hp_value_string_t;

ARRAY_STRUCT(hp_value_string)

typedef struct hp_value_user_id {
	int user_id;
} hp_value_user_id_t;

ARRAY_STRUCT(hp_value_user_id)


typedef struct hp_value_md5 {
	uint8_t md5[EVENT_MD5_LEN];
} hp_value_md5_t;

ARRAY_STRUCT(hp_value_md5)

typedef struct hp_value_ip {
	uint32_t ip;
} hp_value_ip_t;

ARRAY_STRUCT(hp_value_ip)

typedef struct hp_value_port {
	uint16_t port;
} hp_value_port_t;

ARRAY_STRUCT(hp_value_port)

// Hardening Policy Rule
typedef struct hp_rule {
	// rule identifier
	char rule_name[EVENT_MAX_PATH_LEN];

	// The HoP operation type
	enum hp_rule_op_type_t op_type;
        enum sys_caller_t syscall;
	// action to be performed on sys call, 2 is allow, 3 is block, 4 match, 5 prevented
	int priority;

	// 0 if this is a whitelist rule, non-zero if this is a blacklist rule.
	int is_blacklist;

	// caller rules, empty rule will be empty string
	hp_value_string_array_t caller_path;
	hp_value_string_array_t caller_name;
	hp_value_string_array_t caller_cmd;

        /*EYAL I changed it (with Liors permission) from char to pid_t kernel
          do not know about names*/
	//char caller_user[EVENT_MAX_PATH_LEN];
	hp_value_user_id_array_t user_id;

	hp_value_md5_array_t caller_md5;

	union {
		struct {
			hp_value_string_array_t target_path;
			hp_value_string_array_t target_name;
		} process_args;
		struct {
			hp_value_string_array_t target_path;
			hp_value_string_array_t target_name;
			int flags;
		} filesystem_args;
		struct {
			hp_value_ip_array_t ip;   // IP address in network byte order
			hp_value_port_array_t port; // Port in network byte order
		} network_args;
	};
} __attribute__((packed)) hp_rule_t;



/// End Data Channel

/// Driver Log Channel

#define DRIVER_LOG_MAX_SIZE     1024

struct relay_logger_t
{
  /* time of log seconds, nanoseconds*/
  long long tstamp[2];
  /* indication for critical error at driver end*/
  unsigned char log_level;
  /* raw data as text string*/
  unsigned char data[DRIVER_LOG_MAX_SIZE];

}__attribute__((packed));


/// End Driver Log Channel

#endif //DRIVER_API_H
