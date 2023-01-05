#ifndef __OS_INTERCEPTOR_PARAMS_
#define __OS_INTERCEPTOR_PARAMS_


#include <stddef.h>
#include <asm/desc.h>
#include <asm/desc_defs.h>
#include <asm/irq_vectors.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/page.h>
#include <linux/mm.h>
#include <linux/stop_machine.h>
#include <linux/syscalls.h>
#include <linux/init.h>
#include <linux/debugfs.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <asm/processor.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/slab.h> 
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <asm/pgtable_types.h>
#include <linux/spinlock.h>
#include <linux/spinlock_types.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/relay.h>
#include <linux/types.h>
#include <linux/inet.h>
#include <linux/kthread.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/time64.h>
#include <asm/barrier.h>
#include <linux/fdtable.h>
#include <linux/audit.h>
#include <linux/namei.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <linux/fs_struct.h>
#include <asm/errno.h>
#include <linux/pagemap.h>
#include <crypto/hash.h>
#include <asm-generic/scatterlist.h>
#include <linux/scatterlist.h>
#include <linux/jiffies.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <net/tcp.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>
#include <linux/rbtree.h>
#include <linux/rtc.h>
#include <linux/posix-timers.h>

#include "crypto/crypto.h"
#include "../driver_shared/driver_api.h"
#include "disassembler_x86/types.h"
#include "disassembler_x86/extern.h"
#include "disassembler_x86/itab.h"
#include "relay_interface.h"
#include "bpm_handler.h"
#include "module_metadata.h"
#include "cache_process_handler.h"
#include "policy/policy.h"
#include "module_debug.h"
#include "network/network.h"


/*
  ioctl
*/
#define MAGIC_NUMBER                      '4'
#define CMD_SHOW_CACHE                     _IOWR(MAGIC_NUMBER, 0, int )
#define CMD_NOT_IN_USE                     _IOWR(MAGIC_NUMBER, 1, unsigned long )



#define RELAY_FILE                         "cpu0"
#define RELAY_NAME_EVENTS                  "os_interceptor_relay"
#define RELAY_NAME_LOGGER                  "os_interceptor_logger"
#define MODULE_NAME                        "os_interceptor"
#define DEBUGFS_DIR                        "/sys/kernel/debug/"
#define OS_INTERCEPTOR_DFS_NAME            "os_interceptor_dfs"

enum { events_relay = 0, logger_relay = 1 };

#define RELATIVE_CALL_SIZE                 (5)
#define MAX_RELATIVE_CALL_OFFSET           (150)
#define SYM_SYS_CALL_TABLE                 ("sys_call_table")
#define WQ_NAME                            "kcontroller_wq"

/*
  memory mngr
*/
#define THREAD_MAX                         (PID_MAX_DEFAULT -1)
#define KMEM_CACHE_GROUP_BUFFER_SIZE       4
#define BASIC_CACHE_BUFFER_LEN             4096  // 4k page size
#define KMEM_HASH                          "pf_hash"

/* 
   cache defines  
*/
#define PRPCESS_CACHE_HASH_DISTRIBUTION    20   // hash bukets
#define NIC_CACHE_HASH_DISTRIBUTION        10   // hash bukets
#define GET_PARENT_CMDLINE                 0
#define NO_PARENT_CMDLINE                  1
#define NODE_FULL_INSERT                   3
#define MAX_BUF_HALF_K                     512
#define CACHE_NODE_DELETED                 1


/*
  bpm prioritys and action to take   
*/
#define PRIORITY_ALLOW_SYSTEM_CALL          1 
#define SPAWN_LOG_IN_RELAY                  2
#define DO_NOT_SPAWN_LOG_IN_RELAY           3
#define PRIORITY_PREVENT_SYSCALL            4


#if (LINUX_VERSION_CODE != KERNEL_VERSION(3,10,0))
    #error "Only Linux kernel 3.10.0 is supported"
#endif

#define ASSERT_MEMORY_ALLOCATION(mem){					\
				      if ( IS_ERR_OR_NULL(mem)) {	\
					      pr_err("memory allocation error in function  [ %s ]  file [ %s ]"	\
						     " line [ %d ]\n", __func__, __FILE__, __LINE__ ); \
					      return (-ENOMEM);		\
				      }					\
	}


/*
  Print stack trace for debugging
*/
#define FINGERP_PRINT_STACK_TRACE                                   \
  {                                                                 \
      static unsigned long      t_entries[15];                      \
      static struct stack_trace t;                                  \
      t.nr_entries  = 0;                                            \
      t.max_entries = sizeof(t_entries)/sizeof(t_entries[0]);       \
      t.entries     = t_entries;                                    \
      t.skip        = 1;                                            \
      save_stack_trace(&t);                                         \
      print_stack_trace(&t, 4);                                     \
  }


//#define DEBUG_MODE_PRINT 


#define NO_RELAY_LOGGER                   0
#define RELAY_LOGGER_ERR                  1
#define RELAY_LOGGER_INFO                 2
#define RELAY_LOGGER_DEBUG                3  


void write_to_chan_format(unsigned char log_level,unsigned int relay_channel_idx
			  ,const char* fmt, ... );

short logger_param(void);
short events_debug(void);


#define write_to_chan_events(buf, length)\
write_to_chan(buf, length,events_relay);

#define error(str,...)\
  do{\
  if(logger_param()==NO_RELAY_LOGGER)\
    printk(KERN_ERR  str"  %s:%3d  "  ,##__VA_ARGS__,__FILE__,__LINE__);\
  else if(!(logger_param() < RELAY_LOGGER_ERR))\
    write_to_chan_format(RELAY_LOGGER_ERR,logger_relay,str,  ##__VA_ARGS__);\
  }while(0)						   

#define info(str,...)\
  do{\
  if(logger_param()==NO_RELAY_LOGGER)\
    printk(KERN_INFO  str ,##__VA_ARGS__);\
  else if(!(logger_param()<RELAY_LOGGER_INFO))\
    write_to_chan_format(RELAY_LOGGER_INFO,logger_relay,str,  ##__VA_ARGS__); \
  }while(0)						   

#ifdef DEBUG_MODE_PRINT  // only for kernel dmesg
#define debug(str,...)\
  do{\
  if(logger_param()==NO_RELAY_LOGGER)\
    printk(KERN_DEBUG str"  %s:%3d " ,##__VA_ARGS__,__FILE__,__LINE__);\
  else if(!(logger_param()<RELAY_LOGGER_DEBUG))\
    write_to_chan_format(RELAY_LOGGER_DEBUG,logger_relay,str,  ##__VA_ARGS__);\
  }while(0)						   

#else

#define debug(str,...)\
do{ if(!(logger_param()<RELAY_LOGGER_DEBUG))\
write_to_chan_format(RELAY_LOGGER_DEBUG,logger_relay,str,  ##__VA_ARGS__);\
}while(0)
#endif


#define _PRINT_ENGINE_RESPONSE(spawn_log_in_relay,prevent_system_call,priority)\
  debug("[ %s ] after analize_bpm_response() spawn_log_in_relay: [ %d ]" \
	"prevent_system_call: [ %d ] priority [ %d ] ", MODULE_NAME	\
	,spawn_log_in_relay,prevent_system_call,priority);



/* page allocation definition */
#ifndef VM_RESERVED
# define VM_RESERVED (VM_DONTEXPAND | VM_DONTDUMP)
#endif


/* conver ipv4/6 to string macro  */
#define NIPQUAD(addr) \
	  ((unsigned char *)&addr)[0], \
	    ((unsigned char *)&addr)[1], \
	    ((unsigned char *)&addr)[2], \
	    ((unsigned char *)&addr)[3]

#define NIP6(addr) \
	  ntohs((addr).s6_addr16[0]), \
	    ntohs((addr).s6_addr16[1]), \
	    ntohs((addr).s6_addr16[2]), \
	    ntohs((addr).s6_addr16[3]), \
	    ntohs((addr).s6_addr16[4]), \
	    ntohs((addr).s6_addr16[5]), \
	    ntohs((addr).s6_addr16[6]), \
	    ntohs((addr).s6_addr16[7])


/* get base address of page in region */
#define base_of_page(x) ((void*)((unsigned long)(x) & PAGE_MASK))


#endif  //__OS_INTERCEPTOR_PARAMS_
