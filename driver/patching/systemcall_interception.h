#ifndef __SYSTEMCALL_INTERCEPTOR_
#define __SYSTEMCALL_INTERCEPTOR_







/* 
   page with permission used for patching system calles  
*/
struct gl_region {
 
	void *source, *writeable; 
	size_t length; 

}__attribute__((packed));


/*
  systemcall patch entry
 */
struct sct_entry {

	struct list_head list;
	spinlock_t s_lock;
	int syscall_num;        
	volatile unsigned int syscall_counter;

}__attribute__((packed));


#define TEST_STATUS(x)\
	do {\
		if (!g_status) return -x;\
	} while (0)



#define COUNTER_INC(n)\
	do {\
		unsigned long flags = 0;\
		spin_lock_irqsave(&(n->s_lock), flags);\
		__sync_fetch_and_add(&(n->syscall_counter), 1);\
		spin_unlock_irqrestore(&(n->s_lock), flags);\
	} while(0)


#define COUNTER_DEC(n)\
	do {\
		unsigned long flags = 0;\
		spin_lock_irqsave(&(n->s_lock), flags);\
		__sync_fetch_and_sub(&(n->syscall_counter), 1);\
		spin_unlock_irqrestore(&(n->s_lock), flags);\
	} while(0)





#define enable_interrupts() __asm__ volatile("sti");
#define disable_interrupts() __asm__ volatile("cli");

/*   
 * for kernel V 5.3 and above, provided here a bypass to change CR0 bit 16,               
 * as from kernel 5.3 and on its not allowed to do that using write_cr0(...)
 */
static inline __attribute__((always_inline)) void enable_kernel_write(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)

        unsigned long cr0;
        disable_interrupts();
        cr0 = read_cr0();
        cr0 = cr0 & (~0x10000);
        smp_rmb();
        __asm__ volatile("mov %0,%%cr0": "+r" (cr0), "+m" (__force_order));

#else

        disable_interrupts();
        /*
	 * disable the Write Protection bit in CR0 register
	 * so we can modify kernel code
	 */
        write_cr0(read_cr0() & (~0x10000));

#endif
}



static inline __attribute__((always_inline)) void disable_kernel_write(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0)

        unsigned long cr0;
        cr0 = read_cr0();
        cr0 = cr0 | (0x10000);
        smp_rmb();
        __asm__ volatile("mov %0,%%cr0": "+r" (cr0), "+m" (__force_order));
        enable_interrupts();

#else
        /*
	 * enable the Write Protection bit in CR0 register
	 * once we done modifying kernel code
	 */
        write_cr0(read_cr0() | 0x10000);
        enable_interrupts();
#endif
}




typedef long (*cast_read)(unsigned int fd,
			  char __user *buf,
			  size_t count);

typedef long (*cast_write)(unsigned int fd,
			   const char __user *buf,
			   size_t count);

typedef long (*cast_connect)(int fd,
			     struct sockaddr __user* uservaddr,
			     int addrlen);

typedef long (*cast_open)(const char __user *filename,
			  int flags, 
			  umode_t mode);

typedef long (*cast_close)(unsigned fd);

typedef long (*cast_rename)(int olddfd, 
			    const char __user *oldname,
			    int newdfd,
			    const char __user *newname,
			    unsigned int flags);

typedef long (*cast_unlink)(int dfd, const char __user *pathname);

typedef long (*cast_fchmodat)(int dfd, 
			      const char __user *filename,
			      unsigned int lookup_flags,
			      struct path *path);

typedef long (*cast_exit_group)(int error_code);

typedef long (*cast_truncate)(const char __user *path, long length);

typedef long (*cast_ftruncate)(unsigned int fd, unsigned long length);

typedef long (*cast_ptrace)(long request, 
			    long pid, 
			    unsigned long addr,
			    unsigned long data);




#endif  //__SYSTEMCALL_INTERCEPTOR_
