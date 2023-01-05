Os Interceptor  (development in progress)


What is it ?
------------
The provided kernel driver is an example ( POC ), of how we can harden the Linux kernel 
and applay a policy for each process, so under some circumstances we can prevent is from running 
or get notifyed to user space, or both 

Driver features
---------------
1. The Kernel driver support system call table monitoring for some important system calls
2. Networking, quarantine the machine using Net filter
3. Memory management, Slab allocator used for memory pool 


Please notice 
-------------
1. This driver supports kernel version 3.10 only for now.
2. u can track the driver using dmesg -W
   or try to read from  : 
   /sys/kernel/debug/os_interceptor_dfs
   /sys/kernel/debug/os_interceptor_relay/cpu0 


Thanks Eyal Yehuda