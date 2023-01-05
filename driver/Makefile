KDIR ?= /lib/modules/$(shell uname -r)/build
BUILD_DIR ?= $(PWD)
BUILD_DIR_MAKEFILE ?= $(BUILD_DIR)/Makefile

NAME        		 := os_interceptor
obj-m       		 := $(NAME).o

policy-srcs              := policy/hardening_policy.o \
                            policy/policy.o \
                            policy/algorithm.o \
                            policy/utils.o

process-srcs             := process/process_scan.o
disassembler_x86-srcs    := disassembler_x86/decode.o \
                            disassembler_x86/itab.o \
                            disassembler_x86/udis86.o

cache_process-srcs       := cache_process/cache_process.o
patching-srcs            := patching/syscall_stub.o \
			    patching/hook_functions.o	

crypto-srcs              := crypto/crypto.o 
network-srcs	         := network/network.o
memory_mngr-srcs         := memory_mngr/kmem_slab_pool.o \
			    memory_mngr/kmem_slab_pool_hash.o \



$(NAME)-y    := main.o \
                mem_handler.o \
                module_boot.o \
                relay_interface.o \
                common.o \
                communication.o \
                bpm_handler.o \
                cache_process_handler.o \
		wq_task.o \
		thread_task.o \
		$(policy-srcs) \
                $(disassembler_x86-srcs) \
                $(cache_process-srcs) \
		$(process-srcs) \
		$(patching-srcs) \
		$(crypto-srcs) \
		$(network-srcs) \
		$(memory_mngr-srcs)

ccflags-y	 := -D__UD_STANDALONE__

default: 
	make -C $(KDIR) M=$(shell realpath $(BUILD_DIR)) src=$(PWD) modules

clean:
	make -C $(KDIR) M=$(BUILD_DIR) src=$(PWD) clean
	rm -rf *~
