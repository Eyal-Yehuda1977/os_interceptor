KDIR ?= /lib/modules/$(shell uname -r)/build
BUILD_DIR ?= $(PWD)
BUILD_DIR_MAKEFILE ?= $(BUILD_DIR)/Makefile

NAME        := os_interceptor
obj-m       := $(NAME).o

bpm-srcs                 := bpm/hardening_policy.o \
                            bpm/bpm.o \
                            bpm/algorithm.o \
                            bpm/utils.o
lib_process-src          := lib_process/process_scan.o
libudis86-srcs           := libudis86/decode.o \
                            libudis86/itab.o \
                            libudis86/udis86.o
lib_cache_process-srcs   := lib_cache_process/cache_process.o
lib_hooks-srcs           := lib_hooks/syscall_stub.o \
			    lib_hooks/hook_functions.o	
lib_crypto-srcs          := lib_crypto/crypto.o 
lib_network-srcs	 := lib_network/network.o
lib_memory_mngr-srcs     := lib_memory_mngr/kmem_slab_pool.o \
			    lib_memory_mngr/kmem_slab_pool_hash.o \



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
		$(bpm-srcs) \
                $(libudis86-srcs) \
                $(lib_cache_process-srcs) \
		$(lib_process-src) \
		$(lib_hooks-srcs) \
		$(lib_crypto-srcs) \
		$(lib_network-srcs) \
		$(lib_memory_mngr-srcs)

ccflags-y	 := -D__UD_STANDALONE__

default: prepare-build
	make -C $(KDIR) M=$(shell realpath $(BUILD_DIR)) src=$(PWD) modules

prepare-build:
	mkdir -p "$(BUILD_DIR)"
	mkdir -p "$(BUILD_DIR)/bpm"
	mkdir -p "$(BUILD_DIR)/libudis86"
	mkdir -p "$(BUILD_DIR)/lib_cache_process"
	mkdir -p "$(BUILD_DIR)/lib_process"
	mkdir -p "$(BUILD_DIR)/lib_hooks"
	mkdir -p "$(BUILD_DIR)/lib_crypto"
	mkdir -p "$(BUILD_DIR)/lib_network"
	mkdir -p "$(BUILD_DIR)/lib_memory_mngr"
	touch "$(BUILD_DIR_MAKEFILE)"

clean:
	make -C $(KDIR) M=$(BUILD_DIR) src=$(PWD) clean
	rm -rf *~
