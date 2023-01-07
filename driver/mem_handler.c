#include "os_interceptor_data_type.h"
#include "patching/systemcall_interception.h"




/* 
   change pemision flags in pte (page table entry)  so memory become writeble  
*/
int mem_make_rw(unsigned long addr) {

	int ret = SUCCESS;
	pte_t *pte;
	unsigned int level;

	pte = lookup_address(addr, &level);
	if (NULL == pte) {
		ret = ERROR;	
	} else if (0 == (pte->pte & _PAGE_RW)) 
	{ /* Add read & write permissions */
		pte->pte |= _PAGE_RW;
	}

	return ret;
}

/* find assembly inunstruction  offset return back offset ot -1 */
long mem_find_insntruction_offset(unsigned long mem_addr, size_t block_size, int insn_type,
				  size_t insn_size) 
{
	ud_t ud;
	ud_init(&ud);
	ud_set_input_buffer(&ud, (char*) mem_addr, block_size);
	ud_set_mode(&ud, 64);

	/* Run over the memory region */
	while(ud_disassemble(&ud)) {
		if ((insn_type == ud.mnemonic) && (insn_size == ud_insn_len(&ud)) ) {
			return ud_insn_off(&ud);		
		}
	}
 
	return ERROR;
}

#if 0 
/*  get the new hack sys call and patch the original with it 
    and save the original address to put back things when module is unloded  */
int mem_patch_relative_call(unsigned long mem_addr, size_t block_size, unsigned long new_call_addr,
				unsigned long *orig_call_addr) 
{

	int ret = SUCCESS;
	long call_insn_offset, call_insn_addr, call_relative_val, new_call_relative_val;


	/* Find the relative call instruction (E8) offset. this for x86 only !!! */
	call_insn_offset = mem_find_insntruction_offset(mem_addr, block_size, 
							UD_Icall, RELATIVE_CALL_SIZE);	
	if (ERROR == call_insn_offset) {
		error("Error patching the relative call address instruction was not found\n");
		ret = ERROR;
	} else
	{
		/* Calculate the call instruction address */
		call_insn_addr = (mem_addr + call_insn_offset);
        

		mem_make_rw(call_insn_addr);  
		call_relative_val = (*((int *) (call_insn_addr + 1)));

		/* Calculate the relative value for calling the new_sys_execve */
		new_call_relative_val = ((unsigned long) new_call_addr - call_insn_addr - RELATIVE_CALL_SIZE);
  
		/* Save the address of the original sys_execve */
		if (NULL != orig_call_addr) {
			*orig_call_addr = call_insn_addr + RELATIVE_CALL_SIZE + call_relative_val;
		}

		/* 
		   Patch, put the relative offset in byets to our system call
		*/
		(*((int*)(call_insn_addr + 1))) = (int) new_call_relative_val;
	}        


	return ret;
}
#endif


/*  get the new hack sys call and patch the original with it 
 *  and save the original address to put back things when module is unloded  
*/
int mem_patch_relative_call(unsigned long mem_addr,
			    size_t block_size,
			    unsigned long new_call_addr,
			    unsigned long *orig_call_addr) 
{

	int ret = SUCCESS;
	long call_insn_offset = 0, call_insn_addr = 0, call_relative_val = 0, 
		new_call_relative_val = 0;


	/* 
	 * Find the relative call instruction (E8) offset. this for x86 only !!! 
	 */
	call_insn_offset = mem_find_insntruction_offset(mem_addr,
							block_size, 
							UD_Icall, 
							RELATIVE_CALL_SIZE);	
	if ( ERROR == call_insn_offset ) {

		error("[ %s ] error patching the relative call address."\
		      " instruction was not found\n", 
		      MODULE_NAME);

		ret = ERROR;
	} else
	{
		/* 
		   Calculate the call instruction address 
		*/
		call_insn_addr = (mem_addr + call_insn_offset);    
		call_relative_val = (*((int *) (call_insn_addr + 1)));

		/* 
		   Calculate the relative value for calling the system call offset 
		*/
		new_call_relative_val = ((unsigned long) new_call_addr - call_insn_addr 
					 - RELATIVE_CALL_SIZE);
  
		/* 
		   Save the address of the original system call 
		*/
		if ( NULL != orig_call_addr ) {

			*orig_call_addr = call_insn_addr + RELATIVE_CALL_SIZE 
				+ call_relative_val;
		}


		enable_kernel_write();
		/* 
		   patch 
		*/
		(*((int*)(call_insn_addr + 1))) = (int) new_call_relative_val;
		
		disable_kernel_write();
	}        

	return ret;
}


/*
  look up for syetem call table address
*/
int lookup_sys_call_table_addr(unsigned long *sys_call_table_addr) {

	int ret = SUCCESS;
	unsigned long temp_sys_call_table_addr;
	
	temp_sys_call_table_addr = kallsyms_lookup_name(SYM_SYS_CALL_TABLE);

	debug("syscall table address  %p\n", sys_call_table_addr);

	/* 
	   Return error if the symbol doesn't exist 
	*/
	if (0 == sys_call_table_addr) 
		ret = ERROR;
	else	
		*sys_call_table_addr = temp_sys_call_table_addr;

	return ret;
}


/*  
    pages buuffer will point to original system call table pages
 */
static int enumerate_pages(void *region, struct page *pages[], size_t page_num) {


	size_t i;
	void *page_addr = base_of_page(region);

	for (i = 0; i < page_num; i++) {

		if (__module_address((unsigned long) page_addr)) {
			pages[i] = vmalloc_to_page(page_addr);
		} else 
		{
			pages[i] = virt_to_page(page_addr);
			WARN_ON( !PageReserved(pages[i]) );
		}

		if ( !pages[i] ) return -EFAULT;

		page_addr += PAGE_SIZE;
	}

	return 0;
}




static void *remap_with_write_permissions(void *region, size_t len) {


	void *writeable_region = NULL;
	size_t page_num = 0;
	struct page **pages = NULL;

	page_num = DIV_ROUND_UP(offset_in_page(region) + len, PAGE_SIZE);
	pages  = kmalloc(page_num * sizeof(*pages), GFP_KERNEL);

	if( IS_ERR_OR_NULL(pages) ) {	
		error("[ %s ] memory allocation error. ", MODULE_NAME);
		return NULL;
	}


	if ( enumerate_pages(region, pages, page_num) ) {
		error("[ %s ] enumerate_pages() error. ", MODULE_NAME);
		goto err;
	}

	writeable_region = vmap(pages, page_num, VM_MAP, PAGE_KERNEL); 
	if ( !writeable_region ) {
		error("[ %s ] vmap() error. ", MODULE_NAME);
		goto err;
	}

	kfree(pages);
	return writeable_region + offset_in_page(region);

err:
	kfree(pages);
	return NULL;
}



int do_with_write_permissions(int (*fn)(struct gl_region[]),
                              struct gl_region regions[],
                              size_t region_count)
{
	size_t i, j;

        debug("[ %s ] system call table address before remap %p\n",
	      MODULE_NAME,
	      regions[0].source);

	if ( !fn )  
		return (-EINVAL);
	

	if ( !regions || region_count == 0 )
		return fn(NULL);

	for (i = 0; i < region_count; i++) {

		regions[i].writeable =
			remap_with_write_permissions(regions[i].source,
			                             regions[i].length);
		if (!regions[i].writeable) {

			for (j = 0; j < i; j++) {
				vunmap(base_of_page(regions[j].writeable));
			}
			
			error("[ %s ]  regions[i].writeable == NULL ", MODULE_NAME);
			return (-ENOMEM);
		}
	}

        debug("[ %s ] system call table address after remap %p\n", 
	      MODULE_NAME,
	      regions[0].writeable);
	
	fn(regions);

	for (i = 0; i < region_count; i++) {
		vunmap(base_of_page(regions[i].writeable));
	}

	return (SUCCESS);
}




