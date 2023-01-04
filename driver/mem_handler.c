#include "kcontroller_data_type.h"

static unsigned long* find_sys_call_table_ref(u8* code){
  size_t i;

  for (i = 0; i < 256; i++)  //0xFF14c5****48894424
  {
#ifdef CONFIG_X86_64
      if (code[i + 0] == 0xFF && code[i + 1] == 0x14 && code[i + 2] == 0xC5 && code[i + 7] == 0x48 &&
          code[i + 8] == 0x89 && code[i + 9] == 0x44 && code[i +10] == 0x24)
      {
	  u32 offset = *((u32*) &code[i + 3]);
          debug("syscall table address  %p\n", ((unsigned long*) (0xFFFFFFFF00000000 | offset)));
	  return (unsigned long*) (0xFFFFFFFF00000000 | offset);  // 0xFFFFFFFF***** syscall table address 
      }
#else
      if (code[i + 0] == 0xFF && code[i + 1] == 0x14 && code[i + 2] == 0x85 && code[i + 7] == 0x89 &&
	  code[i + 8] == 0x44 && code[i + 9] == 0x24) 
	{
	  u32 offset = *((u32*) &code[i + 3]);
	  return (unsigned long*) offset;
	}
#endif
    }

  return NULL;
}

static inline u8* get_64bit_system_call_handler(void){
  u64 system_call_entry;
  rdmsrl(MSR_LSTAR, system_call_entry);
  return (u8*) system_call_entry;
}


static inline u8* get_32bit_system_call_handler(void){
  struct desc_ptr interrupt_descriptor_table;
  gate_desc* interrupt_gates;

  store_idt(&interrupt_descriptor_table);
  interrupt_gates = (gate_desc*) interrupt_descriptor_table.address;

  return (u8*) gate_offset(interrupt_gates[IA32_SYSCALL_VECTOR]);
}



unsigned long* locate_sys_call_table(void)
{

#ifdef CONFIG_X86_64
     return find_sys_call_table_ref(get_64bit_system_call_handler());
#else
     return find_sys_call_table_ref(get_32bit_system_call_handler());
#endif

}



/* change pemision flags in pte so memory become writeble  */
int mem_make_rw(unsigned long addr) 
{
   int ret = SUCCESS;
   pte_t * pte;
   unsigned int level;

   pte = lookup_address(addr, &level);
   if (NULL == pte) 
   {
   	ret = ERROR;	
   }else if (0 == (pte->pte & _PAGE_RW)) 
   { /* Add read & write permissions if needed */
  	pte->pte |= _PAGE_RW;
   }
   return ret;
}

/* find assembly inunstruction  offset return back offset ot -1 */
long mem_find_insntruction_offset(unsigned long mem_addr, size_t block_size,int insn_type,
				size_t insn_size) 
{
   ud_t ud;
   ud_init(&ud);
   ud_set_input_buffer(&ud, (char * ) mem_addr, block_size);
   ud_set_mode(&ud, 64);

   /* Run over the memory region */
   while(ud_disassemble(&ud)) 
   {
     if ((insn_type == ud.mnemonic) && (insn_size == ud_insn_len(&ud)) ) 
     {
 	return ud_insn_off(&ud);		
     }
   }
 
 return ERROR;
}


/*  get the new hack sys call and patch the original with it 
    and save the original address to put back things when module is unloded  */
int mem_patch_relative_call(unsigned long mem_addr, size_t block_size, unsigned long new_call_addr,
				unsigned long * orig_call_addr) 
{
   int ret = SUCCESS;
   long call_insn_offset, call_insn_addr, call_relative_val, new_call_relative_val;


   /* Find the relative call instruction (E8) offset. this for x86 only !!! */
   call_insn_offset = mem_find_insntruction_offset(mem_addr, 
                                     block_size, UD_Icall, RELATIVE_CALL_SIZE);	
   if (ERROR == call_insn_offset) 
   {
      error("Error patching the relative call address instruction was not found\n");
      ret = ERROR;

   }else
   {
      /* Calculate the call instruction address */
      call_insn_addr = (mem_addr + call_insn_offset);
        
      // EYAL TODO check this permissions issue !        
      mem_make_rw(call_insn_addr);  

      call_relative_val = (*((int *) (call_insn_addr + 1)));

      /* Calculate the relative value for calling the new_sys_execve */
      new_call_relative_val = ((unsigned long) new_call_addr - call_insn_addr - RELATIVE_CALL_SIZE);
  
      /* Save the address of the original sys_execve */
      if (NULL != orig_call_addr) 
      {
        *orig_call_addr = call_insn_addr + RELATIVE_CALL_SIZE + call_relative_val;
      }

      /* Patch */
      (*((int*)(call_insn_addr + 1))) = (int) new_call_relative_val;
   }        

  return ret;
}



int obtain_sys_call_table_addr(unsigned long * sys_call_table_addr) 
{
  int ret = SUCCESS;
  unsigned long temp_sys_call_table_addr;

  temp_sys_call_table_addr = kallsyms_lookup_name(SYM_SYS_CALL_TABLE);


  debug("syscall table address  %p\n", sys_call_table_addr);

  /* Return error if the symbol doesn't exist */
  if (0 == sys_call_table_addr) 
  {
    ret = ERROR;
  }else
  {
    *sys_call_table_addr = temp_sys_call_table_addr;
  }

 return ret;
}


/*  make the page which holds syscall table adress writble . instead of changing pemissions 
we map its virtual address to new page with out permissions */
static int enumerate_pages(void* region, struct page *pages[], size_t page_num)
{
  size_t i;
  void* page_addr = base_of_page(region);

  for (i = 0; i < page_num; i++) 
  {
    // explain check if we can treat it as module so we can use it as page 
    if (__module_address((unsigned long) page_addr)) 
    {
      pages[i] = vmalloc_to_page(page_addr);
    }else 
    {
      pages[i] = virt_to_page(page_addr);
      WARN_ON(!PageReserved(pages[i]));
    }

    if (!pages[i]) return -EFAULT;

    page_addr += PAGE_SIZE;
  }

  return 0;
}




void* remap_with_write_permissions(void* region, size_t len)
{
  unsigned short res=SUCCESS;
  void* writeable_region;
  size_t page_num = DIV_ROUND_UP(offset_in_page(region) + len, PAGE_SIZE);
  struct page **pages = kmalloc(page_num * sizeof(*pages), GFP_KERNEL);

  if (!pages) res=ERROR;
  /* retrive back the system call table with out its permissions */
  if ((res==SUCCESS) && enumerate_pages(region, pages, page_num)) res=ERROR;
    
  if (res==SUCCESS)
  {
     writeable_region = vmap(pages, page_num, VM_MAP, PAGE_KERNEL);
     if (!writeable_region) res=ERROR;
   
     kfree(pages);
                              /* return back writble memory region offset */
     if (res==SUCCESS) return writeable_region + offset_in_page(region);
  }
  
  kfree(pages);
  return NULL;
}






