#include "../kcontroller_params.h"
#include "crypto.h"

#ifdef DEBUG_MODE_PRINT  // only for kernel dmesg
#define HEX_DUMP(buf,len)\
  print_hex_dump(KERN_CONT, "", DUMP_PREFIX_OFFSET,\
	         16, 1,buf, len, false);
#else
#define HEX_DUMP(buf,len)
#endif

static struct crypto_hash* tfm_buf[ENUM_ALGO_SIZE];

static inline __attribute__((always_inline))
int __calculate_md5sum(char* data, int len, char* out)
{
  int ret = SUCCESS;
  struct scatterlist sg;
  struct hash_desc desc;

  memset(out,0x00,MD5_LENGTH);
  
  desc.tfm = tfm_buf[algo_md5];
  desc.flags = 0;

  sg_init_one(&sg, data, len);
  crypto_hash_init(&desc);

  crypto_hash_update(&desc, &sg, len);
  crypto_hash_final(&desc, out);
 
  HEX_DUMP(out,MD5_LENGTH)

  return ret;
}


static inline __attribute__((always_inline))
int __calculate_sha1sum(char* data, int len, char* out)
{
  int ret = SUCCESS;
 
  struct scatterlist sg;
  struct hash_desc desc;

  memset(out,0x00,SHA1_LENGTH);
  
  desc.tfm = tfm_buf[algo_sha1];
  desc.flags = 0;

  sg_init_one(&sg, data, len);
  crypto_hash_init(&desc);

  crypto_hash_update(&desc, &sg, len);
  crypto_hash_final(&desc, out);
 
  HEX_DUMP(out,SHA1_LENGTH)

  return ret;
}




int __crypto_run_algorithem(unsigned char algo
                           ,char* data
                           ,int len
                           ,char* out)
{
  int ret = SUCCESS;

  if(len<=0){
    error("[ %s ] ERROR invalid len: %d ",MODULE_NAME, len);
    return (-EINVAL);
  }
 
  if(data==NULL){
    error("[ %s ] ERROR invalid data: %p ",MODULE_NAME, data);
    return (-EINVAL);
  }

  switch(algo)
  {
  case algo_md5: 
    ret = __calculate_md5sum(data,len,out);
    break;

  case algo_sha1: 
    ret =  __calculate_sha1sum(data,len,out);
    break;
  default: 
    ret = ERROR; 
    error("[ %s ] undefined algorithem for lib crypto.",MODULE_NAME);  
    break;
  }

  return ret;
}





int init_crypto(void)
{
  memset(tfm_buf,0,ENUM_ALGO_SIZE*sizeof(struct crypto_hash*));

  tfm_buf[algo_md5] = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
  if(!tfm_buf[algo_md5]){
     error("[ %s ] ERROR crypto_alloc_hash md5", MODULE_NAME);
    return (-EINVAL);
  }
   
  tfm_buf[algo_sha1] = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);  
  if(!tfm_buf[algo_sha1]){
     error("[ %s ] ERROR crypto_alloc_hash sha1", MODULE_NAME);
    return (-EINVAL);
  }
  
  info("[ %s ] lib crypto  initialized success. ",MODULE_NAME);

  return SUCCESS;
}


void destroy_crypto(void)
{
  crypto_free_hash(tfm_buf[algo_md5]);
  crypto_free_hash(tfm_buf[algo_sha1]);
 
  info("[ %s ] lib crypto destroyed . ",MODULE_NAME); 
}
