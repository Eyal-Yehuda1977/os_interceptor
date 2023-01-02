#ifndef __CRYPTO_H_
#define __CRYPTO_H_




/* crypto defines */
#define SHA1_LENGTH                         20
#define MD5_LENGTH                          16
#define MODULE_CRYPTO                       "crypto"

enum 
{
  algo_md5=0,
  algo_sha1=1
};                            

#define ENUM_ALGO_SIZE                      2

int __crypto_run_algorithem(unsigned char algo
                           ,char* data
                           ,int len
                           ,char* out);


#endif
