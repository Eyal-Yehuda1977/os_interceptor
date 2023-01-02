#ifndef __NETWOEK_H_
#define __NETWOEK_H_



void __enable_quarantine(void);
void __disable_quarantine(void);

int set_quarantine_info(const __be32* daddr, 
			const __be32* saddr,
                        const __be16* port, 
                        char* err); 

int  __quarantine_mode(void);

int __quarantine_data_valid(void);

#endif
