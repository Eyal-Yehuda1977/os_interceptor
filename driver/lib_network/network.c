#include "../kcontroller_data_type.h"


static DEFINE_RWLOCK(s_rwlock);
static atomic_long_t quarantine_enabled = ATOMIC_LONG_INIT(0);

static struct quarantine_info {
  /* server ip  */
  __be32            daddr;
  /* agent ip */
  __be32            saddr;
  /* port (dest/source)  */
  __be16            port;
  /* nic bame */
  char              device[IFNAMSIZ];

} un_q;


#define TRAFFIC_IN   0
#define TRAFFIC_OUT  1

#define __quarantine_mode_ (atomic_long_read(&quarantine_enabled)==1)

#define __debug_mode_ssh_enable_(tcph)\
  if(tcph->source==ntohs(22) || tcph->dest==ntohs(22) ) return NF_ACCEPT;


static inline __attribute__((always_inline)) 
int  validate_net_device(const __be32* daddr, 
			 const __be32* saddr,
                         const __be16* port, 
                         char* err);


int set_quarantine_info(const __be32* daddr, 
			const __be32* saddr,
                        const __be16* port, 
                        char* err) 
{
  int ret=SUCCESS;
  unsigned long flags;

  if(*daddr==0) {
       snprintf(err,CONTROL_BUFFER_DEFAULT_SIZE
               ,"invalid server ip address: daddr = [ %u ] ",*daddr);
      ret = ERROR;
  }

  if(*saddr==0) {
     snprintf(((err + strlen(err))-1),CONTROL_BUFFER_DEFAULT_SIZE,
                " invalid agent ip address: saddr  = [ %u ] ",*saddr);
     ret = ERROR;
  }   
         
  if(*port==0) {
     snprintf(((err + strlen(err))-1),CONTROL_BUFFER_DEFAULT_SIZE,
                    " invalid port:  port = [ %u ] ",*port);
     ret = ERROR;
  }
         

  if(ret==SUCCESS) 
  { 
    /* if the agent ip has changed it needs validation */   
    if((*saddr!=un_q.saddr)) {
        validate_net_device(daddr,saddr,port,err); 
    } else {       

      write_lock_irqsave(&s_rwlock,flags);  

      un_q = (struct quarantine_info) {
           .daddr=*daddr,               
           .port=*port,
      };

      write_unlock_irqrestore(&s_rwlock,flags); 
    }              
  }
 
 return ret;
}


int __quarantine_mode(void) {
  return __quarantine_mode_;
}

void __enable_quarantine(void) {  
  atomic_long_set(&quarantine_enabled,1);
  info("[ %s ]  quarantine enabled. ",MODULE_NAME);
}

void __disable_quarantine(void) {
  atomic_long_set(&quarantine_enabled,0);
  info("[ %s ]  quarantine disabled. ",MODULE_NAME);
}


static inline __attribute__((always_inline)) 
int __quarantine_filter(const struct iphdr*  iph
                       ,const struct tcphdr* tcph
                       ,const unsigned char  direction) 
{

  unsigned long flags; 

  __debug_mode_ssh_enable_(tcph)

  if( __quarantine_mode_ ) 
  {

    read_lock_irqsave(&s_rwlock,flags);

    if(direction==TRAFFIC_IN) 
    { 
      if((memcmp(&(iph->daddr),  &(un_q.saddr),   sizeof(un_q.saddr)) ==0) 
         && (memcmp(&(iph->saddr),  &(un_q.daddr),   sizeof(un_q.daddr)) ==0)
	 && (memcmp(&(tcph->dest),  &(un_q.port),    sizeof(un_q.port))==0))  
      {
        read_unlock_irqrestore(&s_rwlock,flags);
	return NF_ACCEPT;
      }

    } else if(direction==TRAFFIC_OUT)
    {

      if((memcmp(&(iph->daddr),  &(un_q.daddr),   sizeof(un_q.daddr)) ==0) 
         && (memcmp(&(iph->saddr),  &(un_q.saddr),   sizeof(un_q.saddr)) ==0)
	 && (memcmp(&(tcph->source),&(un_q.port),    sizeof(un_q.port))==0))  
      {
        read_unlock_irqrestore(&s_rwlock,flags);
        return NF_ACCEPT;
      }
    }

    read_lock_irqsave(&s_rwlock,flags);

  }else
  {
    return NF_ACCEPT;
  }
 
 return NF_DROP;
}


static unsigned int nf_hook_rcv(const struct nf_hook_ops* ops
                               ,struct sk_buff* skb
                               ,const struct net_device* in
                               ,const struct net_device* out
#ifndef __GENKSYMS__
			       ,const struct nf_hook_state* state
#else
                               ,int (*okfn)(struct sk_buff*)
#endif
			       )
{
    const __be16   iptype = __constant_htons(ETH_P_IP);
    struct iphdr*  iph=NULL;
    struct tcphdr* tcph=NULL;
    int            ret;
    unsigned int   h_num=ops->hooknum;

   
    if ((h_num != NF_INET_PRE_ROUTING) || (skb == NULL ) 
        || (in  == NULL ) || (out != NULL ) ) 
    {         
	error("[ %s ] invalid arguments. hooknum: [ %d ] skb: [ %p ] in: [ %p ] out: [ %p ]" 
  	      ,MODULE_NAME, h_num, skb,in,out);
        return NF_ACCEPT;
    }

    /* verify we are handle only ip packet */
    if (skb->protocol != iptype) {
        error("[ %s ]  not ip packet. skb->protocol: [ 0x%04x ]"
             ,MODULE_NAME, ntohs(skb->protocol));
       return NF_ACCEPT;
    }

    iph = ip_hdr(skb);

    /* verify correct ip version IPv4 */
    if (iph->version != IPVERSION) {
        error("[ %s ] ip packet with incorrect version. iph->version: [ %d ]"
   	     ,MODULE_NAME,iph->version);
        return NF_ACCEPT;
    }

    /* verify minimum IPv4 header length */
    if (iph->ihl < 5) {
        error("[ %s ] ip packet with incorrect header length iph->ihl [ %d ]"
	     ,MODULE_NAME,iph->ihl);
        return NF_ACCEPT;
    }

    /* verify packet to me */
    if (skb->pkt_type != PACKET_HOST)  
        return NF_ACCEPT;
   
    switch(iph->protocol) 
    {
     case IPPROTO_TCP:   
       tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl*4));
       ret=__quarantine_filter(iph,tcph,TRAFFIC_IN);  
     break;
     case IPPROTO_ICMP: 
       if( __quarantine_mode_ )
        ret=NF_DROP;
       else
         ret=NF_ACCEPT;  
     break;
     case IPPROTO_UDP:  ret=NF_ACCEPT;  break; 
     default:           ret=NF_ACCEPT;  break;
    }

  return ret;
}


static unsigned int nf_hook_snd_first(const struct nf_hook_ops* ops
                                     ,struct sk_buff* skb
                                     ,const struct net_device* in
                                     ,const struct net_device* out
#ifndef __GENKSYMS__
	    		             ,const struct nf_hook_state* state
#else
                                     ,int (*okfn)(struct sk_buff*)
#endif
			             )

{
    const __be16   iptype = __constant_htons(ETH_P_IP);
    struct iphdr*  iph=NULL;
    struct tcphdr* tcph=NULL;
    int            ret;
    unsigned int   h_num=ops->hooknum;

    if ((h_num != NF_INET_POST_ROUTING) || (skb == NULL ) 
         || (in != NULL ) || (out == NULL ) ) 
    {
	error("[ %s ] invalid arguments. hooknum: [ %d ] skb: [ %p ] in: [ %p ] out: [ %p ]" 
  	      ,MODULE_NAME, h_num, skb,in,out);
        return NF_ACCEPT;
    }

    /* verify we are handle only ip packet */
    if (skb->protocol != iptype) {
        error("[ %s ]  not ip packet. skb->protocol: [ 0x%04x ]"
             ,MODULE_NAME, ntohs(skb->protocol));
       return NF_ACCEPT;
    }  

    iph = ip_hdr(skb);

    /* verify correct ip version IPv4 */
    if (iph->version != IPVERSION) {
        error("[ %s ] ip packet with incorrect version. iph->version: [ %d ]"
   	     ,MODULE_NAME,iph->version);
       return NF_ACCEPT;
    }

    /* verify minimum IPv4 header length */
    if (iph->ihl < 5) {
        error("[ %s ] ip packet with incorrect header length iph->ihl [ %d ]"
	     ,MODULE_NAME,iph->ihl);
       return NF_ACCEPT;
    }

    switch(iph->protocol) 
    {
     case IPPROTO_TCP:   
       tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl*4));
       ret=__quarantine_filter(iph,tcph,TRAFFIC_OUT);  
     break;
     case IPPROTO_ICMP: 
       if( __quarantine_mode_ )
       	 ret=NF_DROP;
       else
         ret=NF_ACCEPT;  
     break;
     case IPPROTO_UDP:  ret=NF_ACCEPT;  break; 
     default:           ret=NF_ACCEPT;  break;
    }

  return ret;
}



static unsigned int nf_hook_snd_last(const struct nf_hook_ops* ops
                                    ,struct sk_buff* skb
                                    ,const struct net_device* in
                                    ,const struct net_device* out
#ifndef __GENKSYMS__
			            ,const struct nf_hook_state* state
#else
                                    ,int (*okfn)(struct sk_buff*)
#endif
			            )
{
    const __be16   iptype = __constant_htons(ETH_P_IP);
    struct iphdr*  iph=NULL;
    struct tcphdr* tcph=NULL;
    int            ret;
    unsigned int   h_num=ops->hooknum;

    if ((h_num != NF_INET_POST_ROUTING) || (skb == NULL ) 
         || (in != NULL ) || (out == NULL ) ) 
    {
	error("[ %s ] invalid arguments. hooknum: [ %d ] skb: [ %p ] in: [ %p ] out: [ %p ]" 
  	      ,MODULE_NAME, h_num, skb,in,out);
        return NF_ACCEPT;
    }

    /* verify we are handle only ip packet */
    if (skb->protocol != iptype) {
        error("[ %s ]  not ip packet. skb->protocol: [ 0x%04x ]"
             ,MODULE_NAME, ntohs(skb->protocol));
       return NF_ACCEPT;
    }  

    iph = ip_hdr(skb);

    /* verify correct ip version IPv4 */
    if (iph->version != IPVERSION) {
        error("[ %s ] ip packet with incorrect version. iph->version: [ %d ]"
   	     ,MODULE_NAME,iph->version);
        return NF_ACCEPT;
    }

    /* verify minimum IPv4 header length */
    if (iph->ihl < 5) {
        error("[ %s ] ip packet with incorrect header length iph->ihl [ %d ]"
	     ,MODULE_NAME,iph->ihl);
        return NF_ACCEPT;
    }

    switch(iph->protocol) 
    {
     case IPPROTO_TCP:   
       tcph = (struct tcphdr*)((unsigned char*)iph + (iph->ihl*4));
       ret=__quarantine_filter(iph,tcph,TRAFFIC_OUT);  
     break;
     case IPPROTO_ICMP: 
       if( __quarantine_mode_ )
       	 ret=NF_DROP;
       else
         ret=NF_ACCEPT;  
     break;
     case IPPROTO_UDP:  ret=NF_ACCEPT;  break; 
     default:           ret=NF_ACCEPT;  break;
    }
  return ret;
}


static inline __attribute__((always_inline)) 
int  validate_net_device(const __be32* daddr, 
			 const __be32* saddr,
                         const __be16* port, 
                         char* err)
{ 
  int ret=ERROR;
  struct net_device *dev=NULL;
  struct in_device* in_dev=NULL;
  struct in_ifaddr* if_info=NULL;
  char ip_buf[INET6_ADDRSTRLEN+1];
  unsigned long flags;

  memset(&un_q,0,sizeof(struct quarantine_info));

  for_each_netdev(&init_net, dev) {

    info("[ %s ] --------------------------------------------------", MODULE_NAME);
    info("[ %s ] name:   %s ", MODULE_NAME, dev->name);
    info("[ %s ] alias:  %s ", MODULE_NAME, dev->ifalias);
    info("[ %s ] index:  %d ", MODULE_NAME, dev->ifindex);

    in_dev = dev->ip_ptr;
    if_info = in_dev->ifa_list;

    if(if_info) {
      for(;if_info!=NULL;if_info=if_info->ifa_next) {
        if(if_info->ifa_address) {
          if(memcmp(&if_info->ifa_address,saddr,sizeof(if_info->ifa_address))==0) {
               
               write_lock_irqsave(&s_rwlock,flags);  
                
               un_q = (struct quarantine_info) {
                      .daddr=*daddr,
                      .saddr=*saddr,
                      .port=*port,
               };
  
 	       strncpy(un_q.device,dev->name,IFNAMSIZ);

               write_unlock_irqrestore(&s_rwlock,flags); 

               info("[ %s ] device found !",MODULE_NAME);	                    
               ret = SUCCESS;
          }

          memset(ip_buf,0,(INET6_ADDRSTRLEN+1)); 
	  sprintf(ip_buf,"%d.%d.%d.%d",NIPQUAD(if_info->ifa_address));
  	  info("[ %s ] addr:  %s",MODULE_NAME, ip_buf);   
	}
      }
    } 
    info("[ %s ] --------------------------------------------------", MODULE_NAME);
  }

  if(ret==ERROR) {
 
     memset(ip_buf,0,(INET6_ADDRSTRLEN+1)); 
     sprintf(ip_buf,"%d.%d.%d.%d",NIPQUAD(*saddr));
 
     snprintf(err,CONTROL_BUFFER_DEFAULT_SIZE,"ip addres used by agent [ %s ]"\
              " is not related to any network interface. ",ip_buf);
  }

 return ret;
}


static struct nf_hook_ops nf_hook_ops_arr[] =
{
   { 
      .hook     = nf_hook_rcv,
      .owner    = THIS_MODULE,
      .pf       = NFPROTO_IPV4,
      .hooknum  = NF_INET_PRE_ROUTING,
      .priority = NF_IP_PRI_FIRST
   },{
      .hook     = nf_hook_snd_first,
      .owner    = THIS_MODULE,
      .pf       = NFPROTO_IPV4,
      .hooknum  = NF_INET_POST_ROUTING,
      .priority = NF_IP_PRI_FIRST 
   },{
      .hook     = nf_hook_snd_last,
      .owner    = THIS_MODULE,
      .pf       = NFPROTO_IPV4,
      .hooknum  = NF_INET_POST_ROUTING,
      .priority = NF_IP_PRI_LAST  
   }
};


int init_network(void) {

  int ret=SUCCESS;
  
  ret = nf_register_hooks(nf_hook_ops_arr
            ,sizeof(nf_hook_ops_arr)/sizeof(nf_hook_ops_arr[0]));

  if(ret!= 0) {
      error("[ %s ] init_network failed to register hooks ret: [ %d ]"
	   ,MODULE_NAME,ret); 
     return ret;
  }

  info("[ %s ] init_network() loaded ok",MODULE_NAME);

  return ret;
}



void destroy_network(void) {

    nf_unregister_hooks(nf_hook_ops_arr
            ,sizeof(nf_hook_ops_arr)/sizeof(nf_hook_ops_arr[0]));

    info("[ %s ]  destroy_network() unloaded", MODULE_NAME );
}


