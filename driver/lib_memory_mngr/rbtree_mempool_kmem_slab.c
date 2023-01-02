#include "../kcontroller_data_type.h"

static atomic_long_t numerator = ATOMIC_LONG_INIT(0);
/* spin lock for rb tree */
static DEFINE_SPINLOCK(s_lock);
/* memory pool */
static struct kmem_cache* cache_group=NULL;
/* two rb trres for free and taken chunks of memory */
static struct rb_root _root_free  = RB_ROOT;
static struct rb_root _root_taken = RB_ROOT;


static int rb_tree_insert(struct rb_root* root, struct process_cache_node* data);
static struct process_cache_node* rb_search(struct rb_root *root, int value);
struct process_cache_node* _mempool_alloc(void);
void _mempool_free(struct process_cache_node* node);


/*****************************************************************************************/
/*  client  */

void client_usage(void)
{ 
  
  int i; 
  struct process_cache_node* node=NULL, *node_free=NULL;
  struct rb_node* rbnode=NULL; 

  for(i=0; i<THREAD_MAX; i++)
  {
     node=_mempool_alloc();
     pr_info("client_usage allocating node:  [ %d ] ", node->numerator);
  }

  node = NULL;

  for(i=0; i<THREAD_MAX; i++)
  {    
    rbnode = rb_first(&_root_taken);

    node_free = rb_entry(rbnode, struct process_cache_node, node);

    pr_info("client_usage free node:  [ %d ] ",node_free->numerator);

    rb_erase(&node_free->node,&_root_taken);
    rb_tree_insert(&_root_free,node_free); 
    //    rbnode = rb_next(rbnode);
  }

} 


/*****************************************************************************************/
/*  red black tree managment  */


struct process_cache_node* _mempool_alloc(void)
{

  unsigned long flags;
  struct rb_node* node=NULL; 
  
  spin_lock_irqsave(&s_lock,flags);
  
  if((node=rb_first(&_root_free))!=NULL)
  {
      rb_erase(node,&_root_free); 

      spin_unlock_irqrestore(&s_lock,flags);  

      rb_tree_insert(&_root_taken
                    ,rb_entry(node, struct process_cache_node, node)); 

    return rb_search(&_root_taken
                    ,rb_entry(node, struct process_cache_node, node)->numerator);

  }else
  {    
    pr_err("mempool_alloc() error  failed.");
  }

  spin_unlock_irqrestore(&s_lock,flags);  

  return (struct process_cache_node*)NULL;

}



void _mempool_free(struct process_cache_node* node)
{

  if((NULL != rb_search(&_root_taken,node->numerator)))
  {
    rb_erase(&node->node,&_root_taken);
    rb_tree_insert(&_root_free,node); 
  }

}

/*****************************************************************************************/
/*  pool managment */
#if 0 
static void rb_tree_iterator(struct rb_root* root)
{
  struct rb_node* node=NULL;
  for (node = rb_first(root); node; node = rb_next(node))
    info("[ %s ] numerator: [ %d ]",MODULE_NAME
	 , rb_entry(node, struct process_cache_node, node)->numerator);
}
#endif
int rb_tree_insert(struct rb_root* root, struct process_cache_node* data)
{

   struct process_cache_node* this;
   struct rb_node** new = NULL,  *parent = NULL; 
   unsigned long flags;

   spin_lock_irqsave(&s_lock,flags);

   new = &(root->rb_node);
   /* Figure out where to put new node */
   while (*new) 
   {
      this = container_of(*new, struct process_cache_node, node);

      parent = *new;
      if ( this->numerator > data->numerator )
        new = &((*new)->rb_left);
      else if (this->numerator < data->numerator)
        new = &((*new)->rb_right);
   }

   /* Add new node and rebalance tree. */
   rb_link_node(&data->node, parent, new);
   rb_insert_color(&data->node, root);
   spin_unlock_irqrestore(&s_lock,flags);  

 return SUCCESS;
}


static void rb_tree_destroy(struct rb_root* root)
{
  struct rb_node* node;
  struct process_cache_node* node_free;
  for (node = rb_first(root); node; node = rb_next(node)) 
  {
    node_free=NULL;
    node_free=rb_entry(node, struct process_cache_node, node);
    debug("[ %s ] free node numerator: [ %d ]", MODULE_NAME, node_free->numerator);
    rb_erase(node,root);
    kmem_cache_free(cache_group,node_free);    
  }
}

static struct process_cache_node* rb_search(struct rb_root *root, int value)
{
   unsigned long flags;
   struct rb_node *node = NULL;   /* top of the tree */
   
   spin_lock_irqsave(&s_lock,flags);

   node = root->rb_node;

   while (node)
   {
     struct process_cache_node *cur_node = rb_entry(node, struct process_cache_node, node);

     if (cur_node->numerator > value)
	node = node->rb_left;
     else if (cur_node->numerator < value)
	node = node->rb_right;
     else {
           spin_unlock_irqrestore(&s_lock,flags);  
  	   return rb_entry(node, struct process_cache_node, node);
     }
   }

  spin_unlock_irqrestore(&s_lock,flags);  
  return NULL;
}

/*****************************************************************************************/
/* pool allocation */

static void obj_cotr(void* obj)
{ 
  struct process_cache_node*  node = (struct process_cache_node*)obj;
  memset(node,0,sizeof(struct process_cache_node));
}


static int initialize_pool(const unsigned short list_len)
{ 
  int i; 
  struct process_cache_node* node;

  info("[ %s ] adding node to cache. count : [ %d ] ",MODULE_NAME, list_len);

  for(i=0; i<list_len; i++) 
  {
    node=NULL;
    node = (struct process_cache_node*)kmem_cache_alloc(cache_group, GFP_KERNEL);
    if(IS_ERR(node)) 
    {
      error("[ %s ] error allocationg from cache: %ld",MODULE_NAME, PTR_ERR(node));
      kmem_cache_destroy(cache_group);
      return (-ENOMEM);
    }else
    { 

      atomic_long_inc(&numerator);
      node->numerator=atomic_long_read(&numerator);
      // add all obj`s into _root_free
      smp_rmb();
      rb_tree_insert(&_root_free,node);
    }    
  }     
 
 return 0;
}

static inline __attribute__((always_inline))
int create_pool(const unsigned int sizeof_object)
{
  cache_group = kmem_cache_create("rb_memory_pool", sizeof_object,0
				 ,SLAB_HWCACHE_ALIGN|SLAB_POISON|SLAB_RED_ZONE
                                 ,obj_cotr);
  if(IS_ERR(cache_group)) {
     error("[ %s ] error creating cache: %ld", MODULE_NAME, PTR_ERR(cache_group));
    return (-ENOMEM);
  }

  return SUCCESS; 
}




/*****************************************************************************************/
/* module init */

int rbtree_mempool_kmem_slab_init(void)
{
  int ret = SUCCESS; 

  if( (ret=create_pool(sizeof(struct process_cache_node)) == SUCCESS))
  {
    if( (ret=initialize_pool(THREAD_MAX)) == SUCCESS)
    {
      info("[ %s ] memory pool initialized ok. ", MODULE_NAME);
#if 0 
      rb_tree_iterator(&_root_free);
#endif
    }else 
    {
      error("[ %s ] error initializing memory pool driver is going down", MODULE_NAME);
      return ret;
    }
  }else 
  {
    error("[ %s ] error creating memory pool is going down", MODULE_NAME);
    return ret;
  }
  
  //client_usage();

  info("[ %s ] hash_mempool_kmem_slab loaded success.", MODULE_NAME);
 
  return ret; 
}



void rbtree_mempool_kmem_slab_destroy(void)
{
  int i; 
  struct process_cache_node* node_free=NULL;
  struct rb_node* rbnode=NULL; 
  
  for(i=0; i<THREAD_MAX; i++)
  {    
    rbnode = rb_first(&_root_taken);
    if(rbnode && (!IS_ERR(rbnode)))
    { 
      node_free = rb_entry(rbnode, struct process_cache_node, node);
      rb_erase(&node_free->node,&_root_taken);
      rb_tree_insert(&_root_free,node_free); 
    }
  }
 
  rb_tree_destroy(&_root_free);
  kmem_cache_destroy(cache_group); 
}

