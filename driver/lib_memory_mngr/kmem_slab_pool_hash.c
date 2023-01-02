#include "../kcontroller_data_type.h"

/* spin lock for rb tree */
static DEFINE_SPINLOCK(s_lock_rb_tree);

/* two rb trees for free and taken chunks of memory */
static struct rb_root _root_free  = RB_ROOT;
static struct rb_root _root_taken = RB_ROOT;
/* kmem_cache cache_group memory pool */
static struct kmem_cache* cache_group = NULL;

static inline __attribute__((always_inline))
struct process_cache_node* rb_search(struct rb_root *root, struct process_cache_node* value);
static inline __attribute__((always_inline))
int rb_tree_insert(struct rb_root* root, struct process_cache_node* data);
/******************************************************************************************/
/* allocations and freeing of memory */
void* _mempool_alloc_hash(void)
{

  unsigned long flags;
  struct rb_node* node=NULL; 
  
  spin_lock_irqsave(&s_lock_rb_tree,flags);
  
  if((node=rb_first(&_root_free))!=NULL)
  {
      rb_erase(node,&_root_free); 

      rb_tree_insert(&_root_taken
                    ,rb_entry(node, struct process_cache_node, node)); 

      spin_unlock_irqrestore(&s_lock_rb_tree,flags);  

      return (void*)rb_entry(node,struct process_cache_node,node);

  }else
    error("[ %s ] _mempool_alloc_hash() error failed.",MODULE_NAME);

  spin_unlock_irqrestore(&s_lock_rb_tree,flags);  

  return (void*)NULL;
}


void _mempool_free_hash(void* obj)
{
  unsigned long flags;
  struct process_cache_node* node;

  if(obj!=NULL) 
  {

    spin_lock_irqsave(&s_lock_rb_tree,flags);

    node = (struct process_cache_node*)obj;
    if((NULL != rb_search(&_root_taken,node)))
    {
      rb_erase(&node->node,&_root_taken);
      rb_tree_insert(&_root_free,node); 
    }else
      error("[ %s ]  unable to free obj, obj: [ %p ] the given object is not part of"\
            " _root_taken tree " ,MODULE_NAME, obj);

    spin_unlock_irqrestore(&s_lock_rb_tree,flags);  

  }else
    error("[ %s ]  unable to free obj, obj: [ %p ] is not initialized "
          ,MODULE_NAME, obj);
}



/******************************************************************************************/
/* costructors  */

static void hash_cotr(void* obj)
{ 
  struct process_cache_node*  node = (struct process_cache_node*)obj;
  memset(node,0,sizeof(struct process_cache_node));
}

/******************************************************************************************/
/* 1. initialization of red black tree algorithm for hash (lib_cache) usage 
   2. mamangment of red black tree and kmem_cache
*/


/* search node in tree */
static inline __attribute__((always_inline))
struct process_cache_node* rb_search(struct rb_root *root, struct process_cache_node* value)
{

   struct rb_node *node = NULL;   /* top of the tree */

   node = root->rb_node;

   while (node)
   {
     struct process_cache_node *cur_node = rb_entry(node, struct process_cache_node, node);

     if (cur_node > value)
	node = node->rb_left;
     else if (cur_node < value)
	node = node->rb_right;
     else 
 	return rb_entry(node, struct process_cache_node, node);     
   }
  
  return NULL;
}


/* erase and free akk nodes from _root_free tree */
static inline __attribute__((always_inline))
void free_all_nodes_from_root_free_tree(void)
{
  struct rb_node* node;
  struct process_cache_node* node_free;
  for (node = rb_first(&_root_free); node; node = rb_next(node)) 
  {
    node_free=NULL;
    node_free=rb_entry(node, struct process_cache_node, node);
    //debug("[ %s ] free node : [ %p ]", MODULE_NAME, node_free);
    rb_erase(node,&_root_free);
    kmem_cache_free(cache_group,node_free);    
  }
}

/* erase all entries from _root_taken and move them back to _root_free tree */
static inline __attribute__((always_inline))
void free_all_nodes_from_root_taken_tree(void)
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
}


static inline __attribute__((always_inline))
int rb_tree_insert(struct rb_root* root, struct process_cache_node* data)
{

   struct process_cache_node* this;
   struct rb_node** new = NULL,  *parent = NULL; 

   new = &(root->rb_node);
   /* Figure out where to put new node */
   while (*new) 
   {
      this = container_of(*new, struct process_cache_node, node);

      parent = *new;
      if ( this > data )
        new = &((*new)->rb_left);
      else if (this  < data )
        new = &((*new)->rb_right);
   }

   /* Add new node and rebalance tree. */
   rb_link_node(&data->node, parent, new);
   rb_insert_color(&data->node, root);
   //debug("[ %s ] rb_tree_insert() insert : [ %p] "
   //    , MODULE_NAME, data);

 return SUCCESS;
}

static inline __attribute__((always_inline))
int fillup_pf_hash_nodes(void)
{ 
  int i; 
  struct process_cache_node* node;

  info("[ %s ] adding nodes to [ %s ]. count : [ %d ] "
      ,MODULE_NAME,KMEM_HASH,THREAD_MAX);

  for(i=0; i<THREAD_MAX; i++) 
  {
    node=NULL;
    node = (struct process_cache_node*)kmem_cache_alloc(cache_group, GFP_KERNEL);
    if(IS_ERR(node)) 
    {
      error("[ %s ] error allocationg from cache: %ld, to cache: [ %s ]"
	    ,MODULE_NAME, PTR_ERR(node), KMEM_HASH);
      kmem_cache_destroy(cache_group);
      return (-ENOMEM);
    }else
    { 
      smp_rmb();
      rb_tree_insert(&_root_free,node);
    }    
  }     
 
 return 0;
}


/******************************************************************************************/
/* slab kmem_group memory pools initialization  */

int init_memory_hash(void)
{

  cache_group = kmem_cache_create(KMEM_HASH, sizeof(struct process_cache_node),0
	   	                 ,SLAB_HWCACHE_ALIGN|SLAB_POISON|SLAB_RED_ZONE
                                 ,hash_cotr);
  if(IS_ERR(cache_group)) {
     error("[ %s ] error creating cache: [ %ld ], cache name: [ %s ]"
	   ,MODULE_NAME, PTR_ERR(cache_group), KMEM_HASH);
    return (-ENOMEM);
  }

  fillup_pf_hash_nodes();

  info("[ %s ] kmem_cache initialized success.",MODULE_NAME);

  return SUCCESS;
}  


void destroy_memory_hash(void)
{
  free_all_nodes_from_root_taken_tree();
  free_all_nodes_from_root_free_tree();  
  kmem_cache_destroy(cache_group);   

  info("[ %s ] kmem_cache destroyed success.", MODULE_NAME);
}  
