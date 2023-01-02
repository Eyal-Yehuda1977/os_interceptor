#include "../../driver_shared/driver_api.h"






/* hardening policy rule data type */
struct struct_hp_rule
{	// rule identifier
	char rule_name[EVENT_MAX_PATH_LEN];

	// The HoP operation type
	enum hp_rule_op_type_t op_type;
	// action to be performed on sys call, 2 is allow, 3 is block, 4 match, 5 prevented
	int priority;

	// caller rules
	string_rule_t caller_path;
	string_rule_t caller_name;
	string_rule_t caller_cmd;

	hp_value_user_id_array_t user_id;

	hp_value_md5_array_t caller_md5;

	union {
		struct {
			string_rule_t target_path;
			string_rule_t target_name;
		} process_args;
		struct {
			string_rule_t target_path;
			string_rule_t target_name;
			int flags;
		} filesystem_args;
		struct {
			hp_value_ip_array_t ip;
			hp_value_port_array_t port;
		} network_args;
	};
};





static struct struct_hp_rule[]







int build_hardening_policy_rule_map()
{
  int ret=ERROR;

  



  return ret;
}


int _init_hardening_policy(void) 
{
  int ret=ERROR;


  return ret;
}





void _destroy_hardening_policy(void)
{




}
