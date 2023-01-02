#include "macros.h"
#include "bpm.h"
#include "hardening_policy.h"



static ATOMIC_LONG_NEW(message_cnt);

int bpm_engine_initialize(void){
	int ret;
	LG_INFO("initilize");
	ret = init_hardening_policy();
	if(ret) {
		LG_ERROR("Init failed");
	} else {
		LG_INFO("init done");
	}
	return ret;
}

int bpm_engine_load_hardening_policy(hp_rule_file_t *header, hp_rule_t* first_rule) {
	return update_hardening_policy(header, first_rule);
}

int bpm_engine_process(struct event_t* evt, struct bpm_result_t* result) {

	// do BPM polcy process

	// do Hardening policy process
	result->id=ATOMIC_LONG_INC(&message_cnt);

	return process_hardening_policy(evt, result);
}

int bpm_engine_destroy() {
	return destroy_hardening_policy();
}
