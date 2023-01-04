#ifndef __BPM_H_
#define __BPM_H_

#ifdef __KERNEL__ 
   #include <stddef.h>
   #include <asm/pgtable_types.h>
   #include <linux/types.h>
   #include <linux/limits.h>
   #include <linux/string.h>

#endif

#include "../../driver_shared/driver_api.h"

#ifdef __cplusplus
extern "C" {
#endif


enum sc_priorities {
	/* not in use.  allow system call to continue  */
			BPM_PRIORITY_UNINITILIZED = 0,
	/* allow, do not spawn log in relay */
			BPM_PRIORITY_INTERNAL = 1,
	/* allow, and spawn log in relay   */
			BPM_PRIORITY_ALLOW = 2,
	/* allow, and spawn log in relay and agent should
	report it to server */
			BPM_PRIORITY_SUSPECT = 3,
	/* allow, and spawn log in relay and agent should
	report it to server */
			BPM_PRIORITY_SERVER_NOTIFY = BPM_PRIORITY_SUSPECT,
	/* if BPM respond with prevent, but we are in no prevention mode then
	   allow spawn log in relay with detect   */
			BPM_PRIORITY_DETECT = 4,
	/* prevent system call from happening and spawn log in relay
	   with prevent */
			BPM_PRIORITY_PREVENT = 5,
	/* allow system call and spawn log in relay.
	   this is a default and should always be the
	   last entry in this enum !!!!!! */
			BPM_PRIORITY_RULE_NOT_FOUND = 254,
};

/* Application return values */
enum bpm_engine_errors {
	SUCCESS = 0,
	ERROR,
};


int bpm_engine_initialize(void);

/**
 * Load the hardening policy
 * @note: Not Thread Safe
 * @param header
 * Pointer to hp rule header. Includes rule counter and might include other data in future
 * @param rule_array
 * Pointer to hp rule array
 * @return
 * bpm_errors
 */
int bpm_engine_load_hardening_policy(hp_rule_file_t *header, hp_rule_t *rule_array);

/**
 * Process system call described in evt and fill result inside result
 * @param evt
 * System call event data
 * @param result
 * result object to be filled
 * @return
 */
int bpm_engine_process(struct event_t *evt, struct bpm_result_t *result);

/**
 * @note: Not Thread Safe
 * Clean up of bpm engine
 */
int bpm_engine_destroy(void);

#ifdef __cplusplus
}
#endif

#endif
