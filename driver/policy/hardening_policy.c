#include "hardening_policy.h"
#include "policy.h"
#include "algorithm.h"
#include "unicode.h"
#include "../../driver_shared/driver_api.h"


// Hardening Policy Rule after pre-process
typedef struct _hp_rule_processed {
	// rule identifier
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
} hp_rule_processed_t;


static const int max_rule_count = MAX_ALLOCATION / sizeof(hp_rule_processed_t);

/**
 * Describes rule array that share the same system call
 * The rules will be evaluated in order.
 */
typedef struct __syscall_map_entry {
	// how many rules for this syscall
	unsigned int rule_count;
	// the rules are split into how many arrays (because of allocation limits)
	unsigned int array_count;
	// the arrays containing the rules
	hp_rule_processed_t **arrays;

} syscall_map_entry_t;

// Size of map object that maps syscall to rule sequences
#define SYSCALL_MAP_SIZE    MAX_SYS_CALL+1

// syscall to rule seqence map
typedef syscall_map_entry_t syscall_map_t[SYSCALL_MAP_SIZE];

typedef struct __global_rules_atomic {
	// reference count
	ATOMIC_T(ref_count);
	// is the rules loaded
	int loaded;
	// pointer to rule by syscall map
	syscall_map_entry_t *rules_by_syscall;
} global_rules_atomic_t;


/**
 * Holds 2 sets of global rules
 * The updater will
 */
static global_rules_atomic_t global_rules[2] = {{},
                                                {}};


// The index of the current global rules
static ATOMIC_NEW(global_current_index);


/**
 * Describes a hp rule struct to load from
 */
typedef struct __init_hp_pack {
	// hp rule header. Includes rules count, and additional information about the rule set
	hp_rule_file_t header;
	// pointer to rule array
	hp_rule_t *firstRule;
} init_hp_pack_t;

/**
 *  build default hp rules
 * @param rule_set_ptr
 * pointer to rule package
 * @return
 * bpm_errors
 */
static int set_hp_default_rules(init_hp_pack_t *rule_set_ptr);

static int destroy_hp_default_rules(init_hp_pack_t *rule_set_ptr);


/**
 * Free processed hp rule allocations
 * @param rule
 */
void destroy_processed_hp_rule(hp_rule_processed_t *rule) {
	destroy_string_rule(&rule->caller_name);
	destroy_string_rule(&rule->caller_path);
	destroy_string_rule(&rule->caller_cmd);
	switch (rule->op_type) {
		case FILESYSTEM: {
			destroy_string_rule(&rule->filesystem_args.target_name);
			destroy_string_rule(&rule->filesystem_args.target_path);
		}
			break;
		case PROCESS: {
			destroy_string_rule(&rule->process_args.target_name);
			destroy_string_rule(&rule->process_args.target_path);
			//destroy_string_rule(&rule->process_args.target_cmd);
		}
			break;
		case NETWORK: {
		}
			break;
		default:
			LG_ERROR("Unknown operation type, %d", rule->op_type);
			break;
	}

}

void destroy_global_rules(global_rules_atomic_t *global) {
	int i, j, ruleIndex, k;
	if (global->loaded) {
		// for each sys-call entry
		for (i = 0; i < MAX_SYS_CALL; i++) {
			syscall_map_entry_t *entry = global->rules_by_syscall + i;
			ruleIndex = 0;
			// for each array in entry
			for (j = 0; j < entry->array_count; j++) {
				hp_rule_processed_t *array = entry->arrays[j];
				// destory each rule
				for (k = 0; k < max_rule_count; k++) {
					if (ruleIndex >= entry->rule_count) {
						break;
					}
					destroy_processed_hp_rule(array + k);
					ruleIndex++;
				}
				// free array
				FREE(array);
			}
			// free array of arrays
			if (entry->array_count > 0) {
				FREE(entry->arrays);
			}
		}
		// free sys-call map
		FREE(global->rules_by_syscall);
		global->loaded = 0;
	}
}

/***
 * Load the hardening policy for the given packs. Each pack has pointer to
 * @param hpPackArrayLength
 * How many hp rule packages given
 * @param hpPackArray
 * HP rule package array
 * @return
 */
int update_hardening_policy_all(int hpPackArrayLength, init_hp_pack_t *hpPackArray);

int update_hardening_policy(hp_rule_file_t *header, hp_rule_t *firstRule) {
	// build default rules
	init_hp_pack_t rulePacks[2];
	int ret = set_hp_default_rules(&rulePacks[0]);
	if (ret)
		return ret;

	// set given hp rules
	rulePacks[1].header = *header;
	rulePacks[1].firstRule = firstRule;

	// load both packages
	LOCK_BPM();
	ret = update_hardening_policy_all(2, rulePacks);
	UNLOCK_BPM();
	destroy_hp_default_rules(&rulePacks[0]);
	return ret;
}

#define COPY_HP_VALUE_ARRAY(TYPE) \
void copy_array_## TYPE(TYPE ##_array_t *target, TYPE ##_array_t *source, void *heap) { \
    uintptr_t arrayVirtualPtr = (uintptr_t)source->array_start; \
    target->array_size = source->array_size; \
    if (target->array_size) { \
        target->array_start = C_ALLOC(TYPE ##_t, target->array_size); \
        memcpy(target->array_start, heap + arrayVirtualPtr, sizeof(TYPE ##_t[target->array_size])); \
    } \
}

COPY_HP_VALUE_ARRAY(hp_value_user_id)

COPY_HP_VALUE_ARRAY(hp_value_ip)

COPY_HP_VALUE_ARRAY(hp_value_port)

COPY_HP_VALUE_ARRAY(hp_value_md5)

#undef COPY_HP_VALUE_ARRAY

/**
 * Pre Process the hp rule
 * @param target
 * @param source
 */
void process_hp_rule(hp_rule_processed_t *target, hp_rule_t *source, void* heap) {
	// simple copy
#define PROCESS_HP_COPY(name) target->name = source->name
	// copy string
#define PROCESS_HP_COPY_STRING(name) utf8ncpy(target->name, source->name, EVENT_MAX_PATH_LEN - 1);
	// preprocess multiple string rule
#define PROCESS_HP_STRING_RULE(name) process_string_rule(&target->name, &source->name, heap)

	PROCESS_HP_COPY_STRING(rule_name);
	PROCESS_HP_COPY(op_type);
	PROCESS_HP_COPY(priority);
	// copy user id array
	copy_array_hp_value_user_id(&target->user_id, &source->user_id, heap);

	PROCESS_HP_STRING_RULE(caller_name);
	PROCESS_HP_STRING_RULE(caller_path);
	PROCESS_HP_STRING_RULE(caller_cmd);

	// copy md5 array
	copy_array_hp_value_md5(&target->caller_md5, &source->caller_md5, heap);

	switch (source->op_type) {
		case FILESYSTEM: {
			PROCESS_HP_STRING_RULE(filesystem_args.target_name);
			PROCESS_HP_STRING_RULE(filesystem_args.target_path);
			PROCESS_HP_COPY(filesystem_args.flags);
		}
			break;
		case PROCESS: {
			PROCESS_HP_STRING_RULE(process_args.target_name);
			PROCESS_HP_STRING_RULE(process_args.target_path);
		}
			break;
		case NETWORK: {
			// copy ip array
			copy_array_hp_value_ip(&target->network_args.ip, &source->network_args.ip, heap);
			// copy port array
			copy_array_hp_value_port(&target->network_args.port, &source->network_args.port, heap);
		}
			break;
		default:
			LG_ERROR("Unknown operation type, %d", source->op_type);
			break;
	}

#undef PROCESS_HP_COPY
#undef PROCESS_HP_COPY_STRING
#undef PROCESS_HP_STRING_RULE
}

/**
 * Update multiple hp rule packs
 * @param hpPackArrayLength
 * @param hpPackArray
 * @return
 */
int update_hardening_policy_all(int hpPackArrayLength, init_hp_pack_t *hpPackArray) {

	int i, p, curr, totalCount;
	int next_index;
	syscall_map_entry_t *ruleBySysCall;
	global_rules_atomic_t *globalToClean;
	LG_DEBUG("Update hp %d packages", hpPackArrayLength);
	// allocate rule by syscall map
	ruleBySysCall = C_ALLOC(syscall_map_entry_t, SYSCALL_MAP_SIZE);
	ASSERT_MEMORY_ALLOCATION(ruleBySysCall);

	if (ruleBySysCall[SYSCALL_MAP_SIZE - 1].rule_count != 0 ||
	    ruleBySysCall[SYSCALL_MAP_SIZE - 1].array_count != 0) {
		LG_ERROR("Error allocation test, %d, %d", ruleBySysCall[SYSCALL_MAP_SIZE - 1].rule_count,
		         ruleBySysCall[SYSCALL_MAP_SIZE - 1].array_count);
		LG_ERROR("Error allocation test one before, %d, %d", ruleBySysCall[SYSCALL_MAP_SIZE - 2].rule_count,
		         ruleBySysCall[SYSCALL_MAP_SIZE - 2].array_count);
		FREE(ruleBySysCall);
		return -1;
	}
	// count how many rules in each syscall
	totalCount = 0;
	for (p = 0; p < hpPackArrayLength; p++) {
		init_hp_pack_t *pack = (hpPackArray + p);
		hp_rule_file_t header = pack->header;
		hp_rule_t *firstRule = pack->firstRule;
		// count rules by syscall
		for (i = 0; i < header.rule_count; i++) {
			hp_rule_t *rule = firstRule + i;
			ruleBySysCall[rule->syscall].rule_count++;
		}
		totalCount += header.rule_count;
	}

	LG_DEBUG("total rules %d", totalCount);

	// allocate rule arrays for each syscall
	for (i = 0; i < SYSCALL_MAP_SIZE; i++) {
		int rulesRemaining, currentArray;
		hp_rule_processed_t **arrays;
		syscall_map_entry_t *entry = &ruleBySysCall[i];
		// how many arrays we will need for this entry
		unsigned int numberOfArrays = (entry->rule_count + max_rule_count - 1) / max_rule_count;
		if (numberOfArrays == 0)
			continue;
		// allocate array or arrays, and place into map
		arrays = C_ALLOC(hp_rule_processed_t *, numberOfArrays);
		ASSERT_MEMORY_ALLOCATION(arrays);
		entry->array_count = numberOfArrays;
		entry->arrays = arrays;


		// build array of arrays
		rulesRemaining = entry->rule_count;
		currentArray = 0;
		while (rulesRemaining > 0) {
			// check how many rules in this array
			int inCurrentBuffer = rulesRemaining;
			if (inCurrentBuffer > max_rule_count)
				inCurrentBuffer = max_rule_count;
			// allocate rule array
			arrays[currentArray] = C_ALLOC(hp_rule_processed_t, inCurrentBuffer);
			ASSERT_MEMORY_ALLOCATION(arrays[currentArray]);
			// subtract remaining
			rulesRemaining -= inCurrentBuffer;

		}
		// make sure all arrays are used as planned
		if (currentArray != numberOfArrays - 1) {
			// ERROR
			LG_ERROR("Error allocating arrays. in syscall %d, there are %d rules and %d arrays. Last array %d", i,
			         entry->rule_count, numberOfArrays, currentArray);
			return -1;
		}
	}

	LG_DEBUG("Coping rules into buffer by syscall");
	// copy rules into entry arrays, in syscall positions

	{
		// save the current position in array matrix of every syscall
		int *indexOfArrayBySysCall;
		int *positionInArrayBySysCall;
		LG_DEBUG("Allocate indexes");

		indexOfArrayBySysCall = C_ALLOC(int, SYSCALL_MAP_SIZE);
		ASSERT_MEMORY_ALLOCATION(indexOfArrayBySysCall);
		positionInArrayBySysCall = C_ALLOC(int, SYSCALL_MAP_SIZE);
		ASSERT_MEMORY_ALLOCATION(positionInArrayBySysCall);

		// for each hp rule package
		for (p = 0; p < hpPackArrayLength; p++) {
			init_hp_pack_t *pack = (hpPackArray + p);
			hp_rule_file_t header = pack->header;
			hp_rule_t *firstRule = pack->firstRule;
			// get pointer to mini-heap
			size_t totalRulesSize = sizeof(hp_rule_t[header.rule_count]);
			void *miniHeap = ((void *)pack->firstRule) + totalRulesSize;


			LG_DEBUG("Copy hp rules into created arrays, pack %d", p);


			// for each rule in packge
			for (i = 0; i < header.rule_count; i++) {
				int indexOfArray;
				hp_rule_processed_t *targetPosition;
				hp_rule_processed_t *currentArray;
				// get rule and system call
				hp_rule_t *rule = firstRule + i;
				int sysCall = rule->syscall;

				// get map entry for this syscall
				syscall_map_entry_t *entry = &ruleBySysCall[sysCall];

				// get the current index in the array
				int positionInArray = positionInArrayBySysCall[sysCall];
				// if we are in the last position of the array
				if (positionInArray == max_rule_count) {
					// move to next array
					++indexOfArrayBySysCall[sysCall];
					positionInArray = positionInArrayBySysCall[sysCall] = 0;
					// make sure we didn't reached over the last array already
					if (indexOfArrayBySysCall[sysCall] == entry->array_count) {
						LG_ERROR("copy rules to arrays failed");
						// ERROR
						return -1;
					}
				}
				// get current array to be filled
				indexOfArray = indexOfArrayBySysCall[sysCall];
				currentArray = entry->arrays[indexOfArray];

				// get target position for the rule to copy
				targetPosition = currentArray + positionInArray;
				// copy rule into position
				process_hp_rule(targetPosition, rule, miniHeap);
				// increment count for this syscall
				positionInArrayBySysCall[sysCall]++;
			}
		}

		// make sure all arrays are used as planned
		for (i = 0; i < SYSCALL_MAP_SIZE; i++) {
			syscall_map_entry_t *entry = &ruleBySysCall[i];
			int lastArrayCount;
			int expectedIndexOfArray = entry->array_count == 0 ? 0 : entry->array_count - 1;
			if (indexOfArrayBySysCall[i] != expectedIndexOfArray) {
				LG_ERROR("copy rules to arrays failed, test2");
				// ERROR
				return -1;
			}
			// make sure last item in last array is used as planned
			lastArrayCount = entry->rule_count % max_rule_count;
			if (positionInArrayBySysCall[i] != lastArrayCount) {
				LG_ERROR("copy rules to arrays failed, test3");
				// ERROR
				return -1;
			}
		}

		LG_DEBUG("free allocated indexes");

		FREE(indexOfArrayBySysCall);
		FREE(positionInArrayBySysCall);
	}

	LG_DEBUG("Swapping current and new globals");
	// swap the current global with the mirror global

	// get current global
	curr = ATOMIC_GET(&global_current_index);
	// index of mirror global
	next_index = (curr + 1) % 2;
	LG_DEBUG("Current is %d, new is %d", curr, next_index);
	{
		// make sure next is empty (should always be empty, but just to make sure)
		// the sleep should never happen, because this operation is not thread safe, and
		// syscalls will always complete before a new operation is created.
		// but if in some weird scenario it does,
		// at least the process will not break
		int count;
		while ((count = ATOMIC_GET(&global_rules[next_index].ref_count)) > 0) {
			LG_ERROR("reserved global is still in use by %d threads! shouldnt happen", count);
			SLEEP(0);
		}
	}

	LG_DEBUG("Cleaning reserved");
	// get the mirror global
	globalToClean = &global_rules[next_index];
	// free old buffers
	destroy_global_rules(globalToClean);

	LG_DEBUG("setting up new global");
	// set buffers into mirror global
	global_rules[next_index].rules_by_syscall = ruleBySysCall;
	// set ref count to 1
	ATOMIC_SET(&global_rules[next_index].ref_count, 1);
	// mark as loaded
	global_rules[next_index].loaded = 1;

	// decrement count of current global
	ATOMIC_DEC(&global_rules[curr].ref_count);

	LG_DEBUG("Perform atomic switch");
	// exchange mirror global with current global
	ATOMIC_SET(&global_current_index, next_index);

	//UNLOCK_BPM();

	LG_DEBUG("Update hp packages %d success", hpPackArrayLength);
	// now the mirror global still exists, but should not be used for new sys-calls
	// (it might still be used by ongoing syscalls)
	// it will stay allocated until next time we update hardening policy
	// this cause the memory usage of the hardening policy to be double in size, but saves us
	// from performing garbage cleaning logic
	// TBD, should we add some mechanism to periodically check to clean this?
	return SUCCESS;
}


#define MATCH_STR_RULE_OR_RETURN_FALSE(rulePath, stringPath) \
    if(rulePath.not_empty && !str_match(stringPath, &rulePath)) \
        return 0;

#define MATCH_STR_RULE_OR_CONTINUE(rulePath, stringPath) \
    if(rulePath.not_empty && !str_match(stringPath, &rulePath)) \
        continue;

/**
 * Process syscall rule evaluation
 * @param hpr
 * Rule
 * @param evt
 * Event data
 * @return
 * 0 if not qualifies
 */
//static inline __attribute__((always_inline))
int process_validation(const hp_rule_processed_t *hpr, const struct event_t *evt) {
	MATCH_STR_RULE_OR_RETURN_FALSE(hpr->process_args.target_path, evt->target.target_path)
	MATCH_STR_RULE_OR_RETURN_FALSE(hpr->process_args.target_name, evt->target.target_name)
	//MATCH_STR_RULE_OR_RETURN_FALSE(hpr->process_args.target_cmd, evt->target.target_cmd)
	return 1;
}

/**
 * Filesystem syscall rule evaluation
 * @param hpr
 * Rule
 * @param evt
 * Event data
 * @return
 * 0 if not qualifies
 */
//static inline __attribute__((always_inline))
int filesystem_validation(const hp_rule_processed_t *hpr, const struct event_t *evt) {
	MATCH_STR_RULE_OR_RETURN_FALSE(hpr->filesystem_args.target_path, evt->target.target_path)
	MATCH_STR_RULE_OR_RETURN_FALSE(hpr->filesystem_args.target_name, evt->target.target_name)

	// check if either read or write qualifies
	if (hpr->filesystem_args.flags & FILE_ACCESS_FLAG_READ) {
		if (evt->target.file_access.flags & FILE_ACCESS_FLAG_READ)
			return 1;
	}
	if (hpr->filesystem_args.flags & FILE_ACCESS_FLAG_WRITE) {
		if (evt->target.file_access.flags & FILE_ACCESS_FLAG_WRITE)
			return 1;
	}
	return 0;
}

/**
 * Network syscall rule evaluation
 * @param hpr
 * Rule
 * @param evt
 * Event data
 * @return
 * 0 if not qualifies
 */
//static inline __attribute__((always_inline))
int network_validation(const hp_rule_processed_t *hpr, const struct event_t *evt) {
	int i;
	if (hpr->network_args.ip.array_size > 0) {
		char found = 0;
		for(i=0; i<hpr->network_args.ip.array_size; i++) {
			if(hpr->network_args.ip.array_start[i].ip == evt->network.ipv4) {
				found = 1;
				break;
			}
		}
		if(!found)
			return 0;
	}

	if (hpr->network_args.port.array_size > 0) {
		char found = 0;
		for(i=0; i<hpr->network_args.port.array_size; i++) {
			if(hpr->network_args.port.array_start[i].port == evt->network.target_port) {
				found = 1;
				break;
			}
		}
		if(!found)
			return 0;
	}
	return 1;
}

/**
 * Process evt into result data using rules
 * @param evt
 * Syscall event data
 * @param result_data
 * output object
 * @param rules
 * hp rules to use
 * @return
 */
//static inline __attribute__((always_inline))
int process_harderning_policy_inner(struct event_t *evt, struct bpm_result_t *result_data,
                                    global_rules_atomic_t *rules);

/**
 * Gets the global rules and execute the inner process function
 * @param evt
 * @param result_data
 * @return
 */
int process_hardening_policy(struct event_t *evt, struct bpm_result_t *result_data) {

	int ret;
	// get the current set of rules to use
	int index = ATOMIC_GET(&global_current_index);
	// get the global rules
	global_rules_atomic_t *globalRules = &global_rules[index];
	if (!globalRules->loaded)
		return SUCCESS;
	// increment reference counter
	ATOMIC_INC(&globalRules->ref_count);
	// do the processing
	ret = process_harderning_policy_inner(evt, result_data, globalRules);
	// decrement reference counter
	ATOMIC_DEC(&globalRules->ref_count);
	return ret;

}

//static inline __attribute__((always_inline))
int process_harderning_policy_inner(struct event_t *evt, struct bpm_result_t *result_data,
                                    global_rules_atomic_t *globalRules) {

	int i, j;
	// get the entry for this syscall
	syscall_map_entry_t *sysCallEntry = globalRules->rules_by_syscall + evt->syscall;

	// go over each array in the syscall entry
	for (j = 0; j < sysCallEntry->array_count; j++) {
		// get current array
		hp_rule_processed_t *thisSysCallRules = sysCallEntry->arrays[j];

		// how many rules in the current array
		int ruleCountInArray = max_rule_count;
		// if this is the last array, then its the remainder
		if (j == sysCallEntry->array_count - 1)
			ruleCountInArray = sysCallEntry->rule_count % max_rule_count;
		// go over each rule in the array
		for (i = 0; i < ruleCountInArray; i++) {
			// get the rule
			hp_rule_processed_t *rule = thisSysCallRules + i;

			// make the validation, continue if validation is false
			// common event validation
			MATCH_STR_RULE_OR_CONTINUE(rule->caller_path, evt->caller_path)
			MATCH_STR_RULE_OR_CONTINUE(rule->caller_name, evt->caller_name)
			MATCH_STR_RULE_OR_CONTINUE(rule->caller_cmd, evt->caller_cmd)

			if (rule->user_id.array_size > 0) {
				char found = 0;
				int i;
				for(i=0; i<rule->user_id.array_size; i++) {
					if(rule->user_id.array_start[i].user_id == evt->user_id) {
						found = 1;
						break;
					}
				}
				if(!found)
					continue;
			}

			if(rule->caller_md5.array_size > 0) {
				char found = 0;
				int i;
				// if syscall has no md5, rule is ignored
				if(!evt->caller_md5.is_valid)
					continue;
				// try to match syscall md5 against md5 list
				for(i=0; i<rule->caller_md5.array_size; i++) {
					if(memcmp(&evt->caller_md5.md5, &rule->caller_md5.array_start[i].md5, EVENT_MD5_LEN) == 0) {
						found = 1;
						break;
					}
				}
				if(!found)
					continue;
			}

			// sys-call specific validation
			switch (rule->op_type) {
				case PROCESS:
					if (!process_validation(rule, evt))
						continue;
					break;
				case FILESYSTEM:
					if (!filesystem_validation(rule, evt))
						continue;
					break;
				case NETWORK:
					if (!network_validation(rule, evt))
						continue;
					break;
				case NONE:
					break; //prevent warnnings in compilation
			}

			// if we reached here -> rule qualifies. now lets set the result
			result_data->priority = rule->priority;
			utf8ncpy(result_data->rule_name, rule->rule_name, EVENT_MAX_PATH_LEN - 1);
			// stop processing after 1st qualified rule
			return SUCCESS;
		}
	}

	// now rule qualified, mark as allowed
	result_data->priority = BPM_PRIORITY_UNINITILIZED;
	result_data->rule_name[0] = 0;
	return SUCCESS;
}


static int set_hp_default_rules(init_hp_pack_t *rulePack) {

	hp_rule_t *ruleBuffer;
	hp_rule_t *hpr;
	const char *rule_name1 = "do not report default read",
			*rule_name2 = "do not report default write";
	char *heapBuffer;
	char *heapCursor;
	uintptr_t heapStart;
	int heapSize, rulesSize, sizeOfArray, i, strLen;
	hp_value_string_t *arr;
	rulesSize = sizeof(hp_rule_t[2]);
	heapSize = 1000;
	rulePack->header.rule_count = 2;
	ruleBuffer = (hp_rule_t *) MM_ALLOC(rulesSize + heapSize);
	ASSERT_MEMORY_ALLOCATION(ruleBuffer);
	rulePack->firstRule = ruleBuffer;
	hpr = ruleBuffer;
	heapBuffer = (char *) ruleBuffer + rulesSize;
	heapStart = (uintptr_t)heapBuffer;
	heapCursor = heapBuffer;

	rulePack[0].header.mini_heap_size = heapSize;
/*-------------------------------------------------------------------------------*/
/* do not report sshd  */
	memset(hpr, 0, sizeof(hp_rule_t));
// global rule setup
	memcpy(hpr->rule_name, rule_name1, strlen(rule_name1));
	hpr->op_type = FILESYSTEM;
	hpr->syscall = SC_READ;
	hpr->priority = BPM_PRIORITY_UNINITILIZED;
	hpr->is_blacklist = 0;
	hpr->user_id.array_size = 0;  // root
	hpr->filesystem_args.flags = FILE_ACCESS_FLAG_READ;

	sizeOfArray = sizeof(hp_value_string_t[4]);
	arr = (hp_value_string_t *) heapBuffer;
	hpr->caller_name.array_size = 4;
	hpr->caller_name.array_start = (hp_value_string_t *) ((void *) arr - heapStart);
	heapCursor += sizeOfArray;
	i = 0;
#define PUSH_STRING_TO_ARRAY(str) { \
    strLen = strlen(str); \
    arr[i].size = strLen; \
    strcpy(heapCursor, str); \
    arr[i].string = heapCursor - heapStart; \
    heapCursor += strLen + 1; \
    i++; \
}
	PUSH_STRING_TO_ARRAY("sshd");
	PUSH_STRING_TO_ARRAY("dmesg");
	PUSH_STRING_TO_ARRAY("systemd-journal");
	PUSH_STRING_TO_ARRAY("relay_read");

/*-------------------------------------------------------------------------------*/
/* do not report dmesg */

	hpr = ruleBuffer + 1;
	memset(hpr, 0, sizeof(hp_rule_t));
	strcpy(hpr->rule_name, rule_name2);

// global rule setup
	hpr->op_type = FILESYSTEM;
	hpr->syscall = SC_WRITE;
	hpr->priority = BPM_PRIORITY_UNINITILIZED;
	hpr->is_blacklist = 0;
	hpr->user_id.array_size = 0;
	hpr->filesystem_args.flags = FILE_ACCESS_FLAG_WRITE;

	arr = (hp_value_string_t *) heapBuffer;
	hpr->caller_name.array_size = 4;
	hpr->caller_name.array_start = (hp_value_string_t *) ((uintptr_t) arr - (uintptr_t) heapBuffer);
	heapCursor += sizeOfArray;

	i = 0;
	PUSH_STRING_TO_ARRAY("sshd");
	PUSH_STRING_TO_ARRAY("dmesg");
	PUSH_STRING_TO_ARRAY("systemd-journal");
	PUSH_STRING_TO_ARRAY("relay_read");


	return 0;
}


static int destroy_hp_default_rules(init_hp_pack_t *rulePack) {
	FREE(rulePack->firstRule);
	return SUCCESS;
}

/**
 * loads only the default hp rules into global
 * @return
 * bpm_engine_errors
 */
int init_hardening_policy() {
	int ret;
	init_hp_pack_t rulePacks[1];
	LG_INFO("Init Hardening policy");
	// make sure both are not loaded
	global_rules[0].loaded = 0;
	global_rules[1].loaded = 0;
	ATOMIC_SET(&global_rules[0].ref_count, 0);
	ATOMIC_SET(&global_rules[1].ref_count, 0);

	// build default rules
	ret = set_hp_default_rules(&rulePacks[0]);
	if (ret)
		return ret;

	// load only default package packages
	ret = update_hardening_policy_all(1, rulePacks);
	// clean up default rules
	destroy_hp_default_rules(&rulePacks[0]);
	LG_INFO("Init Hardening policy - Success");
	return ret;
}

int destroy_hardening_policy() {
	// free the global rules
	int i;
	for (i = 0; i < 2; i++) {
		destroy_global_rules(&global_rules[i]);
	}
	return SUCCESS;

}

#undef MATCH_STR_RULE_OR_CONTINUE
#undef MATCH_STR_RULE_OR_RETURN_FALSE
