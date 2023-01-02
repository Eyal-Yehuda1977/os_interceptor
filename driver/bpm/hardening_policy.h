//
// Created by ubunto on 29/04/18.
//

#ifndef BPMTESTER_HARDENING_POLICY_H
#define BPMTESTER_HARDENING_POLICY_H

#include "macros.h"

/**
 * Init hardening policy globals
 * @return
 * bpm_engine_errors
 */
int init_hardening_policy(void);
/**
 * load hardening policy
 * @param header
 * @param firstRule
 * @return
 * bpm_engine_errors
 */
int update_hardening_policy(hp_rule_file_t *header, hp_rule_t* firstRule);

/**
 * Process system call (event_data) using loaded hardening policy. Fill result in result_data
 * @param event_data
 * @param result_data
 * @return
 * bpm_engine_errors
 */
int process_hardening_policy(struct event_t* event_data,struct bpm_result_t* result_data);

/**
 * Clean up of loaded hardening policy
 */
int destroy_hardening_policy(void);

#endif //BPMTESTER_HARDENING_POLICY_H
