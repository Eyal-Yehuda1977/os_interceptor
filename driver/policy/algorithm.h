#ifndef __ALGORITHM_H_
#define __ALGORITHM_H_


#include "unicode.h"
#include "../../driver_shared/driver_api.h"

// how many edges for each regex step. This regex is pretty flat
#define REGEX_MAX_EDGE  5

#define UNICODE_CHAR    utf8_int32_t

// single step of wildcard regex
typedef struct _wildcard_regex_step{
	// how many edges from this step (exclude other_char)
	int edge_count;
	// the characters for each edge
	UNICODE_CHAR chars[REGEX_MAX_EDGE];
	// the target step indexes for each edge
	int edges[REGEX_MAX_EDGE];
	// the target step of any other character (-1 leads to dis-qualify)
	int other_char;
} wildcard_regex_step_t;



enum string_match_type {
	// Empty no need to match
	STR_EMPTY,
	// simple ascii string
	STR_SIMPLE,
	// unicode string
	STR_UNICODE,
	// unicode string with wildcard
	STR_WILDCARD,
	STR_LAST = STR_WILDCARD
};

typedef struct _wildcard_regex {
	int step_count;
	char *source;
	wildcard_regex_step_t *steps;
} wildcard_regex_t;

typedef struct _string_rule {
	int not_empty;
	// array of simple strings
	int simple_count;
	char **simple_strings;
	// array of unicode strings
	int unicode_count;
	char **unicode_strings;
	// array of wildcard strings
	int wildcard_count;
	wildcard_regex_t *wildcard_strings;
} string_rule_t;

// parse reg into wildcard_regex
void build_wildcard_regex(int *outStepCount, wildcard_regex_step_t *outSteps, const char *reg);


/**
 * Build string rule from input string
 * @param target
 * @param array
 */
void process_string_rule(string_rule_t *target, hp_value_string_array_t *array, void *heap);

/**
 * Try to match string to reg
 * @param string
 * Input regular string
 * @param reg
 * wildcard regex automat
 * @param maxChars
 * Max length of strings
 * @return boolean
 */
int str_match_with_wildcard(const char *string, int wildcard_step_count, const wildcard_regex_step_t *reg, int maxChars);

int str_match(const char *string, const string_rule_t* rule);

/**
 * Free rule allocations if needed.
 * @param rule
 */
void destroy_string_rule(string_rule_t *rule);

#endif //__ALGORITHM_H_
