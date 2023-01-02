//
// Created by ubunto on 03/06/18.
//

#include "algorithm.h"
#include "macros.h"
#include "unicode.h"

// does character exists in chars
int was_char_used(UNICODE_CHAR c, UNICODE_CHAR *chars, int count){
	int i;
	for(i=0; i<count; i++){
		if(chars[i] == c) {
			return 1;
		}
	}
	return 0;
}

/**
 * Gets the unicode character at index
 * @param str
 * @param index
 * @return
 */
UNICODE_CHAR get_char_at_index(const void *str, int index) {
	UNICODE_CHAR c;
	do{
		str = utf8codepoint(str, &c);
		if(!c)
			return 0;
	}
	while(--index >= 0);
	return c;
}



void log_regex(const char *source, int stepCount, wildcard_regex_step_t *regex) {
	int i, j;

	LG_DEBUG("Regex %s", source);
	for(i=0; i<stepCount; i++) {
		wildcard_regex_step_t *step = regex + i;
		LG_DEBUG("Step %d:", i);
		for(j=0; j<step->edge_count; j++) {
			LG_DEBUG("%c -> (%d)", step->chars[j], step->edges[j]);
		}
		if(step->other_char > -1)
			LG_DEBUG("%c -> (%d)", step->chars[j], step->other_char);
	}
}

void build_wildcard_regex(int *outStepCount, wildcard_regex_step_t *outRegex, const char *reg){
	// current character
	UNICODE_CHAR c;
	// current position in string
	int i=0, j;
	// output regex steps
	wildcard_regex_step_t *steps = outRegex;
	// index in string of last wildcard
	int wildCardStep = -1;
	// current stepIndex
	int stepIndex = 0;
	// keep track of partials matches in current word, so we can jump forward
	int partials[10];
	int partialCount = 0;
	const void *currentPosition = (const void *)reg;
	const void *nextPosition = 0;
	const void *lastWildPosition = 0;

	// go over every char

	while(1) {
		nextPosition = utf8codepoint(currentPosition, &c);
		if(!c)
			break;
		if(c == '*') {
			//lastWild = i;
			lastWildPosition = currentPosition;
			wildCardStep = stepIndex;
			// clear partials
			partialCount = 0;
		} else {
			// add new step
			wildcard_regex_step_t *step = &steps[stepIndex];
			step->edge_count = 0;
			// add basic char step, that leads to next step
			step->edge_count++;
			step->chars[0] = c;
			step->edges[0] = stepIndex+1;

			// if we have a wildcard in the past
			if(lastWildPosition) {
				int oldPartialCount;
				if(currentPosition - lastWildPosition > 1) {
					// add 1st char partial
					partials[partialCount] = 0;
					partialCount++;
				}

				// for each of the partials, last char should jump to forward step (instead of returning to last
				// wild card step)
				// go over partials from long to short, because we prefer big leap forward
				for(j=0; j<partialCount; j++) {
					int partialLength = partials[j];
					// get last partial char
					UNICODE_CHAR c1 = get_char_at_index(lastWildPosition, partialLength + 1);
					// if not added already, add this edge
					if(!was_char_used(c1, step->chars, step->edge_count)) {
						// edge will lead to length after wild card step
						step->chars[step->edge_count] = c1;
						step->edges[step->edge_count] = wildCardStep + partialLength + 1;
						step->edge_count++;
					}
				}
				// clean partials that don't fit current char, and extend the length of those of do
				oldPartialCount = partialCount;
				// clear new partial array
				partialCount = 0;
				// for each of the old partials
				for(j=0; j<oldPartialCount; j++){
					int partialLength = partials[j];
					// get partial next suppose char
					UNICODE_CHAR partialNextChar = get_char_at_index(lastWildPosition, partialLength + 1);
					// if no match, ignore
					if(c == partialNextChar) {
						// if match, add this partial to the new partial list, now with bigger length.
						partials[partialCount] = partialLength + 1;
						partialCount++;
					}
				}
				// other chars will go back to wildcard
				step->other_char = wildCardStep;
			} else {
				step->other_char = -1;
			}
			// go to next step
			stepIndex++;
		}
		// go to next char
		i++;
		currentPosition = nextPosition;
	}
	*outStepCount = stepIndex;
	//log_regex(reg, *outStepCount, outRegex);
}

void process_string_rule(string_rule_t *target, hp_value_string_array_t *array, void *heap) {
	int i;
	uintptr_t arrayStartVirtual;
	hp_value_string_t *arrayStart;

	target->simple_strings = 0;
	target->unicode_count = 0;
	target->wildcard_count = 0;
	arrayStartVirtual = (uintptr_t)array->array_start;
	arrayStart = heap + arrayStartVirtual;
	// just count types
	for(i = 0; i<array->array_size; i++) {
		hp_value_string_t *item = &arrayStart[i];
		uintptr_t stringPtrVirtual = (uintptr_t)item->string;
		char *str = heap + stringPtrVirtual;
		// number of characters
		int len = utf8len(str);
		// size in bytes
		int size = utf8size(str);
		if(len == 0) {
			continue;
		} else {
			if(!utf8chr(str, '*')) {
				if(size == len + 1) {
					target->simple_count++;
				} else {
					target->unicode_count++;
				}
			} else {
				target->wildcard_count++;
			}
		}
	}
	if(target->simple_count > 0) {
		target->simple_strings = C_ALLOC(char *, target->simple_count);
	}
	if(target->unicode_count > 0) {
		target->unicode_strings = C_ALLOC(char *, target->unicode_count);
	}
	if(target->wildcard_count > 0) {
		target->wildcard_strings = C_ALLOC(wildcard_regex_t, target->wildcard_count);
	}
	if(target->simple_count || target->wildcard_count || target->wildcard_count)
		target->not_empty = 1;

	{
		int simpleCounter = 0, unicodeCounter = 0, wildcardCounter = 0;
		for (i = 0; i < array->array_size; i++) {
			hp_value_string_t *item = &arrayStart[i];
			uintptr_t stringPtrVirtual = (uintptr_t) item->string;
			char *str = heap + stringPtrVirtual;

			// number of characters
			int len = utf8len(str);
			// size in bytes
			int size = utf8size(str);
			if (len == 0) {
				continue;
			} else {
				if (!utf8chr(str, '*')) {
					if (size == len + 1) {
						target->simple_strings[simpleCounter] = (char *) MM_ALLOC(len + 1);
						strcpy(target->simple_strings[simpleCounter], str);
						simpleCounter++;
					} else {
						target->unicode_strings[unicodeCounter] = (char *) MM_ALLOC(size);
						utf8cpy(target->unicode_strings[unicodeCounter], str);
						unicodeCounter++;
					}
				} else {
					wildcard_regex_t *wc = &target->wildcard_strings[wildcardCounter];
					// copy source
					wc->source = (char *) MM_ALLOC(size);
					utf8cpy(wc->source, str);
					// build regex steps
					wc->steps = C_ALLOC(wildcard_regex_step_t, len);
					build_wildcard_regex(&wc->step_count, wc->steps, str);

					wildcardCounter++;
				}
			}
		}
	}
}


int str_match_with_wildcard(const char *string, int wildcard_step_count, const wildcard_regex_step_t *reg, int maxChars) {
	int i;
	int stepIndex = 0;
	UNICODE_CHAR c;
	const wildcard_regex_step_t *step;
	const void *position = (const void *)string;
	const void *end = position + maxChars;
	// if regex empty, it's a match
	if(wildcard_step_count == 0)
		return 1;
	step = reg;
	while(1) {
		int edgeIndex = -1;
		position = utf8codepoint(position, &c);
		// if reached null, disqualify
		if(!c) {
			return 0;
		}

		// find edge to use according to character
		for(i=0; i<step->edge_count; i++) {
			if(step->chars[i] == c) {
				edgeIndex = i;
				break;
			}
		}
		// move to next step
		if(edgeIndex == -1){
			// if no edge found, try other char edge, otherwise disqualify
			if(step->other_char > -1)
				stepIndex = step->other_char;
			else
				return 0;
		} else
			stepIndex = step->edges[edgeIndex];

		// if reached end, it's a match
		if(stepIndex == wildcard_step_count)
			return 1;
		// move to next step
		step = reg + stepIndex;

		// if over max chars, disqualify
		if(position >= end)
			return 0;
	}
}


int str_match(const char *string, const string_rule_t* rule) {
	char found = 0;
	int i;
	for(i=0; i<rule->simple_count; i++) {
		if(strncmp(string, rule->simple_strings[i], EVENT_MAX_PATH_LEN) == 0) {
			found = 1;
			break;
		}
	}
	if(found)
		return 1;
	for(i=0; i<rule->unicode_count; i++) {
		if(utf8ncmp(string, rule->unicode_strings[i], EVENT_MAX_PATH_LEN) == 0) {
			found = 1;
			break;
		}
	}
	if(found)
		return 1;
	for(i=0; i<rule->wildcard_count; i++) {
		if(str_match_with_wildcard(string, rule->wildcard_strings[i].step_count, rule->wildcard_strings[i].steps, EVENT_MAX_PATH_LEN)) {
			found = 1;
			break;
		}
	}
	if(found)
		return 1;
	return 0;
}


void destroy_string_rule(string_rule_t *rule) {
	int i=0;
	if(rule->simple_count) {
		for(i=0; i<rule->simple_count; i++) {
			FREE(rule->simple_strings[i]);
		}
		FREE(rule->simple_strings);
	}
	if(rule->unicode_count) {
		for(i=0; i<rule->unicode_count; i++) {
			FREE(rule->unicode_strings[i]);
		}
		FREE(rule->unicode_strings);
	}
	if(rule->wildcard_count) {
		for(i=0; i<rule->wildcard_count; i++) {
			FREE(rule->wildcard_strings[i].source);
			FREE(rule->wildcard_strings[i].steps);
		}
		FREE(rule->wildcard_strings);
	}
}
