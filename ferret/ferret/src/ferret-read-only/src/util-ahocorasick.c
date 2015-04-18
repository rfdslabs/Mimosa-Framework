/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
		AHO-CORASICK

  This module implements the "Aho-Corasick" algorithm for multiple-pattern 
  searching.

  This algorithm is good for two conditions.

  The first is when multiple patterns are being searched for at the same
  time. Instead of searching the same data repeatedly for each pattern, 
  only a single search is performed.

  The second reason is when data needs to be searched as a "stream".
  For example, the "Ferret" program does not reassemble packets, but
  instead only 're-orders' them. The first half of the pattern may
  be in one packet, band the last half in the following packet. The
  Aho-Corasick algorithm allows us to easily stop the search at the
  end of the first packe and continue where we left off. We only have
  to remember some simply 'state' information from one packet to
  the next.

  CHANGES

  This version is a just a quick-and-dirty version to get it into the
  system. It's not very fast nor scalable.

  
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

struct ACpattern
{
	unsigned char *text;
	unsigned length;
	unsigned *ids;
	unsigned id_count;
};
struct DFArow
{
	unsigned short column[256];
};

struct ACENGINE
{
	unsigned rows;
	unsigned columns;

	struct ACpattern *patterns;
	unsigned pattern_count;
	unsigned pattern_max;

	/** Once compiled, this will indicate which of the patterns are
	 * in the 'accept' state that actually match a pattern, as opposed
	 * to the remainder which are intermediate patterns */
	unsigned match_count;

	struct DFArow *dfa;
	
};


/**
 * When two patterns, such as "rally" and "ally", match at the same time, then we
 * need to copy over the IDs from one to the other
 */
static void
add_ids(struct ACpattern *p, const unsigned *ids, unsigned id_count)
{
	unsigned *new_ids;
	
	if (ids[0] == 0) {
		printf("." "%s %u", __FILE__, __LINE__);
	}
	
	new_ids = (unsigned*)malloc((p->id_count+id_count)*sizeof(new_ids[0]));

	if (p->id_count)
		memcpy(new_ids, p->ids, p->id_count*sizeof(new_ids[0]));
	if (p->ids)
		free(p->ids);

	memcpy(new_ids+p->id_count, ids, id_count*sizeof(new_ids[0]));
	p->ids = new_ids;
	p->id_count += id_count;
}

void ac_add_pattern(struct ACENGINE *ac, unsigned id, const void *v_pattern, int in_pattern_length)
{
	const char *pattern = (const char*)v_pattern;
	unsigned pattern_length;
	unsigned i;
	struct ACpattern *p;
	
	if (ac == NULL)
		return;

	if (pattern == NULL)
		return;

	if (in_pattern_length == 0)
		return;

	/* Allow null terminated strings as patterns when the length is set to -1.
	 * Binary patterns should set their length */
	if (in_pattern_length == -1)
		pattern_length = (unsigned)strlen(pattern);
	else
		pattern_length = (unsigned)in_pattern_length;

	/* Search for this pattern to prevent duplicates
	 * TODO: we should do a performance improvement, such as a binary search.
	 */
	for (i=0; i<ac->pattern_count; i++) {
		p = &ac->patterns[i];
		if (pattern_length != p->length || memcmp(pattern, p->text, p->length) != 0)
			continue;

		/* Found a duplicate pattern. If the ID is not zero, then add that to our
		 * ID list */
		if (id != 0)
			add_ids(p, &id, 1);

		/* Don't create a new entry for the duplicate pattern, exit the
		 * function now */
		return;
	}


	/* Make room for more patterns if necessary */
	if (ac->pattern_count + 1 > ac->pattern_max) {
		unsigned new_max = ac->pattern_max+1;
		struct ACpattern *new_patterns;

		new_patterns = (struct ACpattern*)malloc(sizeof(new_patterns[0]) * new_max);
		if (ac->pattern_count)
			memcpy(new_patterns, ac->patterns, sizeof(new_patterns[0]) * ac->pattern_count);
		if (ac->patterns)
			free(ac->patterns);
		ac->patterns = new_patterns;
		ac->pattern_max = new_max;
	}

	/* Add this pattern onto the end */
	p = &ac->patterns[ac->pattern_count];
	ac->pattern_count++;
	memset(p, 0, sizeof(*p));
	p->text = malloc(pattern_length+1);
	memcpy(p->text, pattern, pattern_length);
	p->text[pattern_length] = '\0'; /* nul terminate for easier debugging */
	p->length = pattern_length;
	if (id != 0)
		add_ids(p, &id, 1);

	/* TODO: remove this test statement */
	printf("'%.*s' added\n", p->length, p->text);
}


struct ACENGINE *ac_create()
{
	struct ACENGINE *ac;

	ac = (struct ACENGINE*)malloc(sizeof(*ac));
	memset(ac, 0, sizeof(*ac));

	/* Create a default state empty pattern */
	ac->patterns = (struct ACpattern*)malloc(sizeof(ac->patterns[0]));
	memset(ac->patterns, 0, sizeof(ac->patterns[0]));
	ac->pattern_count = 1;
	ac->pattern_max = 1;

	return ac;
}

void ac_destroy(struct ACENGINE *ac)
{
	unsigned i;

	/*
	 * Free the DFA
	 */
	if (ac->dfa)
		free(ac->dfa);

	/*
	 * Free the patterns
	 */
	for (i=0; i<ac->pattern_count; i++) {
		struct ACpattern *p = &ac->patterns[i];

		if (p->ids)
			free(p->ids);
		if (p->text)
			free(p->text);
	}
	if (ac->patterns)
		free(ac->patterns);

	/*
	 * Free the main object container
	 */
	free(ac);
}

/**
 * See if the trailing bytes of this pattern match the begining bytes of the 
 * other pattern. In other words, we are testing if the remaining characters
 * of 'pattern/length' will lead to a transition to 'p'. For this to be
 * true, all bute the last character of 'p' must match the trailing characters
 * of 'pattern/length'.
 */
static unsigned 
leads_to(struct ACpattern *this_p, const unsigned char *next_pattern, unsigned next_length)
{
	if (next_length == 0)
		return 0;
	else
		next_length--; /* skip the last byte of the pattern */

	/* test boundary condition for the default state */
	if (this_p->length == 0) {
		if (next_length == 0)
			return 1; /* default state leads to all 1-byte patterns */
		else
			return 0;
	}

	/* Make sure lengths are correct. This pattern had better match all but
	 * the trailing last byte of the next pattern */
	if (this_p->length < next_length)
		return 0;

	return memcmp(this_p->text + this_p->length - next_length, next_pattern, next_length) == 0;
}

/**
 * See if the current pattern will also "match" the indicated pattern
 */
static unsigned 
also_matches(struct ACpattern *p, const unsigned char *pattern, unsigned pattern_length)
{
	if (p->length < pattern_length)
		return 0;
	return memcmp(p->text+p->length-pattern_length, pattern, pattern_length) == 0;
}


void ac_compile(struct ACENGINE *ac)
{
	unsigned i;
	//struct ACpattern *p;
	unsigned short default_row_index;

	/* All the patterns so far are "accept" patterns that will match
	 * something and trigger an event. All patterns after this point
	 * are intermediate patterns that don't match
	 */
	ac->match_count = ac->pattern_count;


	/* Fill in all the prefixes. For exampe, if the orignal
	 * pattern was "basketball", the prefixes will be:
	 *	b
	 *  ba
	 *  bas
	 *  bask
	 *  baske
	 *  basket
	 *  .......
	 */
	for (i=0; i<ac->pattern_count; i++) {
		unsigned j;
		const unsigned char *pattern_text;
		unsigned pattern_length;

		pattern_length = ac->patterns[i].length;
		pattern_text = ac->patterns[i].text;

		/* 1-byte patterns do not have prefixes */
		if (pattern_length <= 1)
			continue;

		/* Add all the prefixes */
		for (j=1; j<pattern_length; j++)
			ac_add_pattern(ac, 0, pattern_text, j);
	}

	/* Go find all the duplicate matches. For example "rally" and "ally"
	 * will both trigger when the pattern "rally" is seen. */
	for (i=0; i<ac->match_count; i++) {
		unsigned j;

		for (j=0; j<ac->pattern_count; j++) {
			if (i == j)
				continue; /* obvious, it matches itself */
			if (ac->patterns[i].length == 0 || ac->patterns[j].length == 0)
				continue;

			if (also_matches(&ac->patterns[j], ac->patterns[i].text, ac->patterns[i].length)) {
				/*printf("'%.*s' will also trigger '%.*s'\n", ac->patterns[j].length, ac->patterns[j].text, ac->patterns[i].length, ac->patterns[i].text);*/

				/* Add over the IDs that it matches */
				add_ids(&ac->patterns[j], ac->patterns[i].ids, ac->patterns[i].id_count);
			}
		}
	}


	/* Create a DFA table. Reserve 2 rows for the default state (one the start
	 * row, the other the main working row) */
	ac->dfa = malloc((ac->pattern_count + 2) * sizeof(ac->dfa[0]));
	

	/* Fill in the default state-transition, which always points back to the 
	 * default empty pattern row */
	default_row_index = 0;
	for (i=0; i<ac->pattern_count; i++) {
		struct DFArow *row;
		unsigned j;

		row = &ac->dfa[i];
		for (j=0; j<256; j++)
			row->column[j] = default_row_index;
	}


	/* Fill in all the pointers. This means that we look at each pattern,
	 * then fill in all the possible other patterns that it can transition
	 * to.*/
	for (i=0; i<ac->pattern_count; i++) {
		unsigned j;

		//p = &ac->patterns[i];

		/* Find another sub-pattern that we will leed to on a transition */
		for (j=1; j<ac->pattern_count; j++) {

 			if (leads_to(&ac->patterns[i], ac->patterns[j].text, ac->patterns[j].length)) {
				unsigned prefix_length = ac->patterns[j].length-1;
				unsigned transition_char = ac->patterns[j].text[prefix_length];
				unsigned old_prefix_length;
				unsigned old_transition;

				/* Don't overwrite if the existing transition is better than the current
				 * one */
				old_transition = ac->dfa[i].column[transition_char];
				old_prefix_length = ac->patterns[old_transition].length;
				if (old_prefix_length > prefix_length+1)
					continue;

				/* Mark the transition */
				ac->dfa[i].column[transition_char] = (unsigned short)j;
			}
		}
	}

	/* Fill in the default state. Remember, there are two default states. The one
	 * we start with, which is used only once, then the one at the end of the
	 * list that we use constantly and spend most of our time at */
	memcpy(&ac->dfa[ac->pattern_count], &ac->dfa[0], sizeof(ac->dfa[0]));
}

unsigned ac_search(struct ACENGINE *ac, unsigned *r_state, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned offset = *r_offset;
	unsigned state = *r_state;

	/*
	 * First, see if there are any remaining multiple-match items from
	 * a previous search. These are encoded in the upper bits of the
	 * state variable.
	 */
	if (state & 0xFFF00000) {
		unsigned match_index;
		unsigned pattern_index;
		unsigned match_id;

		/* Extract the match-index and pattern-idnex from the state variable */
		match_index = ((state>>20)&0xfFF)-1;
		pattern_index = state&0x000fFFFF;

		/* Find the 'match-id' that we'll return */
		match_id = ac->patterns[pattern_index].ids[match_index];

		/* Reconstruct the new state variable with the decremented match_index */
		*r_state = pattern_index | (match_index<<20);

		return match_id;
	}

	/*======================================================================
	 * Inner search loop. This is where the code spends 99.99% of its time
	 *======================================================================*/
	while (offset<length) {
		unsigned c = 

		c = px[offset++];
		state = ac->dfa[state].column[c];

		if (ac->patterns[state].id_count)
			break;
	}

	/*
	 * Whoot! We found a pattern! We'll return the match-id that corresponds to
	 * this pattern. However, we have to take care of the case when multiple
	 * patterns are found at once. This function will return only one at a time.
	 * Therefore, we need to encode the count of the remaining patterns to return
	 * and encode them in the upper bits of the state. The next time we enter this
	 * function, we'll hit that code at the start that will continue to return
	 * the remaining patterns until we are done.
	 */
	if (ac->patterns[state].id_count) {
		unsigned match_index;
		unsigned pattern_index;
		unsigned match_id;

		/* The new state will be composed from the old state (representing
		 * the pattern-index) and the number of remaining patterns to
		 * return in the high order bits */
		match_index = ac->patterns[state].id_count-1;
		pattern_index = state;

		/* Find the 'match-id' that we'll return this itteration */
		match_id = ac->patterns[pattern_index].ids[match_index];

		/* Reconstruct the new state variable with the decremented match_index */
		*r_state = pattern_index | (match_index<<20);

		*r_offset = offset;
		return match_id;
	}

	/* Nothing found so far. However, as more data streams into the system, we'll 
	 * possibly find more data */
	*r_offset = offset;
	*r_state = state;
	return 0;
}


/****************************************************************************

  MODULETEST

  This code is designed to regression test this module. It is only included
  when this file is compiled as a standalone program.

 ****************************************************************************/
#ifdef MODULETEST
#include <ctype.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	struct ACENGINE *ac;
	const char *px = "rallysergiconfabuferconferallyrendit";
	unsigned state = 0;
	unsigned offset = 0;
	unsigned length = strlen(px);

	/*
	 * Create the pattern search engine
	 */
	ac = ac_create();

	/*
	 * Add a bunch of patterns to look for
	 */
	ac_add_pattern(ac,  1, "conference", -1);
	ac_add_pattern(ac,  1, "sconferenc", -1);
	ac_add_pattern(ac,  1, "conferenc", -1);
	ac_add_pattern(ac,  2, "feral", -1);
	ac_add_pattern(ac,  3, "erros", -1);
	ac_add_pattern(ac,  4, "rendition", -1);
	ac_add_pattern(ac, 42, "rendition", -1);
	ac_add_pattern(ac,  5, "on-top", -1);
	ac_add_pattern(ac,  6, "rally", -1);
	ac_add_pattern(ac,  7, "ally", -1);
	ac_add_pattern(ac,  8, "prallyxia", -1);
	ac_add_pattern(ac,  9, "lysergic", -1);


	/*
	 * Compile the patterns into a "state-machine".
	 */
	ac_compile(ac);

	/*
	 * Do searches
	 */
	while (offset<length) {
		unsigned matched;

		matched = ac_search(ac, &state, px, length, &offset);
		if (matched) {
			printf("found %d\n", matched);
		}

	}
	

	/*
	 * Destroy the engine and release all the memory
	 */
	ac_destroy(ac);

}

#endif /* MODULETEST */
