/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	TCP FRAGMENTATION REASSEMBLY

  This code only implements the fragment tracking bits needed for 
  TCP reassembly. It actually has no knowledge of the TCP protocol
  itself, other than TCP sequence numbers.

  TODO: We need to test this code for 64-bit compilers, because it
  relies upon 32-bit 2s-complement integer overflow arithmetics.


*/
#include "stack-tcpfrag.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef int SEQNO; /*must be ONLY 32-bits*/


/**
 * TODO: make 64-bit compliant
 */
unsigned SEQ_FIRST_BEFORE_SECOND(unsigned seqno1, unsigned seqno2)
{
	int compare;

	compare = seqno2-seqno1;

	if (compare > 0)
		return 1;
	else
		return 0;
}
/**
 * TODO: make 64-bit compliant
 */
unsigned SEQ_FIRST_GTE_SECOND(unsigned seqno1, unsigned seqno2)
{
	unsigned compare;
	
	compare = seqno1-seqno2;

	if (compare < 0x7FFFFFFF)
		return 1;
	else
		return 0;
}

static struct TCP_segment *
tcpfrag_create(
	const unsigned char *px, 
	unsigned seqno_start,
	unsigned seqno_end,
	struct TCP_segment *next)
{
	unsigned length = seqno_end-seqno_start;
	struct TCP_segment *frag;


	frag = (struct TCP_segment*)malloc(sizeof(*frag)+length);
	frag->px = ((unsigned char*)frag) + sizeof(*frag);
	memcpy(frag->px, px, length);
	frag->seqno = seqno_start;
	frag->length = length;
	frag->next = next;
	return frag;
}

unsigned tcpfrag_max_contiguous(struct TCP_segment *frag, unsigned in_seqno)
{
	SEQNO seqno = (SEQNO)in_seqno;
	SEQNO max_seqno;

	/* Find the starting fragment */
	for ( ; frag; frag = frag->next) {
		if ((int)(seqno - frag->seqno) < 0) /*FIXME: this may be wrong*/
			continue;
		if (frag->seqno + frag->length - seqno <= 0)
			continue;
		break;
	}
	if (frag == NULL)
		return 0;

	/* Go forward as long as the fragments are contiguous */
	for (;;) {
		max_seqno = frag->seqno + frag->length;
		if (frag->next == NULL)
			break;
		if ((SEQNO)frag->next->seqno != max_seqno)
			break;
		frag = frag->next;
	}

	/* Now return the length of how much data we have */
	return (unsigned)(max_seqno - seqno);
}


void
tcpfrag_add(struct TCP_segment **r_frag, const unsigned char *px, unsigned length, unsigned seqno)
{

	SEQNO next_start, next_end, this_start, this_end;

again:
	this_start = (SEQNO)seqno;
	this_end = (SEQNO)(seqno+length);

	if (length == 0)
		return;

	/* [0] - first fragment
		old: ........,,,,,,,........
		new: ======.................
	*/
	if (*r_frag == NULL) {
		*r_frag = tcpfrag_create(px, this_start, this_end, *r_frag);
		return;
	}

	next_start = (SEQNO)(*r_frag)->seqno;
	next_end = (SEQNO)(next_start + (*r_frag)->length);

	/* [1] - any part of the fragment in front of existing fragments
		old: ........*******........
		new: ======???????????......
	*/
	if ((next_start - this_start) > 0) { /* if this segment is before any of the others */
		if ((next_start - this_end) < 0) {	/* if overlap the beginning of the next */
			this_end = next_start;			/* shorten this segment to only the new data */
		}

		*r_frag = tcpfrag_create(px, this_start, this_end, *r_frag);

		px += this_end-this_start;
		seqno += this_end-this_start;
		length -= this_end-this_start;
		goto again;
	}
	
	/* [2] - any part of the new fragment overlaps the existing fragment
		old: ........*******........
		new: ........?====?????.....
	*/
	if ((this_start - next_start) >= 0 && (next_end - this_start) > 0 ) {
		if ((next_end - this_end) >= 0)
			return; /* complete overlap */

		px += next_end - this_start;
		seqno += next_end - this_start;
		length -= next_end - this_start;
		goto again;
	}

	if ((this_start - next_end) >= 0) {
		r_frag = &(*r_frag)->next;
		goto again;
	}


	printf("never\n");
}


/**
 * Delete the current fragment, then replace the current pointer
 * to point to the next one in the chain.
 */
void tcpfrag_delete(struct TCP_segment **r_frag)
{
	struct TCP_segment *next = (*r_frag)->next;
	free(*r_frag);
	*r_frag = next;
}

/**
 * Delete the entire chain
 */
void tcpfrag_delete_all(struct TCP_segment **r_frag)
{
	while (*r_frag)
		tcpfrag_delete(r_frag);
}


/****************************************************************************

  MODULETEST

  This code is designed to regression test this module. It is only included
  when this file is compiled as a standalone program.

 ****************************************************************************/
#ifdef MODULETEST

#define DONE 0xa3a3a3a3

struct TEST {
	unsigned start;
	unsigned end;
};

struct TEST cases[] = {
	{0,	10},	{10, 20},	{20, 30},	{DONE, DONE},
	{0,	 9},	{10, 20},	{20, 30},	{DONE, DONE},
	{0,	11},	{10, 20},	{20, 30},	{DONE, DONE},
	{0,	10},	{ 9, 21},	{20, 30},	{DONE, DONE},
	{0,1}, {2,3}, {4,5}, {6,7}, {8,9}, {2,6}, {2,7}, {4,10}, {1,8},  {DONE, DONE}, /* AIBFCFDHEH */
	{DONE, DONE}
};

unsigned re_tests[] = {
	0x7FFFfff8,
	0x7FFFfffe,
	0xFFFFFFF8,
	0xFFFFFFFe,
	DONE
};

void run_test(struct TEST *testcase, unsigned offset)
{
	struct TCP_segment *segments = NULL;
	unsigned i;
	unsigned char payload[64];
	unsigned last;

	for (i=0; testcase[i].start != testcase[i].end || testcase[i].start != DONE; i++) {
		memset(payload, 'A'+(i%26), sizeof(payload));
		//printf("{%d,%d},", testcase[i].start, testcase[i].end);
		tcpfrag_add(&segments, payload, testcase[i].end - testcase[i].start, testcase[i].start+offset);
	}
	//printf("\n");
	if (segments == NULL) {
		printf("(null)\n");
		return;
	}

	last = segments->seqno;
	while (segments) {
		for (i=last; i != segments->seqno; i++)
			; //printf(".");
		for (i=0; i<segments->length; i++)
			printf("%c", segments->px[i]);
		last = segments->seqno + segments->length;

		tcpfrag_delete(&segments);
	}
	printf("\n");
}

void main(int argc, char *argv[1])
{
	unsigned r = 0;

	/* Aggression Test: This test "fuzzes" the module by testing a billion
	 * different random inputs */
	srand(0);
	if (argc > 1 && strcmp(argv[1], "aggress") == 0) {
		for (r=0; r<1000000000; r++) {
			unsigned count = 10 + rand() % 50;
			unsigned i;
			struct TEST *aggress = (struct TEST *)malloc(count * sizeof(*cases));
			unsigned offset = rand() | rand()<<14 | rand() << 28;
			
			for (i=0; i<count; i++) {
				unsigned start = rand()&0x1F;
				unsigned length = 1+rand()&0x7;

				aggress[i].start = start;
				aggress[i].end = start+length;

				//if (r == 9924602)
				//	printf("{%d,%d},", start, start+length);
			}
			//if (r == 99924602)
			//	printf("\n");
			aggress[count-1].start = DONE;
			aggress[count-1].end = DONE;


			printf("%8d ", r);
			run_test(&aggress[0], offset);
			free(aggress);
		}
	}

	/* Regression Test: This test generates a repeatable set of tests with
	 * know outputs that can be tested from version to version to make sure
	 * that the output doesn't change. */
	r = 0;
	printf("-- MODULE TEST START: %s\n", "tcpfrag.c");
	while (re_tests[r] != DONE) {
		unsigned i = 0;
		printf("seqno = 0x%08x\n", re_tests[r]);
		while (cases[i].start != cases[i].end && cases[i].start != DONE) {
			run_test(&cases[i], re_tests[r]);
			while (cases[i].start != cases[i].end && cases[i].start != DONE)
				i++;
			i++;
		}
		r++;
	}
	printf("-- MODULE TEST END: %s\n\n", "tcpfrag.c");
}

#endif /* MODULETEST */
