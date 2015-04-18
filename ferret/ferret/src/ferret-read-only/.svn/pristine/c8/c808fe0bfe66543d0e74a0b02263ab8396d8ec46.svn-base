/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	MALLOC TRACKING

  This code wraps malloc()/free() in order to keep track of memory corruption
  and memory leaks.

  This assumes that the code does not use APIs that have hidden malloc/free
  in them, such as strdup() and realloc().

  TODO: We should add robust heap protection (such as heap cookies) in here 
  as well.

  TODO: We should change the rest of the code so that it increases its use
  of 'object-pools' and decrease its use of malloc/free.

  TODO: We should add detection for memory growth issues, which is memory that
  isn't precisely 'leaked' and lost by the system, but for some reason that
  over the long run, memory keeps getting allocated by the system during
  normal running, but does not get freed. For example, image if we never
  timed out a TCP connection. We haven't lost the connections, and will
  properly clean up upon a shutdown, but the system will keep allocating
  more memory until it fails.

*/
#undef malloc
#undef free
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct MallocTracker
{
	unsigned id;
	unsigned count;

	struct MallocHeader *headers;

} tracker;

struct MallocHeader
{
	size_t size;
	unsigned id;

	struct MallocHeader *next;
	struct MallocHeader *prev;
};


/**
 * replacement for malloc
 */
void *t_malloc(size_t size)
{
	char *p = (char*)malloc(size+sizeof(struct MallocHeader)+16);
	struct MallocHeader *hdr;

	memset(p, 0xa3, size+sizeof(struct MallocHeader)+16);

	hdr = (struct MallocHeader *)p;
	p += sizeof(*hdr) + 8;
	
	hdr->size = size;
	hdr->id = ++tracker.id;

	/* TEMP: for tracking a block */
	//if (hdr->id == 81)
		//printf(".");

	/*
	 * Insert into doubly-linked list
	 */
	if (tracker.headers == NULL) {
		tracker.headers = hdr;
		hdr->next = hdr;
		hdr->prev = hdr;
	} else {
		hdr->next = tracker.headers->next;
		hdr->next->prev = hdr;
		hdr->prev = tracker.headers;
		hdr->prev->next = hdr;
	}

	/*if (hdr->id == 158)
		printf("");*/

	tracker.count++;
	return p;
}

void t_free(void *v)
{
	char *p = v;
	struct MallocHeader *hdr;

	p -= sizeof(*hdr) + 8;

	hdr = (struct MallocHeader *)p;

	if (memcmp(p+sizeof(*hdr), "\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3", 8) != 0)
		printf("memory corruption on block %d\n", hdr->id);
	if (memcmp(p+sizeof(*hdr)+8+hdr->size, "\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3", 8) != 0)
		printf("memory corruption on block %d\n", hdr->id);


	/*
	 * Remove from the doubly-linked list
	 */
	hdr->next->prev = hdr->prev;
	hdr->prev->next = hdr->next;

	if (tracker.headers == hdr)
		tracker.headers = hdr->next;
	if (tracker.headers == hdr)
		tracker.headers = NULL;

	hdr->next = NULL;
	hdr->prev = NULL;

	tracker.count--;

	free(p);
}

void t_leak_check()
{
	struct MallocHeader *hdr = tracker.headers;

	if (hdr == NULL && tracker.count == 0)
		return;

	printf("--- %d leaked blocks ---\n", tracker.count);

	while (hdr) {
		printf("%d ", hdr->id);
		hdr = hdr->next;
		if (hdr == tracker.headers)
			break;
	}
	printf("---\n");
}

