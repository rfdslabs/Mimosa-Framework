/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __HOUSEKEEPING_H
#define __HOUSEKEEPING_H
#ifdef __cplusplus
extern "C" {
#endif
#include <time.h>

struct Housekeeping;
struct NetFrame;


typedef void (*HOUSEKEEPING_CALLBACK)(struct Housekeeping *housekeeper, void *housekeeping_data, time_t now, struct NetFrame *frame);

struct HousekeepingEntry
{
	struct HousekeepingEntry *next;
	struct HousekeepingEntry *prev;
	time_t timestamp;
	HOUSEKEEPING_CALLBACK housekeeping_callback; 
	void *housekeeping_data;

	/** TODO: this is a temporary feature that allows us to track the ID of
	 * insertions and deletions into the housekeeping system */
	unsigned id;
};

/**
 * This function is called by things that need to be cleaned up later.
 * For example, when a new TCP connection is created, it will register
 * itself with the housekeeping system and a timestamp when it wants
 * to be called back.
 */
void housekeeping_remember(
	struct Housekeeping *housekeeper, 
	time_t timestamp,
	HOUSEKEEPING_CALLBACK housekeeping_callback, 
	void *housekeeping_data,
	struct HousekeepingEntry *entry);

void housekeeping_timeout(struct Housekeeping *housekeeper, time_t now, struct NetFrame *frame);

struct Housekeeping *housekeeping_create();
void housekeeping_destroy(struct Housekeeping *housekeeper);


/**
 * Unlink the housekeeping record from the link list
 */
void housekeeping_remove(struct Housekeeping *housekeeper, struct HousekeepingEntry *entry);


#ifdef __cplusplus
}
#endif
#endif /*__HOUSEKEEPING_H*/
