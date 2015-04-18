/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	HOUSEKEEPING

  This module forms the basic of the 'housekeeping' service. This
  service handles the varioius timeouts used in the system.

  For example, it tracks when a TCP connection has timed out and
  needs to be de-allocated.

  Other modules register with this module and the time when they
  want to be contacted again.

  See the 'read-code.txt' file for more about housekeeping.

*/
#include "util-housekeeping.h"
#include <stdlib.h>
#include <string.h>


struct Housekeeping
{
	/**
	 * Provide for 15-minutes worth of future
	 * records
	 */
	struct HousekeepingEntry *entries[1024];

	/** 
	 * A pool of used entry records. Instead of free()ing the allocated records,
	 * we put them back into a pool.
	 */
	struct HousekeepingEntry *free_pool;

	/*
	 * The last time that we did some timeouts
	 */
	time_t last_timeout;

	/*
	 * Count of the number of tasks we have left to do. This helps us
	 * figure out how many things we have left while destroying the object
	 */
	unsigned count;

	unsigned id;
};


struct Housekeeping *
housekeeping_create()
{
	struct Housekeeping *result;

	result = (struct Housekeeping *)malloc(sizeof(*result));
	memset(result, 0, sizeof(*result));


	return result;
}


void housekeeping_destroy(struct Housekeeping *housekeeper)
{
	
	if (housekeeper == NULL)
		return;

	/* Before this function is called, the caller should probably have already
	 * called us to timeout everything, so there shouldn't be any objects
	 * left that we need to timeout */


	/* Free the free pool */
	while (housekeeper->free_pool) {
		struct HousekeepingEntry *entry;

		entry = housekeeper->free_pool;
		housekeeper->free_pool = entry->next;
		free(entry);
	}

	/* Now do the remaining free() */
	free(housekeeper);
}


void 
housekeeping_remember(
	struct Housekeeping *housekeeper, 
	time_t timestamp,
	HOUSEKEEPING_CALLBACK housekeeping_callback, 
	void *housekeeping_data,
	struct HousekeepingEntry *entry)
{
	static const unsigned ENTRY_COUNT = sizeof(housekeeper->entries)/sizeof(housekeeper->entries[0]);
	unsigned index;


	/*
	 * Put that entry into our list
	 */
	index = timestamp % ENTRY_COUNT;
	if (housekeeper->entries[index] == NULL) {
		housekeeper->entries[index] = entry;
		entry->next = entry;
		entry->prev = entry;
	} else {
		entry->next = housekeeper->entries[index]->next;
		entry->next->prev = entry;
		entry->prev = housekeeper->entries[index];
		entry->prev->next = entry;
	}
	
	/*
	 * Fill in the entry
	 */
	entry->timestamp = timestamp;
	entry->housekeeping_callback = housekeeping_callback;
	entry->housekeeping_data = housekeeping_data;

	housekeeper->count++;

	entry->id = ++housekeeper->id;
}

void housekeeping_remove(struct Housekeeping *housekeeper, struct HousekeepingEntry *entry)
{
	static const unsigned ENTRY_COUNT = sizeof(housekeeper->entries)/sizeof(housekeeper->entries[0]);
	unsigned index = entry->timestamp % ENTRY_COUNT;

	if (entry->next == NULL && entry->prev == NULL)
		return;

	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;

	if (housekeeper->entries[index] == entry)
		housekeeper->entries[index] = entry->next;
	if (housekeeper->entries[index] == entry)
		housekeeper->entries[index] = NULL;

	entry->next = NULL;
	entry->prev = NULL;

	housekeeper->count--;
}
void housekeeping_timeout(struct Housekeeping *housekeeper, time_t now, struct NetFrame *frame)
{
	static const unsigned ENTRY_COUNT = sizeof(housekeeper->entries)/sizeof(housekeeper->entries[0]);

	if (housekeeper->last_timeout == 0)
		housekeeper->last_timeout = now;

	/*
	 * Go through all seconds since the last timeout
	 */
	while (housekeeper->last_timeout <= now) {
		struct HousekeepingEntry *entry;
		struct HousekeepingEntry *skipped_entry = NULL;
		unsigned index;

		/* Get the hashed entries */
		index = housekeeper->last_timeout % ENTRY_COUNT;
		entry = housekeeper->entries[index];


		/*
		 * Go through the multiple timeoutes at this point in time
		 */
		while (entry != skipped_entry && entry != NULL) {
			struct HousekeepingEntry *next_entry = entry->next;

			if (next_entry->next == next_entry)
				next_entry = NULL;

			/* Since we hash the timestamps, not every entry at this hashed point
			 * could be the same time, but could be 1024 seconds in the future, or
			 * 2048 seconds, etc. Therefore, we go through the linked list of entries
			 * one-by-one and test each one for the right timestamp */
			if (entry->timestamp > housekeeper->last_timeout) {
				/* TODO: the entry->timestamp should never be BEFORE housekeeper->last_timeout,
				 * but there is a bug that results in this condition. By checking for all
				 * entries before the current time, we'll still catch it, so the  bug
				 * is currently being masked */
				if (skipped_entry == NULL)
					skipped_entry = entry;
				entry = entry->next;
				continue;
			}

			/*
			 * Remove the entry from the list
			 */
			housekeeping_remove(housekeeper, entry);

			/*
			 * Do the housekeeping task associated with this entry, such as timeing
			 * out TCP connections, and other stuff I'll think of later.
			 */
			entry->housekeeping_callback(housekeeper, entry->housekeeping_data, now, frame);
			entry = NULL; /*the housekeeping callback has freed the structure */


			/*
			 * Go to the next entry at this timestamp
			 */
			entry = next_entry;
		}

		housekeeper->last_timeout++;
	}
}	

