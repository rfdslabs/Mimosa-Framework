#include "stack-listener.h"
#include "ferret.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>


#define TABLE_SIZE 0x4000

struct ListenerItem {
	struct ListenerItem *next;
	unsigned timestamp;
	unsigned ip;
	unsigned short port;
	unsigned short protocol;
};

struct Listener {
	struct ListenerItem table_udp[TABLE_SIZE];
	struct ListenerItem table_tcp[TABLE_SIZE];
};

struct Listener *
listener_create()
{
	struct Listener *result;

	result = (struct Listener *)malloc(sizeof(*result));
	memset(result, 0, sizeof(*result));

	return result;
}

void
listener_destroy(struct Listener *listener)
{
	unsigned i;

	for (i=0; i<sizeof(listener->table_udp)/sizeof(listener->table_udp[0]); i++) {
		struct ListenerItem *item = listener->table_udp[i].next;

		while (item) {
			struct ListenerItem *next = item->next;
			free(item);
			item = next;
		}
	}

	for (i=0; i<sizeof(listener->table_tcp)/sizeof(listener->table_tcp[0]); i++) {
		struct ListenerItem *item = listener->table_tcp[i].next;

		while (item) {
			struct ListenerItem *next = item->next;
			free(item);
			item = next;
		}
	}

	free(listener);
}

unsigned hash(unsigned ip, unsigned port)
{
	unsigned result = 0;

	result ^= ip;
	result ^= (ip>>4);
	result ^= (ip<<3);
	result ^= (ip>>12);
	result += (ip>>20);
	result ^= (ip>>28);
	result += port;
	result ^= (port>>5);

	return result;
}

void
listener_register_udp(
	struct Ferret *ferret, 
	enum LISTENER_TYPE application_protocol,
	unsigned ip,
	unsigned port,
	unsigned time_secs
	)
{
	unsigned index;
	struct ListenerItem *item;
	struct Listener *listener;

	if (ferret->listener == NULL)
		ferret->listener = listener_create();
	listener = ferret->listener;


	index = hash(ip, port);
	index &= TABLE_SIZE-1; /*table size must be power of 2 */


	/*
	 * Check for duplicates. This is actually quite common. We are 
	 * just going to update the timestamp and exit
	 */
	item = &listener->table_udp[index];
	while (item) {
		if (item->ip == ip && item->port == port && item->protocol == application_protocol) {
			return;
		}
		item = item->next;
	}

	/*
	 * Not found, so insert a new one
	 */
	item = &listener->table_udp[index];
	while (item) {
		if (item->timestamp + 60*60 < time_secs) {
			/* The previous record is over an hour old. Therefore, just discard
			 * that record and replace it with this new one */
			break;
		}

		if (item->next == NULL) {
			item->next = (struct ListenerItem *)malloc(sizeof(*item));
			item = item->next;
			item->next = 0;
			break;
		}

		item = item->next;
	}
    
    if (item == 0)
        return;


	item->ip = ip;
	item->port = port;
	item->protocol = application_protocol;
	item->timestamp = time_secs;
}

	void
listener_register_tcp(
	struct Ferret *ferret, 
	enum LISTENER_TYPE application_protocol,
	unsigned ip,
	unsigned port,
	unsigned time_secs
	)
{
	unsigned index;
	struct ListenerItem *item;
	struct Listener *listener;

	if (ferret->listener == NULL)
		ferret->listener = listener_create();
	listener = ferret->listener;


	index = hash(ip, port);
	index &= TABLE_SIZE-1; /*table size must be power of 2 */


	/*
	 * Check for duplicates. This is actually quite common. We are 
	 * just going to update the timestamp and exit
	 */
	item = &listener->table_tcp[index];
	while (item) {
		if (item->ip == ip && item->port == port && item->protocol == application_protocol) {
			return;
		}
		item = item->next;
	}

	/*
	 * Not found, so insert a new one
	 */
	item = &listener->table_tcp[index];
	while (item) {
		if (item->timestamp + 60*60 < time_secs) {
			/* The previous record is over an hour old. Therefore, just discard
			 * that record and replace it with this new one */
			break;
		}

		if (item->next == NULL) {
			item->next = (struct ListenerItem *)malloc(sizeof(*item));
			item = item->next;
			item->next = 0;
			break;
		}

		item = item->next;
	}
    
    if (item == 0)
        return;


	item->ip = ip;
	item->port = port;
	item->protocol = application_protocol;
	item->timestamp = time_secs;
}


unsigned
listener_lookup_udp(
	struct Ferret *ferret, 
	unsigned ip,
	unsigned port
	)
{
	unsigned index;
	struct ListenerItem *item;
	struct Listener *listener;

	if (ferret->listener == NULL)
		return 0;
	listener = ferret->listener;


	index = hash(ip, port) & (TABLE_SIZE-1);


	item = &listener->table_udp[index];
	while (item) {
		if (item->ip == ip && item->port == port)
			return item->protocol;
		item = item->next;
	}

	return 0;
}
unsigned
listener_lookup_tcp(
	struct Ferret *ferret, 
	unsigned ip,
	unsigned port
	)
{
	unsigned index;
	struct ListenerItem *item;
	struct Listener *listener;

	if (ferret->listener == NULL)
		return 0;
	listener = ferret->listener;


	index = hash(ip, port) & (TABLE_SIZE-1);


	item = &listener->table_tcp[index];
	while (item) {
		if (item->ip == ip && item->port == port)
			return item->protocol;
		item = item->next;
	}

	return 0;
}
