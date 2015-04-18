#include "ferret.h"
#include "report.h"
#include "stack-netframe.h"
#include "parse-address.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

#define TABLE_SIZE 0x4000

struct HostRecord
{
	struct HostRecord *next;
	uint64_t packets_sent;
	uint64_t packets_received;
	uint64_t bytes_sent;
	uint64_t bytes_received;

	unsigned ip;
	unsigned timestamp;
};

struct filter
{
	unsigned ip;
	unsigned mask;
};

struct ReportHosts
{
	struct HostRecord table[TABLE_SIZE];
	unsigned host_count;

	struct filter include_filters[32];
	unsigned include_count;

	struct filter exclude_filters[32];
	unsigned exclude_count;
};



struct ReportHosts *
hosts_create()
{
	struct ReportHosts *hosts;

	hosts = (struct ReportHosts *)malloc(sizeof(*hosts));
	memset(hosts, 0, sizeof(*hosts));
	
	return hosts;
}

void report_hosts_set_parameter(struct Ferret *ferret, const char *name, const char *value)
{
	if (ferret->report_hosts == 0)
		ferret->report_hosts = hosts_create();

	if (strcmp(name, "addr") == 0) {
		struct ParsedIpAddress addr;
		unsigned offset = 0;
		//unsigned is_exclude = 0;
		struct filter *filters;
		unsigned *filter_count;

		if (value[0] == '!') {
			//is_exclude = 1;
			filters = ferret->report_hosts->exclude_filters;
			filter_count = &ferret->report_hosts->exclude_count;
			value++;
		} else {
			filters = ferret->report_hosts->include_filters;
			filter_count = &ferret->report_hosts->include_count;
		}


		if (parse_ip_address(value, &offset, (unsigned)strlen(value), &addr)) {
			if (*filter_count > sizeof(ferret->report_hosts->include_filters)/sizeof(ferret->report_hosts->include_filters[0]))
				fprintf(stderr, "too many: report.host.%s=%s\n", name, value);
			else if (addr.version != 4) {
				fprintf(stderr, "only support IPv4 addresses for this feature at this time\n");
			} else {
				int64_t mask = -1;

				mask ^= 0xFFFFFFFF;
				mask >>= addr.prefix_length;

				filters[*filter_count].ip = addr.address[0]<<24 | addr.address[1]<<16 | addr.address[2]<<8 | addr.address[3];
				filters[*filter_count].mask = (unsigned)mask;
				(*filter_count)++;
			}
		} else
			fprintf(stderr, "bad IP address: report.host.%s=%s\n", name, value);


	} else
		fprintf(stderr, "cfg: unknown parm: report.host.%s=%s\n", name, value);
}

int
is_displayed(struct Ferret *ferret, unsigned ipv4)
{
	struct filter *filters;
	unsigned filter_count;
	int is_included = 0;
	int is_excluded = 0;
	unsigned i;



	/* Included */
	filters = ferret->report_hosts->include_filters;
	filter_count = ferret->report_hosts->include_count;
	for (i=0; i<filter_count; i++) {
		if ((ipv4 & filters[i].mask) == (filters[i].ip & filters[i].mask))
			is_included = 1;
	}
	if (filter_count == 0)
		is_included = 1;

	/* Excluded */
	filters = ferret->report_hosts->exclude_filters;
	filter_count = ferret->report_hosts->exclude_count;
	for (i=0; i<filter_count; i++) {
		if ((ipv4 & filters[i].mask) == (filters[i].ip & filters[i].mask))
			is_excluded = 1;
	}

	return is_included && !is_excluded;
}


static unsigned
hash(unsigned ipv4)
{
	unsigned result;

	result = ipv4;
	result += ipv4>>23;
	result ^= ipv4<<7;

	return result;
}

static struct HostRecord *
hosts_lookup(struct Ferret *ferret, unsigned ipv4)
{
	unsigned index;
	struct HostRecord *record;

	if (ferret->report_hosts == NULL)
		ferret->report_hosts = hosts_create();

	index = hash(ipv4) & (TABLE_SIZE-1);

	record = &ferret->report_hosts->table[index];

	while (record) {
		if (record->ip == ipv4)
			return record;
		if (record->ip == 0 && record->next == 0 && record->bytes_received == 0 && record->bytes_sent == 0) {
			ferret->report_hosts->host_count++;
			record->ip = ipv4;
			return record;
		}
		if (record->next == 0) {
			ferret->report_hosts->host_count++;
			record->next = (struct HostRecord *)malloc(sizeof(*record));
			record = record->next;
			memset(record, 0, sizeof(*record));
			record->ip = ipv4;
			return record;
		}

		record = record->next;
	}

	return 0;
}

void record_host_transmit(struct Ferret *ferret, unsigned ipv4, unsigned frame_size)
{
	struct HostRecord *host;

	host = hosts_lookup(ferret, ipv4);

	host->packets_sent += 1;
	host->bytes_sent += frame_size;
}

void record_host_receive(struct Ferret *ferret, unsigned ipv4, unsigned frame_size)
{
	struct HostRecord *host;
	
	host = hosts_lookup(ferret, ipv4);

	host->packets_received += 1;
	host->bytes_received += frame_size;
}

struct tmprecord {
	uint64_t byte_count;
	struct HostRecord *record;
};

static void
sort_records(struct tmprecord *list, unsigned count)
{
	unsigned i;

	for (i=0; i<count; i++) {
		unsigned j;
		unsigned max = count - i - 1;
		for (j=0; j<max; j++) {
			if (list[j].byte_count < list[j+1].byte_count) {
				struct tmprecord swap;

				swap.byte_count = list[j].byte_count;
				swap.record = list[j].record;

				list[j].byte_count = list[j+1].byte_count;
				list[j].record = list[j+1].record;

				list[j+1].byte_count = swap.byte_count;
				list[j+1].record = swap.record;
			}
		}
	}

}

void print_ip_id(struct Ferret *ferret, unsigned ip);

void
report_hosts_topn(struct Ferret *ferret, unsigned report_count)
{
	struct tmprecord *list;
	unsigned i;
	unsigned host_count;
	unsigned n;

	if (ferret->report_hosts == NULL)
		return;
	host_count = ferret->report_hosts->host_count;

	list = (struct tmprecord *)malloc(host_count * sizeof(*list));

	/*
	 * Walk through the hash table grabbing all the records
	 */
	n = 0;
	for (i=0; i<TABLE_SIZE; i++) {
		struct HostRecord *rec = &ferret->report_hosts->table[i];
		
		while (rec) {
			assert(n <= host_count);
			if (rec->ip == 0)
				break;
			if (is_displayed(ferret, rec->ip)) {
				list[n].byte_count = rec->bytes_received + rec->bytes_sent;
				list[n].record = rec;
				n++;
			}
			rec = rec->next;
		}
	}

	sort_records(list, n);

	/*
	 * Print the results
	 */
	for (i=0; i<report_count && i<n; i++) {
		unsigned ip = list[i].record->ip;
		char sz_address[16];

		snprintf(sz_address, sizeof(sz_address), "%u.%u.%u.%u", (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);

		printf("%3u  %-16s  %11llu - ", i, sz_address, list[i].byte_count);
		print_ip_id(ferret, ip);
		printf("\n");
	}

	printf("\n");
}
