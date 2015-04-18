#include "ferret.h"
#include "report.h"
#include "stack-netframe.h"
#include "parse-address.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

#define TABLE_SIZE 0x4000

struct FanoutRecord
{
	struct FanoutRecord *next;
	uint64_t packets;
	uint64_t bytes;
	unsigned ip_src;
	unsigned ip_dst;
};

struct filter
{
	unsigned ip;
	unsigned mask;
};

struct FanoutHost
{
	struct FanoutHost *next;
	unsigned ip;
	unsigned count;
};

struct ReportFanout
{
	struct FanoutRecord table[TABLE_SIZE];
	unsigned table_count;

	struct FanoutHost hostout[TABLE_SIZE];
	unsigned hostouts_count;

	struct FanoutHost hostin[TABLE_SIZE];
	unsigned hostins_count;

	struct filter include_filters[32];
	unsigned include_count;

	struct filter exclude_filters[32];
	unsigned exclude_count;
};



struct ReportFanout *
fanout_create()
{
	struct ReportFanout *hosts;

	hosts = (struct ReportFanout *)malloc(sizeof(*hosts));
	memset(hosts, 0, sizeof(*hosts));
	
	return hosts;
}

void report_fanout_set_parameter(struct Ferret *ferret, const char *name, const char *value)
{
	if (ferret->report_fanout == 0)
		ferret->report_fanout = fanout_create();

	if (strcmp(name, "addr") == 0) {
		struct ParsedIpAddress addr;
		unsigned offset = 0;
		//unsigned is_exclude = 0;
		struct filter *filters;
		unsigned *filter_count;

		if (value[0] == '!') {
			//is_exclude = 1;
			filters = ferret->report_fanout->exclude_filters;
			filter_count = &ferret->report_fanout->exclude_count;
			value++;
		} else {
			filters = ferret->report_fanout->include_filters;
			filter_count = &ferret->report_fanout->include_count;
		}


		if (parse_ip_address(value, &offset, (unsigned)strlen(value), &addr)) {
			if (*filter_count > sizeof(ferret->report_fanout->include_filters)/sizeof(ferret->report_fanout->include_filters[0]))
				fprintf(stderr, "too many: report.fanout.%s=%s\n", name, value);
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
			fprintf(stderr, "bad IP address: report.fanout.%s=%s\n", name, value);


	} else
		fprintf(stderr, "cfg: unknown parm: report.fanout.%s=%s\n", name, value);
}

static int
is_displayed(struct Ferret *ferret, unsigned ipv4)
{
	struct filter *filters;
	unsigned filter_count;
	int is_included = 0;
	int is_excluded = 0;
	unsigned i;


	/* Included */
	filters = ferret->report_fanout->include_filters;
	filter_count = ferret->report_fanout->include_count;
	for (i=0; i<filter_count; i++) {
		if ((ipv4 & filters[i].mask) == (filters[i].ip & filters[i].mask))
			is_included = 1;
	}
	if (filter_count == 0)
		is_included = 1;

	/* Excluded */
	filters = ferret->report_fanout->exclude_filters;
	filter_count = ferret->report_fanout->exclude_count;
	for (i=0; i<filter_count; i++) {
		if ((ipv4 & filters[i].mask) == (filters[i].ip & filters[i].mask))
			is_excluded = 1;
	}

	return is_included && !is_excluded;
}


static unsigned
hash(unsigned ip_src, unsigned ip_dst)
{
	unsigned result;

	result = ip_src;
	result += ip_src>>23;
	result ^= ip_src<<7;

	result |= ip_dst<<3;
	result += ip_dst>>11;
	result ^= ip_dst<<11;

	return result;
}

static struct FanoutHost *
fanout_lookup_hostout(struct Ferret *ferret, unsigned ip)
{
	unsigned index;
	struct FanoutHost *record;

	if (ferret->report_fanout == NULL)
		ferret->report_fanout = fanout_create();

	index = hash(ip, 0) & (TABLE_SIZE-1);

	record = &ferret->report_fanout->hostout[index];

	while (record) {
		if (record->ip == ip)
			return record;
		if (record->ip == 0 && record->count == 0) {
			ferret->report_fanout->hostouts_count++;
			record->ip = ip;
			record->count = 0;
			return record;
		}
		if (record->next == 0) {
			ferret->report_fanout->hostouts_count++;
			record->next = (struct FanoutHost *)malloc(sizeof(*record));
			record = record->next;
			memset(record, 0, sizeof(*record));
			record->ip = ip;
			record->count = 0;
			return record;
		}

		record = record->next;
	}

	return 0;
}
static struct FanoutHost *
fanout_lookup_hostin(struct Ferret *ferret, unsigned ip)
{
	unsigned index;
	struct FanoutHost *record;

	if (ferret->report_fanout == NULL)
		ferret->report_fanout = fanout_create();

	index = hash(ip, 0) & (TABLE_SIZE-1);

	record = &ferret->report_fanout->hostin[index];

	while (record) {
		if (record->ip == ip)
			return record;
		if (record->ip == 0 && record->count == 0) {
			ferret->report_fanout->hostins_count++;
			record->ip = ip;
			record->count = 0;
			return record;
		}
		if (record->next == 0) {
			ferret->report_fanout->hostins_count++;
			record->next = (struct FanoutHost *)malloc(sizeof(*record));
			record = record->next;
			memset(record, 0, sizeof(*record));
			record->ip = ip;
			record->count = 0;
			return record;
		}

		record = record->next;
	}

	return 0;
}

static struct FanoutRecord *
fanout_lookup(struct Ferret *ferret, unsigned ip_src, unsigned ip_dst)
{
	unsigned index;
	struct FanoutRecord *record;

	if (ferret->report_fanout == NULL)
		ferret->report_fanout = fanout_create();

	index = hash(ip_src, ip_dst) & (TABLE_SIZE-1);

	record = &ferret->report_fanout->table[index];

	while (record) {
		if (record->ip_src == ip_src && record->ip_dst == ip_dst)
			return record;
		if (record->ip_src == 0 && record->ip_dst == 0 && record->next == 0 && record->bytes == 0 && record->packets == 0) {
			ferret->report_fanout->table_count++;
			record->ip_src = ip_src;
			record->ip_dst = ip_dst;
			fanout_lookup_hostin(ferret, ip_src)->count++;
			fanout_lookup_hostout(ferret, ip_dst)->count++;
			return record;
		}
		if (record->next == 0) {
			ferret->report_fanout->table_count++;
			record->next = (struct FanoutRecord *)malloc(sizeof(*record));
			record = record->next;
			memset(record, 0, sizeof(*record));
			record->ip_src = ip_src;
			record->ip_dst = ip_dst;
			fanout_lookup_hostin(ferret, ip_src)->count++;
			fanout_lookup_hostout(ferret, ip_src)->count++;
			return record;
		}

		record = record->next;
	}

	return 0;
}

void record_host2host(struct Ferret *ferret, unsigned ip_src, unsigned ip_dst, unsigned frame_size)
{
	struct FanoutRecord *host;

	host = fanout_lookup(ferret, ip_src, ip_dst);

	host->packets += 1;
	host->bytes += frame_size;
}


struct tmprecord {
	unsigned ip;
	unsigned count;
};

static void
sort_records(struct tmprecord *list, unsigned count)
{
	unsigned i;

	for (i=0; i<count; i++) {
		unsigned j;
		unsigned max = count - i - 1;
		for (j=0; j<max; j++) {
			if (list[j].count < list[j+1].count) {
				struct tmprecord swap;

				memcpy(&swap,		&list[j],		sizeof(swap));
				memcpy(&list[j],	&list[j+1],		sizeof(swap));
				memcpy(&list[j+1],	&swap,			sizeof(swap));
			}
		}
	}

}

void print_ip_id(struct Ferret *ferret, unsigned ip);

void
report_fanout(struct Ferret *ferret, unsigned report_count, struct FanoutHost *hosts, unsigned host_count, const char *name)
{
	struct tmprecord *list;
	unsigned i;
	unsigned n;

	

	list = (struct tmprecord *)malloc(host_count * sizeof(*list));

	/*
	 * Walk through the hash table grabbing all the records
	 */
	n = 0;
	for (i=0; i<TABLE_SIZE; i++) {
		struct FanoutHost *rec = &hosts[i];
		
		while (rec) {
			assert(n <= host_count);
			if (rec->ip == 0)
				break;
			if (is_displayed(ferret, rec->ip)) {
				list[n].count = rec->count;
				list[n].ip = rec->ip;
				n++;
			}
			rec = rec->next;
		}
	}

	sort_records(list, n);

	/*
	 * Print the results
	 */
	printf("----- %s -----\n", name);
	for (i=0; i<report_count && i<n; i++) {
		unsigned ip = list[i].ip;
		char sz_address[16];

		snprintf(sz_address, sizeof(sz_address), "%u.%u.%u.%u", (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);

		printf("%3u  %-16s  %6u - ", i, sz_address, list[i].count);
		print_ip_id(ferret, ip);
		printf("\n");
	}

	free(list);
	printf("\n");
}

void
report_fanout_topn(struct Ferret *ferret, unsigned report_count)
{
	if (ferret->report_fanout == NULL)
		return;

	report_fanout(ferret, report_count, ferret->report_fanout->hostin, ferret->report_fanout->hostins_count, "Fanout");
}

void
report_fanin_topn(struct Ferret *ferret, unsigned report_count)
{
	if (ferret->report_fanout == NULL)
		return;

	report_fanout(ferret, report_count, ferret->report_fanout->hostout, ferret->report_fanout->hostouts_count, "Fanin");
}

