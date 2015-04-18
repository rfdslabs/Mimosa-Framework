#include "ferret.h"
#include "report.h"
#include "stack-netframe.h"
#include "parse-address.h"
#include "util-memcasecmp.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

#define TABLE_SIZE 0x4000

struct BannerRecord
{
	struct BannerRecord *next;
	char *banner;
};
struct ProtoRecord
{
	struct ProtoRecord *next;
	struct BannerRecord *banners;
	const char *proto;
};

struct PortRecord
{
	struct PortRecord *next;
	struct ProtoRecord *protos;
	unsigned port;
};
struct HostRecord
{
	struct HostRecord *next;
	struct PortRecord *tcp_ports;
	struct PortRecord *udp_ports;
	unsigned ip;
	unsigned hops;
	unsigned timestamp;
};

struct filter
{
	unsigned ip;
	unsigned mask;
};

struct ReportNmap
{
	struct HostRecord table[TABLE_SIZE];
	unsigned host_count;

	struct filter include_filters[32];
	unsigned include_count;

	struct filter exclude_filters[32];
	unsigned exclude_count;
};



static struct ReportNmap *
nmap_create()
{
	struct ReportNmap *nmap;

	nmap = (struct ReportNmap *)malloc(sizeof(*nmap));
	memset(nmap, 0, sizeof(*nmap));
	
	return nmap;
}

void report_nmap_set_parameter(struct Ferret *ferret, const char *name, const char *value)
{
	if (ferret->report_nmap == 0)
		ferret->report_nmap = nmap_create();

	if (strcmp(name, "addr") == 0) {
		struct ParsedIpAddress addr;
		unsigned offset = 0;
		//unsigned is_exclude = 0;
		struct filter *filters;
		unsigned *filter_count;

		if (value[0] == '!') {
			//is_exclude = 1;
			filters = ferret->report_nmap->exclude_filters;
			filter_count = &ferret->report_nmap->exclude_count;
			value++;
		} else {
			filters = ferret->report_nmap->include_filters;
			filter_count = &ferret->report_nmap->include_count;
		}


		if (parse_ip_address(value, &offset, (unsigned)strlen(value), &addr)) {
			if (*filter_count > sizeof(ferret->report_nmap->include_filters)/sizeof(ferret->report_nmap->include_filters[0]))
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

static int
is_displayed(struct Ferret *ferret, unsigned ipv4)
{
	struct filter *filters;
	unsigned filter_count;
	int is_included = 0;
	int is_excluded = 0;
	unsigned i;



	/* Included */
	filters = ferret->report_nmap->include_filters;
	filter_count = ferret->report_nmap->include_count;
	for (i=0; i<filter_count; i++) {
		if ((ipv4 & filters[i].mask) == (filters[i].ip & filters[i].mask))
			is_included = 1;
	}
	if (filter_count == 0)
		is_included = 1;

	/* Excluded */
	filters = ferret->report_nmap->exclude_filters;
	filter_count = ferret->report_nmap->exclude_count;
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

/****************************************************************************
 ****************************************************************************/
static struct HostRecord *
hosts_lookup(struct Ferret *ferret, unsigned ipv4, unsigned hops)
{
	unsigned index;
	struct HostRecord *record;

	if (ferret->report_nmap == NULL)
		ferret->report_nmap = nmap_create();

	index = hash(ipv4+hops) & (TABLE_SIZE-1);

	record = &ferret->report_nmap->table[index];

	while (record) {
		if (record->ip == ipv4 && record->hops == hops)
			return record;
		if (record->ip == 0 && record->next == 0 && record->tcp_ports == 0 && record->udp_ports == 0) {
			ferret->report_nmap->host_count++;
			record->ip = ipv4;
			record->hops = hops;
			return record;
		}
		if (record->next == 0) {
			ferret->report_nmap->host_count++;
			record->next = (struct HostRecord *)malloc(sizeof(*record));
			record = record->next;
			memset(record, 0, sizeof(*record));
			record->ip = ipv4;
			record->hops = hops;
			return record;
		}

		record = record->next;
	}

	return 0;
}

/****************************************************************************
 ****************************************************************************/
static int
match(const char *sz, const unsigned char *name, unsigned name_length)
{
	if (memcasecmp(name, sz, name_length) == 0 && sz[name_length] == '\0')
		return 1;
	else
		return 0;
}

/****************************************************************************
 ****************************************************************************/
void
record_listening_port(struct Ferret *ferret, unsigned hops, unsigned ipver, unsigned in_host, const unsigned char *in_ipv6, unsigned in_transport, unsigned in_port, const char *in_proto, const unsigned char *in_banner, unsigned in_banner_length)
{
	struct HostRecord *host;
	struct PortRecord *port;
	struct ProtoRecord *proto;
	struct BannerRecord *banner;


	if (!ferret->cfg.report_nmap)
		return;

	if (5 < hops && hops <= 64)
		hops = 64-hops;
	else if (65 <= hops && hops <= 128)
		hops = 128 - hops;
	else if (129 <= hops && hops <= 255)
		hops = 255 - hops;

	/*
	 * Host
	 */
	host = hosts_lookup(ferret, in_host, hops);

	/*
	 * Port
	 */
	switch (in_transport) {
	case LISTENING_ON_TCP:
		port = host->tcp_ports;
		break;
	case LISTENING_ON_UDP:
		port = host->udp_ports;
		break;
	case LISTENING_ON_ETHERNET:
		return;
	default:
		return;
	}
	for (; port; port=port->next) {
		if (port->port == in_port)
			break;
	}
	if (!port) {
		port = (struct PortRecord *)malloc(sizeof(*port));
		memset(port, 0, sizeof(*port));
		port->port = in_port;
		switch (in_transport) {
		case LISTENING_ON_TCP:
			port->next = host->tcp_ports;
			host->tcp_ports = port;
			break;
		case LISTENING_ON_UDP:
			port->next = host->udp_ports;
			host->udp_ports = port;
			break;
		default:
			return;
		}
	}

	/*
	 * Protocol
	 */
	if (in_proto == NULL)
		return;
	for (proto=port->protos; proto; proto=proto->next) {
		if (strcmp(proto->proto, in_proto) == 0)
			break;
	}
	if (!proto) {
		proto = (struct ProtoRecord *)malloc(sizeof(*proto));
		memset(proto, 0, sizeof(*proto));
		proto->proto = in_proto;
		proto->next = port->protos;
		port->protos = proto;
	}

	/*
	 * Banner
	 */
	if (in_banner == 0)
		return;
	for (banner=proto->banners; banner; banner=banner->next) {
		if (match(banner->banner, in_banner, in_banner_length))
			break;
	}
	if (!banner) {
		banner = (struct BannerRecord *)malloc(sizeof(*banner));
		memset(banner, 0, sizeof(*banner));
		banner->banner = (char*)malloc(in_banner_length+1);
		memcpy(banner->banner, in_banner, in_banner_length+1);
		banner->banner[in_banner_length] = '\0';
		banner->next = proto->banners;
		proto->banners = banner;
	}
}


struct tmprecord {
	unsigned byte_count;
	struct HostRecord *record;
};

/****************************************************************************
 ****************************************************************************/
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


/****************************************************************************
 ****************************************************************************/
static void
report_nmap_transport(unsigned ip, unsigned hops, const char *transport, struct PortRecord **ports)
{
	struct PortRecord *x;
	char sz_address[16];

	snprintf(sz_address, sizeof(sz_address), "%u.%u.%u.%u", (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF);

	if (transport == 0) {
		printf("%3d %-16s %3s %5s %10s \"%s\"\n", hops, sz_address, "", "", "", "");
		return;
	}

	if (ports == 0 || *ports == 0)
		return;

	/* Sort the ports */

	for (x = *ports; x; x = x->next) {
		struct PortRecord **rec;
		for (rec=ports; (*rec)->next; rec = &(*rec)->next) {
			if ((*rec)->next->port < (*rec)->port) {
				struct PortRecord swap;
				
				swap.port = (*rec)->port;
				swap.protos = (*rec)->protos;
				(*rec)->port = (*rec)->next->port;
				(*rec)->protos = (*rec)->next->protos;
				(*rec)->next->port = swap.port;
				(*rec)->next->protos = swap.protos;
			}
		}
	}

	/*
	 * Print the results
	 */
	for (x = *ports; x; x = x->next) {
		struct ProtoRecord *protos;

		if (x->protos == NULL)
			printf("%3d %-16s %3s %5u %10s \"%s\"\n", hops, sz_address, transport, x->port, "", "");

		for (protos=x->protos; protos; protos=protos->next) {
			struct BannerRecord *banner;

			if (protos->banners == 0)
				printf("%3d %-16s %3s %5u %10s \"%s\"\n", hops, sz_address, transport, x->port, protos->proto, "");


			for (banner=protos->banners; banner; banner=banner->next) {
				/* 192.168.10.134   TCP   80   HTTP  "Apache/1.3.45" */
				printf("%3d %-16s %3s %5u %10s \"%s\"\n", hops, sz_address, transport, x->port, protos->proto, banner->banner);
			}
		}
	}

}

/****************************************************************************
 ****************************************************************************/
void
report_nmap(struct Ferret *ferret, unsigned report_count)
{
	struct tmprecord *list;
	unsigned i;
	unsigned host_count;
	unsigned n;

	if (ferret->report_nmap == NULL)
		return;
	report_count = 1000;
	host_count = ferret->report_nmap->host_count;

	list = (struct tmprecord *)malloc(host_count * sizeof(*list));

	/*
	 * Walk through the hash table grabbing all the records
	 */
	n = 0;
	for (i=0; i<TABLE_SIZE; i++) {
		struct HostRecord *rec = &ferret->report_nmap->table[i];
		
		while (rec) {
			assert(n <= host_count);
			if (rec->ip == 0)
				break;
			if (is_displayed(ferret, rec->ip)) {
				list[n].byte_count = rec->ip;
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
		unsigned hops = list[i].record->hops;

		report_nmap_transport(ip, hops, "TCP", &list[i].record->tcp_ports);
		report_nmap_transport(ip, hops, "UDP", &list[i].record->udp_ports);

		if (list[i].record->tcp_ports == 0 && list[i].record->udp_ports == 0) {
			/* only a host record, probably from an ARP response*/
			report_nmap_transport(ip, hops, 0, 0);
		}
	}

	return;
}
