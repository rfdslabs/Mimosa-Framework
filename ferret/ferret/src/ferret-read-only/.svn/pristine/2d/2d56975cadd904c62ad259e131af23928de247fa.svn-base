#include "ferret.h"
#include "stack-netframe.h"
#include "filters.h"
#include "parse-address.h"

#include <ctype.h>
#include <string.h>


void flt_addr_set_parameter(struct SniffFilter *flt, const char *name, const char *value)
{
	struct FilterItem item;
	unsigned exclude = 0;
	struct ParsedIpAddress addr;
	unsigned offset = 0;
	int x;
	unsigned value_length = (unsigned)strlen(value);

	/*
	 * Look for the exclusion operator
	 */
	if (*value == '!') {
		exclude = 1;
		offset++;
	}


	/*
	 * Parse the IP address
	 */
	x = parse_ip_address(value, &offset, value_length, &addr);
	if (x == 0) {
		fprintf(stderr, "cfg: bad IP address: %s\n", value);
		return;
	}

	/*
	 * Look for port specifier
	 */
	while (offset < value_length && ispunct(value[offset]&0xFF))
		offset++;
	if (offset < value_length && isdigit(value[offset]&0xFF)) {
		unsigned port_start=0, port_end=0;

		while (offset<value_length && isdigit(value[offset]&0xFF)) {
			port_start = port_start*10 + (value[offset]-'0');
			offset++;
		}

		if (offset >= value_length)
			port_end = port_start;
		else if (ispunct(value[offset]&0xFF)) {
			while (offset<value_length && ispunct(value[offset]&0xFF)) {
				offset++;
			}

			if (offset >= value_length) {
				port_end = 0xFFFF;
			} else {
				while (offset<value_length && isdigit(value[offset]&0xFF)) {
					port_end = port_start*10 + (value[offset]-'0');
					offset++;
				}
			}
		}

		if (port_start > 0xFFFF || port_end > 0xFFFF) {
			fprintf(stderr, "cfg: bad port number: %s\n", value);
		}
		
		item.u.addr.port_first = port_start;
		item.u.addr.port_last = port_end;
	} else {
		item.u.addr.port_first = 0;
		item.u.addr.port_last = 0xFFFF;
	}



	item.type = FLT_TYPE_ADDR;
	item.include = !exclude;
	item.exclude = exclude;
	item.u.addr.ver = addr.version;
	item.u.addr.ipv4 =	  addr.address[0] << 24 
						| addr.address[1] << 16 
						| addr.address[2] <<  8 
						| addr.address[3] <<  0;
	memcpy(item.u.addr.ipv6, addr.address, 16);

	flt_add_item(flt, &item);
}


void
flt_addr_eval_src(const struct SniffFilter *flt, const struct FilterItem *item, const struct NetFrame *frame, unsigned *include, unsigned *exclude)
{
	if (item->u.addr.ver == 4) {
		if (frame->ipver != 0 && frame->ipver != 4)
			return;
		if (frame->src_ipv4 != item->u.addr.ipv4)
			return;

	} else if (item->u.addr.ver == 6) {
		if (frame->ipver != 1 && frame->ipver != 6)
			return;
		if (memcmp(frame->src_ipv6, item->u.addr.ipv6, 16) != 0)
			return;
	}

	if (frame->src_port < item->u.addr.port_first)
		return;
	if (frame->src_port > item->u.addr.port_last)
		return;

	if (item->exclude)
		*exclude = 1;
	if (item->include)
		*include = 1;
}

void
flt_addr_eval_dst(const struct SniffFilter *flt, const struct FilterItem *item, const struct NetFrame *frame, unsigned *include, unsigned *exclude)
{
	if (item->u.addr.ver == 4) {
		if (frame->ipver != 0 && frame->ipver != 4)
			return;
		if (frame->dst_ipv4 != item->u.addr.ipv4)
			return;

	} else if (item->u.addr.ver == 6) {
		if (frame->ipver != 1 && frame->ipver != 6)
			return;
		if (memcmp(frame->dst_ipv6, item->u.addr.ipv6, 16) != 0)
			return;
	}

	if (frame->dst_port < item->u.addr.port_first)
		return;
	if (frame->dst_port > item->u.addr.port_last)
		return;

	if (item->exclude)
		*exclude = 1;
	if (item->include)
		*include = 1;
}

void
flt_addr_eval(const struct SniffFilter *flt, const struct FilterItem *item, const struct NetFrame *frame, unsigned *include, unsigned *exclude)
{
	flt_addr_eval_src(flt, item, frame, include, exclude);
	flt_addr_eval_dst(flt, item, frame, include, exclude);
}

