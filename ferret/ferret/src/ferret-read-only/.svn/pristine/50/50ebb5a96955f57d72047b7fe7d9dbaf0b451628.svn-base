/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"
#include "stack-tcpfrag.h"

#include <string.h>

void
ipv6_fragment_free_all(struct Ferret *ferret)
{
	unsigned i;

	for (i=0; i<sizeof(ferret->ipv6frags)/sizeof(ferret->ipv6frags[0]); i++) {
		struct IPv6frag **r_entry = &(ferret->ipv6frags[i]);

		while (*r_entry) {
			struct IPv6frag *entry = *r_entry;
			(*r_entry) = (*r_entry)->next;

			tcpfrag_delete_all(&(entry->segments));
			free(entry);
		}

	}

}

/**
 * This adds an IPv6 fragment to the systemm. It takes as argument
 * the beginning of the IPv6 fragmentation header, although it 
 * will only actually save off the data portion of that header.
 */
void
parse_ipv6_fragment(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset)
{
	unsigned hash=0;
	unsigned i;
	struct IPv6frag *entry;
	unsigned frag_id;
	unsigned frag_offset;
	unsigned frag_is_last;
	unsigned frag_length;
	unsigned whole_length;

	/* WARNING: 'px' must point to the start of the IPv6 header, and 'offset' must
	 * point to the start of the fragmentation header */

	/* Verify space for header */
	if (offset + 8 > length) {
		FRAMERR(frame, "%s: truncated\n", "IPv6");
		return;
	}
	frag_id = ex32be(px+offset+4);
	frag_offset = ex16be(px+offset+2) & 0xFFFE;
	frag_is_last = !(px[offset+3] & 0x01);
	frag_length = length-offset-8;

	/* First of all, hash all the elements together */
	for (i=8; i<40; i++) {
		hash = (hash + px[i]) ^ (px[i]<<8);
	}
	hash ^= (px[offset+4]<<24);
	hash ^= (px[offset+5]<<16);
	hash ^= (px[offset+6]<< 8);
	hash ^= (px[offset+7]<< 0);

	/* Shorten the hash to just 1 byte. Eventually, we'll want to expand
	 * the table to a larger value, but for now, we have small table
	 * sizes for this */
	hash ^= ((hash>>24)&0xFF);
	hash ^= ((hash>>16)&0xFF);
	hash ^= ((hash>> 8)&0xFF);
	hash &= 0xFF;

	/* Find an existing entry, or create a new entry if needed */
	{
		struct IPv6frag **r_entry = &(ferret->ipv6frags[hash&0xFF]);

		while (*r_entry != NULL) {
			/* Compare addresses */
			if (memcmp(px+8, (*r_entry)->ipv6_hdr + 8, 32) != 0)
				continue;

			/* Compare ID */
			if ((*r_entry)->id != frag_id)
				continue;

			break;
		}

		if (*r_entry == NULL) {
			*r_entry = malloc(sizeof(**r_entry));
			memset(*r_entry, 0, sizeof(**r_entry));
			entry = *r_entry;
			memcpy(entry->ipv6_hdr, px, 40);
			entry->id = frag_id;
			entry->next_hdr = px[offset+0];
		}

		entry = *r_entry;
	}

	/* If a fragment arrives after we've finished processing
	 * the fragments, then ignore the incoming fragment. */
	if (entry->is_done)
		return;

	/* Add this fragment to the entry */
	tcpfrag_add(&entry->segments, px+offset+8, length-8-offset, frag_offset);
	if (frag_is_last)
		entry->last_offset = frag_offset + frag_length;

	if (entry->last_offset == 0)
		return;
	whole_length = tcpfrag_max_contiguous(entry->segments, 0);
	if (whole_length < entry->last_offset)
		return;

	/* Process this fragment */
	{
		const struct TCP_segment *frag;
		unsigned char *new_packet = malloc(entry->last_offset+40);
		memcpy(new_packet, entry->ipv6_hdr, 40);
		new_packet[6] = (unsigned char)entry->next_hdr;
		new_packet[4] = (unsigned char)((entry->last_offset>>8)&0xFF);
		new_packet[5] = (unsigned char)((entry->last_offset>>0)&0xFF);
		for (frag=entry->segments; frag && frag->seqno < entry->last_offset; frag = frag->next) {
			unsigned len;
			
			if (frag->seqno+frag->length >= entry->last_offset)
				len = entry->last_offset-frag->seqno;
			else
				len = frag->length;
				
			memcpy(new_packet+40+frag->seqno, frag->px, len);
		}
		

		/* Process the packet */
		process_ipv6(ferret, frame, new_packet, entry->last_offset+40);

		/* TODO: malloc/free for this packet is really lame, I should reserve a buffer for it */
		free(new_packet);
	}

}

void process_ipv6(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	struct {
		unsigned version;
		unsigned traffic_class;
		unsigned flow_label;
		unsigned payload_length;
		unsigned next_header;
		unsigned hop_limit;
		unsigned char src_ipv6[16];
		unsigned char dst_ipv6[16];
	} ip;

	ferret->statistics.ipv6++;
	frame->layer3_protocol = LAYER3_IPV6;

	if (length == 0) {
		FRAMERR(frame, "ip: frame empty\n");
		return;
	}
	if (length < 40) {
		FRAMERR(frame, "ip: truncated\n");
		return;
	}

	ip.version = px[0]>>4;
	ip.traffic_class = ((px[0]&0xF)<<4) | ((px[1]&0xF0)>>4);
	ip.flow_label = ((px[1]&0xF)<<16) | ex16be(px+2);
	ip.payload_length = ex16be(px+4);
	ip.next_header = px[6];
	ip.hop_limit = px[7];
	memcpy(frame->src_ipv6, px+8, 16);
	memcpy(frame->dst_ipv6, px+24, 16);
	frame->ipver = 6;

	if (ip.version != 6) {
		FRAMERR(frame, "ip: version=%d, expected version=6\n", ip.version);
		return;
	}
	offset += 40;

	SAMPLE(ferret,"IPv6", JOT_NUM("next-header", ip.next_header));

again:
	if (offset > length) {
		FRAMERR(frame, "ipv6: truncated\n");
		return;
	}
	switch (ip.next_header) {
	case 0: /* IPv6 options field */
	case 43: /* routing header */
	case 60: /* destination options */
		if (offset + 8 > length) {
			FRAMERR(frame, "ipv6: truncated\n");
			return;
		}
		ip.next_header = px[offset];
		offset += px[offset+1] + 8;
		goto again;
		break;
		break;
	case 44: /* fragment header */
		//TODO: parse_ipv6_fragment(ferret, frame, px, length, offset);
		return;
	case 59: /* no next header */
		return;
	case 58: /* ICMPv6 */
		process_icmpv6(ferret, frame, px+offset, length-offset);
		break;
	case 17:
		process_udp(ferret, frame, px+offset, length-offset);
		break;
	default:
		FRAMERR(frame, "ipv6: unknown next header=%d\n", ip.next_header);
	}

}

