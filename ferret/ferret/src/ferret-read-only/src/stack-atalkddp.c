/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	APPLETALK DATAGRAM DELIVERY PROTOCOL

  This is the network-layer for Apple's proprietary protocol suite.
  It's equivelent to the IP protocol in the TCP/IP protocol suite.
*/
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"

void parse_atalk_ddp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	struct {
		unsigned hop_count;
		unsigned datagram_length;
		unsigned checksum;
		unsigned protocol_type;
		unsigned address_src;
		unsigned address_dst;
		unsigned port_src;
		unsigned port_dst;
	} ddp;

	ferret->statistics.atalk++;

	if (length < 13) {
		FRAMERR(frame, "%s: truncated\n", "DDP");
		return;
	}



	ddp.hop_count = px[0]>>4;
	ddp.datagram_length = (px[0]&0xF)<<8 | px[1];
	ddp.checksum = ex16be(px+2);
	ddp.address_dst = ex16be(px+4)<<8;
	ddp.address_src = ex16be(px+6)<<8;
	ddp.address_dst |= px[8];
	ddp.address_src |= px[9];
	ddp.port_dst = px[10];
	ddp.port_src = px[11];
	ddp.protocol_type = px[12];

	if (length > ddp.datagram_length) {
		if (length-ddp.datagram_length == 4)
			ferret->statistics.remaining_4++; /*hints that an FCS trails*/
		length = ddp.datagram_length;
	}

	frame->ipver = ADDRESS_ATALK_EDDP;
	frame->src_ipv4 = ddp.address_src;
	frame->dst_ipv4 = ddp.address_dst;
	frame->src_port = ddp.port_src;
	frame->dst_port = ddp.port_dst;

	/* skip the header */
	offset += 13;

	/* If this is a broadcast packet, we can make the assumption
	 * that the sender is on the local subnet */
	JOTDOWN(ferret,
		JOT_MACADDR("ID-MAC", frame->src_mac),
		JOT_SRC("AppleTalk", frame),
		0);

	/* Parse the next layer */
	SAMPLE(ferret, "ATALK-DDP",JOT_NUM("protocol", ddp.protocol_type));
	SAMPLE(ferret, "ATALK-DDP",JOT_NUM("dst-port", ddp.port_dst));

	switch (ddp.protocol_type) {
	case 0x02: /* NBP - Name Binding Protocol */
		parse_atalk_nbp(ferret, frame, px+offset, length-offset);
		break;
	case 0x06: /* ZIP (Zone Information Protocol) */
		break;
	case 0x01: /* RTMP (Routing Table Maintenance Protocol), works like RIP */
	case 0x03: /* ATP (Appletalk Transfer Protocol) */
	case 0x04: /* Echo, works like ICMP Echo */
	case 0x05: /* RTMP requests */
	case 0x07: /* ADSP (Appletalk Data Stream Protocol) */
	case 0x08: /* SNMP, same as normal SNMP */
	case 0x16: /* IP over AppleTalk */
	default:
		FRAMERR(frame, "%s: unknown protocol=%d, srcport=%d, dstport=%d\n", "DDP", ddp.protocol_type,
			ddp.port_src, ddp.port_dst);
	}

}

