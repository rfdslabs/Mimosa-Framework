/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	INTERNET CONTROL MESSAGE PROTOCOL
*/
#include "stack-parser.h"
#include "ferret.h"
#include "stack-netframe.h"
#include "stack-extract.h"


void process_icmp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned type = px[0];
	unsigned code = px[1];
	unsigned checksum = ex16be(px+2);

	UNUSEDPARM(length);UNUSEDPARM(frame);UNUSEDPARM(checksum);

	ferret->statistics.icmp++;
	frame->layer4_protocol = LAYER4_ICMP;

	JOTDOWN(ferret, 
		JOT_SZ("TEST","icmp"),
		JOT_NUM("type",type),
		JOT_NUM("code",code),
		0);
}

void process_icmpv6(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned type = px[0];
	unsigned code = px[1];
	unsigned checksum = ex16be(px+2);

	UNUSEDPARM(length);UNUSEDPARM(frame);UNUSEDPARM(checksum);

	frame->layer4_protocol = LAYER4_ICMP;

	JOTDOWN(ferret, 
		JOT_SZ("TEST","icmp"),
		JOT_NUM("type",type),
		JOT_NUM("code",code),
		0);

	if (frame->dst_ipv6[0] == 0xFF)
	JOTDOWN(ferret, 
		JOT_MACADDR("ID-MAC", frame->src_mac),
		JOT_IPv6("ipv6", frame->src_ipv6, 16),
		0);
}


