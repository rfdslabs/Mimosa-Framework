/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"

#include <ctype.h>
#include <string.h>

/**
 * Copy and format a NetBIOS name. A NetBIOS name potentially contains binary
 * characters, especially the last character at the end. It may also contain
 * spaces that we would like to remove.
 */
static unsigned 
netbios_copy_name_raw(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, char *name, unsigned sizeof_name)
{
	unsigned j=0;
	unsigned k=0;

	name[0] = '\0';

	for (j=0; j<16 && offset<length; j++) {
		char c = px[offset++];

		while (j == 15 && (k>0 && name[k-1] == ' '))
			k--;

		name[k] = c;
		name[k+1] = '\0';

		if (!isprint(name[k]) || j == 15) {
			if (k+3 > sizeof_name-1) {
				FRAMERR(frame, "netbios: name too long\n");
				break;
			}
			name[k+1] = "0123456789ABCDEF"[(name[k]>>4)&0xF];
			name[k+2] = "0123456789ABCDEF"[(name[k]>>0)&0xF];
			name[k+3] = '>';
			name[k+4] = '\0';
			name[k] = '<';
			k += 4;
		} else
			k++;
	}
	return offset;
}

void parse_novell_netbios_name(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	//unsigned name_flag;
	unsigned opcode;
	unsigned offset=0;
	char name[128];

	offset += 16*2; /*skip src/dst names */

	if (offset+2 >= length) {
		FRAMERR(frame, "%s: truncated\n", "IPXNB");
		return;
	}

	/* Parse the header */
	//name_flag = px[offset+0];
	opcode = px[offset+1];
	offset += 2;

	/* Parse the different packet types */
	switch (opcode) {
	case 1: /* lookup */
		if (length > offset + 16)
			length = offset + 16;
		netbios_copy_name_raw(frame, px, length, offset, name, sizeof(name));
		JOTDOWN(ferret,
			JOT_SRC("ID-IP", frame),
			JOT_SZ("NetBIOS-lookup", name),
			0);
		break;
	default:
		FRAMERR(frame, "%s: unknown type: 0x%x\n", "IPXNB", opcode);
	}
}

void parse_novell_netbios_dgram(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	//unsigned name_flag;
	unsigned opcode;
	unsigned offset=0;

	offset += 16*2; /*skip src/dst names */

	if (offset+2 >= length) {
		FRAMERR(frame, "%s: truncated\n", "IPXNB");
		return;
	}

	/* Parse the header */
	opcode = px[offset+0];
	//name_flag = px[offset+1];

	/* Parse the different packet types */
	switch (opcode) {
	case 0xfc: /* Mailslot write */
		offset += 4;
		offset += 32;
		if (offset+4 < length && memcmp(px+offset, "\xFF" "SMB", 4) == 0)
			process_smb_dgm(ferret, frame, px+offset, length-offset);
		break;
	default:
		FRAMERR(frame, "%s: unknown type: 0x%x\n", "IPXNB", opcode);
	}
}


void parse_novell_ipx(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	struct {
		unsigned checksum;
		unsigned length;
		unsigned hops;
		unsigned packet_type;
		unsigned char src_ipx[16];
		unsigned char dst_ipx[16];
		unsigned src_port;
		unsigned dst_port;
	} ipx;

	ferret->statistics.ipx++;

	if (length == 0) {
		FRAMERR(frame, "%s: frame empty\n", "IPX");
		return;
	}
	if (length < 30) {
		FRAMERR(frame, "%s: truncated\n", "IPX");
		return;
	}

	ipx.checksum = ex16be(px+0);
	ipx.length = ex16be(px+2);
	ipx.hops = px[4];
	ipx.packet_type = px[5];
	memcpy(frame->dst_ipv6, px+6, 10);
	ipx.dst_port = ex16be(px+16);
	memcpy(frame->src_ipv6, px+18, 10);
	ipx.src_port = ex16be(px+28);

	frame->ipver = ADDRESS_IPX;

	offset += 30;

	SAMPLE(ferret,"IPX", JOT_NUM("type", ipx.packet_type));
	SAMPLE(ferret,"IPX", JOT_NUM("srcport", ipx.src_port));
	SAMPLE(ferret,"IPX", JOT_NUM("dstport", ipx.dst_port));


	if (offset >= length)
		return;

	switch (ipx.packet_type) {
	case 0x01: /* RIP broadcast */
		switch (ipx.dst_port) {
		case 0x0453: /* Novel RIP (Routing Information Protocol) */
			break;
		default:
			FRAMERR(frame, "%s: unknown port: 0x%x\n", "IPX", ipx.dst_port);
		}
		break;
		break;
	case 0x14: /* NetBIOS Broadcast */
		switch (ipx.dst_port) {
		case 0x0455:
			parse_novell_netbios_name(ferret, frame, px+offset, length-offset);
			break;
		case 0x0553:
			parse_novell_netbios_dgram(ferret, frame, px+offset, length-offset);
			break;
		default:
			FRAMERR(frame, "%s: unknown port: 0x%x\n", "IPX", ipx.dst_port);
		}
		break;
	default:
		FRAMERR(frame, "%s: unknown type: 0x%x\n", "IPX", ipx.packet_type);
		break;
	}
}

