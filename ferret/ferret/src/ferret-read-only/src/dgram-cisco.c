/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	CISCO miscellaneous

  Cisco has a number of link-local protocols that will tell us
  about the structure of the local network. Using these protocols,
  we can build a map of the local bridged network.

*/
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"
#include <ctype.h>


#include <string.h>

/*
 * Cisco Discovery Protocol 
 */
static void 
parse_CDP(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned version;
	//unsigned ttl;
	//unsigned checksum;

	if (offset+4 > length) {
		FRAMERR(frame, "%s: truncated\n", "cisco");
		return;
	}

	frame->layer3_protocol = LAYER3_MGMT;

	version = px[offset++];
	//ttl = px[offset++];
	//checksum = ex16be(px+2);
	offset += 2;

	SAMPLE(ferret,"Cisco Discovery Protocol", 
		JOT_NUM("version",version));

	while (offset < length) {
		unsigned tag;
		unsigned len;
		unsigned i;

		if (offset+4 > length) {
			FRAMERR(frame, "%s: truncated\n", "cisco");
			return;
		}

		tag = ex16be(px+offset);
		len = ex16be(px+offset+2);
		offset += 4;

		if (len < 4) {
			FRAMERR(frame, "%s: bad value: 0x%x\n", "cdp", tag);
			return;
		} else
			len -= 4;

		if (len > length-offset)
			len = length-offset;
		
		SAMPLE(ferret,"Cisco Discovery Protocol", JOT_NUM("tag",  tag));

		switch (tag) {
		case 0x0000:
			return;
		case 0x0001: /* Device ID */
			JOTDOWN(ferret, 
				JOT_MACADDR("ID-MAC", frame->src_mac),
				JOT_PRINT("Cisco Device ID", px+offset,len),
				0);
			break;
		case 0x0002: /* Addresses */
			if (len < 4) {
				FRAMERR(frame, "%s: truncated\n", "cdp");
				break;
			}
			i=0;
			{
				unsigned address_count = ex32be(px+offset);

				i += 4;

				while (address_count && i<len) {
					unsigned protocol_type;
					unsigned protocol_length;
					unsigned protocol = 0;
					unsigned address_length;
					if (i-len < 5)
						break;
					address_count--;

					protocol_type = px[offset+i++];
					protocol_length = px[offset+i++];
					if (protocol_length != 1)
						FRAMERR(frame, "%s: unknown value: 0x%x\n", "cdp", protocol_length);
					while (protocol_length && i<len) {
						protocol <<= 8;
						protocol |= px[offset+i++];
						protocol_length--;
					}
					address_length = ex16be(px+offset+i);
					i+= 2;
					switch (protocol_type) {
					case 1:
						switch (protocol) {
						case 0xCC: /*IPv4 address */
							if (address_length != 4)
								FRAMERR(frame, "%s: unknown value: 0x%x\n", "cdp", address_length);
							else if (len-i < 4)
								FRAMERR(frame, "%s: truncated\n", "cdp");
							else {
								unsigned ip = ex32be(px+offset+i);
								JOTDOWN(ferret, 
									JOT_MACADDR("ID-MAC", frame->src_mac),
									JOT_IPv4("ip", ip),
									0);
								JOTDOWN(ferret, 
									JOT_IPv4("ID-IP", ip),
									JOT_MACADDR("mac", frame->src_mac),
									0);
							}
							break;
						default:
							SAMPLE(ferret,"CDP", JOT_NUM("ip-protocol-type",  protocol));
							FRAMERR(frame, "%s: unknown value: 0x%x\n", "cdp", protocol);
						}
						break;
					default:
						SAMPLE(ferret,"CDP", JOT_NUM("address-protocol-type",  protocol_type));
						FRAMERR(frame, "%s: unknown value: 0x%x\n", "cdp", protocol_type);
						break;
					}
				}
			}


			break;
		case 0x0003: /* Port ID*/
			JOTDOWN(ferret, 
				JOT_MACADDR("ID-MAC", frame->src_mac),
				JOT_PRINT("Cisco Port ID", px+offset,len),
				0);
			break;
		case 0x0004:
			{
				unsigned n = 0;

				for (i=0; i<len; i++) {
					n <<= 8;
					n |= px[offset + i];
				}
				if (n & 0x00000001)
					JOTDOWN(ferret, JOT_MACADDR("ID-MAC", frame->src_mac), JOT_SZ("Capabilities", "router"), 0);
				if (n & 0x00000002)
					JOTDOWN(ferret, JOT_MACADDR("ID-MAC", frame->src_mac), JOT_SZ("Capabilities", "bridge"), 0);
				if (n & 0x00000004)
					JOTDOWN(ferret, JOT_MACADDR("ID-MAC", frame->src_mac), JOT_SZ("Capabilities", "source route bridge"), 0);
				if (n & 0x00000008)
					JOTDOWN(ferret, JOT_MACADDR("ID-MAC", frame->src_mac), JOT_SZ("Capabilities", "switch"), 0);
				if (n & 0x00000010)
					JOTDOWN(ferret, JOT_MACADDR("ID-MAC", frame->src_mac), JOT_SZ("Capabilities", "host"), 0);
				if (n & 0x00000020)
					JOTDOWN(ferret, JOT_MACADDR("ID-MAC", frame->src_mac), JOT_SZ("Capabilities", "IGMP"), 0);
				if (n & 0x00000040)
					JOTDOWN(ferret, JOT_MACADDR("ID-MAC", frame->src_mac), JOT_SZ("Capabilities", "repeater"), 0);
			}
			break;
		case 0x0005: /* IOS Version */
			for (i=0; i<len; i++)
				if (!isspace(px[offset+i]))
					break;
			JOTDOWN(ferret, 
				JOT_MACADDR("ID-MAC", frame->src_mac),
				JOT_PRINT("IOS Version", px+offset+i,len-i),
				0);
			break;
		case 0x0006: /* Platform*/
			JOTDOWN(ferret, 
				JOT_MACADDR("ID-MAC", frame->src_mac),
				JOT_PRINT("Cisco Platform", px+offset,len),
				0);
			break;
		case 0x0008: /* Hello: cluster mgmt */
			break;
		case 0x0009: /* VTP mgmnt domain */
			JOTDOWN(ferret, 
				JOT_MACADDR("ID-MAC", frame->src_mac),
				JOT_PRINT("VTP Mgmt Domain", px+offset,len),
				0);
			break;
		case 0x000a: /* Native VLAN */
			break;
		case 0x000b: /* Duplex */
			break;
		case 0x0012: /* Trust Bitmap */
			break;
		case 0x0013: /* Untrusted Port CoS */
			break;
		case 0x0016: /* Management Addresses */
			/* TODO: decode the management addresses */
			break;
		default:
			FRAMERR(frame, "%s: unknown value: 0x%x\n", "cdp", tag);
		}

		offset += len;
		
	}
}



void parse_PVSTP(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned port_id;

	if (length < 4) {
		FRAMERR(frame, "truncated\n");
		return;
	}

	/* Protocol Identifier */
	if (ex16be(px+0) != 0) {
		FRAMERR(frame, "unexpected\n");
		return;
	}

	frame->layer3_protocol = LAYER3_STP;

	/* Protocol Version Identifier */
	if (px[2] != 0) {
		FRAMERR(frame, "unexpected\n");
		return;
	}

	/* BPDU type */
	switch (px[3]) {
	case 0:
		if (length < 28) {
			FRAMERR(frame, "truncated\n");
			return;
		}
		JOTDOWN(ferret, 
			JOT_MACADDR("ID-MAC", frame->src_mac),
			JOT_SZ("Type", "bridge"),
			JOT_MACADDR("root", px+7),
			0);
		JOTDOWN(ferret, 
			JOT_MACADDR("ID-MAC", frame->src_mac),
			JOT_SZ("Type", "bridge"),
			JOT_MACADDR("ID", px+19),
			0);
		port_id = ex16be(px+25);
		JOTDOWN(ferret, 
			JOT_MACADDR("ID-MAC", frame->src_mac),
			JOT_SZ("Type", "bridge"),
			JOT_NUM("port-id", port_id),
			0);
		break;
	case 0x80:
		JOTDOWN(ferret, 
			JOT_MACADDR("ID-MAC", frame->src_mac),
			JOT_SZ("Type", "bridge"),
			0);
		break;
	default:
		FRAMERR(frame, "unexpected\n");
		return;
	}



}

void parse_dynamic_trunking_protocol(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;

	if (length < 1) {
		FRAMERR(frame, "truncated\n");
		return;
	}

	/* Version */
	if (px[0] != 0x01) {
		FRAMERR(frame, "unexpected\n");
		return;
	}

	/* Look for TLV values */
	for (offset=1; offset+4<length; ) {
		unsigned tag = ex16be(px+offset+0);
		unsigned length = ex16be(px+offset+2);

		if (tag == 0 && length == 0)
			break;

		if (length < 4) {
			FRAMERR(frame, "unexpected\n");
			return;
		}

		length -= 4;
		offset += 4;

		switch (tag) {
		case 0x0001: /* domain */
			JOTDOWN(ferret, 
				JOT_MACADDR("ID-MAC", frame->src_mac),
				JOT_PRINT("DTP-Domain", px+offset, length),
				0);
			break;
		case 0x0002: /* status */
			break;
		case 0x0003: /* Dtptype */
			break;
		case 0x0004: /* neighbor */
			/* TODO: is this interesting? */
			break;
		default:
			FRAMERR(frame, "unknown 0x%x\n", tag);
		}

		offset += length;
	}


}

/**
 * Cisco VLAN Trunking Protocol.
 */
void process_cisco_vtp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct vtp_summary {
     unsigned char  version;         
     unsigned char  code;            
     unsigned char  followers;       
     unsigned char  domain_length;
     unsigned char  domain[32]; 
     unsigned revision;                    
     unsigned updater;                     
     unsigned char  timestamp[12];    
     unsigned char  md5[16];
	} vtp;
	unsigned offset=0;
	const unsigned char *domain_name;
	
	if (offset+4 > length) {
		FRAMERR(frame, "%s: truncated\n", "VTP");
		return;
	}

	vtp.version = px[offset++];
	SAMPLE(ferret,"Cisco", JOT_NUM("VTP version",  vtp.version));
	if (vtp.version != 1) {
		FRAMERR(frame, "%s: unknown version %d\n", "VTP", vtp.version);
		return;
	}

	vtp.code = px[offset++];
	SAMPLE(ferret,"Cisco", JOT_NUM("VTP code",  vtp.code));
	vtp.followers = px[offset++];
	SAMPLE(ferret,"Cisco", JOT_NUM("VTP followers",  vtp.followers));
	vtp.domain_length = px[offset++];
	if (offset + vtp.domain_length > length) {
		FRAMERR(frame, "%s: truncated\n", "VTP");
		return;
	}
	domain_name = px+offset;
	offset += 32;
	
	if (offset + 8 > length) {
		FRAMERR(frame, "%s: truncated\n", "VTP");
		return;
	}
	vtp.revision = ex32be(px+offset);
	offset += 4;

	vtp.updater = ex32be(px+offset);
	offset += 4;

	JOTDOWN(ferret, 
		JOT_MACADDR("ID-MAC", frame->src_mac),
		JOT_PRINT("Cisco VTP Domain", domain_name, vtp.domain_length),
		JOT_NUM("Revision", vtp.revision),
		JOT_IPv4("Updater", vtp.updater),
		0);



}



void process_cisco00000c(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned pid;

	if (offset+2 > length) {
		FRAMERR(frame, "%s: truncated\n", "cisco");
		return;
	}

	pid = ex16be(px);
	SAMPLE(ferret,"Cisco", JOT_NUM("0x00000c-pid",  pid));
	offset+= 2;

	switch (pid) {
	case 0x2000:
		parse_CDP(ferret, frame, px+offset, length-offset);
		break;
	case 0x010b:
		parse_PVSTP(ferret, frame, px+offset, length-offset);
		break;
	case 0x2003: /* Cisco VLAN Trunking Protocol */
		process_cisco_vtp(ferret, frame, px+offset, length-offset);
		break;
	case 0x2004: /* Cisco Dynamic Trunking Protocol */
		parse_dynamic_trunking_protocol(ferret, frame, px+offset, length-offset);
		break;
	default:
		FRAMERR(frame, "%s: unknown value: 0x%x\n", "cisco", pid);
	}
}

