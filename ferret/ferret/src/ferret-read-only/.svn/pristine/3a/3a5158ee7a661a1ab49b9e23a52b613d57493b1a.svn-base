/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	ETHERNET

  This decodes packets coming from an Ethernet network.

  While Ethernet is a simple header (dest, sourc, type), there is actually
  a lot of complexity with optional components.

  http://en.wikipedia.org/wiki/QinQ
  http://en.wikipedia.org/wiki/Ethernet_II_framing
*/
#include "stack-parser.h"
#include "stack-extract.h"
#include "stack-netframe.h"
#include "ferret.h"
#include <string.h>
#include <stdio.h>

typedef unsigned char MACADDR[6];

extern void parse_PVSTP(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void process_llc_frame(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length);
void dispatch_ethertype(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned oui, unsigned ethertype);


/****************************************************************************
 ****************************************************************************/
void
process_8021q_vlan(
	struct Ferret *ferret, 
	struct NetFrame *frame, 
	const unsigned char *px, unsigned length,
	unsigned oui)
{
	unsigned ethertype = 0;
	unsigned vlan_id = 0;

	if (length < 4)
		return;

	/*
	 * 802.1q is a 4 byte protocol consisting of a VLAN tag followed by
	 * an Etheretype field, after which the frame continues as if there
	 * were no vlan header */
q_in_q:
	vlan_id |= ex16be(px+0) & 0xFFF ; /* 12 bits*/
	ethertype = ex16be(px+2);

	if (ethertype <= 1536) {
		unsigned new_length = ethertype;

		px += 4;
		length -= 4;
		if (new_length > length) {
			FRAMERR_BADVAL(frame, "ethertype", ethertype);
			return;
		} else if (new_length < length)
			length = new_length;
		process_llc_frame(ferret, frame, px, length);
		return;
	} else if (	ethertype == 0x8100		/*802.1q, invalid */
				|| ethertype == 0x9100 /*802.1Q */
				|| ethertype == 0x88a8 /*802.1ad */) { 
		/* http://en.wikipedia.org/wiki/QinQ */
		/* nested 802.1q */
		px += 4;
		length -= 4;
		vlan_id <<= 12;
		goto q_in_q;
	} else {
		dispatch_ethertype(ferret, frame, px+4, length-4, oui, ethertype);
	}
}


/****************************************************************************
 * Called by the Ethernet header to call the next layer protocol,
 * such as IP for an EtherType of 0x800. This can be called in
 * many places, such as from the normal Ethernet frame, the 
 * LLC/SNAP header, or from 802.1q processing.
 ****************************************************************************/
void 
dispatch_ethertype(
	struct Ferret *ferret, 
	struct NetFrame *frame, 
	const unsigned char *px, 
	unsigned length, 
	unsigned oui, 
	unsigned ethertype)
{
	SAMPLE(ferret,"SAP", JOT_NUM("oui", oui));
	SAMPLE(ferret,"SAP", JOT_NUM("ethertype", ethertype));

	switch (ethertype) {
	case 0x0800: /* TCP/IP -- which is 99% of the time */
		process_ip(ferret, frame, px, length);
		break;
	case 0x0806:
		process_arp(ferret, frame, px, length);
		break;
	case 0x0842: /* Wake-on-LAN Magic packet */
		break;
	case 0x1083: /* Regress: defcon2008\dump070.pcap(2939) */
	case 0x2b5c: /* Regress: defcon2008\dump113.pcap(89673) */
	case 0x8f08: /* Regress: defcon2008\dump143.pcap(70839) */
	case 0x8c79: /* Regress: defcon2008\dump191.pcap(847) */
	case 0x08cf: /* Regress: defcon2008\dump191.pcap(847) */
	case 0x08a8: /* Regress: defcon2008\dump218.pcap(42163) */
	case 0xf3ba: /* Regress: defcon2008\dump271.pcap(5933) */
		break;
	case 0x8100: /* 802.1q VLAN */
		process_8021q_vlan(ferret, frame, px, length, oui);
		break;
	case 0x888e: /*802.11x authentication*/
		process_802_1x_auth(ferret, frame, px, length);
		break;
	case 0x88cc: /* Link Layer Discovery Protocol */
		frame->layer3_protocol = LAYER3_MGMT;
		break;
	case 0x86dd: /* IPv6*/
		process_ipv6(ferret, frame, px, length);
		break;
	case 0x872d: /* Cisco OWL */
		break;
	case 0x886d:
		frame->layer3_protocol = LAYER3_MGMT;
		break;
	case 0x9000: /* Loopback */
		break;
	case 0x80f3: /* AARP - Appletalk ARP */
		break;
	case 0x809b: /* Appletalk DDP */
		break;
	default:
		FRAMERR_BADVAL(frame, "ethertype", ethertype);
	}
}


/****************************************************************************
 ****************************************************************************/
void
process_spanningtree_frame(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	/* see parse_PVSTP */
	unsigned protocol_identifier;
	unsigned protocol_version;
	unsigned type;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "SpanningTree");
		return;
	}

	frame->layer3_protocol = LAYER3_STP;

	protocol_identifier = ex16be(px);
	protocol_version = px[2];
	type = px[3];
	
	if (protocol_identifier != 0) {
		FRAMERR(frame, "%s: unknown protocol: 0x%x\n", "SpanningTree", protocol_identifier);
	}
	if (protocol_version != 0) {
		FRAMERR(frame, "%s: unknown version: 0x%x\n", "SpanningTree", protocol_identifier);
	}

	switch (type){
	case 0:
	case 0x80:
		parse_PVSTP(ferret, frame, px, length);
		break;
	default:
		FRAMERR(frame, "%s: unknown type: 0x%x\n", "SpanningTree", type);
		return;
	}
}

/****************************************************************************
 ****************************************************************************/
void
process_snap_frame(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned oui;
	unsigned ethertype;

	if (length < 5) {
		FRAMERR_TRUNCATED(frame, "SNAP");
		return;
	}

	oui = ex24be(px);
	ethertype = ex16be(px+3);

	switch (oui){
	case 0x000000:
		/* fall through below */
		break;
	case 0x004096: /* Cisco Wireless */
		FRAMERR(frame, "Unknown SAP OUI: 0x%06x\n", oui);
		return;
		break;
	case 0x00000c:
		offset +=3; /* skip OUI, pass Ethertype into function */
		process_cisco00000c(ferret, frame, px+offset, length-offset);
		return;
	case 0x080007: /* AppleTalk -- should just process it like any other ethertype */
		break;
	default:
		FRAMERR(frame, "Unknown SAP OUI: 0x%06x\n", oui);
		return;
	}

	dispatch_ethertype(ferret, frame, px+offset, length-offset, oui, ethertype);
}

/****************************************************************************
 ****************************************************************************/
void
process_llc_frame(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned dsap;
	unsigned ssap;
	unsigned control;
	unsigned offset=0;

	if (length < 3) {
		//FRAMERR_TRUNCATED(frame, "LLC");
		return;
	}

	dsap = px[0];
	ssap = px[1];
	control = px[2];

	if (dsap == 0 && ssap == 0 && control == 0 && memcmp(frame->dst_mac, "\x01\x00\x5e", 3)==0) {
		/* Regress: defcon2008/dump000.pcap(6239) */
		; /* TODO: process_upnp_discovery */
		return;
	}	
	if (dsap == 0 && ssap == 0 && control == 0 && memcmp(frame->dst_mac, "\x33\x33\xff", 3)==0) {
		/* Regress: defcon2008/dump001.pcap(90968) */
		; /* TODO: process_upnp_discovery */
		return;
	}	
	if (dsap == 0 && ssap == 0 && control == 0 && memcmp(frame->dst_mac, "\x33\x33\x00", 3)==0) {
		/* Regress: defcon2008/dump001.pcap(90968) */
		; /* TODO: process_upnp_discovery */
		return;
	}	

	if ((control & 1) == 0) {
		/* This is an "information frame */
		offset += 4;
		if (offset < length) {
			switch (dsap<<8 | ssap) {
			case 0x0000:
				break;
			default:
				FRAMERR_UNPARSED(frame, "LLC:control", control);
				break;
			}
			return;
		}
		return;
	}

	if (control != 0x03) {
		FRAMERR_UNPARSED(frame, "LLC:control", control);
		return;
	}

	offset += 3;

	if (dsap == 0xAA || ssap == 0xAA)
		process_snap_frame(ferret, frame, px+offset, length-offset);
	else if ((dsap == 0xf0 || ssap == 0xf0) && (offset+4 < length) && ex16le(px+offset+2) == 0xefff) {
		frame->layer3_protocol = LAYER3_NETBEUI;
	} else if (dsap == 0x42 || ssap == 0x42)
		process_spanningtree_frame(ferret, frame, px+offset, length-offset);
	else {
		FRAMERR_UNPARSED(frame, "LLC:dsap:ssap", ((dsap<<8)|(ssap)));
		return;
	}
}

#if 0
		if (ethertype < 1536) {
			if (memcmp(px+offset, "\xaa\xaa\x03", 3) != 0) {
				JOTDOWN(ferret,
					JOT_SZ("proto","ethernet"),
					JOT_SZ("op","data.unknown"),
					JOT_PRINT("data", 	px+offset,				length-offset),
					0);
				return;
			}
			offset +=3 ;

			oui = ex24be(px+offset);

			/* Look for OUI code */
			switch (oui){
			case 0x000000:
				/* fall through below */
				break;
			case 0x004096: /* Cisco Wireless */
				return;
				break;
			case 0x00000c:
				offset +=3;
				if (offset < length)
				process_cisco00000c(ferret, frame, px+offset, length-offset);
				return;
			case 0x080007:
				break; /*apple*/
			default:
				FRAMERR(frame, "Unknown SAP OUI: 0x%06x\n", oui);
				return;
			}
			offset +=3;

			/* EtherType */
			if (offset+2 >= length) {
				FRAMERR(frame, "ethertype: packet too short\n");
				return;
			}

		}

		if (ethertype == length-offset && ex16be(px+offset) == 0xAAAA) {
			;
		}
		else
#endif

			

/****************************************************************************
 ****************************************************************************/
void
process_ethernet_frame(
	struct Ferret *ferret, 
	struct NetFrame *frame, 
	const unsigned char *px, 
	unsigned length)
{
	unsigned offset = 0;
	unsigned ethertype;
	
	/*
	 * The Ethernet header, as received from the network card,
	 * consists of the dest/source MAC addresses and a two
	 * byte field that is a 'length' field to be followed by
	 * LLC (and SNAP) if its value is less than 1536, or a 
	 * 'ethertype' field for values between 1536 and 65535,
	 * the most common being 0x0800 to indicate that the IP
	 * header follows next.
	 *
	 * +--------+--------+--------+--------+--------+--------+
	 * |               Destination MAC Address               |
	 * +--------+--------+--------+--------+--------+--------+
	 * |                  Source MAC Address                 |
	 * +--------+--------+--------+--------+--------+--------+
	 * | EtherType/length|
	 * +--------+--------+
	 */

	if (length <= 14) {
		; /*FRAMERR(frame, "wifi.data: too short\n");*/
		return;
	}

	frame->src_mac = px+6;
	frame->dst_mac = px+0;
	ethertype = ex16be(px+12);
	offset += 14;

	if (ethertype > 1536)
		dispatch_ethertype(ferret, frame, px+offset, length-offset, 0, ethertype);
	else {
		unsigned new_length = ethertype;

		/* Ethertypes less than 1536 are 802.3 length fields instead, and
		 * are followed by an LLC header */

		if (ethertype == 0x0000) {
			/* Regress: defcon2008/dump000.pcap(114689) */
			/* I don't know what this is */
			return;
		}

		px += offset;
		length -= offset;
		if (new_length > length) {
			FRAMERR_BADVAL(frame, "ethertype", ethertype);
			return;
		} else if (new_length < length)
			length = new_length;
		process_llc_frame(ferret, frame, px, length);
		return;
	}
}
