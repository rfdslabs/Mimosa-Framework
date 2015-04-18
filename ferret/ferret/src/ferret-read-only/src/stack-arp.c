/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	ADDRESS RESOLUTION PROTOCOL

  This protocol is used to discover the local hardware address for machines
  given their IP address.

  Our goal is to report the mapping of IP address to MAC address. Some of the
  bits of data we discover will be tied to a MAC address only (such as wifi
  probes), others will be tied to an IP address.

  TODO: Eventually we'll keep a table of mappings so that we can detect when
  the mappings change, such as when one person logs off and another person
  logs on, and is given the IP address of the previous person. We need to
  create a "break" at this point, so that we don't accidentally associate 
  different people with the same IP address
*/
#include "platform.h"
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"
#include "util-manuf.h"
#include "util-memcasecmp.h"
#include "report.h"
#include <string.h>



void
rfc4536_check(struct Ferret *ferret, struct NetFrame *frame, 
	unsigned opcode, 
	const unsigned char *mac_src, unsigned ip_src, 
	const unsigned char *mac_dst, unsigned ip_dst)\
{
	
	UNUSEDPARM(mac_dst);

	//oui = ex24be(frame->dst_mac);

	if (opcode != 1)
		return;

	if (frame->layer2_protocol != 127)
		return;

	if (memcmp(mac_src, frame->src_mac, 6) != 0)
		return;

	/* Ignore broadcast ARPs. We are looking only for DIRECTED
	 * ARPs
	 */
	if (memcmp(frame->dst_mac, "\xFF\xFF\xFF\xFF\xFF\xFF", 6) == 0)
		return;

	JOTDOWN(ferret,
		JOT_MACADDR("ID-MAC", mac_src),
		JOT_IPv4("ID-IP", ip_src),
		JOT_MACADDR("rfc4536router-mac", frame->dst_mac),
		JOT_IPv4("rfc4536router-ip", ip_dst),
		0);

	{
		const char *name;

		name = manuf2_from_mac(mac_src);
		if (name && name[0]) {
			/*JOTDOWN(ferret,
				JOT_SZ("rfc4536-oui", name),
				0);*/
			if (memcasecmp(name, "Apple", 5) != 0) {
				JOTDOWN(ferret,
					JOT_SZ("rfc4536-oui", name),
					JOT_MACADDR("ID-MAC", mac_src),
					JOT_IPv4("ID-IP", ip_src),
					JOT_MACADDR("rfc4536router-mac", frame->dst_mac),
					JOT_IPv4("rfc4536router-ip", ip_dst),
					0);
			}
		} else 
			if (memcasecmp(name, "Apple", 5) != 0) {
				JOTDOWN(ferret,
					JOT_HEXSTR("rfc4536-oui", mac_src, 3),
					JOT_MACADDR("ID-MAC", mac_src),
					JOT_SZ("rfc4536-oui", name),
					JOT_IPv4("ID-IP", ip_src),
					JOT_MACADDR("rfc4536router-mac", frame->dst_mac),
					JOT_IPv4("rfc4536router-ip", ip_dst),
					0);
			}
	}
}


/*
    Ethernet transmission layer (not necessarily accessible to
	 the user):
	48.bit: Ethernet address of destination
	48.bit: Ethernet address of sender
	16.bit: Protocol type = ether_type$ADDRESS_RESOLUTION
    Ethernet packet data:
	16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
			 Packet Radio Net.)
	16.bit: (ar$pro) Protocol address space.  For Ethernet
			 hardware, this is from the set of type
			 fields ether_typ$<protocol>.
	 8.bit: (ar$hln) byte length of each hardware address
	 8.bit: (ar$pln) byte length of each protocol address
	16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
	nbytes: (ar$sha) Hardware address of sender of this
			 packet, n from the ar$hln field.
	mbytes: (ar$spa) Protocol address of sender of this
			 packet, m from the ar$pln field.
	nbytes: (ar$tha) Hardware address of target of this
			 packet (if known).
	mbytes: (ar$tpa) Protocol address of target.
	*/

void process_arp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned layer2_address_type;
	unsigned layer2_address_length;
	unsigned layer3_address_type;
	unsigned layer3_address_length;
	unsigned opcode;
	unsigned ip_src;
	unsigned ip_dst;
	const unsigned char *mac_src;
	const unsigned char *mac_dst;

	ferret->statistics.arp++;
	frame->layer3_protocol = LAYER3_ARP;

	if (length < 8) {
		FRAMERR(frame, "%s: truncated\n", "ARP");
		return;
	}

	layer2_address_type = ex16be(px+0);
	layer3_address_type = ex16be(px+2);
	layer2_address_length = px[4];
	layer3_address_length = px[5];
	opcode = ex16be(px+6);


	SAMPLE(ferret,"ARP", JOT_NUM("layer2-type",layer2_address_type));
	SAMPLE(ferret,"ARP", JOT_NUM("layer3-type",layer3_address_type));
	SAMPLE(ferret,"ARP", JOT_NUM("layer2-length",layer2_address_length));
	SAMPLE(ferret,"ARP", JOT_NUM("layer3-length",layer2_address_length));
	SAMPLE(ferret,"ARP", JOT_NUM("opcode",opcode));

	if (layer2_address_type != 0x0001) {
		FRAMERR(frame, "%s: unknown\n", "ARP");
	}
	if (layer2_address_length != 0x06) {
		FRAMERR(frame, "%s: unknown\n", "ARP");
		return; /* Even if the type is not Ethernet, we'll continue, but the MAC address must be 6 bytes long, or we fail*/
	}

	if (layer3_address_type != 0x0800) {
		FRAMERR(frame, "%s: unknown\n", "ARP");
		return; /* If it's not IP, then ignore it */
	}
	if (layer3_address_length != 0x04) {
		FRAMERR(frame, "%s: unknown\n", "ARP");
		return; /* If IP addresses are not 4-bytes, then leave. TODO: what about 16 bytes addresses in ARP? */
	}
	if (opcode != 1 && opcode != 2) {
		FRAMERR(frame, "%s: unknown\n", "ARP");
		return;
	}

	mac_src = px+8;
	ip_src = ex32be(px+8+layer2_address_length);
	mac_dst = px+8+layer2_address_length+layer3_address_length;
	ip_dst = ex32be(px+8+layer2_address_length+layer3_address_length+layer2_address_length);

	/* Report the existance of the machine */
	{
		record_listening_port(
			ferret, 0,
			4, ip_src, 0,
			LISTENING_ON_ETHERNET,
			0,	/* no port */
			0,	/* no proto */
			0,
			0);

	}

	rfc4536_check(ferret, frame, opcode, mac_src, ip_src, mac_dst, ip_dst);

	/*
	 * Process the source-address
	 */
	JOTDOWN(ferret,
		JOT_IPv4("ID-IP", ip_src),
		JOT_MACADDR("macaddr", mac_src),
		0);
	JOTDOWN(ferret,
		JOT_MACADDR("ID-MAC", mac_src),
		JOT_IPv4("ip", ip_src),
		0);

	/* Check for remaining data in the packet. This hints that the packet
	 * might have been captured with a trailing 4-byte CRC/FCS field.*/
	{
		unsigned min_length = 8 + layer2_address_length*2 + layer3_address_length*2;
		if (length - min_length == 4)
			ferret->statistics.remaining_4++;
	}
}

