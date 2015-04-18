/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "ferret.h"
#include "stack-netframe.h"
#include "stack-extract.h"


static const char *group_name(struct NetFrame *frame, unsigned group_address)
{
	switch (group_address) {
	case 0xeffffffa: return "SSDP"; break;
	case 0xe0000001: return "all local hosts"; break;
	case 0xe0000002: return "all local routers"; break;
	case 0xe0000005: return "ospf"; break;
	case 0xe0000009: return "RIPv2"; break; /* Regress: defcon2008\dump186.pcap(958) */
	case 0xe000000d: return "pim"; break;
	case 0xe0000016: return "igmp"; break;
	case 0xe00000fb: return "mDNS"; break;
	case 0xe00000fc: return "mDNS Local Name Resolution"; break;
	case 0xe0000116: return "SLP (General)"; break;
	case 0xe0000123: return "SLP (Discovery)"; break;
	case 0xe4c8c8c9: return "(unknown)"; break;
	case 0xeffffffd: return "SLP (Admin Scoped)"; break;
	default: 
		FRAMERR(frame, "igmp: unknown group: %d.%d.%d.%d (0x%08x)\n", 
			(group_address>>24)&0xFF,
			(group_address>>16)&0xFF,
			(group_address>> 8)&0xFF,
			(group_address>> 0)&0xFF,
			group_address
			);
		return "(unknown)";
	}
}
void process_igmp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct {
		unsigned version;
		unsigned type;
		unsigned max_resp_time;
		unsigned checksum;
		unsigned group_address;
	} igmp;

	frame->layer4_protocol = LAYER4_IGMP;

	if (length == 0) {
		FRAMERR(frame, "igmp: frame empty\n");
		return;
	}
	if (length < 8) {
		FRAMERR(frame, "igmp: frame too short\n");
		return;
	}

	igmp.type = px[0];
	igmp.max_resp_time = px[1];
	igmp.checksum = ex16be(px+2);
	igmp.group_address = ex32be(px+4);

	SAMPLE(ferret,"IGMP", JOT_NUM("opcode", igmp.type));

	switch (igmp.type) {
	case 0x11: /* membership query */
		break;
	case 0x12: /* Membership report */
		JOTDOWN(ferret,
			JOT_SRC("ID-IP",frame),
			JOT_IPv4("Multicast-groups", igmp.group_address),
			JOT_SZ("groupname", group_name(frame, igmp.group_address)),
			0);
		break;
	case 0x16: /* membership report */
		JOTDOWN(ferret,
			JOT_SRC("ID-IP",frame),
			JOT_IPv4("Multicast-groups", igmp.group_address),
			JOT_SZ("groupname", group_name(frame, igmp.group_address)),
			0);
		break;
	case 0x17:
		JOTDOWN(ferret,
			JOT_SRC("ID-IP",frame),
			JOT_IPv4("Multicast-groups", igmp.group_address),
			JOT_SZ("groupname", group_name(frame, igmp.group_address)),
			0);
		break;
	case 0x22: /*v3 membersip report */
		{
			unsigned num_records = ex16be(px+6);
			unsigned i;
			unsigned offset=8;

			if (num_records != 1) 
				SAMPLE(ferret,"igmp", JOT_NUM("igmpv3.numrecs", num_records));

			for (i=0; i<num_records && offset+8 <= length; i++) {
				unsigned ip = ex32be(px+offset+4);
				unsigned sources = ex16be(px+offset+2);
				unsigned aux_data_len = px[offset+1]*4;

				igmp.group_address = ip;

				JOTDOWN(ferret,
					JOT_SRC("ID-IP",frame),
					JOT_IPv4("Multicast-groups", igmp.group_address),
					JOT_SZ("groupname", group_name(frame, igmp.group_address)),
					0);
				offset += sources*4+aux_data_len+8;
			}
		}
		break;
	default:
		FRAMERR(frame, "igmp: unknown type=%d\n", igmp.type);
		break;
	}
}

