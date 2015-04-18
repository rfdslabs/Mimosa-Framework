/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	POINT TO POINT PROTOCOL

  PPP is used as as a VPN protocol (PPTP). We can grab the username (and
  possible the password hash) of the logon.

  PPP is also used as PPoE. This protocol is used to tunnel over an 
  Ethernet connection.

*/
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include <string.h>
#include <stdint.h>

enum {
	PPP_AUTH_TYPE_UNKNOWN=0,
	PPP_AUTH_TYPE_MSCHAPV1=1,
	PPP_AUTH_TYPE_MSCHAPV2=2,
};

struct ProtoPPP_Record
{
	unsigned char src_ip[16];
	unsigned char dst_ip[16];
	unsigned ip_proto;
	unsigned char auth_type;
	unsigned char challenge_length;
	unsigned char name_length;
	unsigned char challenge[16];
	unsigned char name[32];
};

struct ProtoPPP
{
	struct ProtoPPP_Record records[16384];
};

static unsigned hash_ipv4(unsigned result1, unsigned result2)
{
	result1 = result1 * (result1>>23);
	result2 = result2 * (result2>>23);
	result1 ^= (result1>>16);
	result2 ^= (result2>>16);
	result1 += (result1>>13);
	result2 += (result2>>13);
	return result1 ^ result2;
}

static struct ProtoPPP_Record *
lookup_record_ipv4(struct Ferret *ferret, unsigned src_ipv4, unsigned dst_ipv4)
{
	struct ProtoPPP_Record *rec;
	unsigned index;

	index = hash_ipv4(src_ipv4, dst_ipv4);
	rec = &ferret->proto_ppp->records[index & 16385];
	if (*(unsigned *)rec->src_ip != src_ipv4 || *(unsigned *)rec->dst_ip != dst_ipv4) {
		memset(rec, 0, sizeof(*rec));
		*(unsigned *)rec->src_ip = src_ipv4;
		*(unsigned *)rec->dst_ip = dst_ipv4;
	}
	return rec;
}

static struct ProtoPPP_Record *
lookup_record(struct Ferret *ferret, struct NetFrame *frame, int direction)
{
	if (ferret->proto_ppp == NULL) {
		ferret->proto_ppp = (struct ProtoPPP *)malloc(sizeof(*ferret->proto_ppp));
		if (ferret->proto_ppp == NULL)
			return 0;
		memset(ferret->proto_ppp, 0, sizeof(*ferret->proto_ppp));
	}
	switch (frame->ipver) {
	case 0:
	case 4:
		if (direction > 0)
			return lookup_record_ipv4(ferret, frame->src_ipv4, frame->dst_ipv4);
		else
			return lookup_record_ipv4(ferret, frame->dst_ipv4, frame->src_ipv4);
		break;
	case 6:
		return 0;
		break;
	}

	return 0;
}


static unsigned 
get_option(const unsigned char *px, unsigned offset, unsigned length, unsigned in_opcode, unsigned *r_offset, unsigned *r_length)
{
	while (offset + 2 < length) {
		unsigned opcode = px[offset];
		unsigned oplength = px[offset+1];
		
		if (oplength < 2)
			break;

		if (opcode == in_opcode) {
			*r_offset = offset + 2; /* offset to just the data portion */
			*r_length = oplength - 2;
			return 1; /* success */
		}

		offset += oplength;
	}

	return 0; /* couldn't find it */
}

void process_pptp_linkcontrol(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned code;
	//unsigned id;
	unsigned ppp_length;
	unsigned offset = 0;
	static struct ProtoPPP_Record *rec;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "gre");
		return;
	}

	code = px[0];
	//id = px[1];
	ppp_length = ex16be(px+2);
	if (length > ppp_length)
		length = ppp_length;

	offset += 4;

	SAMPLE(ferret,"PPP", JOT_NUM("link-control-code", code));
	switch (code) {
	case 1: /* configuration request */
		{
			unsigned opoffset;
			unsigned oplength;
			if (get_option(px, offset, length, 0x03, &opoffset, &oplength)) {
				if (oplength >= 2) {
					unsigned auth_proto = ex16be(px+opoffset);
					switch (auth_proto) {
					case 0xc223:
						if (oplength >= 3)
						switch (px[opoffset+2]) {
						case 0x81:
							rec = lookup_record(ferret, frame, 1);
							rec->auth_type = PPP_AUTH_TYPE_MSCHAPV2;
							JOTDOWN(ferret,
								JOT_SZ("proto","PPP"),
								JOT_SZ("auth","MS-CHAPv2"),
								0);
							break;
						default:
							FRAMERR_BADVAL(frame, "PPP link-control auth", px[opoffset+2]);
						}
						break;
					default:
						FRAMERR_BADVAL(frame, "PPP link-control-code", code);
					}
				}
			}
		}
		break;
	default:
		FRAMERR_BADVAL(frame, "PPP link-control-code", code);
		break;
	}
}

void process_pptp_chap(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned code;
	//unsigned id;
	unsigned sublength;
	unsigned offset;
	struct ProtoPPP_Record *rec;
	struct ProtoPPP_Record *rev;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "gre");
		return;
	}

	/* RFC 1994
	 * +--------+--------+--------+--------+
	 * |  code  |   id   |      length     |
	 * +--------+--------+--------+--------+
	 */
	code = px[0];
	//id = px[1];
	sublength = ex16be(px+2);
	if (sublength < 4) {
		FRAMERR_BADVAL(frame, "ppp-chap", sublength);
		return;
	}
	offset = 4;

	if (length > sublength)
		length = sublength;

	SAMPLE(ferret,"PPP", JOT_NUM("chap-code", code));
	switch (code) {
	case 2: /* response */
		{
			unsigned value_size;
			const unsigned char *value;

			if (offset+1 >= length) {
				FRAMERR_TRUNCATED(frame, "ppp-chap");
				return;
			}
			value_size = px[offset++];
			if (value_size > length-offset)
				value_size = length-offset;
			value = px+offset;
			offset += value_size;

			rev = lookup_record(ferret, frame, -1);
			switch (rev->challenge_length) {
			case 16:
				
				JOTDOWN(ferret,
					JOT_SZ("proto","PPP"),
					JOT_SZ("auth","MS-CHAPv2"),
					JOT_HEXSTR("challenge", rev->challenge, rev->challenge_length),
					JOT_PRINT("name", px+offset, length-offset),
					JOT_HEXSTR("response", value, value_size),
					0);
				break;
			case 8:
				rec = lookup_record(ferret, frame, 1);
				memcpy(rec->challenge, value, 8);
				rec->challenge_length = 8;
				JOTDOWN(ferret,
					JOT_SZ("proto","PPP"),
					JOT_SZ("auth","MS-CHAPv1"),
					JOT_HEXSTR("challenge", rev->challenge, rev->challenge_length),
					JOT_PRINT("name", px+offset, length-offset),
					JOT_HEXSTR("response", value, value_size),
					0);
				break;
			default:
				FRAMERR_BADVAL(frame, "ppp-chap", value_size);
			}
		}
		break;

	case 3: /* success */
		break;

	case 4: /* failure */
		FRAMERR(frame, "PPP: auth unknown code\n");
		break;

	case 1: /* challenge */
		{
			unsigned value_size;
			const unsigned char *value;

			if (offset+1 >= length) {
				FRAMERR_TRUNCATED(frame, "ppp-chap");
				return;
			}
			value_size = px[offset++];
			if (value_size > length-offset)
				value_size = length-offset;
			value = px+offset;
			offset += value_size;

			switch (value_size) {
			case 16:
				rec = lookup_record(ferret, frame, 1);
				memcpy(rec->challenge, value, 16);
				rec->challenge_length = 16;

				JOTDOWN(ferret,
					JOT_SZ("proto","PPP"),
					JOT_SZ("auth","MS-CHAPv2"),
					JOT_HEXSTR("challenge", value, value_size),
					JOT_PRINT("name", px+offset, length-offset),
					0);
				break;
			case 8:
				rec = lookup_record(ferret, frame, 1);
				memcpy(rec->challenge, value, 8);
				rec->challenge_length = 8;
				JOTDOWN(ferret,
					JOT_SZ("proto","PPP"),
					JOT_SZ("auth","MS-CHAPv1"),
					JOT_HEXSTR("challenge", value, value_size),
					JOT_PRINT("name", px+offset, length-offset),
					0);
				break;
			default:
				FRAMERR_BADVAL(frame, "ppp-chap", value_size);
			}

		}
		break;
	default:
		FRAMERR(frame, "PPP: auth unknown code\n");
	}


}
void parse_ppoe_discovery(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned ver;
	unsigned type;
	unsigned code;
	//unsigned payload_length;
	//unsigned session_id;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "PPoE");
		return;
	}

	ver = px[0]>>4;
	type = px[0]&0x0F;
	code = px[1];
	//session_id = ex16be(px+2);
	//payload_length = ex16be(px+4);

	switch ((ver<<12) | (type<<8) | code) {
	case 0x1109:
		JOTDOWN(ferret,
			JOT_SZ("proto","PPPoE"),
			JOT_SZ("code","discovery"),
			0);
		break;
	default:
		FRAMERR_BADVAL(frame, "PPPoE-discovery-code", code);
		break;
	}

}

void process_pptp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned protocol;

	if (length < 4) {
		FRAMERR_TRUNCATED(frame, "gre");
		return;
	}

	if (ex16be(px) == 0xFF03) {
		px+=2;
		length-=2;
	}

	protocol = ex16be(px);
	SAMPLE(ferret,"PPP", JOT_NUM("packet-type", protocol));
	switch (protocol) {
	case 0xc021: /* Link Control Protocol */
		process_pptp_linkcontrol(ferret, frame, px+2, length-2);
		break;
	case 0xc223: /* PPP CHAP - Challenge Handshake Authentication protocol */
		process_pptp_chap(ferret, frame, px+2, length-2);
		break;
	default:
		FRAMERR_UNKNOWN_UNSIGNED(frame, "ppp", protocol);
	}


}

