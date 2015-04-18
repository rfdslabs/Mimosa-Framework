/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "util-mystring.h"
#include "util-memcasecmp.h"
#include "stack-listener.h"
#include <string.h>

#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

/**
 * Looks for a pattern within the payload.
 *
 * TODO: we need to swap this out for the generic pattern-search feature.
 */
static unsigned
udp_contains_sz(const unsigned char *px, unsigned length, const char *sz)
{
	unsigned sz_length = (unsigned)strlen(sz);
	unsigned offset=0;

	if (length < sz_length)
		return 0;
	length -= sz_length;

	while (offset<length) {
		if (px[offset] == sz[0] && memcmp(px+offset, sz, sz_length) == 0)
			return 1;
		offset++;
	}

	return 0;
}

enum {
    SMELLS_SRC,
    SMELLS_DST,
};

static unsigned
smellslike_udp_ntp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned direction)
{
    UNUSEDPARM(ferret);
    UNUSEDPARM(frame);
    UNUSEDPARM(px);
    UNUSEDPARM(length);
    UNUSEDPARM(direction);
    return 1;
}

static unsigned
smellslike_udp_tivoconnect(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned direction)
{
    UNUSEDPARM(ferret);
    UNUSEDPARM(frame);
    UNUSEDPARM(direction);

	if (length> 12) {
		if (MATCHES("tivoconnect=",px, 12)) {
            return true;
		}
	}
    return false;
}

int is_kludge_rtp_ports(struct NetFrame *frame)
{
	if (frame->src_port == 8000
		|| frame->src_port == 8001
		|| frame->src_port == 8002
		|| frame->src_port == 8003
		|| frame->src_port == 8700
		|| frame->src_port == 8701
		)
		return 1;
	if (frame->dst_port == 8000
		|| frame->dst_port == 8001
		|| frame->dst_port == 8002
		|| frame->dst_port == 8003
		|| frame->dst_port == 8700
		|| frame->dst_port == 8701
		)
		return 1;
	return 0;
}

int is_kludge_rtp_addrs(struct NetFrame *frame)
{
	if ((frame->src_ipv4>>8) == ((10<<16)+(1<<8)+5)
		&& (frame->dst_ipv4>>24) == 74)
		return 1;
	if ((frame->dst_ipv4>>8) == ((10<<16)+(1<<8)+5)
		&& (frame->src_ipv4>>24) == 74)
		return 1;
	return 0;
}

#if 0
static unsigned
smellslike_udp_bootp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned direction)
{
    unsigned i;

    UNUSEDPARM(ferret);
    UNUSEDPARM(frame);
    UNUSEDPARM(direction);

    /* BOOTP packets must have at least 300 bytes */
    if (length < 300)
        return false;

    /* The first few bytes must have small values */
    for (i=0; i<4; i++) {
        if (px[i] > 30)
            return false;
    }

    /* The elapsed time must be less than 5 minutes */
    if (!(ex32le(px+8) < 900 || ex16le(px+8) < 900))
        return false;
    return true;
}
#endif


#if 0
static unsigned
smellslike_udp_dhcp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned direction)
{
    UNUSEDPARM(ferret);
    UNUSEDPARM(frame);
    UNUSEDPARM(px);
    UNUSEDPARM(length);
    UNUSEDPARM(direction);

	return 0;
}
#endif

int
has_newline(const unsigned char *px, unsigned offset, unsigned length)
{
	length--;
	while (offset < length) {
		if (px[offset] == '\r' && px[offset+1] == '\n')
			return 1;
		offset++;
	}
	return 0;
}

void process_udp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	struct {
		unsigned src_port;
		unsigned dst_port;
		unsigned length;
		unsigned checksum;
	} udp;

	ferret->statistics.udp++;
	frame->layer4_protocol = LAYER4_UDP;

	if (length == 0) {
		FRAMERR(frame, "udp: frame empty\n");
		return;
	}
	if (length < 8) {
		FRAMERR(frame, "udp: frame too short\n");
		return;
	}

	udp.src_port = ex16be(px+0);
	udp.dst_port = ex16be(px+2);
	udp.length = ex16be(px+4);
	udp.checksum = ex16be(px+6);

	frame->src_port = udp.src_port;
	frame->dst_port = udp.dst_port;

	if (udp.length < 8) {
		FRAMERR_TRUNCATED(frame, "udp");
		return;
	}

	if (length > udp.length)
		length = udp.length;

	offset += 8;

	switch (frame->dst_ipv4) {
	case 0xe0000123: /* 224.0.1.35 - SLP */
		if (udp.dst_port == 427)
			SAMPLE(ferret,"SLP", JOT_SZ("packet", "test"));
		else
			FRAMERR(frame, "unknown port %d\n", udp.dst_port);
		return;
	}

	SAMPLE(ferret,"UDP", JOT_NUM("src", udp.src_port));
	SAMPLE(ferret,"UDP", JOT_NUM("dst", udp.dst_port));

	/*
	 * SIP
	 */
	if (udp.src_port > 1024 && udp.dst_port > 1024 && length-offset > 12) {
		if (memcasecmp(px+offset, "INVITE sip:", 11) == 0 && has_newline(px, offset, length)) {
			parse_dgram_sip_request(ferret, frame, px+offset, length-offset);
			return;
		}
		if (memcasecmp(px+offset, "ACK sip:", 8) == 0 && has_newline(px, offset, length)) {
			parse_dgram_sip_request(ferret, frame, px+offset, length-offset);
			return;
		}
		if (memcasecmp(px+offset, "CANCEL", 6) == 0 && has_newline(px, offset, length)) {
			parse_dgram_sip_request(ferret, frame, px+offset, length-offset);
			return;
		}
		if (memcasecmp(px+offset, "OPTIONS sip:", 7) == 0 && has_newline(px, offset, length)) {
			parse_dgram_sip_request(ferret, frame, px+offset, length-offset);
			return;
		}
		if (memcasecmp(px+offset, "BYE sip:", 8) == 0 && has_newline(px, offset, length)) {
			parse_dgram_sip_request(ferret, frame, px+offset, length-offset);
			return;
		}
		if (memcasecmp(px+offset, "REFER", 5) == 0 && has_newline(px, offset, length)) {
			parse_dgram_sip_request(ferret, frame, px+offset, length-offset);
			return;
		}
		if (memcasecmp(px+offset, "NOTIFY ", 7) == 0 && has_newline(px, offset, length) && frame->dst_port != 1900) {
			parse_dgram_sip_request(ferret, frame, px+offset, length-offset);
			return;
		}
		if (memcasecmp(px+offset, "MESSAGE", 7) == 0 && has_newline(px, offset, length)) {
			parse_dgram_sip_request(ferret, frame, px+offset, length-offset);
			return;
		}
		if (memcasecmp(px+offset, "SUBSCRIBE", 9) == 0 && has_newline(px, offset, length)) {
			parse_dgram_sip_request(ferret, frame, px+offset, length-offset);
			return;
		}
		if (memcasecmp(px+offset, "INFO", 4) == 0 && has_newline(px, offset, length)) {
			parse_dgram_sip_request(ferret, frame, px+offset, length-offset);
			return;
		}
		if (memcasecmp(px+offset, "REGISTER sip:", 13) == 0 && has_newline(px, offset, length)) {
			parse_dgram_sip_request(ferret, frame, px+offset, length-offset);
			return;
		}

		if (memcasecmp(px+offset, "SIP/", 4) == 0 && has_newline(px, offset, length)) {
			parse_dgram_sip_response(ferret, frame, px+offset, length-offset);
			return;
		}
	}

    /*********************
     *  SSS   RRR    CCC
     * S      R  R  C
     *  SSS   RRR   C
     *     S  R R   C
     *  SSS   R  R   CCC
     *********************/
    switch (udp.src_port) {
    case 123:
        if (smellslike_udp_ntp(ferret, frame, px+offset, length-offset, SMELLS_SRC))
           	ferret->statistics.udp_.ntp++;
        break;
    case 2190:
        if (smellslike_udp_tivoconnect(ferret, frame, px+offset, length-offset, SMELLS_SRC)) {
           	ferret->statistics.udp_.tivoconnect++;
   			parse_tivo_broadcast(ferret, frame, px+offset, length-offset);
			return;
        }
        break;
    case 48000:
    case 48001:
    case 48002:
        if (udp_contains_sz(px+offset, length-offset, "nimbus/1"))
            frame->layer7_protocol = LAYER7_CLOUD_NIMBUS;
        break;
    }

    /*************************
     * DDD   EEEE  SSS  TTTTT
     * D  D  E    S       T
     * D  D  EEE   SSS    T
     * D  D  E        S   T
     * DDD   EEEE  SSS    T
     *************************/
    switch (udp.dst_port) {
    case 123:
        if (smellslike_udp_ntp(ferret, frame, px+offset, length-offset, SMELLS_DST))
           	ferret->statistics.udp_.ntp++;
        break;
    case 546:
    case 547:
        if (frame->ipver == 6)
            parse_dhcpv6(ferret, frame, px+offset, length-offset);
        break;
    case 2190:
        if (smellslike_udp_tivoconnect(ferret, frame, px+offset, length-offset, SMELLS_DST)) {
           	ferret->statistics.udp_.tivoconnect++;
   			parse_tivo_broadcast(ferret, frame, px+offset, length-offset);
			return;
        }
    case 38293:
		if (	udp_contains_sz(px+offset, length-offset, "LDVPHiCM")
			||	udp_contains_sz(px+offset, length-offset, "HiCMHiCM")) {
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_SZ("Software", "Norton AntiVirus Corporate Edition"),
				0);
           	ferret->statistics.udp_.norton_av++;
			return;
		}
        break;
    case 48000:
    case 48001:
    case 48002:
        if (udp_contains_sz(px+offset, length-offset, "nimbus/1"))
            frame->layer7_protocol = LAYER7_CLOUD_NIMBUS;
        break;
    }

	switch (udp.src_port) {
	case 68:
	case 67:
		process_dhcp(ferret, frame, px+offset, length-offset);
		break;
	case 53:
		process_dns(ferret, frame, px+offset, length-offset);
		break;
	case 137:
		process_dns(ferret, frame, px+offset, length-offset);
		break;
	case 138:
		process_netbios_dgm(ferret, frame, px+offset, length-offset);
		break;
	case 389:
		process_ldap(ferret, frame, px+offset, length-offset);
		break;
    case 546:
    case 547:
        if (frame->ipver == 6)
            parse_dhcpv6(ferret, frame, px+offset, length-offset);
        break;
	case 631:
		if (udp.dst_port == 631) {
			process_cups(ferret, frame, px+offset, length-offset);
		}
		break;
	case 1900:
		if (length-offset > 9 && strnicmp((const char*)px+offset, "HTTP/1.1 ", 9) == 0) {
			process_upnp_response(ferret, frame, px+offset, length-offset);
		}
		break;
	case 14906: /* ??? */
		break;
	case 4500:
		break;
	default:
		switch (udp.dst_port) {
		case 0:
			break;
		case 68:
		case 67:
			process_dhcp(ferret, frame, px+offset, length-offset);
			break;
		case 53:
		case 5353:
        case 5355:
			process_dns(ferret, frame, px+offset, length-offset);
			break;
		case 137:
			process_dns(ferret, frame, px+offset, length-offset);
			break;
		case 138:
			process_netbios_dgm(ferret, frame, px+offset, length-offset);
			break;
		case 1900:
			if (frame->dst_ipv4 == 0xeffffffa)
				parse_ssdp(ferret, frame, px+offset, length-offset);
			break;
		case 5369:
			break;
		case 29301:
			break;
		case 123:
			break;
		case 5499:
			break;
		case 2233: /*intel/shiva vpn*/
			break;
		case 27900: /* GameSpy*/
			break;
		case 9283:
			process_callwave_iam(ferret, frame, px+offset, length-offset);
			break;
		case 161:
			process_snmp(ferret, frame, px+offset, length-offset);
			break;
		case 192: /* ??? */
			break;
		case 389:
			process_ldap(ferret, frame, px+offset, length-offset);
			break;
		case 427: /* SRVLOC */
			process_srvloc(ferret, frame, px+offset, length-offset);
			break;
		case 14906: /* ??? */
			break;
		case 500:
			process_isakmp(ferret, frame, px+offset, length-offset);
			break;
		case 2222:
			break;
		default:
			if (frame->dst_ipv4 == 0xc0a8a89b || frame->src_ipv4 == 0xc0a8a89b)
				;
			else {
				if (smellslike_bittorrent_XYZ(px+offset, length-offset))
					process_bittorrent_XYZ(ferret, frame, px+offset, length-offset);
				else if (px[offset] == 'd' && smellslike_bittorrent_DHT(px+offset, length-offset))
					process_bittorrent_DHT(ferret, frame, px+offset, length-offset);
				else if ((px[offset]&0x8F) == 0x01 && smellslike_bittorrent_uTP(px+offset, length-offset))
					process_bittorrent_uTP(ferret, frame, px+offset, length-offset);
                else if (length-offset >= 23 && px[offset+18] <= 4 && px[offset+17] < 3 && smellslike_bittorrent_uTP(px+offset, length-offset))
                    process_bittorrent_uTP(ferret, frame, px+offset, length-offset);
				else
					; /*
				FRAMERR(frame, "udp: unknown, [%d.%d.%d.%d]->[%d.%d.%d.%d] src=%d, dst=%d\n", 
					(frame->src_ipv4>>24)&0xFF,(frame->src_ipv4>>16)&0xFF,(frame->src_ipv4>>8)&0xFF,(frame->src_ipv4>>0)&0xFF,
					(frame->dst_ipv4>>24)&0xFF,(frame->dst_ipv4>>16)&0xFF,(frame->dst_ipv4>>8)&0xFF,(frame->dst_ipv4>>0)&0xFF,
					frame->src_port, frame->dst_port);*/
			}
		}
	}

	if (frame->ipver == 0 || frame->ipver == 4) {
		unsigned proto;

		proto = listener_lookup_udp(ferret, frame->dst_ipv4, frame->dst_port);
		if (proto == 0)
			listener_lookup_udp(ferret, frame->src_ipv4, frame->src_port);
		
		switch (proto) {
		case 0:
			break;
		case LISTENER_UDP_RTPAVP:
			process_rtp_avp(ferret, frame, px+offset, length-offset);
			break;
		case LISTENER_UDP_RTCP:
			process_rtp_rtcp(ferret, frame, px+offset, length-offset);
			break;
		}
	}

	/*
	 * Kludge
	 */
	if (frame->layer7_protocol == 0) {
		if (is_kludge_rtp_addrs(frame)) {
			if (is_kludge_rtp_ports(frame))
				frame->layer7_protocol = LAYER7_RTP;
		}

		if (frame->src_port == 5060 || frame->dst_port == 5060) {
			if (length-offset == 4 && memcmp(px+offset, "\r\n\r\n", 4) == 0)
				frame->layer7_protocol = LAYER7_SIP;
			else
				printf(".");
		}

		if (frame->dst_port == 1985 && frame->dst_ipv4 == (224<<24|2))
			frame->layer7_protocol = LAYER7_HSRP;

		if (frame->src_port == 3205 && frame->dst_ipv4 == 0xFFFFFFFF)
			frame->layer7_protocol = LAYER7_ISCSI;

		if (frame->src_port == 1900 && frame->dst_port == 1900)
			frame->layer7_protocol = LAYER7_SSDP;
	}
}

