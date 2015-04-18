/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	AOL INSTANT MESSENGER (AIM) - OSCAR PROTOCOL

  This is a decode for AOL's Instant Messenger (AIM) protocol.

  We implement this as a TCP 'state-machine' as described in the document
  'read-code.txt' in the source tree.

  What we are primarily looking for is the user's account name and
  a list of all the user's "buddies". 

*/
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "platform.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef WIN32
#include <malloc.h>
#endif

/*

	AIM PROTOCOL


  AIM is transmitting as a series of PDUs over TCP. This header
  protocol is known as 'FLAP'.

  +--------+--------+
  |  0x2a  | channel|
  +--------+--------+
  |      seqno      |
  +--------+--------+
  |      length     |
  +--------+--------+
  |                 |
  .                 .
  .                 .

  0x2a:
  This is always the first byte of a PDU

  CHANNEL:
	0x01 - New Connection Negotiation
	0x02 - SNAC data (non connection-oriented data)
	0x03 - FLAP-level Error
	0x04 - Close Connection Negotiation


  SEQNO:
  This starts at a random value and monotonically increases. They are
  independent of channels -- one sequence per TCP connection, not per
  channel.

On channel 2, there is SNAC data inside the PDU (starting after
the FLAP length field). Only one SNAC may be in a FLAP.
This protocol looks like:

  +--------+--------+
  |     family      |
  +--------+--------+
  |     subtype     |
  +--------+--------+
  |      flags      |
  +--------+--------+
  |                 |
  +-  request ID   -+
  |                 |
  +--------+--------+
  |                 |
  .                 .
  .                 .


Family 0x0001: Generic Service Controls
0x0001	Client or Server	Error
0x0002	Client	Client is now online and ready for normal function
0x0003	Server	Server is now ready for normal functions
0x0004	Client	Request for new service (the server will redirect the client to a new host where the service is available)
0x0005	Server	Redirect (response to subtype 0x0004 from client)
0x0006	Client	Request Rate Information (request rate at which client can send SNACs)
0x0007	Server	Rate information response (response to subtype 0x0006)
0x0008	Client	Rate Information Response Ack
0x000A	Server	Rate information change
0x000B	Server	Pause
0x000D	Server	Resume
0x000E	Client	Request information on the screen name you've been authenticated under.
0x000F	Server	Information the screen name you've been authenticated under.
0x0010	Server	Evil notification
0x0012	Server	Migration notice/request
0x0013	Server	Message of the day
0x0014	Client	Set Privacy flags
0x0015	Server	Well known urls
0x0016	Server	No op
Family 0x0002: Location Services
0x0001	Client or Server	Error
0x0002	Client	Request rights information
0x0003	Server	Rights information
0x0004	Client	Set user information
0x0005	Client	Request user information
0x0006	Server	User information
0x0007	Client	Watcher sub request
0x0008	Server	Watcher notification
Family 0x0003: Buddy List Management
0x0001	Client or Server	Error
0x0002	Client	Request rights information
0x0003	Server	Rights information
0x0004	Client	Add buddy to buddy list
0x0005	Client	Remove buddy from buddy list
0x0006	Client	Watcher list query
0x0007	Server	Watcher list response
0x0008	Client	Watcher sub request
0x0009	Server	Watcher notification
0x000A	Server	Reject notification
0x000B	Server	Oncoming buddy
0x000C	Server	Offgoing buddy
Family 0x0004: Messaging
0x0001	Client or Server	Error
0x0002	Client	Add ICBM parameter
0x0003	Client	Remove ICBM parameter
0x0004	Client	Request parameter information
0x0005	Server	Parameter information
0x0006	Client	Message from the client
0x0007	Server	Message to the client
0x0008	Client	Evil request
0x0009	Server	Evil reply
0x000A	Server	Missed calls
0x000B	Client or Server	Client error
0x000C	Server	Host ack
Family 0x0005: Advertisments
0x0001	Client or Server	Error
0x0002	Client	Request advertisments
0x0003	Server	Advertisment data (GIFs)
Family 0x0006: Invitation and Client-to-Client
0x0002	Client	Invite a friend to join AIM
0x0003	Server	Invite a friend to join AIM ack
Family 0x0007: Administrative
0x0001	Server	Admin error
0x0002	Client	Information request
0x0003	Server	Information reply
0x0004	Client	Information change request
0x0005	Server	Information change reply
0x0006	Client	Account confirm request
0x0007	Server	Account confirm reply
0x0008	Client	Account delete request
0x0009	Server	Account delete reply
Family 0x0008: Popup Notices
0x0001	Client or Server	Error
0x0002	Server	Display popup
Family 0x0009: BOS-specific
0x0001	Client or Server	Error
0x0002	Client	Request BOS Rights
0x0003	Server	BOS Rights
0x0004	Client	Set group permission mask
0x0005	Client	Add permission list entries
0x0006	Client	Delete permission list entries
0x0007	Client	Add deny list entries
0x0008	Client	Delete deny list entries
0x0009	Server	BOS error
Family 0x000A: User Lookup
0x0001	Client or Server	Error (often Search Failed)
0x0002	Client	Search for screen name by email address
0x0003	Server	Search Response
Family 0x000B: Stats
0x0001	Client or Server	Error
0x0002	Server	Set minimum report interval
0x0003	Client	Report events
0x0004	Server	Report ack
Family 0x000C: Translate
0x0001	Client or Server	Error
0x0002	Client	Translate request
0x0003	Server	Translate reply
Family 0x000D: Chat Navigation
0x0001	Client or Server	Error
0x0002	Client	Request chat rights
0x0003	Client	Request exchange information
0x0004	Client	Request room information
0x0005	Client	Request more room information
0x0006	Client	Request occupant list
0x0007	Client	Search for room
0x0008	Client	Create room
0x0009	Server	Navigation information
Family 0x000E: Chat
0x0001	Client or Server	Error
0x0002	Server	Room information update
0x0003	Server	Users joined
0x0004	Server	Users left
0x0005	Client	Channel message from client
0x0006	Server	Channel message to client
0x0007	Server	Evil request
0x0008	Server	Evil reply
0x0009	Client or Server	Client error
Family 0x0045: Unknown (Client Something?)
0x0002	Client	Add to notify list



*/

void process_simple_aim_response(struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	UNUSEDPARM(stream);UNUSEDPARM(frame);UNUSEDPARM(px);UNUSEDPARM(length);
}

void parse_aim_data(struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	UNUSEDPARM(stream);UNUSEDPARM(frame);UNUSEDPARM(px);UNUSEDPARM(length);
}

/**
 * Parse the "rendez-vous" TLV within a packet. Since this is a TLV, it has
 * already been reassembled by our string frag parser.
 */
static void
parse_message_filexfer_rendezvous(struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct Ferret *jot = frame->sess->eng->ferret;
	unsigned offset=0;

	/* skip some fields */
	offset += 2+8;

	/* verify we have the file transfer ID */
	while (offset < 2+8+16) {
		if (px[offset] != (unsigned char)("\x09\x46\x13\x43\x4c\x7f\x11\xd1\x82\x22\x44\x45\x53\x54\x00\x00"[offset-8-2]))
			return; /* not a file transfer command */ /*TODO: SAMPLE this */
		offset++;
	}

	/* go through the embeded TLVs */
	while (offset<length) {
		unsigned tag;
		unsigned len;

		if (offset+4>length)
			break;

		tag = ex16be(px+offset+0);
		len = ex16be(px+offset+2);

		offset += 4;

		/*
            TLV: Unknown
                Value ID: Unknown (0x000a)
                Length: 2
                Value
            TLV: Unknown
                Value ID: Unknown (0x000f)
                Length: 0
                Value
            TLV: Internal IP
                Value ID: Internal IP (0x0003)
                Length: 4
                Value: 12625930
            TLV: External Port
                Value ID: External Port (0x0005)
                Length: 2
                Value: 5190
            TLV: Extended Data
                Value ID: Extended Data (0x2711)
                Length: 17
                Value
		*/
		switch (tag) {
		case 0x000a:
		case 0x000f:
		case 0x0010:
			break;
		case 3: /* Internet IP */
			{
				unsigned j;
				unsigned ip=0;
				for (j=0; j<4 && offset+j<length; j++)
					ip = ip << 8 | px[offset+j];

				JOTDOWN(jot, 
					JOT_SRC("ID-IP",frame),
					JOT_SZ("AIM", "File-Transfer"),
					JOT_IPv4("Internal-IP", ip),
					0);
			}
			break;
		case 5: /* Internal Port */
			{
				unsigned j;
				unsigned port=0;
				for (j=0; j<2 && offset+j<length; j++)
					port = port << 8 | px[offset+j];

				JOTDOWN(jot, 
					JOT_SRC("ID-IP",frame),
					JOT_SZ("AIM", "File-Transfer"),
					JOT_NUM("Internal-Port", port),
					0);
			}
			break;
		case 0x2711: /* filename */
			if (len > length-offset)
				len = length-offset;
			if (len > 4) {
				len -= 4;
				offset += 4;
			}

			while (offset < length && len && px[offset] < 26) {
				offset++;
				len--;
			}

			JOTDOWN(jot, 
				JOT_SRC("ID-IP",frame),
				JOT_SZ("AIM", "File-Transfer"),
				JOT_PRINT("Filename", px+offset, len),
				0);
			break;
		default:
			/* TODO: SAMPLE this */
			FRAMERR(frame, "%s: unknown\n", "AIM");
			break;
		}

		offset += len;
	}
	
}


unsigned
strip_html_tags(const unsigned char *px, unsigned length, unsigned char *dst, unsigned dst_length)
{
	unsigned state=0;
	unsigned offset=0;
	unsigned d=0;
	enum {S_NORMAL, S_LT};

	while (offset<length)
	switch (state) {
	case S_NORMAL:
		if (px[offset] == '<')
			state = S_LT;
		else {
			if (d<dst_length)
				dst[d++] = px[offset];
		}
		offset++;
		break;
	case S_LT:
		/* Search until the end part of the tag */
		while (offset<length && px[offset] != '>')
			offset++;
		if (offset<length) {
			state = S_NORMAL;
			offset++;
		}
		break;
	}

	if (d < dst_length)
		dst[d] = '\0'; /* nul termiante for debugging*/
	return d;
}

void decode_message(struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned is_outgoing)
{
	struct Ferret *ferret = frame->sess->eng->ferret;
	const unsigned char *msg = px;
	unsigned msg_length = length;
	unsigned msg_offset = 0;

	if (msg_length > 2 && ex16be(msg+msg_offset) == 0x501) {
		/*unsigned flags = ex16be(msg+msg_offset);*/
		unsigned len=0;
		msg_offset += 2;
		
		if (msg_offset+2 < msg_length) {
			len = ex16be(msg+msg_offset);
			msg_offset += len+2;
		}

		if (msg_offset+2 < msg_length)
			msg_offset += 2; /* block info */

		if (msg_offset+2 < msg_length) {
			len = ex16be(msg+msg_offset);
			msg_offset += 2; /* block length */
		}

		msg_offset += 4; /* character set */
		if (len > 4)
			len -= 4; /* subtract the charset info from the block lenght*/

		if (msg_offset > msg_length) {
			FRAMERR(frame, "%s: integer overflow\n", "AIM");
			return;
		}

		if (msg_offset + len > msg_length)
			len = msg_length - msg_offset;

		if (len > 6 && strnicmp((const char*)msg+msg_offset, "<HTML>", 6)==0) {
			unsigned char *msg2 = alloca(len);
			unsigned msg2_len;

			msg2_len = strip_html_tags(msg+msg_offset, len, msg2, len);

			if (is_outgoing)
				JOTDOWN(ferret, 
					JOT_SRC("ID-IP",frame),
					JOT_PRINT("AIM-Message-To", stream->str[1].the_string, stream->str[1].length),
					JOT_PRINT("AIM-Message", msg2, msg2_len),
					0);
			else
				JOTDOWN(ferret, 
					JOT_DST("ID-IP",frame),
					JOT_PRINT("AIM-Message-From", stream->str[1].the_string, stream->str[1].length),
					JOT_PRINT("AIM-Message", msg2, msg2_len),
					0);

		} else  {
			if (is_outgoing)
				JOTDOWN(ferret, 
					JOT_SRC("ID-IP",frame),
					JOT_PRINT("AIM-Message-To", stream->str[1].the_string, stream->str[1].length),
					JOT_PRINT("AIM-Message", msg+msg_offset, msg_length-msg_offset),
					0);
			else
				JOTDOWN(ferret, 
					JOT_DST("ID-IP",frame),
					JOT_PRINT("AIM-Message-From", stream->str[1].the_string, stream->str[1].length),
					JOT_PRINT("AIM-Message", msg+msg_offset, msg_length-msg_offset),
					0);
		}

	} else {
		while (msg_offset<msg_length && msg[msg_offset] < 26)
			msg_offset++;

		if (is_outgoing)
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP",frame),
				JOT_PRINT("AIM-Message-To", stream->str[1].the_string, stream->str[1].length),
				JOT_PRINT("AIM-Message", msg+msg_offset, msg_length-msg_offset),
				0);
		else
			JOTDOWN(ferret, 
				JOT_DST("ID-IP",frame),
				JOT_PRINT("AIM-Message-From", stream->str[1].the_string, stream->str[1].length),
				JOT_PRINT("AIM-Message", msg+msg_offset, msg_length-msg_offset),
				0);
	}
}

/**
 * This parses a TLV record instead of a SNAC packet, which is itself 
 * inside of a FLAP PDU. We identify the precise item by the SNAC-family,
 * SNAC-subtype, and TLV-tag */
static void 
parse_tlv(struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct Ferret *ferret = frame->sess->eng->ferret;
	struct AIMPARSER *aim = &stream->app.aim;
	unsigned h;

	/* This function is going to process the data within a SNAC TLV field. 
	 * We are just going to handle this all in a big switch/case statement. */
#define HASH(x,y,z) (((x)<<16)|((y)<<8)|(z))
	h = HASH(aim->pdu.family, aim->pdu.subtype, aim->tlv_tag);

	/* If we are in the middle of parsing the string, just grab
	 * it in our re-assembly buffer */
	if (px != NULL) {
		strfrag_append(stream->str, px, length);
		return;
	}
	
	/* Process the string we've reassembled. We are going to hash on the full context
	 * of the PDU rather than just the TLV tag */
	switch (h) {
	case 0x00170203: /* family=Sign-on, subtype=Logon, tag=client-id-string */
		JOTDOWN(ferret, 
			JOT_SRC("ID-IP",frame),
			JOT_PRINT("AIM-Client-ID", stream->str->the_string, stream->str->length),
			0);
		break;
	case 0x0017020e: /* family=Sign-on, subtype=Logon, tag=country */
		JOTDOWN(ferret, 
			JOT_SRC("ID-IP",frame),
			JOT_PRINT("AIM-Country", stream->str->the_string, stream->str->length),
			0);
		break;
	case 0x0017020f: /* family=Sign-on, subtype=Logon, tag=language */
		JOTDOWN(ferret, 
			JOT_SRC("ID-IP",frame),
			JOT_PRINT("AIM-Language", stream->str->the_string, stream->str->length),
			0);
		break;
	case 0x00170225: /* family=Sign-on, subtype=Logon, tag=password hash */
		JOTDOWN(ferret, 
			JOT_SRC("ID-IP",frame),
			JOT_HEXSTR("AIM-Password-Hash", stream->str->the_string, stream->str->length),
			0);
		break;
		break;
	case 0x00170201: /* family=Sign-on, subtype=Logon, tag=screen-name */
	case 0x00170601: /* family=Sign-on, subtype=Sign-on, tag=screen-name  */
		/* This is the sign-on 'screen-name' in the packet that the user sends to
		 * the logon server (logon.oscar.aol.com). The server will respond with
		 * a 'challenge'. The user will then send the screen-name and hash of 
		 * challenge and password to the real server he wants to connect to */
		JOTDOWN(ferret, 
			JOT_SRC("ID-IP",frame),
			JOT_PRINT("AIM-Screen-Name", stream->str->the_string, stream->str->length),
			0);
		break;
	case 0x00170301: /* family=Logon, subtype=Reply, tag=screen-name  */
		JOTDOWN(ferret, 
			JOT_DST("ID-IP",frame), /* logon reply screen name sent from server*/
			JOT_PRINT("AIM-Screen-Name", stream->str->the_string, stream->str->length),
			0);
		break;
	case 0x00170311: /* family=Logon, subtype=Reply, tag=email  */
		JOTDOWN(ferret, 
			JOT_DST("ID-IP",frame), /* logon reply screen name sent from server*/
			JOT_PRINT("e-mail", stream->str->the_string, stream->str->length),
			0);
		break;
	case 0x00170349: /* family=Logon, subtype=Reply, tag=auth-protocol  */
		JOTDOWN(ferret, 
			JOT_DST("ID-IP",frame), /* logon reply screen name sent from server*/
			JOT_HEXSTR("AIM-digest-sig", stream->str->the_string, stream->str->length),
			0);
		break;
	case 0x00170700: /*AIM Sign-on(0x17), Sign-on Reply(7), Challenge(10)*/
		/* This is the 'challenge' sent back by logon.oscar.aol.com. The user
		 * will hash this with his password in order to logon to all the other
		 * servers.
		 *
		 * Because of this, we need to attach this string to the session going
		 * in the reverse direction. That will enable us to log the authentication
		 * process in case we want to log the hashes */
		JOTDOWN(ferret, 
			JOT_SRC("ID-IP",frame),
			JOT_PRINT("AIM-Challenge", stream->str->the_string, stream->str->length),
			0);
		break;
	case 0x0017038e: /* authorization cookie */
		/* This is a long string to pull out, but it gives anybody who has
		 * this cookie the ability to log onto any AIM service */
		JOTDOWN(ferret, 
			JOT_DST("ID-IP",frame),
			JOT_HEXSTR("AIM-Auth-Cookie", stream->str->the_string, stream->str->length),
			0);
		break;	
	case  0x00030b00: /* INCOMING oncoming buddy name */
	case  0x00020600:
		if (stream->str->length) {
			JOTDOWN(ferret, 
				JOT_DST("ID-IP",frame),
				JOT_PRINT("AIM-Buddy", stream->str->the_string, stream->str->length),
				0);
			JOTDOWN(ferret, 
				JOT_DST("ID-IP",frame),
				JOT_PRINT("friend", stream->str->the_string, stream->str->length),
				0);
		}
		break;
	case 0x00021500: /* OUTGOING user info query*/
		if (stream->str->length) {
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP",frame),
				JOT_PRINT("AIM-Buddy", stream->str->the_string, stream->str->length),
				0);
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP",frame),
				JOT_PRINT("friend", stream->str->the_string, stream->str->length),
				0);
		}
		break;
	case 0x00040700: /* Messaging, incoming */
		if (stream->str->length) {
			JOTDOWN(ferret, 
				JOT_DST("ID-IP",frame),
				JOT_PRINT("AIM-Buddy", stream->str->the_string, stream->str->length),
				0);
			JOTDOWN(ferret, 
				JOT_DST("ID-IP",frame),
				JOT_PRINT("friend", stream->str->the_string, stream->str->length),
				0);

			strfrag_xfer(stream->str+1, stream->str);
		}
		break;
	case 0x00040702: /* Messaging, INCOMING */
		decode_message(stream, frame, stream->str[0].the_string, stream->str[0].length, 0);
		break;
	case 0x00040600: /* Messaging, outgoing */
		if (stream->str->length) {
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP",frame),
				JOT_PRINT("AIM-Buddy", stream->str->the_string, stream->str->length),
				0);
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP",frame),
				JOT_PRINT("friend", stream->str->the_string, stream->str->length),
				0);

			strfrag_xfer(stream->str+1, stream->str);
		}
		break;
	case 0x00040602: /* Messaging, outgoing */
		decode_message(stream, frame, stream->str[0].the_string, stream->str[0].length, 1);
		break;
	case 0x00020604: /* Buddy Info - away message */
		if (stream->str->length) {
			JOTDOWN(ferret, 
				JOT_DST("ID-IP",frame),
				JOT_PRINT("AIM-Buddy", stream->str[1].the_string, stream->str[1].length),
				JOT_PRINT("Away-Message", stream->str[0].the_string, stream->str[0].length),
				0);
		}
		break;
	case 0x00041400: /* typing, outgoing */
		if (stream->str->length) {
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP",frame),
				JOT_PRINT("AIM-Buddy", stream->str->the_string, stream->str->length),
				0);
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP",frame),
				JOT_PRINT("friend", stream->str->the_string, stream->str->length),
				0);
		}
		break;
	case 0x00040605: /* File transfer */
		parse_message_filexfer_rendezvous(stream, frame, stream->str->the_string, stream->str->length);
		break;

	case 0x00040701:
	case 0x00040703:
	case 0x00040705:
	case 0x0004070b:
	case 0x0004070f:
	case 0x00040713:
	case 0x00040716:
	case 0x0004071d:
	case 0x00040603: /* Messaging, outgoing, server-ack requested */
		break;
	case 0x00130601: /* SNAC Server Side Information Entry List*/
	case 0x001306c9: 
	case 0x001306d6: 
	case 0x0013066a:
	case 0x0013066d: 
	case 0x00130631: 
		/* This is the start of an SSI Entry list, maybe we should 
		 * remember this??? */
		break;
	case 0x00130731:
		if (stream->str[1].length && stream->str[0].length) {
			JOTDOWN(ferret, 
				JOT_DST("ID-IP",frame),
				JOT_PRINT("AIM-Buddy", stream->str[1].the_string, stream->str[1].length),
				JOT_PRINT("AIM-Description", stream->str[0].the_string, stream->str[0].length),
				0);
		}
		break;
	/* Others that I've seen */
	case 0x0017064b:
	case 0x0017065a:
	case 0x0017024c:
	case 0x00170216:
	case 0x00170217:
	case 0x00170218:
	case 0x00170219:
	case 0x0017021a:
	case 0x00170214:
	case 0x0017024a:
	case 0x00170305:
	case 0x00170306:
	case 0x00170313:
	case 0x00170354:
	case 0x00170340:
	case 0x00170343:
	case 0x00170341:
	case 0x00170342:
	case 0x00170348:
	case 0x00170344:
	case 0x00170347:
	case 0x00170345:
	case 0x00170346:
	case 0x00020301:
	case 0x00020302:
	case 0x00020305:
	case 0x00020303:
	case 0x00020304:
	case 0x00030302:
	case 0x00030301:
	case 0x00030304:
	case 0x00040504:
	case 0x00090302:
	case 0x00090301:
	case 0x00020405:
	case 0x00011e1d:
	case 0x00011e06:
	case 0x0004060d:
	case 0x00020601: /* Buddy Info - User Class */
	case 0x00020603: /* Buddy Info - Online Since AND Away Msg Encoding ??? */
	case 0x00020605: /* Buddy Info - Member Since */
	case 0x0002060b: /* Buddy Info - unknown timestamp */
	case 0x0002060d: /* Buddy Info - Capabilities List */
	case 0x0002060f: /* Buddy Info - Session Length */
	case 0x0002061d: /* Buddy Info - Available Message */
	case 0x0002061f: /* Buddy Info - unknown */
	case 0x00020623: /* Buddy Info - unknown timestamp */
	case 0x00020626: /* Buddy Info - unknown timestamp (member since?) */
	case 0x00020627: /* Buddy Info - unknown timestamp */

		break;
	case 0x001306C8: /*SSI: members of this group */
		break;
	default:
		/* TODO: add SAMPLE here */
		switch (h&0xFFFFFF00) {
		case 0x00130300:
			break;
		default:
			FRAMERR(frame, "%s: unknown TLV tag: 0x%08x\n", "AIM", h);
		}
		break;
	}
	strfrag_finish(stream->str);
}

static unsigned
parse_ssi_entry(struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct Ferret *jot = frame->sess->eng->ferret;
	enum {
		SSI_BUDDYLEN_HI, SSI_BUDDYLEN_LOW, SSI_BUDDY, SSI_BUDDY_DONE,
		SSI_GROUPID_HI, SSI_GROUPID_LO,
		SSI_BUDDYID_HI, SSI_BUDDYID_LO,
		SSI_TYPE_HI, SSI_TYPE_LOW,
		SSI_TLVLEN_HI, SSI_TLVLEN_LO,

		SNAC_TLV_START,
		SNAC_TLV_TAG_HI, SNAC_TLV_TAG_LO, SNAC_TLV_LEN_HI, SNAC_TLV_LEN_LO,
		SNAC_TLV_DATA,
		SNAC_TLV_DONE,
		SNAC_IGNORE,
	};
	struct AIMPARSER *aim = &stream->app.aim;
	unsigned offset = 0;
	
	
	while (offset<length)
	switch (aim->ssi_state) {
	case SSI_BUDDYLEN_HI:
		aim->tlv_len = px[offset++];
		aim->ssi_state++;
		break;
	case SSI_BUDDYLEN_LOW: 
		aim->tlv_len <<= 8;
		aim->tlv_len |= px[offset++];
		aim->ssi_state++;
		strfrag_init(stream->str);
		strfrag_init(stream->str+1);
		break;
	case SSI_BUDDY:
		if (aim->tlv_len) {
			unsigned sublen;
			if (aim->tlv_len < length-offset)
				sublen = aim->tlv_len;
			else
				sublen = length-offset;
			strfrag_append(stream->str+1, px+offset, sublen);
			offset += sublen;
			aim->tlv_len -= sublen;
		}
		if (aim->tlv_len == 0) {
			aim->ssi_state = SSI_BUDDY_DONE;
		}
		break;
	case SSI_BUDDY_DONE:
		aim->ssi_state++;
		break;
	case SSI_GROUPID_HI: 
	case SSI_GROUPID_LO:
		/* just ignore these fields */
		aim->ssi_state++;
		offset++;
		break;
	case SSI_BUDDYID_HI: 
	case SSI_BUDDYID_LO:
		/* just ignore these fields */
		aim->ssi_state++;
		offset++;
		break;
	case SSI_TYPE_HI:
		aim->ssi_buddy_type = px[offset++];
		aim->ssi_state++;
		break;
	case SSI_TYPE_LOW:
		aim->ssi_buddy_type <<= 8;
		aim->ssi_buddy_type |= px[offset++];
		aim->ssi_state++;
		if (stream->str[1].length)
		switch (aim->ssi_buddy_type) {
		case 0x0000: /* individual */
			/* TODO: I should also remember what group it is in */
			if (aim->ssi_group)
				JOTDOWN(jot, 
					JOT_DST("ID-IP",frame),
					JOT_PRINT("AIM-Buddy", stream->str[1].the_string, stream->str[1].length),
					JOT_PRINT("AIM-Group", aim->ssi_group->str, aim->ssi_group->length),
					0);
			else
				JOTDOWN(jot, 
					JOT_DST("ID-IP",frame),
					JOT_PRINT("AIM-Buddy", stream->str[1].the_string, stream->str[1].length),
					0);
			break;
		case 0x0001: /* group */
			aim->ssi_group = stringtab_lookup(frame->sess->eng->stringtab, stream->str[1].the_string, stream->str[1].length);
			strfrag_finish(&stream->str[1]);
			break;
		default:
			/*TODO: add SAMPLE */
			break;
		}
		break;
	case SSI_TLVLEN_HI:
		aim->ssi_len = px[offset++];
		aim->ssi_state++;
		break;
	case SSI_TLVLEN_LO:
		aim->ssi_len <<= 8;
		aim->ssi_len |= px[offset++];
		aim->ssi_state++;
		break;
	case SNAC_TLV_START:
	case SNAC_TLV_TAG_HI:
	case SNAC_TLV_TAG_LO:
	case SNAC_TLV_LEN_HI:
	case SNAC_TLV_LEN_LO:
	case SNAC_TLV_DATA:
	case SNAC_TLV_DONE:
		while (offset<length && aim->ssi_len > 0)
		switch (aim->ssi_state) {
		case SNAC_TLV_START:
			strfrag_init(stream->str);
			aim->ssi_state++;
			break;
		case SNAC_TLV_TAG_HI:
			aim->tlv_tag = px[offset++];
			aim->ssi_len--;
			aim->ssi_state++;
			break;
		case SNAC_TLV_TAG_LO:
			aim->tlv_tag <<= 8;
			aim->tlv_tag |= px[offset++];
			aim->ssi_len--;
			aim->ssi_state++;
			break;
		case SNAC_TLV_LEN_HI:
			aim->tlv_len = px[offset++];
			aim->ssi_len--;
			aim->ssi_state++;
			break;
		case SNAC_TLV_LEN_LO:
			aim->tlv_len <<= 8;
			aim->tlv_len |= px[offset++];
			aim->ssi_len--;
			aim->ssi_state++;
			break;
		case SNAC_TLV_DATA:
			if (aim->tlv_len && aim->ssi_len) {
				unsigned sublen;

				if (aim->tlv_len < length-offset)
					sublen = aim->tlv_len;
				else
					sublen = length-offset;
				if (sublen > aim->ssi_len)
					sublen = aim->ssi_len;

				parse_tlv(stream, frame, px+offset, sublen);

				offset += sublen;
				aim->tlv_len -= sublen;
				aim->ssi_len -= sublen;
			}

			/* We can get here 3 ways.
			 * #1 - the TLV len could have started at zero, in
			 *      which case there is no real data to process.
			 * #2 - the TLV len had a value that crossed packets,
			 *      and we slowly decremented it by bits
			 # #3 - we got here right after processing a chunk
			 */
			if (aim->tlv_len == 0 || aim->ssi_len == 0) {
				/* If done parsing the TLV, then do a 'close' operation by
				 * sending a NULL data pointer */
				parse_tlv(stream, frame, 0, 0);
				aim->ssi_state = SNAC_TLV_DONE;
			}
			break;
		case SNAC_TLV_DONE:
			aim->ssi_state = SNAC_TLV_START;
			break;
		}
		if (aim->ssi_len == 0)
			return offset; /* return the number of bytes we analyzed */
		break;
	case SNAC_IGNORE:
		/* Just ignore the remainder of the data from this point on */
		offset = length;
		break;
	}

	return offset;
}

static void 
parse_aim_snac(struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	enum {
		SNAC_START,
		SNAC_FAMILY_HI, SNAC_FAMILY_LO, 
		SNAC_SUBTYPE_HI, SNAC_SUBTYPE_LO, 
		SNAC_FLAGS_HI, SNAC_FLAGS_LO, 
		SNAC_REQUESTID_0, SNAC_REQUESTID_1, SNAC_REQUESTID_2, SNAC_REQUESTID_3, 
		SNAC_REQUEST_DONE,
		SNAC_REQUEST_DATA,
		SNAC_TLV_START,
		SNAC_TLV_TAG_HI, SNAC_TLV_TAG_LO, SNAC_TLV_LEN_HI, SNAC_TLV_LEN_LO,
		SNAC_TLV_DATA,
		SNAC_TLV_DONE,
		SNAC_IGNORE,

		SNAC_ONCOMING_PRE_BUDDY1,
		SNAC_ONCOMING_PRE_BUDDY2,
		SNAC_ONCOMING_PRE_BUDDY3,
		SNAC_ONCOMING_BUDDY, SNAC_ONCOMING_BUDDY_NAME,

		SNAC_SSI_UNKNOWN_HI, SNAC_SSI_UNKNOWN_LO,
		SNAC_SSI_VERSION, SNAC_SSI_OBJ_COUNT_HI, SNAC_SSI_OBJ_COUNT_LO,
		SNAC_SSI_ENTRY,


		SNAC_SKIP_TO_BUDDY,SNAC_SKIP_TO_TLV,
	};
	struct AIMPARSER *aim = &stream->app.aim;
	unsigned offset = 0;

	/* Do the 'close' fucntion that indicates we we've reached the end
	 * of the encapsulating FLAP packet, telling us that anything left undone
	 * parsing the inside SNAC data needs to finish */
	if (px == NULL) {
		if (aim->tlv_len) {
			/* Check to see if the PDU was truncated in the middle
			 * of a TLV */
			FRAMERR(frame, "%s: truncated\n", "AIM");
		}
		return;
	}


	/* Run through the state machine */
	while (offset<length)
	switch (aim->snac_state) {
	case SNAC_START:
		aim->snac_state++;
		break;
	case SNAC_FAMILY_HI:
	case SNAC_FAMILY_LO:
		aim->pdu.family <<= 8;
		aim->pdu.family |= px[offset++];
		aim->snac_state++;
		break;

	case SNAC_SUBTYPE_HI:
	case SNAC_SUBTYPE_LO:
		aim->pdu.subtype <<= 8;
		aim->pdu.subtype |= px[offset++];
		aim->snac_state++;
		break;

	case SNAC_FLAGS_HI:
	case SNAC_FLAGS_LO:
		aim->pdu.flags <<= 8;
		aim->pdu.flags |= px[offset++];
		aim->snac_state++;
		break;

	case SNAC_REQUESTID_0:
	case SNAC_REQUESTID_1:
	case SNAC_REQUESTID_2:
	case SNAC_REQUESTID_3:
		aim->pdu.request_id <<= 8;
		aim->pdu.request_id |= px[offset++];
		aim->snac_state++;
		break;
	case SNAC_REQUEST_DONE:
		if (aim->pdu.channel == 2) {
			switch (aim->pdu.family<<16 | aim->pdu.subtype) {
			case 0x00040006: /* Outgoing Message */
			case 0x00040007: /* Incoming Message */
			case 0x00040014: /* typin to buddy */
				aim->skip_len = 10;
				aim->snac_state = SNAC_SKIP_TO_BUDDY;
				break;
			case 0x0003000b:
			case 0x00020015:
			case 0x00020006:
				aim->snac_state = SNAC_ONCOMING_BUDDY;
				break;
			case 0x00130006: /* family=Server Side Info, subtype=List */
				/* This is a special structure, but it starts with
				 * a 2-byte number followed by a TLV */
				aim->snac_state = SNAC_SSI_UNKNOWN_HI;
				break;
			case 0x00170007: /* signon reply*/
				/* It's just LEN-VALUE encoded, so pretend there is a tag in 
				 * front */
				aim->tlv_tag = 0;
				aim->snac_state = SNAC_TLV_LEN_HI;
				break;
			case 0x00010017: /* family=Generic, subtype=Capabilities */
			case 0x00010018: /* family=Generic, subtype=Capabilities ACK*/
			case 0x00010006: /* family=Generic, subtype=Rate Info request*/
			case 0x00010007: /* family=Generic, subtype=Rate Info responset*/
			case 0x00010008: /* family=Generic, subtype=Rate Info ACK*/
			case 0x00010003:
			case 0x00010002:
			case 0x00040002: /* family=messaging, subtype= Set ICBM Parameter*/
			case 0x00040005: /* family=messaging, subtype=parameter info */
			case 0x0013000e: /* family=aim SSI, subtype=server ack*/
			case 0x00130009: /* family=aim SSI, subtype=modify buffy*/
			case 0x000d0009: /* family=ChatNav , subtype=Info*/
				/* These don't have TLV, but some other data inside */
				aim->snac_state = SNAC_IGNORE;
				break;
			case 0x00010013: /* family=Generic, subtype=message-of-the-day*/
				/* This has some TLVs later in the packet, but starts with
				 * some non-TLV info */
				aim->snac_state = SNAC_IGNORE;
				break;
			case 0x00170002:
			case 0x00170003:
			case 0x00170006:
			case 0x0001001e: /* family=generic, subtype=0x1e*/
				aim->snac_state = SNAC_TLV_START;
				break;
			default:
				switch (aim->pdu.family) {
				case 1:
				case 0x13: /* AIM SSI */
				case 0x18: /* e-mail */
					/* These (probably) don't have TLV stuff */
					aim->snac_state = SNAC_IGNORE;
					break;
				default:
					/* These (probably) have TLV stuff */
					aim->snac_state = SNAC_TLV_START;
				}
				break;

			}
		} else
			aim->snac_state = SNAC_IGNORE;
		break;
	case SNAC_TLV_START:
		strfrag_init(stream->str);
		aim->snac_state++;
		break;
	case SNAC_TLV_TAG_HI:
		aim->tlv_tag = px[offset++];
		aim->snac_state++;
		break;
	case SNAC_TLV_TAG_LO:
		aim->tlv_tag <<= 8;
		aim->tlv_tag |= px[offset++];
		aim->snac_state++;
		break;
	case SNAC_TLV_LEN_HI:
		aim->tlv_len = px[offset++];
		aim->snac_state++;
		break;
	case SNAC_TLV_LEN_LO:
		aim->tlv_len <<= 8;
		aim->tlv_len |= px[offset++];
		aim->snac_state++;
		break;
	case SNAC_TLV_DATA:
		if (aim->tlv_len) {
			unsigned sublen;

			if (aim->tlv_len < length-offset)
				sublen = aim->tlv_len;
			else
				sublen = length-offset;

			parse_tlv(stream, frame, px+offset, sublen);

			offset += sublen;
			aim->tlv_len -= sublen;
		}

		/* We can get here 3 ways.
		 * #1 - the TLV len could have started at zero, in
		 *      which case there is no real data to process.
		 * #2 - the TLV len had a value that crossed packets,
		 *      and we slowly decremented it by bits
		 # #3 - we got here right after processing a chunk
		 */
		if (aim->tlv_len == 0) {
			/* If done parsing the TLV, then do a 'close' operation by
			 * sending a NULL data pointer */
			parse_tlv(stream, frame, 0, 0);
			aim->snac_state = SNAC_TLV_DONE;
		}
		break;
	case SNAC_TLV_DONE:
		switch (aim->pdu.family<<16 | aim->pdu.subtype) {
		case 0x00130006: /* family=Server Side Info, subtype=List */
			/* This has non-TLV data following the TLV */
			aim->snac_state = SNAC_SSI_VERSION;
			break;
		default:
			aim->snac_state = SNAC_TLV_START;
		}
		break;
	case SNAC_IGNORE:
		/* Just ignore the remainder of the data from this point on */
		offset = length;
		break;


	case SNAC_ONCOMING_PRE_BUDDY1:
	case SNAC_ONCOMING_PRE_BUDDY2:
	case SNAC_ONCOMING_PRE_BUDDY3:
		offset++;
		aim->snac_state++;
		break;
	case SNAC_ONCOMING_BUDDY:
		/* The buddy stuff doesn't have a TLV header, so we need
		 * to parse it separately */
		aim->tlv_tag = 0x0000; /* pseudo tag */
		aim->tlv_len = px[offset++];
		if (aim->tlv_len == 0) {
			aim->snac_state = SNAC_ONCOMING_PRE_BUDDY1; 
		} else {
			strfrag_init(stream->str);
			aim->snac_state++;
		}
		break;
	case SNAC_ONCOMING_BUDDY_NAME:
		if (aim->tlv_len) {
			unsigned sublen;
			if (aim->tlv_len < length-offset)
				sublen = aim->tlv_len;
			else
				sublen = length-offset;
			strfrag_append(stream->str, px+offset, sublen);
			offset += sublen;
			aim->tlv_len -= sublen;
		}
		if (aim->tlv_len == 0) {
			/* Save the buddy name */
			strfrag_copy(&stream->str[1], &stream->str[0]);

			/* If done parsing the TLV, then do a 'close' operation by
			 * sending a NULL data pointer */
			parse_tlv(stream, frame, 0, 0);


			switch (aim->pdu.family<<16 | aim->pdu.subtype) {
			case 0x00040006: /* Outgoing Message */
				aim->skip_len = 0;
				aim->snac_state = SNAC_SKIP_TO_TLV;
				break;
			case 0x00040007: /* Incoming Message */
			case 0x00020006: /* Incoming Buddy User Info */
				aim->skip_len = 4;
				aim->snac_state = SNAC_SKIP_TO_TLV;
				break;
			case 0x00040015: /* User Info Query */
				break;
			default:
				aim->snac_state = SNAC_IGNORE;
				break;
			}
		}
		break;
	case SNAC_SSI_UNKNOWN_HI:
		offset++;
		aim->snac_state++;
		break;
	case SNAC_SSI_UNKNOWN_LO:
		offset++;
		aim->snac_state = SNAC_TLV_START;
		break;
	case SNAC_SSI_VERSION:
		if (px[offset++] != 0)
			aim->snac_state = SNAC_IGNORE; /* don't understand this version */
		else
			aim->snac_state = SNAC_SSI_OBJ_COUNT_HI;
		break;
	case SNAC_SSI_OBJ_COUNT_HI:
		aim->ssi_obj_count = px[offset++];
		aim->snac_state++;
		break;
	case SNAC_SSI_OBJ_COUNT_LO:
		aim->ssi_obj_count <<= 8;
		aim->ssi_obj_count |= px[offset++];
		aim->snac_state++;
		break;
	case SNAC_SSI_ENTRY:
		/* Loop through a number of entries */
		while (offset<length && aim->ssi_obj_count) {
			unsigned sublen;

			/* Parse a fragment of data. This function only parses a SINGLE
			 * fragment. Therefore, the returned 'sublen' may be smaller than
			 * the one passed into it */
			aim->ssi_state = 0;
			sublen = parse_ssi_entry(stream, frame, px+offset, length-offset);

			offset += sublen;

			aim->ssi_obj_count--;
		}

		/* there is some more info past the entries, but just ingore it */
		if (aim->ssi_obj_count == 0) {
			aim->snac_state = SNAC_IGNORE;
			strfrag_finish(stream->str+0);
			strfrag_finish(stream->str+1);
		}
		break;
	case SNAC_SKIP_TO_BUDDY:
		{
			unsigned sublen = aim->skip_len;
			if (sublen > length-offset)
				sublen = length-offset;
			aim->skip_len -= sublen;
			offset += sublen;

			if (aim->skip_len == 0)
				aim->snac_state = SNAC_ONCOMING_BUDDY;
		}
		break;
	case SNAC_SKIP_TO_TLV:
		{
			unsigned sublen = aim->skip_len;
			if (sublen > length-offset)
				sublen = length-offset;
			aim->skip_len -= sublen;
			offset += sublen;

			if (aim->skip_len == 0)
				aim->snac_state = SNAC_TLV_START;
		}
		break;
	}
}

unsigned smellslike_aim_oscar(const unsigned char *px, unsigned length)
{
	unsigned pdu_length;
	unsigned offset=0;
	unsigned i;

/*
  +--------+--------+
  |  0x2a  | channel|
  +--------+--------+
  |      seqno      |
  +--------+--------+
  |      length     |
  +--------+--------+
  |                 |
  0x2a:
  This is always the first byte of a PDU

  CHANNEL:
	0x01 - New Connection Negotiation
	0x02 - SNAC data (non connection-oriented data)
	0x03 - FLAP-level Error
	0x04 - Close Connection Negotiation
*/
	for (i=0; i<2; i++) {
	/* make sure we have enbough bytes in the header */
	if (offset+6 > length)
		return 0;

	/* make sure the first byte is the expect '0x2a' that's at the
	 * start of all AIM/OSCAR pdus */
	if (px[offset] != 0x2a)
		return 0;

	/* make sure the channel is within the expected range */
	if (px[offset+1] < 0x01 || 0x04 <= px[offset+1])
		return 0;

	/* check to see if the length is precisely the size of the TCP
	 * payload. This wouldn't work if the packet was fragmented, of 
	 * course */
	pdu_length = ex16be(px+offset+4);
	if (length < 6+pdu_length)
		return 0; /* TCP packet too small*/
	if (length == 6+pdu_length)
		return 1; /* TCP packet just right */

	/* the packet was too long. this may be due to multiple pdus in
	 * a single TCP packet. Therefore, we are going to check the next
	 * one */
	offset += 6 + pdu_length;
	}

	/* We've made it through two loops of the above sequence. There
	 * might be even more, but we'll end here because we have enough
	 * to be pretty sure */
	return 1;
}

void parse_aim_oscar(struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	enum {
		FLAP_START,
		FLAP_CMD_0x2a, FLAP_CHANNEL, FLAP_SEQNO_HI, FLAP_SEQNO_LO,
		FLAP_LENGTH_HI, FLAP_LENGTH_LO, FLAP_LENGTH_DONE,
		FLAP_DATA,
	};
	
	struct AIMPARSER *aim = &stream->app.aim;
	unsigned offset=0;

	frame->layer7_protocol = LAYER7_AIM;

	/* Run the bytes through the state machine */
	while (offset<length)
	switch (aim->flap_state) {
	case FLAP_START:
		memset(aim, 0, sizeof(*aim));
		aim->flap_state++;
		break;
	case FLAP_CMD_0x2a:
		if (px[offset] != 0x2a) {

			/* TEMP: notify on corruption so I can look at some samples */
			FRAMERR(frame, "%s: corrupt", "AIM");

			/* If the first byte isn't the well-known command byte,
			 * then ignore the content and scan forward looking for 
			 * it. */
			FRAMERR(frame, "%s: unknown\n", "AIM");
			offset++;
			while (offset<length) {
				/* scan forward looking for the 0x2a byte */
				while (offset<length && px[offset] != 0x2a)
					offset++;
				if (offset+1<length) {
					if (offset<length && px[offset+1] == 2) {
						break;
					} else
						offset++;
				} else if (offset<length) {
					offset++;
				}
			}
		} else {
			offset++;
			aim->flap_state++;
		}
		break;
	case FLAP_CHANNEL:
		aim->pdu.channel = px[offset++];
		aim->flap_state++;
		break;
	case FLAP_SEQNO_HI:
	case FLAP_SEQNO_LO:
		aim->pdu.seqno <<= 8;
		aim->pdu.seqno |= px[offset++];
		aim->flap_state++;
		break;

	case FLAP_LENGTH_HI:
	case FLAP_LENGTH_LO:
		aim->pdu.length <<= 8;
		aim->pdu.length |= px[offset++];
		aim->flap_state++;
		break;

	case FLAP_LENGTH_DONE:
		aim->remaining = aim->pdu.length;
		aim->snac_state = 0; /*SNAC_START*/
		aim->flap_state++;
		break;
	case FLAP_DATA:
		/* If we still have remaining data in the PDU, then parse it.
		 * Otherwise, just go back and look for a new FLAP PDU header */
		if (aim->remaining) {
			unsigned sublen;

			/* Figure out the segment of data to send to the data parser.
			 * This will be the MIN between the packet size and remaining
			 * data */
			if (aim->remaining < length-offset)
				sublen = aim->remaining;
			else
				sublen = length-offset;

			/* Send it to the appropriate parser, depending upon the 
			 * channel-number and state info */
			switch (aim->pdu.channel) {
			case 2: /*SNAC*/
				parse_aim_snac(stream, frame, px+offset, sublen);
				break;
			default:
				parse_aim_data(stream, frame, px+offset, sublen);
				break;
			}

			/* 'consume' the segment of data. If we have completely
			 * consumed the data, then this will automatically go
			 * back to the starting state to get the next PDU */
			offset += sublen;
			aim->remaining -= sublen;

		}

		/* If we have just parsed the above chunk, we'll probably
		 * go directly here. Note that we need to need to double-check
		 * this at the end of the packet so that house-keeping can more
		 * easily age out connections that are in their default states. */
		if (aim->remaining == 0)
			aim->flap_state = FLAP_START;
		break;

	}
}

void parse_aim_oscar_to_server(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	parse_aim_oscar(stream, frame, px, length);
}
void parse_aim_oscar_from_server(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	parse_aim_oscar(stream, frame, px, length);
}
