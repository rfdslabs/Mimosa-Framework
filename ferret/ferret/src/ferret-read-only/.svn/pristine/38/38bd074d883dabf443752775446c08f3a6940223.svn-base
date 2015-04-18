/* Copyright (c) 2008 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "platform.h"
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"

enum {
        YAHOO_SERVICE_LOGON				= 0x01,
        YAHOO_SERVICE_LOGOFF			= 0x02,
        YAHOO_SERVICE_ISAWAY			= 0x03,
        YAHOO_SERVICE_ISBACK			= 0x04,
        YAHOO_SERVICE_IDLE              = 0x05,
        YAHOO_SERVICE_MESSAGE			= 0x06,
        YAHOO_SERVICE_IDACT				= 0x07,
        YAHOO_SERVICE_IDDEACT			= 0x08,
        YAHOO_SERVICE_MAILSTAT			= 0x09,
        YAHOO_SERVICE_USERSTAT          = 0x0a,
        YAHOO_SERVICE_NEWMAIL			= 0x0b,
        YAHOO_SERVICE_CHATINVITE		= 0x0c,
        YAHOO_SERVICE_CALENDAR			= 0x0d,
        YAHOO_SERVICE_NEWPERSONALMAIL	= 0x0e,
        YAHOO_SERVICE_NEWCONTACT        = 0x0f,
        YAHOO_SERVICE_ADDIDENT          = 0x10,
        YAHOO_SERVICE_ADDIGNORE			= 0x11,
        YAHOO_SERVICE_PING				= 0x12,
        YAHOO_SERVICE_GROUPRENAME		= 0x13,
        YAHOO_SERVICE_SYSMESSAGE        = 0x14,
        YAHOO_SERVICE_PASSTHROUGH2      = 0x16,
        YAHOO_SERVICE_CONFINVITE        = 0x18,
        YAHOO_SERVICE_CONFLOGON			= 0x19,
        YAHOO_SERVICE_CONFDECLINE       = 0x1a,
        YAHOO_SERVICE_CONFLOGOFF		= 0x1b,
        YAHOO_SERVICE_CONFADDINVITE		= 0x1c,
        YAHOO_SERVICE_CONFMSG			= 0x1d,
        YAHOO_SERVICE_CHATLOGON			= 0x1e,
        YAHOO_SERVICE_CHATLOGOFF        = 0x1f,
        YAHOO_SERVICE_CHATMSG           = 0x20,
        YAHOO_SERVICE_GAMELOGON         = 0x28,
        YAHOO_SERVICE_GAMELOGOFF		= 0x29,
        YAHOO_SERVICE_GAMEMSG           = 0x2a,
        YAHOO_SERVICE_FILETRANSFER      = 0x46,
        YAHOO_SERVICE_VOICECHAT         = 0x4a,
        YAHOO_SERVICE_NOTIFY            = 0x4b,
        YAHOO_SERVICE_P2PFILEXFER       = 0x4d,
        YAHOO_SERVICE_PEERTOPEER        = 0x4f,
        YAHOO_SERVICE_AUTHRESP          = 0x54,
        YAHOO_SERVICE_LIST              = 0x55,
        YAHOO_SERVICE_AUTH              = 0x57,
        YAHOO_SERVICE_ADDBUDDY          = 0x83,
        YAHOO_SERVICE_REMBUDDY          = 0x84,
        YAHOO_SERVICE_IGNORECONTACT     = 0x85,
        YAHOO_SERVICE_REJECTCONTACT     = 0x86,
};

/**
 * The YMSG protocol contains a bunch of tag-value pairs,
 * where the tag is an ASCII number. These fields are delimitted
 * by the two-byte sequence 0xC0 0x80. Thus, a field might contains
 * 0x30 0xC0 0x80 (where 0x30 is ASCII for the character '1')
 * 0x41 0x42 0x43 0xC0 0x80 (where these numbers stand for 'A' 'B' 'C')
 */
static void
ymsg_get_next_pair(struct StringReassembler *ymsg_packet, unsigned *r_offset, struct Atom *tag, struct Atom *value)
{
	const unsigned char *px = ymsg_packet->the_string;
	unsigned length = ymsg_packet->length;
	unsigned offset = *r_offset;

	tag->px = px;
	tag->offset = offset;
	tag->len = 0;

	value->px = px;
	value->offset = offset;
	value->len = 0;

	/* Grab the tag */
	while (offset < length) {
		if (px[offset] == 0xC0 && offset+1 < length && px[offset+1] == 0x80) {
			tag->len = offset-tag->offset;
			offset += 2;
			break;
		} else
			offset++;
	}

	/* Grab the value */
	value->offset = offset;
	while (offset < length) {
		if (px[offset] == 0xC0 && offset+1 < length && px[offset+1] == 0x80) {
			value->len = offset-value->offset;
			offset += 2;
			break;
		} else
			offset++;
	}

	*r_offset = offset;
}

/**
 * Given the 'tag' of a 'tag-value' pair, return the value if
 * exists
 */
static struct Atom
ymsg_get_enumerated_item(struct StringReassembler *ymsg_packet, const char *tag_name)
{
	const unsigned char *px = ymsg_packet->the_string;
	unsigned length = ymsg_packet->length;
	unsigned offset = 0;
	struct Atom empty;

	while (offset < length) {
		struct Atom tag;
		struct Atom value;

		ymsg_get_next_pair(ymsg_packet, &offset, &tag, &value);

		if (!atom_is_number(tag)) {
			//FRAMERR(frame, "YMSG.tag bad value %.*s", atom.px+atom.offset, atom.length);
			//return;
		}

		if (atom_equals_ignorecase(tag, tag_name)) 
			return value;
	}


	empty.px = px;
	empty.offset = offset;
	empty.len = 0;
	return empty;
}


void process_ymsg_client_request(
		struct TCPRECORD *sess, 
		struct NetFrame *frame, 
		struct StringReassembler *ymsg_packet)
{
	struct FerretEngine *eng = sess->eng;
	struct Ferret *ferret = eng->ferret;
	struct TCP_STREAM *stream = &sess->to_server;
	unsigned service = stream->app.ymsg.service;
	unsigned status = stream->app.ymsg.status;
	struct Atom atom;


	switch (service) {
	
	case 18: /* Ping */

		break;
	
	case 0x54: /*YAHOO_SERVICE_AUTHRESP - Response to server challenge */
		switch (status) {
		case 0:
		case 1515563605: /* Web Login: Ref: 2009-01-24-1.pcap(6243) */
			atom = ymsg_get_enumerated_item(ymsg_packet, "0"); /* "yahoo_id" */
			if (atom.len) {
				JOTDOWN(ferret,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("username", atom.px+atom.offset, atom.len),
					0);
				strncpy_s((char*)stream->app.ymsg.username, sizeof(stream->app.ymsg.username), (char*)atom.px+atom.offset, atom.len);
			}
			atom = ymsg_get_enumerated_item(ymsg_packet, "1"); /* "active_id", which may differ from "yahoo_id" */
			if (atom.len) {
				JOTDOWN(ferret,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("username", atom.px+atom.offset, atom.len),
					0);
				strncpy_s((char*)stream->app.ymsg.username, sizeof(stream->app.ymsg.username), (char*)atom.px+atom.offset, atom.len);
			}

			/* 
			 * Report challenge/response for password-cracking tools
			 */
			if (sess->from_server.str[1].length) { /* if we have a challenge from the other direction */
				strfrag_init(&sess->from_server.str[1]);
			}

			break;
		default:
			FRAMERR_UNPARSED(frame, "YMSG.service", service);
		}
		break;

	/*YAHOO_SERVICE_AUTH		Authentication */
	case 0x57: 
		switch (status) {
		case 0:
			atom = ymsg_get_enumerated_item(ymsg_packet, "1"); /* "yahoo_id" */
			if (atom.len) {
				JOTDOWN(ferret,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("username", atom.px+atom.offset, atom.len),
					0);
				strncpy_s((char*)stream->app.ymsg.username, sizeof(stream->app.ymsg.username), (char*)atom.px+atom.offset, atom.len);
			}
			break;
		default:
			FRAMERR_UNPARSED(frame, "YMSG.service", service);
		}
		break;
	case 198: /* Yahoo v6 Status Update */
		break;
	case 138:
		/* Ref: 2009-01-24-1.pcap(1441) */
		/* Appears to be the user's login name as the one
		 * field in this packet */
		break;
	case 21: /* skin name */
		/* Ref: 2009-01-24-1.pcap(6394) */
		/* TODO
		 * This contains some information about the user's machine, such as 
		 * what type of machine it is */
		break;
	default:
		FRAMERR_UNPARSED(frame, "YMSG.service", service);
	}
}


void process_ymsg_server_response(
		struct TCPRECORD *sess, 
		struct NetFrame *frame, 
		struct StringReassembler *ymsg_packet)
{
	struct FerretEngine *eng = sess->eng;
	struct Ferret *ferret = eng->ferret;
	struct TCP_STREAM *stream = &sess->from_server;
	unsigned service = stream->app.ymsg.service;
	unsigned status = stream->app.ymsg.status;
	struct Atom atom;

	switch (service) {
	/*YAHOO_SERVICE_AUTH		Authentication */
	case 0x57: 
		switch (status) {
		case 1: /*Ack*/
			{
				struct Atom challenge;
				struct Atom algorithm;
			
				atom = ymsg_get_enumerated_item(ymsg_packet, "1"); /* user account name */
				challenge = ymsg_get_enumerated_item(ymsg_packet, "94"); /* challenge from the server */
				algorithm = ymsg_get_enumerated_item(ymsg_packet, "13"); /* which authentication algorithm to use */
			
				/* Note the username */
				if (atom.len) {
					JOTDOWN(ferret,
						JOT_DST("ID-IP", frame),
						JOT_PRINT("username", atom.px+atom.offset, atom.len),
						0);
					strncpy_s((char*)stream->app.ymsg.username, sizeof(stream->app.ymsg.username), (char*)atom.px+atom.offset, atom.len);
				}

				/* Note the password hash */
				if (atom.len && challenge.len && algorithm.len && atom_is_number(algorithm)) {
					strfrag_init(stream->str+1);
					strfrag_append(stream->str+1, challenge.px+challenge.offset, challenge.len);
					stream->app.ymsg.pwhash_algorithm = atom_to_number(algorithm);
				}
			}
			break;
		default:
			FRAMERR_UNPARSED(frame, "YMSG.service", service);
		}
		break;
	case 85: /* Ref: 2009-01-24-1.pcap(6320) */
		atom = ymsg_get_enumerated_item(ymsg_packet, "3"); /* user account name */
		if (atom.len) {
			JOTDOWN(ferret,
				JOT_DST("ID-IP", frame),
				JOT_PRINT("username", atom.px+atom.offset, atom.len),
				0);
			strncpy_s((char*)stream->app.ymsg.username, sizeof(stream->app.ymsg.username), (char*)atom.px+atom.offset, atom.len);
		}
		break;
	case 241:
		/* Ref: 2009-01-24-1.pcap(6323) */
		/*TODO*/
		break;
	case 240:
		/* Ref: 2009-01-24-1.pcap(6326) */
		/*TODO*/
		break;
	case 239:
		/* Ref: 2009-01-24-1.pcap(6326) */
		/*TODO*/
		break;
	case 18:
		/* Ref: 2009-01-24-1.pcap(6326) */
		/*TODO*/
		break;
	case 11: /* new mail has arrived */
		/* Ref: 2009-01-24-1.pcap(8505) */
		/*TODO*/
		break;
	default:
		FRAMERR_UNPARSED(frame, "YMSG.service", service);
	}
}


