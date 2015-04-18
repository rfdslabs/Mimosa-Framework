/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-extract.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-tcp.h"
#include "util-mystring.h"
#include "util-memcasecmp.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>


/*
FROM SERVER commands
QNG
	Response from a PNG (ping) command that says how many seconds remain
	before the server expects another ping.

	Examples:
		QNG 42

		This example is a response to a ping where the server acknowledges the ping,
		and indicates that it wants another ping within 42 seconds.

*/

/* FROM CLIENT commands

VER
	The client notifies the server of which protocol it is using.

	The major versions are MSNP8, MSNP9, and MSNP10

	Examples:

		VER 1 MSNP8 CVR0

MSG
	This command sends a message
*/

#define CMD(str) ( (str[0]<<24) | (str[1]<<16) | (str[2]<<8) | (str[3]<<0) )

static unsigned msg_header_length(struct StringReassembler *data)
{
	unsigned i;
	const unsigned char *px = data->the_string;
	unsigned length = data->length;

	for (i=0; i<length; i++) {
		if (px[i] == '\n') {
			i++;
			if (i<length && px[i] == '\n')
				return i+1;
			if (i+1<length && px[i] == '\r' && px[i+1] == '\n')
				return i+2;
		}
	}
	return length;
}


/**
 * Instead of doing a series of if-then-else string tests for
 * commands, we just hash them for a single switch() statement.
 * This works because the command are all 4 or fewer characters,
 * so the actual hash should be completely unique.
 * SECURITY: Somebody could intentionally confuse the parser
 * by making a command that is more than 4 characters that
 * hashes to a known value. This wouldn't hurt us for Ferret,,
 * but if somebody else copies this code, then it could
 * be a problem for them.
 */
unsigned hash_command(struct Atom cmd)
{
	unsigned result = 0;
	unsigned i;

	for (i=0; i<cmd.len; i++) {
		unsigned shift = 3-(i%4);

		result ^= cmd.px[cmd.offset+i] << (shift*8);
	}

	return result;
}

#define X_CMD(a,b,c,d) ((a<<24) | (b<<16) | (c<<8) | (d))



/**
 * Certain commands have a "length" value that indicate additional lines
 * of data contain more stuff associated with the command. For example, the
 * "MSG" command will be followed my multiple lines containing message
 * data. This command looks for one of those length fields and returns
 * it.
 */
unsigned msn_more_response_length(struct StringReassembler *command)
{
	unsigned offset = 0;
	struct Atom atom;
	
	/* Get the first string */
	atom = atom_next(command, &offset);


	switch (hash_command(atom)) {
	case X_CMD('2', '0', '5', '\0'): /* 205 */
	case X_CMD('G', 'C', 'F', '\0'): /* GCF */
	case X_CMD('M', 'S', 'G', '\0'): /* MSG - Message */
	case X_CMD('N', 'O', 'T', '\0'): /* NOT - Notification */
	case X_CMD('U', 'B', 'N', '\0'): /* UBN */
	case X_CMD('U', 'B', 'X', '\0'): /* UBX */
	case X_CMD('U', 'U', 'X', '\0'): /* UUX */
		for (;;) {
			struct Atom prev;
			
			memcpy(&prev, &atom, sizeof(atom));

			atom = atom_next(command, &offset);

			if (atom.len == 0 || atom.px == NULL) {
				if (atom_is_number(prev)) {
					return atom_to_number(prev);
				}
				break;
			}
		}
		break;
	default:
		/* Most commands have no additional data */
		;
	}
	return 0;
}

unsigned msn_more_request_length(struct StringReassembler *command)
{
	unsigned offset = 0;
	struct Atom atom;
	
	/* Get the first string */
	atom = atom_next(command, &offset);


	switch (hash_command(atom)) {
	case X_CMD('A', 'D', 'L', '\0'): /* ADL */
	case X_CMD('M', 'S', 'G', '\0'): /* MSG */
	case X_CMD('Q', 'R', 'Y', '\0'): /* QRY */
	case X_CMD('R', 'M', 'L', '\0'): /* RML */
	case X_CMD('U', 'B', 'N', '\0'): /* UBN */
	case X_CMD('U', 'U', 'N', '\0'): /* UUN */
	case X_CMD('U', 'U', 'X', '\0'): /* UUX */
		/* Get the last number on the line */
		for (;;) {
			struct Atom prev;
			
			memcpy(&prev, &atom, sizeof(atom));

			atom = atom_next(command, &offset);

			if (atom.len == 0 || atom.px == NULL) {
				if (atom_is_number(prev)) {
					return atom_to_number(prev);
				}
				break;
			}
		}
		break;
	default:
		/* Most commands have no additional data */
		;
	}
	return 0;
}



static void msg_content_type(struct StringReassembler *data, const unsigned char **r_px, unsigned *r_length)
{
	unsigned i;
	const unsigned char *px = data->the_string;
	unsigned length = data->length;
	unsigned content_type_len = (unsigned)strlen("Content-Type:");
	*r_px = (const unsigned char*)"";
	*r_length = 0;

	for (i=0; i<length; i++) {
		if (px[i] == '\n') {
			i++;
			if (i<length && px[i] == '\n')
				return;
			if (i+1<length && px[i] == '\r' && px[i+1] == '\n')
				return;
			if (i+content_type_len<length && memcasecmp(px+i, "Content-Type:", content_type_len) == 0) {
				unsigned offset;
				i += content_type_len;
				while (i < length && px[i] != '\n' && isspace(px[i]))
					i++;
				offset = i;
				while (i < length && px[i] != '\n' && px[i] != ';')
					i++;
				*r_length = i-offset;
				*r_px = px+offset;

				/* remove trailing whitespace */
				while (*r_length && isspace((*r_px)[*r_length-1]))
					(*r_length)--;
				return;

			}
		}
	}
}

void msg_ignore(struct TCP_STREAM *stream, struct NetFrame *frame, struct StringReassembler *data)
{
	UNUSEDPARM(data);
	UNUSEDPARM(frame);
	UNUSEDPARM(stream);
}
void msg_text_secway(struct TCP_STREAM *stream, struct NetFrame *frame, struct StringReassembler *data)
{
	UNUSEDPARM(data);
	UNUSEDPARM(frame);
	UNUSEDPARM(stream);
	/*
	MSG d95_clj@hotmail.com Carl 290
	MIME-Version: 1.0
	Content-Type: text/x-secway
	Rcpt: brenno@dewinter.com
	MessageType: CryptoRequest
	AsymmetricCipher: Generic; RSA; Diffie-Hellman; None;
	SymmetricCipher: AES-128; 3DES-128; Serpent-128; CAST-128; Twofish-128;
	KeyProviders: Certificate;
	Via: Simp Lite-MSN 2.2.2.11
	*/

}
void msg_msnmsgrp2p(struct TCP_STREAM *stream, struct NetFrame *frame, struct StringReassembler *data)
{
	//const unsigned char *px = data->the_string;
	unsigned offset=0;
	unsigned length = data->length;
#if 0
	struct MSNP2PInfo {
		unsigned channel_session_id;
		unsigned id;
		uint64_t offset;
		uint64_t total_data_size;
		unsigned message_size;
		unsigned flags;
		unsigned ack_id;
		unsigned ack_uid;
		uint64_t ack_size;
	} p2pinfo;
#endif


	offset = msg_header_length(data);

	if (length < offset+48) {
		FRAMERR(frame, "%s: truncated\n", "msnmsgrp2p");
		return;
	}

#if 0
	p2pinfo.channel_session_id = ex32le(px+offset+0);
	p2pinfo.id = ex32le(px+offset+4);
	p2pinfo.offset = ex32le(px+offset+8);
	p2pinfo.total_data_size = ex32le(px+offset+16);
	p2pinfo.message_size = ex32le(px+offset+24);
	p2pinfo.flags = ex32le(px+offset+8);
	p2pinfo.ack_id = ex32le(px+offset+32);
	p2pinfo.ack_uid = ex32le(px+offset+36);
	p2pinfo.ack_size = ex32le(px+offset+40);
	offset += 48;
#endif

	//printf(".");

}
void msg_clientcaps(struct TCP_STREAM *stream, struct NetFrame *frame, struct StringReassembler *data)
{
	/*
MSG 4 U 98
MIME-Version: 1.0
Content-Type: text/x-clientcaps

Client-Name: Purple/2.4.2
Chat-Logging: Y
*/
	UNUSEDPARM(data);
	UNUSEDPARM(frame);
}
void msg_msmsgsprofile(struct TCP_STREAM *stream, struct NetFrame *frame, struct StringReassembler *data)
{
	UNUSEDPARM(data);
	UNUSEDPARM(frame);
/*
MSG Hotmail Hotmail 515
MIME-Version: 1.0
Content-Type: text/x-msmsgsprofile; charset=UTF-8
LoginTime: 1218252230
EmailEnabled: 1
MemberIdHigh: 90496
MemberIdLow: -1586496918
lang_preference: 1036
preferredEmail: 
country: FR
PostalCode: 
Gender: 
Kid: 0
Age: 
BDayPre: 
Birthday: 
Wallet: 
Flags: 1610613827
sid: 507
MSPAuth: 9uDW9DiTTE7c8NVm69SCUmZ1dGh666UhajWgQsrLbWkDRoEcpEO!cWMpqwRPjJFyjwRKD3zV*tQv1Vdk5WwNBuoZ*Xyzq0wIYmQJpUhQZ9R3DvOJH7RNbz6456ll!quFN0&p
ClientIP: 24.120.56.2
ClientPort: 65497
MPOPEnabled: 0
*/
}
static void
msg_text_plain(struct TCP_STREAM *stream, struct NetFrame *frame, struct StringReassembler *data)
{
	struct Ferret *jot = frame->sess->eng->ferret;
	const unsigned char *px = data->the_string;
	unsigned length = data->length;
	unsigned header_length = msg_header_length(data);

	JOTDOWN(jot,
		JOT_SZ("CHAT",			"Message"),
		JOT_SZ("From",			stream->app.msnreq.username),
		JOT_SZ("To",			stream->app.msnreq.toname),
		JOT_PRINT("Message",	px+header_length, length-header_length),
		JOT_SZ("Protocol",		"MSN-MSGR"),
		0);

	UNUSEDPARM(data);
}

void msg_unknown(struct TCP_STREAM *stream, struct NetFrame *frame, struct StringReassembler *data)
{
	const unsigned char *content_type;
	unsigned content_type_length;

	msg_content_type(data, &content_type, &content_type_length);

	FRAMERR(frame, "msn-ms: unknown message from client: %.*s\n", content_type_length, content_type);
}


struct MsgContentTypes {
	const char *content_type;
	void (*pfn_handler)(struct TCP_STREAM *stream, struct NetFrame *frame, struct StringReassembler *data);
} msgcontenttypes[] = {
	{"application/x-msnmsgrp2p", msg_msnmsgrp2p},
	{"text/plain", msg_text_plain},
	{"text/x-clientcaps", msg_clientcaps},
	{"text/x-keepalive", msg_ignore},
	{"text/x-mms-animemoticon", msg_ignore}, /* Regress: defcon2008-msnmsgr.pcap frame(1518) */
	{"text/x-mms-emoticon",		msg_ignore}, /* Regress: defcon2008-msnmsgr.pcap(21298) */
	{"text/x-msmsgscontrol", msg_ignore},
	
	
	{"text/x-msmsgsactivemailnotification", msg_ignore}, /* Regress: defcon2008\dump007.pcap(89918) */
	{"text/x-msmsgsemailnotification", msg_ignore},		/* Regress: defcon2008\dump047.pcap(92249) */
	{"text/x-msmsgsoimnotification", msg_ignore}, /* Regress: defcon2008\dump110.pcap(112361) */
	{"text/x-msmsgsinitialemailnotification", msg_ignore},
	{"text/x-msmsgsinitialmdatanotification", msg_ignore},
	{"text/x-msmsgsprofile", msg_msmsgsprofile},
	{"text/x-secway", msg_text_secway},
	{0,msg_unknown}
};



/**
 * Handle a reassembled server command
 */
void msnms_server_command(
		struct TCPRECORD *sess,
		struct NetFrame *frame, 
		struct StringReassembler *command, 
		struct StringReassembler *data)
{
	struct TCP_STREAM *stream = &sess->to_server;
	struct TCP_STREAM *stream_reverse = &sess->from_server;
	struct Ferret *ferret = frame->sess->eng->ferret;
	struct Atom cmd;
	unsigned offset = 0;
	struct Atom atom;

	UNUSEDPARM(data);

	cmd = atom_next(command, &offset);

	SAMPLE(ferret,"MSN-MSGR", JOT_SZ("command", cmd));
	switch (hash_command(cmd)) {
	case X_CMD('2', '0', '5', '\0'): /* 217 - error message */
		/* Regress: defcon2008-msnmsgr.pcap frame(3488) */
		break;
	case X_CMD('2', '1', '7', '\0'): /* 217 - error message */
		/* Regress: defcon2008-msnmsgr.pcap frame(2393) */
		break;
	case X_CMD('8', '0', '0', '\0'): /* 800 */
		/* Regress: defcon2008\dump006.pcap(101638) */
		break;
	case X_CMD('A', 'D', 'C', '\0'): /* ADC */
		/* Regress: defcon2008\dump056.pcap(61827) */ 
		break;
	case X_CMD('A', 'C', 'K', '\0'): /* ACK */
		break;
	case X_CMD('A', 'D', 'L', '\0'): /* ADL */
		break;
	case X_CMD('A', 'N', 'S', '\0'): /* ANS */
		break;
	case X_CMD('B', 'L', 'P', '\0'): /* BLP */
		break;
	case X_CMD('B', 'P', 'R', '\0'): /* BPR - Buddy personal phone */
		{
			struct Atom num;
			/*
			LST djseba13@hotmail.com (F)-%20*help%20:)%20Seb%20:P 11 4
			BPR PHH 32%2027599906
			BPR PHM 32%20497947496
			<<< LST 54 FL 12182 1 2 example@passport.com Mike 0\r\n
			<<< BPR 12182 example@passport.com PHH\r\n
			<<< BPR 12182 example@passport.com PHW 555%20555-1234\r\n
			<<< BPR 12182 example@passport.com PHM I%20Dont%20Have%20One\r\n
			<<< BPR 12182 example@passport.com MOB N\r\n
			*/
			atom = atom_next(command, &offset);
			if (atom_is_number(atom))
				atom = atom_next(command, &offset);
			num = atom_next(command, &offset);
			switch (hash_command(atom)) {
			case X_CMD('M', 'B', 'E', '\0'): /* MBE - Do I have an MSN Mobile device? */
			case X_CMD('M', 'O', 'B', '\0'): /* MOB - Can others contact my mobile device? */
			case X_CMD('W', 'W', 'E', '\0'): /* WWE */
			case X_CMD('P', 'H', 'H', '\0'): /* PHH - Home phone number */
				JOTDOWN(ferret,
					JOT_SZ("ID-ALIAS", stream->app.msnreq.username),
					JOT_URLENC("Home phone", num.px+num.offset, num.len),
					0);
				break;
			case X_CMD('P', 'H', 'W', '\0'): /* PHW - Work phone number */
				JOTDOWN(ferret,
					JOT_SZ("ID-ALIAS", stream->app.msnreq.username),
					JOT_URLENC("Work phone", num.px+num.offset, num.len),
					0);
				break;
			case X_CMD('P', 'H', 'M', '\0'): /* PHM - Mobile phone number */
				JOTDOWN(ferret,
					JOT_SZ("ID-ALIAS", stream->app.msnreq.username),
					JOT_URLENC("Mobile phone", num.px+num.offset, num.len),
					0);
				break;
			case X_CMD('H', 'S', 'B', '\0'): /* HSB - Has Blog? */
				/* Regress: defcon2008-msnmsgr.pcap(7269) */
				break;
			default:
				FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", cmd.len, cmd.px);
			}
		}
		break;
	case X_CMD('B', 'Y', 'E', '\0'): /* BYE */
		break;
	case X_CMD('C', 'H', 'G', '\0'): /* CHG - Change Presence State */
		break;
	case X_CMD('C', 'H', 'L', '\0'): /* CHL - Server Challenge */
		break;
	case X_CMD('C', 'A', 'L', '\0'): /* CAL - Call response */
		break;
	case X_CMD('C', 'V', 'R', '\0'): /* CVR */
		break;
	case X_CMD('G', 'C', 'F', '\0'): /* GCF - General Configuration */
		/* TODO: parse out the file list and check for new ones */
		break;
	case X_CMD('F', 'L', 'N', '\0'): /* FLN - Friend? */
		break;
	case X_CMD('G', 'T', 'C', '\0'): /* GTC */
		break;
	case X_CMD('I', 'L', 'N', '\0'): /* ILN - friend change status */
		/*
		ILN 9 AWY le_rasta@hotmail.com le_rasta%20.... 1985855524 %3Cmsnobj%20Creator%3D%22le_rasta%40hotmail.com%22%20Type%3D%223%22%20SHA1D%3D%22SiKYfTFwMJv18ftNlGT1EHAtIUo%3D%22%20Size%3D%2229390%22%20Location%3D%220%22%20Friendly%3D%22SQBNAEcAXwAwADMANgA1AAAA%22%2F%3E
		*/
		atom = atom_next(command, &offset);
		if (!atom_is_number(atom)) {
			FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", cmd.len, cmd.px);
		} else {
			atom = atom_next(command, &offset);
			switch (hash_command(atom)) {
			case X_CMD('N','L','N','\0'): /* - Online - This status is used when a user is connected to the NS and is not appearing offline. It is the parent of all six sub-statuses. If a sub-status is used, NLN is replaced with the sub-status, but the user is still considered online, just less available.*/
			case X_CMD('F','L','N','\0'): /* - Offline - This status is used for a user that is not connected to the NS. If a user has blocked you, is appearing offline, or has not approved your "add a contact" request, this status will be sent to you even if they are truly online.*/
			case X_CMD('H','D','N','\0'): /* - Hidden - This status is only seen by the user who sets it, and is never received as a status of someone on a contact list. If a user sets his or her status to hidden, every single user will see this user as offline. The user remains connected to the NS, but has limited capabilities (including, most importantly, no transfers to SB).*/
			case X_CMD('B','S','Y','\0'): /* - Busy*/
			case X_CMD('I','D','L','\0'): /* - Idle*/
			case X_CMD('B','R','B','\0'): /* - Be Right Back*/
			case X_CMD('A','W','Y','\0'): /* - Away*/
			case X_CMD('P','H','N','\0'): /* - On the Phone*/
			case X_CMD('L','U','N','\0'): /* - Out to Lunch*/
				break;
			default:
				FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", cmd.len, cmd.px);
			}

			atom = atom_next(command, &offset);
			JOTDOWN(ferret,
				JOT_SZ("CHAT",			"Buddy"),
				JOT_SZ("Buddy",			stream->app.msnreq.toname),
				JOT_PRINT("Buddy",		atom.px+atom.offset, atom.len),
				JOT_SZ("Protocol",		"MSN-MSGR"),
				0);
		}
		break;
	case X_CMD('I', 'R', 'O', '\0'): /* JOI */
		{
			struct Atom alias;
			atom = atom_next(command, &offset);
			while (atom_is_number(atom))
				atom = atom_next(command, &offset);

			alias = atom_next(command, &offset);

			strncpy_s(	(char*)stream->app.msnreq.username, sizeof(stream->app.msnreq.username),
						(char*)atom.px+atom.offset, atom.len);
			
			if (stream_reverse->app.msnreq.username[0])
				strcpy_s((char*)stream->app.msnreq.toname, sizeof(stream->app.msnreq.username),
							(const char*)stream_reverse->app.msnreq.username);


			JOTDOWN(sess->eng->ferret,
				JOT_SZ("CHAT",			"Buddy"),\
				JOT_PRINT("Buddy",		atom.px+atom.offset, atom.len),
				JOT_SZ("Buddy",			stream->app.msnreq.toname),
				JOT_SZ("Protocol",		"MSN-MSGR"),
				0);

			JOTDOWN(ferret,
				JOT_SZ("CHAT",			"Call"),
				JOT_SZ("From",			stream->app.msnreq.username),
				JOT_SZ("To",			stream->app.msnreq.toname),
				JOT_SZ("Protocol",		"MSN-MSGR"),
				0);

			JOTDOWN(ferret,
				JOT_PRINT("ID-ALIAS", atom.px+atom.offset, atom.len),
				JOT_URLENC("MSN-display", alias.px+alias.offset, alias.len),
				0);
		}
		break;
	case X_CMD('J', 'O', 'I', '\0'): /* JOI */
		{
			struct Atom alias;
			atom = atom_next(command, &offset);
			alias = atom_next(command, &offset);

			strncpy_s(	(char*)stream->app.msnreq.username, sizeof(stream->app.msnreq.username),
						(char*)atom.px+atom.offset, atom.len);

			JOTDOWN(sess->eng->ferret,
				JOT_SZ("CHAT",			"Buddy"),\
				JOT_SZ("Buddy",			stream->app.msnreq.toname),
				JOT_PRINT("Buddy",		atom.px+atom.offset, atom.len),
				JOT_SZ("Protocol",		"MSN-MSGR"),
				0);

			JOTDOWN(ferret,
				JOT_SZ("CHAT",			"Call"),
				JOT_SZ("From",			stream->app.msnreq.toname),
				JOT_SZ("To",			stream->app.msnreq.username),
				JOT_SZ("Protocol",		"MSN-MSGR"),
				0);

			JOTDOWN(ferret,
				JOT_PRINT("ID-ALIAS", atom.px+atom.offset, atom.len),
				JOT_URLENC("MSN-display", alias.px+alias.offset, alias.len),
				0);
		}
		break;
	case X_CMD('L', 'S', 'G', '\0'): /* LSG - List Groups */
		/*
		LSG 0 Individuals 0
		LSG 1 MSP 0
		LSG 2 mes%20ennemis 0
		LSG 3 UMP 0
		LSG 4 Amis 0
		LSG 5 Autres%20contacts 0
		LSG 6 MVS 0
		LSG 7 Buddies 0
		LSG 8 Autre%20pays 0
		LSG 9 Famille 0
		LSG 10 Coll..gues 0
		LSG 11 friends 0
		*/
		break;
	case X_CMD('L', 'S', 'T', '\0'): /* LST - List friends */
		/*
		LST matt_powa@hotmail.com -%20-%20ChArLoTTe_MaTT_%20aLLeZ!! 11 0
		LST naixis@live.fr TBScorpio 11 0
		*/
		atom = atom_next(command, &offset);
		if (atom_is_number(atom)) {
			FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", cmd.len, cmd.px);
		} else {
			JOTDOWN(sess->eng->ferret,
				JOT_SZ("CHAT",			"Buddy"),
				JOT_SZ("Buddy",			stream->app.msnreq.toname),
				JOT_PRINT("Buddy",		atom.px+atom.offset, atom.len),
				JOT_SZ("Protocol",		"MSN-MSGR"),
				0);
			strncpy_s(	
				(char*)stream->app.msnreq.username, sizeof(stream->app.msnreq.username),
				(char*)atom.px+atom.offset, atom.len);
		}
		break;
	case X_CMD('M', 'S', 'G', '\0'): /* MSG - Message */
		{
			const unsigned char *content_type;
			unsigned content_type_length;
			unsigned i;

			msg_content_type(data, &content_type, &content_type_length);

			SAMPLE(ferret,"MSN-MSGR", JOT_PRINT("server-msg", content_type, content_type_length));

			for (i=0; msgcontenttypes[i].content_type; i++) {
				if (MATCHES(msgcontenttypes[i].content_type, content_type, content_type_length))
					break;
			}
			msgcontenttypes[i].pfn_handler(stream,frame,data);
		}
		break;
	case X_CMD('N', 'L', 'N', '\0'): /* NLN - Presence info from friends */
		{
			struct Atom status;
			struct Atom name;

			status = atom_next(command, &offset);
			name = atom_next(command, &offset);

			switch (hash_command(status)) {
			case X_CMD('N', 'L', 'N', '\0'): /* NLN */
				JOTDOWN(ferret,
					JOT_SZ("proto", "MSN-MSGR"),
					JOT_DST("ip", frame),
					JOT_PRINT("buddy",	 	name.px+name.offset, name.len),
					JOT_PRINT("state",	 	status.px+status.offset, status.len),
					0);
				if (stream->app.msnreq.username[0]) {
					FRAMERR(frame, "%s: unimplemented", "MSN-MS");
				}
				break;
			default:
				FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", command->length, command->the_string);
			}

		}				
		break;
	case X_CMD('N', 'O', 'T', '\0'): /* NOT - Notification*/
		/*
		NOT 374
		<NOTIFICATION ver="2" id="2" siteid="0" siteurl="http://g.live.com/"><TO name="mattwood9@hotmail.com" pid="0x0:0x0"/><MSG pri="1" id="2"><ACTION url="5mefr_fr/177"/><SUBSCR url="5mefr_fr/177"/><BODY lang="1033" icon=""><TEXT>New! Send messages to your friends on Yahoo! Messenger - install the latest version of Windows Live(TM) Messenger.</TEXT></BODY></MSG></NOTIFICATION>
		*/
		break;
	case X_CMD('O', 'U', 'T', '\0'): /* OUT */
		/* Regress: defcon2008\dump001.pcap(49303) */
		break;
	case X_CMD('P', 'R', 'P', '\0'): /* PRP - Personal Phone Number */
		{
			struct Atom num;
			/*
			PRP PHH 33%20013371337
			PRP PHW 33%20013371337
			PRP PHM 33%20698809840
			PRP MBE N
			PRP WWE 0
			*/
			atom = atom_next(command, &offset);
			while (atom_is_number(atom))
				atom = atom_next(command, &offset);
			num = atom_next(command, &offset);
			switch (hash_command(atom)) {
			case X_CMD('H', 'S', 'B', '\0'): /* HSB - Has Blog? */
				/* Regress: defcon2008-msnmsgr.pcap(4526) */
				break;
			case X_CMD('M', 'B', 'E', '\0'): /* MBE - Do I have an MSN Mobile device? */
			case X_CMD('M', 'O', 'B', '\0'): /* MOB - Can others contact my mobile device? */
			case X_CMD('W', 'W', 'E', '\0'): /* WWE - Related to the MSN Direct devices */
				break;
			case X_CMD('P', 'H', 'H', '\0'): /* PHH - Home phone number */
				JOTDOWN(ferret,
					JOT_SZ("ID-ALIAS", stream->app.msnreq.toname),
					JOT_URLENC("Home phone", num.px+num.offset, num.len),
					0);
				break;
			case X_CMD('P', 'H', 'W', '\0'): /* PHW - Work phone number */
				JOTDOWN(ferret,
					JOT_SZ("ID-ALIAS", stream->app.msnreq.toname),
					JOT_URLENC("Work phone", num.px+num.offset, num.len),
					0);
				break;
			case X_CMD('P', 'H', 'M', '\0'): /* PHM - Mobile phone number */
				JOTDOWN(ferret,
					JOT_SZ("ID-ALIAS", stream->app.msnreq.toname),
					JOT_URLENC("Mobile phone", num.px+num.offset, num.len),
					0);
			case X_CMD('M', 'F', 'N', '\0'): /* MFN - My Friendly Name */
				JOTDOWN(ferret,
					JOT_SZ("ID-ALIAS", stream->app.msnreq.toname),
					JOT_URLENC("Friendly Name", num.px+num.offset, num.len),
					0);
				JOTDOWN(ferret,
					JOT_SRC("ID-IP", frame),
					JOT_URLENC("username",	num.px+num.offset, num.len),
					0);
				break;
/*    
    * UTL - Utility?
    * WWE - 
    * WPL - Windows ...
    * WPC - Windows ...
    * CID - Contact ID?
    * RES
    * NSD
    * UAC
    * MNI - Mobile ... (something with a mobile device)
	*/
			default:
				FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", command->length, command->the_string);
			}
		}
		break;
	case X_CMD('Q', 'N', 'G', '\0'): /* QNG - Ping Response*/
		break;
	case X_CMD('Q', 'R', 'Y', '\0'): /* QRY */
		break;
	case X_CMD('N', 'A', 'K', '\0'): /* NAK */
		/* Regress: defcon2008-msnmsgr.pcap(11176)*/
		break;
	case X_CMD('R', 'E', 'A', '\0'): /* REA */
		/* Regress: defcon2008\dump014.pcap(18375) */
		break;
	case X_CMD('R', 'E', 'M', '\0'): /* REM */
		/* Regress: defcon2008\dump056.pcap(62025) */
		break;
	case X_CMD('R', 'M', 'L', '\0'): /* RML */
		/* Regress: defcon2008-msnmsgr.pcap(17173) */
		break;
	case X_CMD('R', 'N', 'G', '\0'): /* RNG */
		break;
	case X_CMD('S', 'B', 'P', '\0'): /* SBP */
		break;
	case X_CMD('S', 'B', 'S', '\0'): /* SBS */
		break;
	case X_CMD('S', 'Y', 'N', '\0'): /* SYN */
		break;
	case X_CMD('U', 'B', 'N', '\0'): /* UBN */
		break;
	case X_CMD('U', 'B', 'X', '\0'): /* UBX */
		break;
	case X_CMD('U', 'R', 'L', '\0'): /* URL */
		break;
	case X_CMD('U', 'S', 'R', '\0'): /* USR */
		atom = atom_next(command, &offset);
		if (!atom_is_number(atom))
			FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", cmd.len, cmd.px);
		else {
			atom = atom_next(command, &offset);
			if (!atom_equals_ignorecase(atom, "OK")) {
				; //FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", cmd.len, cmd.px);
			} else {
				struct Atom username;
				struct Atom alias;

				username = atom_next(command, &offset);
				alias = atom_next(command, &offset);

				strncpy_s(	
					(char*)stream->app.msnreq.toname, sizeof(stream->app.msnreq.toname),
					(char*)username.px+username.offset, username.len);

				JOTDOWN(ferret,
					JOT_PRINT("ID-ALIAS", username.px+username.offset, username.len),
					JOT_URLENC("MSN-display", alias.px+alias.offset, alias.len),
					0);
			}
		}
		break;
	case X_CMD('U', 'U', 'N', '\0'): /* UUN */
		break;
	case X_CMD('U', 'U', 'X', '\0'): /* UUX */
		/* Regress: defcon2008-msnmsgr.pcap frame 789 */
		/* Example: UUX 12 0
		 * I don't know what that '0' is on the end. Is that a length field of data
		 * to follow? */
		atom = atom_next(command, &offset); /* TriD */
		if (atom_is_number(atom)) {
			atom = atom_next(command, &offset);
			if (atom_is_number(atom)) {
				unsigned num = atom_to_number(atom);
				if (num != 0)
					FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", cmd.len, cmd.px);
			} else
				FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", cmd.len, cmd.px);
		} else
			FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", cmd.len, cmd.px);
		break;
	case X_CMD('X', 'F', 'R', '\0'): /* XFR - Transfer connection to another server */
		/* Example: XFR 3 NS 207.46.108.52:1863 0 65.54.239.140:1863 */
		break;
	case X_CMD('V', 'E', 'R', '\0'): /* VER - Version Information */
		while (offset < command->length) {
			atom = atom_next(command, &offset);
			
			/* First number is a sequence number */
			if (atom_is_number(atom))
				continue;

			if (MATCHES("CVR0", atom.px+atom.offset, atom.len))
				continue;


			/* Syntax:
			 * VER <TrID> <protocol> <protocol> .... 
			 *
			 *	Indicates a list of protocols supported
			 *
			 *  Examples:
			 *		VER 0 MSNP8 CVR0
			 *		VER 0 MSNP8 MYPROTOCOL CVR0
			 */
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_SZ("eng", "MSN-MSGR"),
				JOT_PRINT("ver", atom.px+atom.offset, atom.len),
				0);
		}				
		break;
	default:
		FRAMERR(frame, "%s: unknown commanded from server: %.*s\n", "MSN-MS", cmd.len, cmd.px);
		break;
	}

}

void msnms_client_command(
		struct TCPRECORD *sess, 
		struct NetFrame *frame, 
		struct StringReassembler *command, 
		struct StringReassembler *data)
{
	struct TCP_STREAM *stream = &sess->to_server;
	struct FerretEngine *eng = sess->eng;
	struct Ferret *ferret = eng->ferret;
	struct Atom cmd;
	unsigned offset = 0;
	struct Atom atom;

	UNUSEDPARM(data);

	cmd = atom_next(command, &offset);

	SAMPLE(ferret,"MSN-MSGR", JOT_SZ("client", cmd));
	switch (hash_command(cmd)) {
	case X_CMD('A', 'D', 'C', '\0'): /* ADC */
		/* Regress: defcon2008\dump056.pcap(61738) */
		break;
	case X_CMD('A', 'D', 'L', '\0'): /* ADL */
		/* TODO: parse these contacts */
		break;
	case X_CMD('A', 'N', 'S', '\0'): /* ANS - Answer */
		/* Within 2-minutes of getting a RNG command from the Notification Server,
		 * the client opens up a TCP session with the Switchboard Server. The first
		 * thing sent will be the ANS command. The format is:
		 * 
		 * ANS <trid> <accountname> <authstring> <switchboardsessionid>
		 *
		 */
		atom = atom_next(command, &offset);
			
		/* First number is a sequence number */
		if (atom_is_number(atom)) {
			/*unsigned trid = atom_to_number(atom);*/
			
			atom = atom_next(command, &offset);
			strncpy_s(	(char*)stream->app.msnreq.username, sizeof(stream->app.msnreq.username),
						(char*)atom.px+atom.offset, atom.len);


			JOTDOWN(ferret,
				JOT_SZ("proto",			"MSN-MSGR"),
				JOT_SRC("ip",			frame),
				JOT_PRINT("username",	atom.px+atom.offset, atom.len),
				0);
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("username",	atom.px+atom.offset, atom.len),
				0);
			JOTDOWN(ferret,
				JOT_SRC("ID-IP",			frame),
				JOT_PRINT("MSN-username",	atom.px+atom.offset, atom.len),
				0);
		} else
			FRAMERR(frame, "%s: unknown commanded from client: %.*s\n", "MSN-MS", cmd.len, cmd.px);

		break;
	case X_CMD('B', 'L', 'P', '\0'): /* BLP */
		break;
	case X_CMD('C', 'A', 'L', '\0'): /* CAL - Call */
		atom = atom_next(command, &offset);
		if (!atom_is_number(atom))
			FRAMERR(frame, "%s: unknown commanded from client: %.*s\n", "MSN-MS", cmd.len, cmd.px);
		else {
			atom = atom_next(command, &offset);
			strncpy_s(	(char*)stream->app.msnreq.toname, sizeof(stream->app.msnreq.toname),
						(char*)atom.px+atom.offset, atom.len);

			JOTDOWN(ferret,
				JOT_SZ("CHAT",			"Call"),
				JOT_SZ("From",			stream->app.msnreq.username),
				JOT_PRINT("To",			atom.px+atom.offset, atom.len),
				JOT_SZ("Protocol",		"MSN-MSGR"),
				0);
		}
		break;
	case X_CMD('C', 'H', 'G', '\0'): /* CHG - Change Presence State */
		break;
	case X_CMD('C', 'V', 'R', '\0'): /* CVR */
/*
    *  The first parameter is hexadecimal number specifying your locale ID (e.g. "0x0409" For U.S. English).
    * The second parameter is your OS type (e.g. "win" for Windows).
    * The third parameter is your OS version (e.g. "4.10" for Windows 98).
    * The fourth parameter is the architecture of your computer (e.g. "i386" for Intel-comaptible PCs of type 386 or above).
    * The fifth parameter is your client name (e.g. "MSMSGR" for the official MSN Messenger client).
    * The sixth parameter is your client version (e.g. "6.0.0602").
    * The seventh parameter is always "MSMSGS" in the official client. Your guess about what this means is as good as mine.
    * The eighth parameter is your passport.
*/
		{
			struct Atom localid, ostype, osver, arch, clientname, clientver, msmsgs, passport;

			atom_next(command, &offset); /*trid*/
			localid = atom_next(command, &offset);
			ostype = atom_next(command, &offset);
			osver = atom_next(command, &offset);
			arch = atom_next(command, &offset);
			clientname = atom_next(command, &offset);
			clientver = atom_next(command, &offset);
			msmsgs = atom_next(command, &offset);
			passport = atom_next(command, &offset);
			
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("Passport",	 	passport.px+passport.offset, passport.len),
				0);

			JOTDOWN(ferret,
				JOT_SZ("proto", "MSN-MSGR"),
				JOT_SRC("ip", frame),
				JOT_PRINT("localid",	  localid.px+localid.offset, localid.len),
				0);
			JOTDOWN(ferret,
				JOT_SZ("proto", "MSN-MSGR"),
				JOT_SRC("ip", frame),
				JOT_PRINT("ostype",	  ostype.px+ostype.offset, ostype.len),
				0);
			JOTDOWN(ferret,
				JOT_SZ("proto", "MSN-MSGR"),
				JOT_SRC("ip", frame),
				JOT_PRINT("osver",	  osver.px+osver.offset, osver.len),
				0);
			JOTDOWN(ferret,
				JOT_SZ("proto", "MSN-MSGR"),
				JOT_SRC("ip", frame),
				JOT_PRINT("arch",		  arch.px+arch.offset, arch.len),
				0);
			JOTDOWN(ferret,
				JOT_SZ("proto", "MSN-MSGR"),
				JOT_SRC("ip", frame),
				JOT_PRINT("clientname",	  clientname.px+clientname.offset, clientname.len),
				0);
			JOTDOWN(ferret,
				JOT_SZ("proto", "MSN-MSGR"),
				JOT_SRC("ip", frame),
				JOT_PRINT("clientver",  clientver.px+clientver.offset, clientver.len),
				0);
			JOTDOWN(ferret,
				JOT_SZ("proto", "MSN-MSGR"),
				JOT_SRC("ip", frame),
				JOT_PRINT("msmsgs",	  msmsgs.px+msmsgs.offset, msmsgs.len),
				0);
			JOTDOWN(ferret,
				JOT_SZ("proto", "MSN-MSGR"),
				JOT_SRC("ip", frame),
				JOT_PRINT("passport",	  passport.px+passport.offset, passport.len),
				0);

		}				
		break;
	case X_CMD('G', 'C', 'F', '\0'): /* GCF - General Configuration */
		/* Regress: defcon2008-msnmsgr.pcap frame 1855 */
		break;
	case X_CMD('M', 'S', 'G', '\0'): /* MSG - Message */
		{
			const unsigned char *content_type;
			unsigned content_type_length;
			unsigned i;

			msg_content_type(data, &content_type, &content_type_length);

			SAMPLE(ferret,"MSN-MSGR", JOT_PRINT("client-msg", content_type, content_type_length));

			for (i=0; msgcontenttypes[i].content_type; i++) {
				if (MATCHES(msgcontenttypes[i].content_type, content_type, content_type_length))
					break;
			}
			msgcontenttypes[i].pfn_handler(stream,frame,data);
		}
		break;
	case X_CMD('O', 'U', 'T', '\0'): /* OUT - Logging out, closing TCP connection */
		break;
	case X_CMD('P', 'N', 'G', '\0'): /* PNG - Ping */
		/* Contains no additional data. Sent from client to server as sort
		 * of a keep alive message */
		break;
	case X_CMD('P', 'R', 'P', '\0'): /* PRP */
		break;
	case X_CMD('Q', 'R', 'Y', '\0'): /* SYN */
		break;
	case X_CMD('R', 'E', 'A', '\0'): /* REA */
		/* Regress: defcon2008\dump014.pcap(18331) */
		break;
	case X_CMD('R', 'E', 'M', '\0'): /* REM */
		/* Regress: defcon2008\dump056.pcap(61828) */
		break;
	case X_CMD('R', 'M', 'L', '\0'): /* RML */
		/* Regress: defcon2008-msnmsgr.pcap(17172) */
		break;
	case X_CMD('S', 'B', 'P', '\0'): /* SBP */
		/* Regress: defcon2008\dump006.pcap(101543) */
		break;
	case X_CMD('S', 'Y', 'N', '\0'): /* SYN */
		break;
	case X_CMD('U', 'B', 'N', '\0'): /* UBN */
		break;
	case X_CMD('U', 'R', 'L', '\0'): /* URL */
		break;
	case X_CMD('U', 'S', 'R', '\0'): /* USR - User login */
			/* This format is different depending upon which type of server
			 * it's sent to
			 * FORMAT: USR trid TWN I passport (dispatch/notification server)
			 * FORMAT: USR trid TWN S ticket (dispatch/notification server)
			 * FORMAT: USR trid accountname ticket (switchboard server)
			 */

			atom = atom_next(command, &offset);
			
			/* First number is a sequence number */
			if (atom_is_number(atom)) {
				/*unsigned trid = atom_to_number(atom);*/
				
				atom = atom_next(command, &offset);
				if (atom_equals_ignorecase(atom, "TWN")) {
					atom = atom_next(command, &offset);
					if (atom_equals_ignorecase(atom, "I")) {
						atom = atom_next(command, &offset);
						JOTDOWN(ferret,
							JOT_SZ("proto",			"MSN-MSGR"),
							JOT_SRC("ip",			frame),
							JOT_PRINT("username",	atom.px+atom.offset, atom.len),
							0);
						JOTDOWN(ferret,
							JOT_SRC("ID-IP", frame),
							JOT_PRINT("username",	atom.px+atom.offset, atom.len),
							0);
						JOTDOWN(ferret,
							JOT_SRC("ID-IP",			frame),
							JOT_PRINT("MSN-username",	atom.px+atom.offset, atom.len),
							0);
					} else
						; //FRAMERR(frame, "%s: unknown commanded from client: %.*s\n", "MSN-MS", cmd.len, cmd.px);
				} else {
					strncpy_s(	(char*)stream->app.msnreq.username, sizeof(stream->app.msnreq.username),
								(char*)atom.px+atom.offset, atom.len);


					JOTDOWN(ferret,
						JOT_SZ("proto",			"MSN-MSGR"),
						JOT_SRC("ip",			frame),
						JOT_PRINT("username",	atom.px+atom.offset, atom.len),
						0);
					JOTDOWN(ferret,
						JOT_SRC("ID-IP", frame),
						JOT_PRINT("username",	atom.px+atom.offset, atom.len),
						0);
					JOTDOWN(ferret,
						JOT_SRC("ID-IP",			frame),
						JOT_PRINT("MSN-username",	atom.px+atom.offset, atom.len),
						0);
				}
			} else
				FRAMERR(frame, "%s: unknown commanded from client: %.*s\n", "MSN-MS", cmd.len, cmd.px);

		break;
	case X_CMD('U', 'U', 'N', '\0'): /* UUN - User User Notification */
		break;
	case X_CMD('U', 'U', 'X', '\0'): /* UUN - User User Notification */
		break;
	case X_CMD('V', 'E', 'R', '\0'): /* VER */
		for (;;) {
			struct Atom atom;

			atom = atom_next(command, &offset);
			if (atom.len == 0)
				break;

			if (atom_is_number(atom))
				continue;

			if (atom_equals_ignorecase(atom, "CVR0"))
				continue;


			/* Syntax:
			 * VER <TrID> <protocol> <protocol> .... 
			 *
			 *	Indicates a list of protocols supported
			 *
			 *  Examples:
			 *		VER 0 MSNP8 CVR0
			 *		VER 0 MSNP8 MYPROTOCOL CVR0
			 */
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_SZ("eng", "MSN-MSGR"),
				JOT_PRINT("ver",		 	atom.px+atom.offset, atom.len),
				0);
		}				

		break;
	case X_CMD('X', 'F', 'R', '\0'): /* XFR - Request new chat session */
		/* Client sends this to the Notification server to request a new
		 * chat session.
		 * FORMAT: XFR trid SB
		 * EXAMPLE: XFR 11 SB
		 */
		break;
	default:
		FRAMERR(frame, "%s: unknown commanded from client: %.*s\n", "MSN-MS", cmd.len, cmd.px);
		break;
	}

	
}


void 
process_msnms_server_response(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned eol=0;
	struct StringReassembler *string_command = stream->str+0;
	struct StringReassembler *string_data = stream->str+1;

	/* IF CLOSING CONNECTION */
	if (px == NULL) {
		return;
	}
	frame->layer7_protocol = LAYER7_MSNMSGR;

	/* Run a state-machine reassembling the commands */
	while (offset < length)
	switch (stream->parse.state) {
	case 0: 
		/* Start processing command line */
		strfrag_init(string_command);
		strfrag_init(string_data);
		stream->parse.state++;
		continue;

	case 1: 
		/* continue processign command line until EOL */
		/* Find the end-of-line, or as much of the text as we
		 * can get so far */
		for (eol=offset; eol<length && px[eol] != '\n'; eol++)
			;

		/* Add that to our line buffer */
		strfrag_append(string_command, px+offset, eol-offset);

		/* If we aren't done yet, then return until we get more fragments */
		offset = eol;
		if (offset >= length)
			continue;
		else
			offset++;

		/* If the command has additional data, then start grabbing that
		 * data as well. */
		stream->parse.remaining = msn_more_response_length(string_command);
		if (stream->parse.remaining == 0) {
			msnms_server_command(sess, frame, string_command, string_data);
			strfrag_init(string_command);
			strfrag_init(string_data);
			stream->parse.state = 0;
		} else {
			stream->parse.state = 2;
		}
		break;
	case 2: /* process value, if any */
		if (stream->parse.remaining) {
			unsigned len = length-offset;
			if (len > stream->parse.remaining)
				len = stream->parse.remaining;
			strfrag_append(string_data, px+offset, len);
			stream->parse.remaining -= len;
			offset += len;

			if (stream->parse.remaining == 0) {
				/* Handle the command */
				msnms_server_command(sess, frame, string_command, string_data);
				strfrag_init(string_command);
				strfrag_init(string_data);
				stream->parse.state = 0;
			}
		} else
			stream->parse.state = 0;
		break;
	}
}

void
process_simple_msnms_client_request(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned eol=0;
	struct StringReassembler *string_command = stream->str+0;
	struct StringReassembler *string_data = stream->str+1;

	/* IF CLOSING CONNECTION */
	if (px == NULL) {
		return;
	}

	frame->layer7_protocol = LAYER7_MSNMSGR;

	/* Run a state-machine reassembling the commands */
	while (offset < length)
	switch (stream->parse.state) {
	case 0: 
		/* Start processing command line */
		strfrag_init(string_command);
		strfrag_init(string_data);
		stream->parse.state++;
		continue;

	case 1: 
		/* continue processign command line until EOL */
		/* Find the end-of-line, or as much of the text as we
		 * can get so far */
		for (eol=offset; eol<length && px[eol] != '\n'; eol++)
			;

		/* Add that to our line buffer */
		strfrag_append(string_command, px+offset, eol-offset);

		/* If we aren't done yet, then return until we get more fragments */
		offset = eol;
		if (offset >= length)
			continue;
		else
			offset++;

		/* If the command has additional data, then start grabbing that
		 * data as well. */
		stream->parse.remaining = msn_more_request_length(string_command);
		if (stream->parse.remaining == 0) {
			msnms_client_command(sess, frame, string_command, string_data);
			strfrag_init(string_command);
			strfrag_init(string_data);
			stream->parse.state = 0;
		} else {
			stream->parse.state = 2;
		}
		break;
	case 2: /* process value, if any */
		if (stream->parse.remaining) {
			unsigned len = length-offset;
			if (len > stream->parse.remaining)
				len = stream->parse.remaining;
			strfrag_append(string_data, px+offset, len);
			stream->parse.remaining -= len;
			offset += len;

			if (stream->parse.remaining == 0) {
				/* Handle the command */
				msnms_client_command(sess, frame, string_command, string_data);
				strfrag_init(string_command);
				strfrag_init(string_data);
				stream->parse.state = 0;
			}
		} else
			stream->parse.state = 0;
		break;
	}
}

