/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	SESSION INITIATION PROTOCOL

  This protocol starts a VoIP connection. We can find out the phone
  number of the person making the call, as well as information about
  who they are making calls to.

  With SIP will be the an embedded protocol that will tell us about
  the multi-media session that will be set up. We will need to decode
  that as well in order to then grab the audio session of the phone
  call.

*/
#include "platform.h"
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "stack-listener.h"
#include "util-memcasecmp.h"
#include "parse-address.h"
#include "dgram-sip.h"
#include "util-memcasecmp.h"
#include <string.h>
#include <ctype.h>




enum SIP_METHOD {
	SIP_METHOD_UNKNOWN,
	SIP_METHOD_INVITE,
	SIP_METHOD_REGISTER,
};

struct SIP {
	enum SIP_METHOD method;
};


/****************************************************************************
 ****************************************************************************/
static void
trim_whitespace(const void *vpx, unsigned *offset, unsigned length)
{
	const unsigned char *px = (const unsigned char *)vpx;
	while (*offset < length && isspace(px[*offset]))
		(*offset)++;
}

/****************************************************************************
 ****************************************************************************/
static int
is_next_char(int c, const void *vpx, unsigned offset, unsigned length)
{
	const char *px = (const char *)vpx;

	if (offset >= length)
		return 0; /*false*/
	return px[offset] == c;
}

/****************************************************************************
 ****************************************************************************/
int
field_is_number(const struct Field *field, unsigned offset)
{
	if (field->length > offset && isdigit(field->px[offset]&0xFF))
		return 1;
	else
		return 0;
}

/****************************************************************************
 ****************************************************************************/
uint64_t
field_next_number(const struct Field *field, unsigned *inout_offset)
{
	unsigned offset;
	uint64_t result = 0;

	if (inout_offset)
		offset = *inout_offset;
	else
		offset = 0;

	while (offset < field->length && isdigit(field->px[offset]&0xFF)) {
		result = result * 10 + (field->px[offset] - '0');
		offset++;

	}

	/* strip trailing whitespace after the number */
	while (isspace(field->px[offset]&0xFF))
		offset++;

	if (inout_offset)
		*inout_offset = offset;
	return result;
}

/****************************************************************************
 ****************************************************************************/
int
field_equals_nocase(const char *name, const struct Field *field)
{
	unsigned i;

	for (i=0; i<field->length && name[i]; i++)
		if (tolower(name[i]&0xFF) != tolower(field->px[i]))
			return 0;
	if (i != field->length)
		return 0;
	return 1;
}

/****************************************************************************
 ****************************************************************************/
static int
match(const char *sz, const unsigned char *name, unsigned name_length)
{
	if (memcasecmp(name, sz, name_length) == 0 && sz[name_length] == '\0')
		return 1;
	else
		return 0;
}

static int
match2(const char *lhs, const void *vpx, unsigned offset, unsigned length)
{
	const char *px = (const char*)vpx;
	unsigned lhs_length = (unsigned)strlen(lhs);

	if (length-offset < lhs_length)
		return 0;

	return memcasecmp(lhs, px+offset, lhs_length) == 0;
}

/****************************************************************************
 ****************************************************************************/
static enum SIP_METHOD
sip_get_method(const unsigned char *px, unsigned length)
{
	unsigned name_length;
	
	/* name is all the chars up to the first space */
	for (name_length = 0; name_length < length && !isspace(px[name_length]); name_length++)
		;

	if (match("INVITE", px, name_length)) {
		return SIP_METHOD_INVITE;
	} else if (match("REGISTER", px, name_length)) {
		return SIP_METHOD_REGISTER;
	} else
		return SIP_METHOD_UNKNOWN;
}

/****************************************************************************
 ****************************************************************************/
static enum SIP_METHOD
sip_get_response_code(const unsigned char *px, unsigned length)
{
	unsigned offset = 0;
	unsigned code = 0;

	/* skip SIP-version */
	while (offset < length && !isspace(px[offset]))
		offset++;

	/* skip intervening space */
	while (offset < length && isspace(px[offset]) && px[offset] != '\n')
		offset++;


	while (offset < length && isdigit(px[offset]))
		code = code * 10 + px[offset++] - '0';

	return code;
}

/****************************************************************************
 ****************************************************************************/
static int
sip_get_header(const char *in_name, const unsigned char *px, unsigned length, struct Field *field)
{
	unsigned offset = 0;

	while (offset < length) {
		unsigned i;
		unsigned line_length;
		unsigned name_length;
		unsigned value_offset;
		unsigned next_offset;

		/* Find the end of the line */
		for (i=0; offset+i<length && px[offset+i] != '\n'; i++)
			;
		next_offset = offset+i+1;

		/*
		 * Skip the method
		 */
		if (offset == 0) {
			offset = next_offset;
			continue;
		}

		/* Find the total length of the line minus space at end */
		line_length = i;
		while (line_length > 0 && isspace(px[offset+line_length-1]))
			line_length--;

		/*
		 * Find the name
		 */
		name_length = 0;
		while (name_length < line_length && px[offset+name_length] != ':')
			name_length++;
		if (!match(in_name, px+offset, name_length)) {
			offset = next_offset;
			continue;
		}

		/*
		 * Grab the value
		 */
		value_offset = name_length;
		if (value_offset < line_length && px[offset+value_offset] == ':')
			value_offset++;
		while (value_offset < line_length && isspace(px[offset+value_offset]))
			value_offset++;
 
		field->px = px+offset+value_offset;
		field->length = line_length-value_offset;

		return 1; /* found */
	}

	field->px = (const unsigned char *)"";
	field->length = 0;
	return 0;
}

/****************************************************************************
 ****************************************************************************/
static unsigned
sip_get_next_header(const char *in_name, const unsigned char *px, unsigned *r_offset, unsigned length, struct Field *field)
{
	unsigned offset = *r_offset;

	while (offset < length) {
		unsigned i;
		unsigned line_length;
		unsigned name_length;
		unsigned value_offset;
		unsigned next_offset;

		/* Find the end of the line */
		for (i=0; offset+i<length && px[offset+i] != '\n'; i++)
			;
		next_offset = offset+i+1;
		*r_offset = next_offset;

		/*
		 * Skip the method
		 */
		if (offset == 0) {
			offset = next_offset;
			continue;
		}

		/* Find the total length of the line minus space at end */
		line_length = i;
		while (line_length > 0 && isspace(px[offset+line_length-1]))
			line_length--;

		/*
		 * Find the name
		 */
		name_length = 0;
		while (name_length < line_length && px[offset+name_length] != ':')
			name_length++;
		if (!match(in_name, px+offset, name_length)) {
			offset = next_offset;
			continue;
		}

		/*
		 * Grab the value
		 */
		value_offset = name_length;
		if (value_offset < line_length && px[offset+value_offset] == ':')
			value_offset++;
		while (value_offset < line_length && isspace(px[offset+value_offset]))
			value_offset++;
 
		field->px = px+offset+value_offset;
		field->length = line_length-value_offset;

		return 1; /* found */
	}

	field->px = (const unsigned char *)"";
	field->length = 0;
	*r_offset = offset;
	return 0;
}

/****************************************************************************
 ****************************************************************************/
void
sip_INVITE_request(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct Field field;
	struct Field content_type = {0,0};
	unsigned content_offset = length;
	uint64_t content_length = 0;
	
	/*
	 * Find the end of the header (the start of the content)
	 */
	{
		unsigned i, is_eol = 0;
		for (i=0; i<length; i++) {
			if (px[i] == '\n') {
				if (is_eol) {
					content_offset = i+1;
					break;
				} else
					is_eol = 1;
			} else if (px[i] == '\r')
				;
			else
				is_eol = 0;
		}
	}

	/*
	 * Get the content length
	 */
	content_length = length - content_offset;
	if (sip_get_header("Content-Length", px, length, &field)) {
		if (field_is_number(&field,0)) {
			content_length = field_next_number(&field,0);
			if (content_length > length - content_offset)
				content_length = length - content_offset;
		}
	}

	/*
	 * Get the Content-type
	 */
	if (sip_get_header("Content-Type", px, length, &content_type)) {
	}

	if (field_equals_nocase("application/sdp", &content_type)) {
		parse_sdp_invite_request(ferret, frame, px+content_offset, (unsigned)content_length);
	} else if (content_type.length) {
		/*application/dtmf-relay*/
		/*application/dtmf*/
		printf("%s: %.*s\n", "Content-Type", content_type.length, content_type.px);
	}
}

/****************************************************************************
 ****************************************************************************/
void
parse_dgram_sip_request(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	enum SIP_METHOD method;

	frame->layer7_protocol = LAYER7_SIP;

	method = sip_get_method(px, length);

	switch (method) {
	case SIP_METHOD_INVITE:
		sip_INVITE_request(ferret, frame, px, length);
		break;
	case SIP_METHOD_REGISTER:
	case SIP_METHOD_UNKNOWN:
	default:
		;
	}
}

/****************************************************************************
 ****************************************************************************/
/****************************************************************************
 ****************************************************************************/
static int
via_get_parm(const char *in_name, const unsigned char *px, unsigned length, struct Field *field)
{
	unsigned offset = 0;

	while (offset < length) {
		unsigned i;
		unsigned name_length;
		unsigned next_offset;
		unsigned end_offset;

		/* Find the end of the parm */
		for (i=0; offset+i<length && px[offset+i] != '\n' && px[offset+i] != ';'; i++)
			;
		next_offset = offset+i+1;

		/* Remove trailing whitespace*/
		end_offset = offset + i;
		while (end_offset > offset && isspace(px[end_offset-1]))
			end_offset--;

		/*
		 * Find the name
		 */
		while (offset<end_offset && isspace(px[offset]))
			offset++;
		for (i=offset; i<end_offset && px[i] != '='; i++)
			;
		name_length = i-offset;
		while (name_length > 0 && isspace(px[offset+name_length-1]))
			name_length--; /* remove trailing whitespace from name */
		if (!match(in_name, px+offset, name_length)) {
			offset = next_offset;
			continue;
		} else
			offset += name_length;

		/*
		 * Grab the value
		 */
		while (offset<end_offset && isspace(px[offset]))
			offset++;
		if (offset<end_offset && px[offset] == '=')
			offset++;
		while (offset<end_offset && isspace(px[offset]))
			offset++;
		field->px = px+offset;
		field->length = end_offset-offset;

		return 1; /* found */
	}

	field->px = (const unsigned char *)"";
	field->length = 0;
	return 0;
}

/****************************************************************************
 ****************************************************************************/
static void
sip_via(struct Ferret *ferret, struct NetFrame *frame, const void *vpx, unsigned length)
{
	const unsigned char *px = (const unsigned char *)vpx;
	unsigned offset = 0;
	unsigned vers_major = 0;
	unsigned vers_minor = 0;
	enum {TRANSPORT_UDP, TRANSPORT_TCP} transport = TRANSPORT_UDP;
	struct Field host = {0,0};
	unsigned port = 5060;

	/*
	 * SIP/2.0/UDP 10.1.2.3:5060;branch=z9hG4bk-3858492752094
	 * ^^^^..................................................
	 */
	trim_whitespace(px, &offset, length);
	if (!match2("SIP/", px, offset, length)) {
		FRAMERR(frame, "sip: URI doesn't start with \"SIP/\"\n");
		return;
	} else
		offset += 4;

	/*
	 * SIP/2.0/UDP 10.1.2.3:5060;branch=z9hG4bk-3858492752094
	 * ....^..................................................
	 */
	trim_whitespace(px, &offset, length);
	vers_major = 0;
	while (offset<length && isdigit(px[offset]))
		vers_major = vers_major * 10 + px[offset++] - '0';
	
	/*
	 * SIP/2.0/UDP 10.1.2.3:5060;branch=z9hG4bk-3858492752094
	 * .....^..................................................
	 */
	trim_whitespace(px, &offset, length);
	if (offset>=length || px[offset++] != '.') {
		FRAMERR(frame, "unknown Via URI\n");
		return;
	}


	/*
	 * SIP/2.0/UDP 10.1.2.3:5060;branch=z9hG4bk-3858492752094
	 * ......^..................................................
	 */
	trim_whitespace(px, &offset, length);
	vers_minor = 0;
	while (offset<length && isdigit(px[offset]))
		vers_minor = vers_minor * 10 + px[offset++] - '0';
	if (vers_major != 2 && vers_minor != 0) {
		FRAMERR(frame, "unknown Via URI\n");
		return;	
	}

	/*
	 * SIP/2.0/UDP 10.1.2.3:5060;branch=z9hG4bk-3858492752094
	 * .......^^^^...........................................
	 */
	trim_whitespace(px, &offset, length);
	if (offset<length && px[offset] == '/') {
		unsigned offset2;
		offset++;
		offset2 = offset;
		for (offset2=offset; offset2<length && !isspace(px[offset2]); offset2++)
			;
		if (offset2-offset != 3) {
			FRAMERR(frame, "unknown Via URI\n");
			return;
		}
		if (match("UDP", px+offset, 3))
			transport = TRANSPORT_UDP;
		else if (match("TCP", px+offset, 3))
			transport = TRANSPORT_TCP;
		else {
			FRAMERR(frame, "unknown Via URI\n");
			return;
		}

		offset = offset2;
	}

	/*
	 * SIP/2.0/UDP 10.1.2.3:5060;branch=z9hG4bk-3858492752094
	 * ............^^^^^^^^..................................
	 */
	trim_whitespace(px, &offset, length);
	{
		unsigned start = offset;
		host.px = px+offset;
		while (offset<length && px[offset] != ':' && !isspace(px[offset]) && px[offset] != ';')
			offset++;
		host.length = start-offset;
	}


	/*
	 * SIP/2.0/UDP 10.1.2.3:5060;branch=z9hG4bk-3858492752094
	 * ....................^^^^^..................................
	 */
	trim_whitespace(px, &offset, length);
	if (match2(":", px, offset, length)) {
		port = 0;
		offset++; /* skip ':' */
		while (offset<length && isdigit(px[offset]))
			port = port * 10 + px[offset++] - '0';
		if (port > 65535) {
			FRAMERR(frame, "sip: bad port number\n");
			return;
		}
	}

	/*
	 * Now handle the IP/port combo
	 */
	{
		struct ParsedIpAddress ip;

		/* Parse IP address if it exists */
		if (parse_ip_address(host.px, 0, host.length, &ip)) {
			if (ip.version == 4) {
				unsigned ipv4 = ip.address[0]<<24 | ip.address[1]<<16 | ip.address[2]<<8 | ip.address[3];
				if (transport == TRANSPORT_UDP)
					listener_register_udp(ferret, LISTENER_UDP_SIP, ipv4, port, frame->time_secs);
				else if (transport == TRANSPORT_TCP)
					listener_register_tcp(ferret, LISTENER_TCP_SIP, ipv4, port, frame->time_secs);
				else {
					FRAMERR(frame, "unknown Via URI\n");
					return;
				}
			} else {
				FRAMERR(frame, "unknown Via URI\n");
				return;
			}
		} else {
			;
		}
	}

	/* do "received" and "rport" parameters */
	{
		struct Field received = {0,0};
		struct Field rport = {0,0};
		int found_received = 0;
		int found_rport = 0;

		found_received = via_get_parm("received", px+offset, length-offset, &received);
		found_rport = via_get_parm("rport", px+offset, length-offset, &rport);

		if (found_received || found_rport) {
			unsigned ipv4 = frame->src_ipv4;
			unsigned port = frame->src_port;

			/* If no 'received' header exists, then assume the IP address
			 * from the packet */
			ipv4 = frame->src_ipv4;
			if (found_received) {
				struct ParsedIpAddress ip;

				/* Parse IP address if it exists */
				if (parse_ip_address(received.px, 0, received.length, &ip)) {
					if (ip.version == 4) {
						ipv4 = ip.address[0]<<24 | ip.address[1]<<16 | ip.address[2]<<8 | ip.address[3];
					} else {
						FRAMERR(frame, "sip: don't handle IPv6 addresses yet\n");
						return;
					}
				} else {
					FRAMERR(frame, "sip: invalid IP address\n");
				}
			}

			/* If no 'rport' header exists, then assume port from packet */
			port = frame->src_port;
			if (transport == TRANSPORT_UDP)
				listener_register_udp(ferret, LISTENER_UDP_SIP, ipv4, port, frame->time_secs);
			else if (transport == TRANSPORT_TCP)
				listener_register_tcp(ferret, LISTENER_TCP_SIP, ipv4, port, frame->time_secs);
			else {
				FRAMERR(frame, "sip: unknown transport\n");
				return;
			}
		}
	}

}


/****************************************************************************
 ****************************************************************************/
static void
sip_parse_uri(struct Ferret *ferret, struct NetFrame *frame, const void *vpx, unsigned length)
{
	const unsigned char *px = (const unsigned char *)vpx;
	unsigned offset = 0;
	struct Field friendly = {0,0};
	struct Field name = {0,0};
	struct Field password = {0,0};
	struct Field host = {0,0};
	unsigned port;


	/* 	"name"<sip:<user>[:<password>]@<host>[:<port>][;<uri-parameters>][?<headers>]
	 *  ^^^^^.........................
	 */
	trim_whitespace(px, &offset, length);
	if (px[offset] != '<') {
		unsigned start = offset;
		friendly.px = px+offset;
		while (offset<length && px[offset] != '<') {
			if (px[offset] == '"') {
				while (offset<length && px[offset] != '"')
					offset++;
				if (offset<length && px[offset] == '"')
					offset++;
			} else
				offset++;
		}
		friendly.length = offset-start;
        friendly=friendly; /*compiler warning*/
	}

	/*
	 * <sip:rob:Foobar123@1.2.3.4:5060;user=rob;>;tag=1234
	 * ^..................................................
	 */
	trim_whitespace(px, &offset, length);
	if (is_next_char('<', px, offset, length)) {
		offset++;
	}

	/*
	 * <sip:rob:Foobar123@1.2.3.4:5060;user=rob;>;tag=1234
	 * .^^^...............................................
	 */
	trim_whitespace(px, &offset, length);
	if (match2("sip", px, offset, length)) {
		offset += 3;
	} else {
		FRAMERR(frame, "not \"sip:\" in URI\n");
		return;
	}

	/*
	 * <sip:rob:Foobar123@1.2.3.4:5060;user=rob;>;tag=1234
	 * ....^..............................................
	 */
	trim_whitespace(px, &offset, length);
	if (match2(":", px, offset, length)) {
		offset += 1;
	} else {
		FRAMERR(frame, "not \"sip:\" in URI\n");
		return;
	}

	/*
	 * <sip:rob:Foobar123@1.2.3.4:5060;user=rob;>;tag=1234
	 * .....^^^...........................................
	 */
	trim_whitespace(px, &offset, length);
	{
		unsigned start = offset;
		name.px = px+offset;
		while (offset<length && px[offset] != ':' && px[offset] != '@' && px[offset] != '>' && px[offset] != ';')
			offset++;
		name.length = offset-start;
	}

	/*
	 * <sip:rob:Foobar123@1.2.3.4:5060;user=rob;>;tag=1234
	 * ........^^^^^^^^^^.................................
	 */
	trim_whitespace(px, &offset, length);
	if (match2(":", px, offset, length)) {
		unsigned start;

		offset++; /* skip ':' */
		trim_whitespace(px, &offset, length);
		
		start = offset;
		password.px = px+offset;
		while (offset<length && px[offset] != ':' && px[offset] != '@' && px[offset] != '>' && px[offset] != ';')
			offset++;
		password.length = offset-start;
   		JOTDOWN(ferret,
			JOT_SZ("proto","SIP"),
			JOT_PRINT("name", name.px, name.length),
			JOT_PRINT("password", password.px, password.length),
			0);

	}

	/*
	 * <sip:rob:Foobar123@1.2.3.4:5060;user=rob;>;tag=1234
	 * ..................^................................
	 */
	trim_whitespace(px, &offset, length);
	if (!match2("@", px, offset, length)) {
		FRAMERR(frame, "not \"sip:\" in URI\n");
		return;
	} else
		offset++;

	/*
	 * <sip:rob:Foobar123@1.2.3.4:5060;user=rob;>;tag=1234
	 * ...................^^^^^^^.........................
	 */
	trim_whitespace(px, &offset, length);
	{
		unsigned start;
		
		start = offset;
		host.px = px+offset;
		while (offset<length && px[offset] != ':' && px[offset] != '>' && px[offset] != ';')
			offset++;
		host.length = offset-start;
        host=host;
	}

	/*
	 * <sip:rob:Foobar123@1.2.3.4:5060;user=rob;>;tag=1234
	 * ..........................^^^^^....................
	 */
	trim_whitespace(px, &offset, length);
	if (match2(":", px, offset, length)) {

		offset++; /* skip ':' */
		trim_whitespace(px, &offset, length);
		
		port = 0;
		while (offset<length && isdigit(px[offset]))
			port = port * 10 + px[offset++] - '0';
	}

	/*
	 * <sip:rob:Foobar123@1.2.3.4:5060;user=rob;>;tag=1234
	 * ...............................^^^^^^^^^...........
	 */
	trim_whitespace(px, &offset, length);
	while (match2(";", px, offset, length)) {
		struct Field name = {0,0};
		struct Field value = {0,0};
		unsigned start;
		offset++; /* skip ':' */
		
		/* name */
		trim_whitespace(px, &offset, length);
		name.px = px+offset;
		start = offset;
		while (offset<length && px[offset] != '>' && px[offset] != ';' && px[offset] != '=')
			offset++;
		name.length = offset-start;

		/* value */
		trim_whitespace(px, &offset, length);
		if (match2("=", px, offset, length)) {
			offset++;
			trim_whitespace(px, &offset, length);
			value.px = px+offset;
			start = offset;
			while (offset<length && px[offset] != '>' && px[offset] != ';')
				offset++;
			value.length = offset-start;
		}

        name=name;value=value;
		trim_whitespace(px, &offset, length);
	}

	/*
	 * <sip:rob:Foobar123@1.2.3.4:5060;user=rob;>;tag=1234
	 * .........................................^.........
	 */
	trim_whitespace(px, &offset, length);
	if (match2(">", px, offset, length)) {
		offset++;
	}

	/*
	 * <sip:rob:Foobar123@1.2.3.4:5060;user=rob;>;tag=1234
	 * ..........................................^^^^^^^^^
	 */
	trim_whitespace(px, &offset, length);
	while (match2(";", px, offset, length)) {
		struct Field name = {0,0};
		struct Field value = {0,0};
		unsigned start;
		offset++; /* skip ':' */
		
		/* name */
		trim_whitespace(px, &offset, length);
		name.px = px+offset;
		start = offset;
		while (offset<length && px[offset] != '>' && px[offset] != ';' && px[offset] != '=')
			offset++;
		name.length = offset-start;

		/* value */
		trim_whitespace(px, &offset, length);
		if (match2("=", px, offset, length)) {
			offset++;
			trim_whitespace(px, &offset, length);
			value.px = px+offset;
			start = offset;
			while (offset<length && px[offset] != '>' && px[offset] != ';')
				offset++;
			value.length = offset-start;
		}

        name=name;value=value;
		trim_whitespace(px, &offset, length);
	}

}


/****************************************************************************
 ****************************************************************************/
void
parse_dgram_sip_response(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned code = 0;
	unsigned offset;
	struct Field field;

	frame->layer7_protocol = LAYER7_SIP;

	/*
	 * Get teh response code. Some expected values are:
	 * 100 trying
	 * 180 ringing
	 * 200 ok
	 * 401 unauthorized
	 * 407 proxy authentication required
	 */
	code = sip_get_response_code(px, length);
    code=code; /*compiler warning*/

	/* Process all "Via" headers */
	offset = 0;
	while (sip_get_next_header("Via", px, &offset, length, &field)) {
		sip_via(ferret, frame, field.px, field.length);
	}

	/* "To" */
	offset = 0;
	while (sip_get_next_header("To", px, &offset, length, &field)) {
		sip_parse_uri(ferret, frame, field.px, field.length);
	}

	/* "From" */
	offset = 0;
	while (sip_get_next_header("From", px, &offset, length, &field)) {
		sip_parse_uri(ferret, frame, field.px, field.length);
	}



	UNUSEDPARM(ferret);UNUSEDPARM(frame);UNUSEDPARM(px);UNUSEDPARM(length);
}


