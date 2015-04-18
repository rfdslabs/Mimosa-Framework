#include "ferret.h"
#include "stack-netframe.h"
#include "dgram-sip.h"
#include "parse-address.h"
#include "stack-listener.h"

#include <ctype.h>


/****************************************************************************
 ****************************************************************************/
static int
sdp_next_header(const char name, const unsigned char *px, unsigned length, struct Field *field, unsigned index)
{
	unsigned offset = 0;
	unsigned count = 0;

	while (offset < length) {
		unsigned i;
		unsigned line_length;
		unsigned value_offset;
		unsigned next_offset;

		/* Find the end of the line */
		for (i=0; offset+i<length && px[offset+i] != '\n'; i++)
			;
		next_offset = offset+i+1;


		/* Find the total length of the line minus space at end */
		line_length = i;
		while (line_length > 0 && isspace(px[offset+line_length-1]))
			line_length--;

		/*
		 * Find the name
		 */
		if (name != px[offset]) {
			offset = next_offset;
			continue;
		}

		if (count++ < index) {
			offset = next_offset;
			continue;
		}

		/*
		 * Grab the value
		 */
		value_offset = 1;
		while (value_offset < line_length && isspace(px[offset+value_offset]))
			value_offset++;
		if (value_offset < line_length && px[offset+value_offset] == '=')
			value_offset++;
		while (value_offset < line_length && isspace(px[offset+value_offset]))
			value_offset++;

		while (value_offset < line_length && isspace(px[offset+value_offset]))
			value_offset++;
 
		field->px = px+offset+value_offset;
		field->length = line_length-value_offset;

		return 1; /* found */
	}

	field->px = (const unsigned char*)"";
	field->length = 0;
	return 0;
}

/****************************************************************************
 ****************************************************************************/
int
field_next(const struct Field *field, unsigned *r_offset, struct Field *tok)
{
	unsigned i = *r_offset;

	if (i >= field->length) {
		tok->px = field->px + field->length;
		tok->length = 0;
		return 0;
	}

	/* up to next non-space character */
	while (i < field->length && !isspace(field->px[i]))
		i++;
	tok->px = field->px + *r_offset;
	tok->length = i - *r_offset;

	/* strip trailing whitespace */
	while (i < field->length && isspace(field->px[i]))
		i++;

	*r_offset = i;

	return 1;
}


#if 0
/****************************************************************************
 ****************************************************************************/
static int
field_has_prefix(const char *prefix, const struct Field *field, unsigned offset)
{
	unsigned i;

	for (i=0; i+offset<field->length; i++) {
		if (tolower(prefix[i]) != tolower(field->px[offset+i]))
			return 0;
	}
	if (i < field->length)
		return 0;
	return 1;
}
#endif

/****************************************************************************
 ****************************************************************************/
static int
field_next_nonnumber(const struct Field *field, unsigned *offset, struct Field *tok)
{
	tok->px = field->px + *offset;
	tok->length = 0;
	if (*offset >= field->length)
		return 0;

	while (*offset + tok->length < field->length && !isdigit(tok->px[tok->length]))
		tok->length++;
	return 1;
}

/****************************************************************************
 ****************************************************************************/
void
register_rtpavp(struct Ferret *ferret, unsigned connection_ip_address, const struct Field *port_field, unsigned time_secs)
{
	struct Field slash[1];
	uint64_t port_number;
	unsigned offset = 0;

	port_number = field_next_number(port_field, &offset);
	if (port_number > 65535)
		return;
	listener_register_udp(ferret, LISTENER_UDP_RTPAVP, connection_ip_address, (unsigned)port_number, time_secs);
	listener_register_udp(ferret, LISTENER_UDP_RTCP, connection_ip_address, (unsigned)port_number+1, time_secs);

	/* See if a range was specified */
	if (field_next_nonnumber(port_field, &offset, slash) && field_equals_nocase("/",slash)) {
		uint64_t ttl = field_next_number(port_field, &offset);
		UNUSEDPARM(ttl);
		if (field_next_nonnumber(port_field, &offset, slash) && field_equals_nocase("/",slash)) {
			if (field_is_number(port_field, offset)) {
				uint64_t range = field_next_number(port_field, &offset);
				unsigned i;

				for (i=1 /*already did first one */; i<range; i++) {
					port_number += 2;
					listener_register_udp(ferret, LISTENER_UDP_RTPAVP, connection_ip_address, (unsigned)port_number, time_secs);
					listener_register_udp(ferret, LISTENER_UDP_RTCP, connection_ip_address, (unsigned)port_number+1, time_secs);
				}
			}
		}
	}
}

/****************************************************************************
 ****************************************************************************/
void
parse_sdp_invite_request(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct Field field[1];
	unsigned connection_ip_address = 0;
	unsigned index = 0;

	/*GSKY
v=0
o=vcc 27936 1 IN IP4 72.5.65.87
s=-
c=IN IP4 74.201.114.143
t=0 0
m=audio 10940 RTP/AVP 4 18 0 8 101
a=rtpmap:4 G723/8000/1
a=rtpmap:18 G729/8000/1
a=rtpmap:0 PCMU/8000/1
a=rtpmap:8 PCMA/8000/1
a=rtpmap:101 telephone-event/8000
a=ptime:20
*/

	/*
	 * c (Connection Information)
	 */
	index = 0;
	while (sdp_next_header('c', px, length, field, index)) {
		struct Field network_type[1];
		unsigned offset = 0;
		
		index++;

		field_next(field, &offset, network_type);
		if (field_equals_nocase("IN",network_type)) {
			struct Field addr_type[1];
			field_next(field, &offset, addr_type);
			if (field_equals_nocase("IP4",addr_type)) {
				struct Field addr[1];
				unsigned offset2 = 0;
				struct ParsedIpAddress ip;

				field_next(field, &offset, addr);
				if (parse_ipv4_address((const char*)addr->px, &offset2, addr->length, &ip)) {
					connection_ip_address = ip.address[0]<<24 | ip.address[1]<<16 | ip.address[2]<<8 | ip.address[3]<<0;
				}
			} else if (field_equals_nocase("IP6",addr_type)) {
			} else {
				fprintf(stderr, "SDP: unknown addr type: %.*s\n", addr_type->length, addr_type->px);
			}
		}
	}

	/*
	 * m (Media Information)
	 */
	index = 0;
	while (sdp_next_header('m', px, length, field, index)) {
		struct Field media_type[1];
		struct Field port_field[1];
		struct Field protocol_type[1];
		unsigned offset = 0;
		
		index++;

		/*
		 * Currently defined media are "audio",
         * "video", "text", "application", and "message",
		 */
		field_next(field, &offset, media_type);
		
		/*
		 * <port> 0..65535
		 */
		field_next(field, &offset, port_field);

		/*
		 * <protocol>
		 */
		field_next(field, &offset, protocol_type);
		if (field_equals_nocase("RTP/AVP", protocol_type)) {
			register_rtpavp(ferret, connection_ip_address, port_field, frame->time_secs);
		}

		if (protocol_type->length) {
			unsigned offset2 = 0;
			//uint64_t port_number;

			/*port_number = */field_next_number(port_field, &offset2);
		}

	}

}
