/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	UPnP SSDP

  This is a Microsoft Windows protocol that is now supported by most
  WiFi access points and home routers.

  The WiFi access point will send out broadcasts notifying the local
  network telling everybody about what services it provides. We can
  discover, for example, the vendor of the device and it's operating
  system (such as Linux or VxWorks).


  A desktop application might use it to open ports. For example, the
  BitTorrent application knowwn as 'Azureus' will send a request to 
  the UpNP device asking it to open ports for incoming connections.


*/
#include "platform.h"
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"
#include "util-mystring.h"
#include <ctype.h>
#include <string.h>

enum {
	SSDP_UNKNOWN,
	SSDP_NOTIFY,
	SSDP_LOCATION,
	SSDP_M_SEARCH,
};
struct SSDP
{
	unsigned method;
};

typedef void (*HANDLE_HEADER)(struct Ferret *ferret, struct NetFrame *frame, 
				 struct StringReassembler *name,
				struct StringReassembler *value,
				void *v_data);




static void parse_headers(
	struct Ferret *ferret, struct NetFrame *frame, 
	const unsigned char *px, unsigned length,
	unsigned *r_state,
	struct StringReassembler *name,
	struct StringReassembler *value,
	HANDLE_HEADER handle_header,
	void *v_data)
{
	unsigned state=*r_state, offset=0;
	unsigned old_offset;
	enum {	S_PRE_METHOD, S_METHOD,S_METHOD_URL,S_URL,S_URL_VERSION, S_VERSION,
		S_NEWLINE,S_NAME,S_NAME_VALUE,S_VALUE,S_END };

	while (offset<length && state != S_END) {
		switch (state) {
		case S_PRE_METHOD:
			strfrag_init(name);
			strfrag_init(value);
			state++;
			break;
		case S_METHOD:
			old_offset = offset;
			while (offset<length && !isspace(px[offset]))
				offset++;
			strfrag_append(value, px+old_offset, offset-old_offset);
			
			/* if DONE */
			if (offset<length) {
				offset++;
				state++;
				strfrag_append(name, (const unsigned char*)" METHOD", 7);
				handle_header(ferret, frame, name, value, v_data);
				strfrag_init(name);
				strfrag_init(value);
			}
			break;
		case S_METHOD_URL:
			while (offset<length && isspace(px[offset]) && px[offset] != '\n')
				offset++;
			if (offset<length) {
				state++;
			}
			break;
		case S_URL:
			old_offset = offset;
			while (offset<length && !isspace(px[offset]))
				offset++;
			strfrag_append(value, px+old_offset, offset-old_offset);
			
			/* if DONE */
			if (offset<length) {
				offset++;
				state++;
				strfrag_append(name, (const unsigned char*)" URL", 4);
				handle_header(ferret, frame, name, value, v_data);
				strfrag_init(name);
				strfrag_init(value);
			}
			break;
		case S_URL_VERSION:
			while (offset<length && isspace(px[offset]) && px[offset] != '\n')
				offset++;
			if (offset<length) {
				state++;
			}
			break;
		case S_VERSION:
			old_offset = offset;
			while (offset<length && px[offset] != '\n')
				offset++;
			strfrag_append(value, px+old_offset, offset-old_offset);
			
			/* if DONE */
			if (offset<length) {
				offset++;
				state = S_NEWLINE;
				while (value->length && isspace(value->the_string[value->length-1]))
					value->length--; /*strip trailing whitespace*/
				strfrag_append(name, (const unsigned char*)" VERSION", 8);
				handle_header(ferret, frame, name, value, v_data);
				strfrag_init(name);
				strfrag_init(value);
			}
			break;
		case S_NEWLINE:
			switch (px[offset]) {
			case '\r':
				offset++;
				break;
			case '\n':
				offset++;
				state = S_END;
				break;
			case ':':
				offset++;
				state = S_NAME_VALUE;
				break;
			default:
				state = S_NAME;
			}
			break;
		case S_NAME:
			old_offset = offset;
			while (offset<length && px[offset] != ':' && px[offset] != '\n')
				offset++;
			strfrag_append(name, px+old_offset, offset-old_offset);
			
			/* if DONE */
			if (offset<length) {
				while (name->length && isspace(name->the_string[name->length-1]))
					name->length--; /*strip trailing whitespace*/

				if (px[offset] == ':')
					offset++;
				state = S_NAME_VALUE;
			}
			break;
		case S_NAME_VALUE:
			while (offset<length && isspace(px[offset]) && px[offset] != '\n')
				offset++;
			if (offset<length)
				state = S_VALUE;
			break;
		case S_VALUE:
			old_offset = offset;
			while (offset<length && px[offset] != '\n')
				offset++;
			strfrag_append(value, px+old_offset, offset-old_offset);
			
			/* if DONE */
			if (offset<length) {
				while (value->length && isspace(value->the_string[value->length-1]))
					value->length--; /*strip trailing whitespace*/
				state = S_NEWLINE;
				offset++;

				handle_header(ferret, frame, name, value, v_data);
				strfrag_init(name);
				strfrag_init(value);
			}
			break;
		}
	}
	*r_state = state;
}

void handle_ssdp_item(struct Ferret *ferret, struct NetFrame *frame, 
				 struct StringReassembler *name,
				struct StringReassembler *value,
				void *v_data)
{
	struct SSDP *ssdp = (struct SSDP *)v_data;

	UNUSEDPARM(frame);

	if (name->length == 0 || value->length == 0)
		return;

	SAMPLE(ferret,"SSDP", JOT_PRINT("header", name->the_string, name->length));

	switch (toupper(name->the_string[0])) {
	case ' ':
		if (MATCHES(" METHOD", name->the_string, name->length)) {
			SAMPLE(ferret,"SSDP", JOT_PRINT("method", value->the_string, value->length));
			if (MATCHES("NOTIFY", value->the_string, value->length))
				ssdp->method = SSDP_NOTIFY;
			else if (MATCHES("LOCATION", value->the_string, value->length))
				ssdp->method = SSDP_LOCATION;
			else if (MATCHES("M_SEARCH", value->the_string, value->length))
				ssdp->method = SSDP_M_SEARCH;
		}
		break;
	case 'L':
		if (MATCHES("LOCATION", name->the_string, name->length)) 
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP", frame),
				JOT_SZ("Device", "UPnP"),
				JOT_PRINT("LOCATION", value->the_string, value->length),
				0);
		break;
	case 'N':
		if (MATCHES("NT", name->the_string, name->length)) {
			if (value->length > 5 && memcmp(value->the_string, "uuid:", 5)==0)
				break; /* ignore those speciall uuid: records */
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP", frame),
				JOT_SZ("Device", "UPnP"),
				JOT_PRINT("SERVICE", value->the_string, value->length),
				0);
		}
		break;
	case 'S':
		if (MATCHES("SERVER", name->the_string, name->length))
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP", frame),
				JOT_SZ("Device", "UPnP"),
				JOT_PRINT("SOFTWARE", value->the_string, value->length),
				0);
		break;
	}

}

void parse_ssdp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct SSDP ssdp[1];
	unsigned state = 0;
	struct StringReassembler name[1];
	struct StringReassembler value[1];

	frame->layer7_protocol = LAYER7_SSDP;

	memset(ssdp, 0, sizeof(*ssdp));
	memset(name, 0, sizeof(*name));
	memset(value, 0, sizeof(*value));

	/* Call the generic "HTTP-like" parser */
	parse_headers(ferret, frame, px, length,
		&state, name, value, 
		handle_ssdp_item, ssdp);
	
}

