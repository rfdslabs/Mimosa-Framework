/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	depricated

  See the file 'ssdp' instead.
*/
#include "stack-parser.h"
#include "ferret.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include <ctype.h>
#include <string.h>


/*
	urn:schemas-upnp-org:service:ContentDirectory:1

*/



void process_upnp_response(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;

	frame->layer7_protocol = LAYER7_UPNP;

	while (offset < length) {
		const unsigned char *line = px+offset;
		unsigned line_length;

		for (line_length=0; offset+line_length < length && px[offset+line_length] != '\n'; line_length++)
			;
		offset += line_length;
		if (offset<length && px[offset] == '\n')
			offset++;
		while (line_length && isspace(line[line_length-1]))
			line_length--;

		if (line_length>3 && strnicmp((const char*)line, "ST:", 3) == 0) {
			JOTDOWN(ferret,
				JOT_SZ("proto","upnp"),
				JOT_SRC("ip.src", frame),
				JOT_PRINT("ST",		 	line+3, line_length-3),
				0);
		}
	}
}


