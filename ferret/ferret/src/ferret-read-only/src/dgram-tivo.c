/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	TiVo

  TiVo is a television recording device. When hooked up to a local
  network, other computers can access the recorded video on the TiVo
  box.
*/
#include "stack-parser.h"
#include "ferret.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "util-mystring.h"
#include <ctype.h>

void 
handle_tivo_item(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *name, unsigned name_length, const unsigned char *value, unsigned value_length)
{
	if (name_length == 0|| value_length == 0)
		return;

	switch (toupper(name[0])) {
	case 'I':
		if (MATCHES("identity", name, name_length))
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP", frame),
				JOT_SZ("Device", "TiVo"),
				JOT_PRINT("Identity", value, value_length),
				0);
		break;
	case 'M':
		if (MATCHES("machine", name, name_length))
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP", frame),
				JOT_SZ("Device", "TiVo"),
				JOT_PRINT("Machine", value, value_length),
				0);
		break;
	case 'P':
		if (MATCHES("platform", name, name_length))
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP", frame),
				JOT_SZ("Device", "TiVo"),
				JOT_PRINT("Platform", value, value_length),
				0);
		break;
	case 'S':
		if (MATCHES("swversion", name, name_length))
			JOTDOWN(ferret, 
				JOT_SRC("ID-IP", frame),
				JOT_SZ("Device", "TiVo"),
				JOT_PRINT("Software-Version", value, value_length),
				0);
		if (MATCHES("services", name, name_length)) {

			/* This can be a comma-separated list, so let's report them
			 * individually */
			while (value_length) {
				unsigned i=0;

				while (i<value_length && value[i] != ',')
					i++;

				JOTDOWN(ferret, 
					JOT_SRC("ID-IP", frame),
					JOT_SZ("Device", "TiVo"),
					JOT_PRINT("Services", value, i),
					0);

				if (i<value_length)
					i++;

				value += i;
				value_length -= i;
			}
		}
		break;
	}

}

void 
parse_tivo_broadcast(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;

	frame->layer7_protocol = LAYER7_TIVO;

	while (offset<length) {
		const unsigned char *name;
		unsigned name_length;
		const unsigned char *value;
		unsigned value_length;

		/* Remove leading whitespace */
		while (offset<length && isspace(px[offset]))
			offset++;

		/* Grab the name */
		name = px+offset;
		while (offset<length && px[offset] != '=' && px[offset] != '\n')
			offset++;
		while (px+offset>name && isspace(px[offset-1]))
			offset--; /*trim trailing whitespace*/
		name_length = (unsigned)(px+offset-name);
		while (offset<length && (isspace(px[offset]) || px[offset]=='=') && px[offset] != '\n')
			offset++;

		/* Grab the value */
		value = px+offset;
		while (offset<length && px[offset] != '=' && px[offset] != '\n')
			offset++;
		while (px+offset>name && isspace(px[offset-1]))
			offset--; /*trim trailing whitespace*/
		value_length = (unsigned)(px+offset-value);
		while (offset<length && px[offset] != '\n')
			offset++;
		if (offset<length)
			offset++; /* skip '\n' */

		/* Handle the <name=value> pair */
		handle_tivo_item(ferret, frame, name, name_length, value, value_length);
	}
}

