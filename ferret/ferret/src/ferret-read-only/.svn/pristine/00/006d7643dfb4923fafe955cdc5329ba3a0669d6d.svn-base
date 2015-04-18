/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	COMMON UNIX PRINTING SERVICE

  CUPS is a protocol used by Linux, Mac OS X, and some other Unix systems.
  These packets tell us about all the printers that a system either provides
  or wants connectivity to. When we see broadcasts from a mobile notebook
  computer, we'll discover hints about it's home network.

  In addition, printers and printer drivers are notoriously full of 
  vulnerabilities. Therefore, CUPS will tell us about vulnerabilities
  that we can possibly exploits.
*/
#include "stack-parser.h"
#include "ferret.h"
#include "stack-netframe.h"
#include "stack-extract.h"

#include <ctype.h>

void extract_num(const unsigned char *px, unsigned length, unsigned *r_offset, unsigned *r_num)
{
	*r_num = 0;

	while (*r_offset<length && isspace(px[*r_offset]))
		(*r_offset)++;
	while (*r_offset<length && isdigit(px[*r_offset])) {
		(*r_num) *= 10;
		(*r_num) += px[*r_offset] - '0';
		(*r_offset)++;
	}
	while (*r_offset<length && isspace(px[*r_offset]))
		(*r_offset)++;
}

void extract_string(const unsigned char *px, unsigned length, unsigned *r_offset, const unsigned char **r_start, unsigned *r_length)
{
	unsigned quoted=0;
	*r_length = 0;

	if (*r_offset >= length)
		return;

	if (px[*r_offset] == '\"') {
		quoted = 1;
		(*r_offset)++;
	}
	*r_start = px+*r_offset;

	while (*r_offset < length) {
		if (quoted) {
			if (px[*r_offset] == '\"') {
				(*r_offset)++;
				break;
			}
		} else {
			if (isspace(px[*r_offset]))
				break;
		}

		(*r_offset)++;
		(*r_length)++;
	}

	while (*r_offset<length && isspace(px[*r_offset]))
		(*r_offset)++;
}
void process_cups(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset = 0;
	unsigned type=0;
	unsigned state = 0;
	const unsigned char *uri;
	unsigned uri_length;
	const unsigned char *location;
	unsigned location_length;
	const unsigned char *information;
	unsigned information_length;
	const unsigned char *model;
	unsigned model_length;

	frame->layer7_protocol = LAYER7_CUPS;

	extract_num(px, length, &offset, &type);
	extract_num(px, length, &offset, &state);

	extract_string(px, length, &offset, &uri, &uri_length);
	extract_string(px, length, &offset, &location, &location_length);
	extract_string(px, length, &offset, &information, &information_length);
	extract_string(px, length, &offset, &model, &model_length);

	JOTDOWN(ferret,
			JOT_SZ("proto", "CUPS"),
			JOT_SRC("ip.src", frame),
			JOT_NUM("type",type),
			0);
	JOTDOWN(ferret,
			JOT_SZ("proto", "CUPS"),
			JOT_SRC("ip.src", frame),
			JOT_NUM("state",state),
			0);
	JOTDOWN(ferret,
			JOT_SZ("proto", "CUPS"),
			JOT_SRC("ip.src", frame),
			JOT_PRINT("uri",		 	uri, uri_length),
			0);
	JOTDOWN(ferret,
			JOT_SZ("proto", "CUPS"),
			JOT_SRC("ip.src", frame),
			JOT_PRINT("location",		 	location, location_length),
			0);
	JOTDOWN(ferret,
			JOT_SZ("proto", "CUPS"),
			JOT_SRC("ip.src", frame),
			JOT_PRINT("info",		 	information, information_length),
			0);
	JOTDOWN(ferret,
			JOT_SZ("proto", "CUPS"),
			JOT_SRC("ip.src", frame),
			JOT_PRINT("model",	 	model, model_length),
			0);
}

