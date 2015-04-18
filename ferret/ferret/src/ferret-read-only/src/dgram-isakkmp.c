/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	ISAKMP

  This protocol is used for encrypted VPN connections. When
  the user sets up a connection, we can grab information from
  the private keys to figure out what company they work for.

  TODO: this is just a place holder right now.

*/
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include <string.h>


void process_isakmp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
    UNUSEDPARM(ferret);
    UNUSEDPARM(frame);
    UNUSEDPARM(px);
    UNUSEDPARM(length);

	frame->layer7_protocol = LAYER7_ISAKMP;

	return; /*TODO: add code later */
#if 0
    unsigned type;
	if (length < 1) {
		FRAMERR_TRUNCATED(frame, "isakmp");
		return;
	}

	type = px[0];
	SAMPLE(ferret,"ISAKMP", JOT_NUM("type", type));

	switch (type) {
	case 0xFF: /* keep alive */
		break;
	default:
		FRAMERR_UNKNOWN_UNSIGNED(frame, "isakmp", type);
		break;
	}
#endif
}

