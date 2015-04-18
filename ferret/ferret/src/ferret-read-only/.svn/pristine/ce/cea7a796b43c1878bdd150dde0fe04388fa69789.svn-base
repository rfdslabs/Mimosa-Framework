/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	CALLWAVE IM

  This is an instant messenger program based upon UDP.

  TODO: We need to right a decode for it. For the moment, we just
  decode the fact that we've seen the traffic.
*/
#include "stack-parser.h"
#include "ferret.h"
#include "stack-netframe.h"
#include "stack-extract.h"

#include <ctype.h>
#include <string.h>


void process_callwave_iam(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	if (length > 5) {
		if (ex32le(px+1) == (int)length) {
			unsigned op = px[0];

			frame->layer7_protocol = LAYER7_CALLWAVE;

			JOTDOWN(ferret,
				JOT_SZ("proto", "CallWave-IAM"),
				JOT_NUM("op",op),
				JOT_SRC("ip.src", frame),
				JOT_NUM("length",length),
				0);

		}
	}
}

