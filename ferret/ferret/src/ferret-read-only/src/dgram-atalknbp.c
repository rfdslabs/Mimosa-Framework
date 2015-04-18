/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	APPLETALK NAME BINDING PROTOCOL

  This protocol is similar in concept to the NetBIOS naming protocols,
  and/or the DNS protocol (for the AppleTalk suite).

  The sorts of information we want to get from this protocol are what
  name the client has, and what servers it wants to connect to.
*/
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"

void extract_item(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, 
				  unsigned length, unsigned *r_offset, 
				  const unsigned char **r_object, unsigned *r_object_len)
{
	unsigned len;

	UNUSEDPARM(ferret);

	if (*r_offset + 1 > length) {
		FRAMERR(frame, "truncated\n");
		*r_offset = length+1;
		return;
	}

	len = px[*r_offset];
	(*r_offset)++;

	if (*r_offset + len > length)
		len = length-*r_offset;

	*r_object = px + *r_offset;
	*r_object_len = len;

	*r_offset += len;
}

void parse_atalk_nbp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct {
		unsigned op;
		unsigned count;
		unsigned xid;
	} nbp;
	unsigned offset=0;

	if (length < 2) {
		FRAMERR(frame, "%s: truncated\n", "NBP");
		return;
	}

	/*
	 * Parse the header first
	 */
	nbp.op = (px[0]>>4)&0x0F;
	nbp.count = (px[0]>>0)&0x0F;
	nbp.xid = px[1];

	offset = 2;

	/*
	 * Parse all the name-bindings
	 */
	while (nbp.count) {
		unsigned atalk_addr;
		unsigned atalk_port;
		unsigned enumerator;
		unsigned object_len;
		const unsigned char *object;
		unsigned type_len;
		const unsigned char *type;
		unsigned zone_len;
		const unsigned char *zone;

		nbp.count--;

		if (offset + 6 > length) {
			FRAMERR(frame, "%s: truncated\n", "NBP");
			return;
		}

		atalk_addr = ex24be(px+offset);
		offset += 3;
		atalk_port = px[offset++];
		enumerator = px[offset++];
		
		UNUSEDPARM(enumerator);
		UNUSEDPARM(atalk_port);
		UNUSEDPARM(atalk_addr);


		/* Extract the items */
		extract_item(ferret, frame, px, length, &offset, &object, &object_len);
		extract_item(ferret, frame, px, length, &offset, &type, &type_len);
		extract_item(ferret, frame, px, length, &offset, &zone, &zone_len);

		if (offset > length)
			break;

		switch (nbp.op) {
		case 2:
			JOTDOWN(ferret,
				JOT_SRC("ID-ATALK", frame),
				JOT_PRINT("Lookup",  type, type_len),
				JOT_PRINT("Object",  object, object_len),
				JOT_PRINT("Zone",  zone, zone_len),
				0);
			break;
		default:
			FRAMERR(frame, "%s: not implemented\n", "NBP");
		}

	}


	
}

