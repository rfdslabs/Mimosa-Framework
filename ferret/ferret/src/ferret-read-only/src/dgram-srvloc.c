/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	SERVICE LOCATION

  This is a local broadcast protocol that services use to 
  publish their location on the network, and used by clients
  to find those services. W
*/
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "out-jotdown.h"
#include <string.h>

struct SRVLOC {
	unsigned version;
	unsigned function;
	unsigned packet_length;
	unsigned flags;
	unsigned next_extension_offset;
	unsigned transaction_id;
	const unsigned char *lang;
	unsigned lang_len;
	unsigned dialect;
	unsigned encoding;


	struct {
		struct {
			const unsigned char *prlist;
			unsigned prlist_length;
			const unsigned char *srvtype;
			unsigned srvtype_length;
			const unsigned char *scopes;
			unsigned scopes_length;
			const unsigned char *predicate;
			unsigned predicate_length;
			const unsigned char *slpspi;
			unsigned slpspi_length;
			
		} request;
	} pdu;
};

static void get_string(const unsigned  char *px, unsigned length, unsigned *r_offset, const unsigned char **r_str, unsigned *r_str_length)
{
	*r_str_length = 0;
	if ((*r_offset) + 4 > length)
		return;

	*r_str_length = ex16be(px+*r_offset);
	(*r_offset) += 2;
	*r_str = px + *r_offset;
	*r_offset += *r_str_length;
}

void process_srvloc_v1(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct SRVLOC loc[1];
	unsigned offset = 0;

	if (offset+14>length) {
		FRAMERR_TRUNCATED(frame, "srvloc");
		return;
	}

	loc->version = px[0];
	loc->function = px[1];
	loc->packet_length = ex24be(px+2);
	loc->flags = px[4];
	loc->dialect = px[5];
	loc->lang = px+6;
	loc->lang_len = 2;
	loc->encoding = ex16be(px+8);
	loc->transaction_id = ex16be(px+10);
	loc->lang_len = ex16be(px+12);
	loc->lang = px+14;

	SAMPLE(ferret,"SRVLOCv1", JOT_NUM("function", loc->function));
	SAMPLE(ferret,"SRVLOCv1", JOT_NUM("dialect", loc->dialect));
	SAMPLE(ferret,"SRVLOCv1", JOT_NUM("encoding", loc->encoding));
	SAMPLE(ferret,"SRVLOCv1", JOT_PRINT("language", loc->lang, loc->lang_len));

	switch (loc->function) {
	case 6:
		break;
	default:
		FRAMERR_BADVAL(frame, "srvloc", loc->function);
	}

}


void process_srvloc(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct SRVLOC loc[1];
	unsigned offset = 0;
	
	if (offset+14>length) {
		FRAMERR_TRUNCATED(frame, "srvloc");
		return;
	}

	frame->layer7_protocol = LAYER7_SRVLOC;

	switch (px[0]) {
	case 0x01:
		process_srvloc_v1(ferret, frame, px, length);
		return;
	}

	memset(loc,0,sizeof(*loc));

	/*
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |    Version    |  Function-ID  |            Length             |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     | Length, contd.|O|F|R|       reserved          |Next Ext Offset|
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Next Extension Offset, contd.|              XID              |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |      Language Tag Length      |         Language Tag          \
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */


	loc->version = px[0];
	loc->function = px[1];
	loc->packet_length = ex24be(px+2);
	loc->flags = ex16be(px+5);
	loc->next_extension_offset = ex24be(px+7);
	loc->transaction_id = ex16be(px+10);
	loc->lang_len = ex16be(px+12);
	loc->lang = px+14;
	
	offset = 14+loc->lang_len;

	SAMPLE(ferret,"SRVLOC", JOT_NUM("version", loc->version));
	SAMPLE(ferret,"SRVLOC", JOT_NUM("function", loc->function));
	SAMPLE(ferret,"SRVLOC", JOT_PRINT("language", loc->lang, loc->lang_len));

	if (loc->version != 2) {
		FRAMERR_UNKNOWN_UNSIGNED(frame, "srvloc", loc->version);
		return;
	}
	 
	switch (loc->function) {
	case 1: /*service request*/
		get_string(px, length, &offset, &loc->pdu.request.prlist, &loc->pdu.request.prlist_length);
		get_string(px, length, &offset, &loc->pdu.request.srvtype, &loc->pdu.request.srvtype_length);
		get_string(px, length, &offset, &loc->pdu.request.scopes, &loc->pdu.request.scopes_length);
		get_string(px, length, &offset, &loc->pdu.request.predicate, &loc->pdu.request.predicate_length);
		get_string(px, length, &offset, &loc->pdu.request.slpspi, &loc->pdu.request.slpspi_length);

		SAMPLE(ferret,"SRVLOC", JOT_PRINT("prlist", loc->pdu.request.prlist, loc->pdu.request.prlist_length));
		SAMPLE(ferret,"SRVLOC", JOT_PRINT("srvtype", loc->pdu.request.srvtype, loc->pdu.request.srvtype_length));
		SAMPLE(ferret,"SRVLOC", JOT_PRINT("scopes", loc->pdu.request.scopes, loc->pdu.request.scopes_length));
		SAMPLE(ferret,"SRVLOC", JOT_PRINT("predicate", loc->pdu.request.predicate, loc->pdu.request.predicate_length));
		SAMPLE(ferret,"SRVLOC", JOT_PRINT("slpspi", loc->pdu.request.slpspi, loc->pdu.request.slpspi_length));

		JOTDOWN(ferret,
			JOT_SZ("proto","srvloc"),
			JOT_SZ("function", "request"),
			JOT_PRINT("service", loc->pdu.request.srvtype, loc->pdu.request.srvtype_length),
			JOT_PRINT("scope", loc->pdu.request.scopes, loc->pdu.request.scopes_length),
			0);

		break;
	default:
		FRAMERR_UNKNOWN_UNSIGNED(frame, "srvloc", loc->version);
	}


}

