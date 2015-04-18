/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "util-mystring.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

struct X224_PDU
{
	unsigned state;
	unsigned char header_length;
	unsigned char code;
};

struct RDP_PDU
{
	unsigned tpkt_state;
	unsigned tpkt_length;
	struct X224_PDU x224;
};

#define CHECK(offset,length) if (offset >= length) continue
#define CHECK2(offset,length,state,s) if (offset >= length || state != s) continue

void parse_x224_pdu(struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length, struct X224_PDU *pdu, int to_server)
{
	struct Ferret *jot = frame->sess->eng->ferret;
	struct StringReassembler *name = &stream->str[0];
	unsigned offset = 0;
	unsigned state = pdu->state;
	enum {
		X224_HEADER_LENGTH,
		X224_HEADER_CODE,
		X224_DISPATCH,

		X224_CONNECT_DST_REF1,
		X224_CONNECT_DST_REF2,
		X224_CONNECT_SRC_REF1,
		X224_CONNECT_SRC_REF2,
		X224_CONNECT_CLASS,
		X224_CONNECT_DISPATCH,

		X224_CONNECT_C = 100,
		X224_CONNECT_CO,
		X224_CONNECT_COO,
		X224_CONNECT_COOK,
		X224_CONNECT_COOKI,
		X224_CONNECT_COOKIE,
		X224_CONNECT_COOKIEX,
		X224_CONNECT_COOKIEX_,

		X224_CONNECT_M,
		X224_CONNECT_MS,
		X224_CONNECT_MST,
		X224_CONNECT_MSTS,
		X224_CONNECT_MSTSH,
		X224_CONNECT_MSTSHA,
		X224_CONNECT_MSTSHAS,
		X224_CONNECT_MSTSHASH,
		X224_CONNECT_MSTSHASHX,

		X224_CONNECT_NAME,

		X224_CONNECT_UNKNOWN,
		X224_DONE,
		X224_ERROR,
	};

	while (offset<length)
	switch (state) {
	case X224_HEADER_LENGTH:
		pdu->header_length = px[offset++];
		if (pdu->header_length < 2) {
			state = X224_ERROR;
			continue;
		}
		pdu->header_length -= 2;
		state++;
		CHECK(offset,length);

	case X224_HEADER_CODE:
		pdu->code = (px[offset]>>4) & 0xF;
		offset++;
		state++;
		CHECK(offset,length);

	case X224_DISPATCH:
		switch (pdu->code) {
		case 0x0e:
			state = X224_CONNECT_DST_REF1;
			break;
		case 0x0f:
			state = X224_DONE;
			offset = length;
			break;
		default:
			state = X224_DONE;
			offset = length;
			//printf("." "%s %u", __FILE__, __LINE__); exit(1);
		}
		CHECK2(offset,length,state,X224_CONNECT_DST_REF1);

	case X224_CONNECT_DST_REF1:
	case X224_CONNECT_DST_REF2:
	case X224_CONNECT_SRC_REF1:
	case X224_CONNECT_SRC_REF2:
	case X224_CONNECT_CLASS:
		while (offset<length && state != X224_CONNECT_DISPATCH) {
			offset++;
			state++;
		}
		CHECK2(offset,length,state,X224_CONNECT_DISPATCH);

	case X224_CONNECT_DISPATCH:
		if (px[offset] == 'C') {
			state = X224_CONNECT_C;
		} else {
			state = X224_CONNECT_UNKNOWN;
		}
		CHECK2(offset,length,state,X224_CONNECT_C);

	case X224_CONNECT_C:
	case X224_CONNECT_CO:
	case X224_CONNECT_COO:
	case X224_CONNECT_COOK:
	case X224_CONNECT_COOKI:
	case X224_CONNECT_COOKIE:
	case X224_CONNECT_COOKIEX:
		while (offset<length && toupper(px[offset]) == "COOKIE:"[state-X224_CONNECT_C]) {
			state++;
			offset++;
		}
		if (offset<length && state != X224_CONNECT_COOKIEX_)
			state = X224_ERROR;

		CHECK2(offset,length,state,X224_CONNECT_COOKIEX_);

	case X224_CONNECT_COOKIEX_:
		while (offset<length && isspace(px[offset])) {
			offset++;
		}

		if (offset<length) {
			state = X224_CONNECT_M;
			strfrag_init(name);
		}

		CHECK2(offset,length,state,X224_CONNECT_M);

	case X224_CONNECT_M:
	case X224_CONNECT_MS:
	case X224_CONNECT_MST:
	case X224_CONNECT_MSTS:
	case X224_CONNECT_MSTSH:
	case X224_CONNECT_MSTSHA:
	case X224_CONNECT_MSTSHAS:
	case X224_CONNECT_MSTSHASH:
	case X224_CONNECT_MSTSHASHX:
		while (offset<length && toupper(px[offset]) == "mstshash="[state-X224_CONNECT_M]) {
			state++;
			offset++;
		}
		if (offset<length && state != X224_CONNECT_NAME)
			state = X224_ERROR;

		CHECK2(offset,length,state,X224_CONNECT_NAME);


	case X224_CONNECT_NAME:
		while (offset<length && px[offset] != '\r' && px[offset] != '\n') {
			strfrag_append(name, px+offset, 1);
			offset++;
		}
		if (offset<length && (px[offset] == '\r' || px[offset] == '\n')) {
			state = X224_DONE;
			JOTDOWN(jot,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("RDP-name", name->the_string, name->length),
				0);
		}
		break;

	case X224_ERROR:
	case X224_DONE:
	default:
		offset = length;
		break;
	}

	pdu->state = state;
}


void parse_tpkt_pdu(struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length, struct RDP_PDU *pdu, int to_server)
{
	unsigned offset = 0;
	unsigned state = pdu->tpkt_state;

	while (offset<length)
	switch (state) {
	case 0:
		if (px[offset++] != 3) {
			state = (unsigned)-1;
			continue;
		}
		state++;
		CHECK(offset,length);

	case 1:
		if (px[offset++] != 0) {
			state = (unsigned)-1;
			continue;
		}
		state++;
		CHECK(offset,length);

	case 2:
		pdu->tpkt_length = px[offset++]<<8;
		state++;
		CHECK(offset,length);

	case 3:
		pdu->tpkt_length |= px[offset++];
		if (pdu->tpkt_length < 4) {
			state = (unsigned)-1;
			continue;
		}
		pdu->tpkt_length -= 4;
		pdu->x224.state = 0;
		state++;
		CHECK(offset, length);

	case 4: /* */
		{
			unsigned len = pdu->tpkt_length;
			if (len > length-offset)
				len = length-offset;
			parse_x224_pdu(stream, frame, px+offset, len, &pdu->x224, to_server);
			offset += len;
			pdu->tpkt_length -= len;
			if (pdu->tpkt_length == 0)
				state = 0;
		}
		break;
	default:
		offset = length;
		break;
	}

	pdu->tpkt_state = state;
}

void parse_rdp_response(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct TCP_STREAM *from_server = &sess->from_server;
	struct RDP_PDU *pdu = (struct RDP_PDU*)&from_server->app;

	frame->layer7_protocol = LAYER7_RDP;

	parse_tpkt_pdu(from_server, frame, px, length, pdu, 0);
}
void parse_rdp_request(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct TCP_STREAM *to_server = &sess->to_server;
	struct RDP_PDU *pdu = (struct RDP_PDU*)&to_server->app;

	frame->layer7_protocol = LAYER7_RDP;
	
	parse_tpkt_pdu(to_server, frame, px, length, pdu, 0);
}

