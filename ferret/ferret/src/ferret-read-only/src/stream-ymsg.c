/* Copyright (c) 2008 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "platform.h"
#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"

extern void process_ymsg_client_request(
		struct TCPRECORD *sess, 
		struct NetFrame *frame, 
		struct StringReassembler *ymsg_packet);
extern void process_ymsg_server_response(
		struct TCPRECORD *sess, 
		struct NetFrame *frame, 
		struct StringReassembler *ymsg_packet);


/*
     <------- 4B -------><------- 4B -------><---2B--->
    +-------------------+-------------------+---------+
    |   Y   M   S   G   |      version      | pkt_len |
    +---------+---------+---------+---------+---------+
    | service |      status       |    session_id     |
    +---------+-------------------+-------------------+
    |                                                 |
    :                    D A T A                      :
    |                   0 - 65535*                    |
    +-------------------------------------------------+
*/
void stack_tcp_ymsg_client_request(struct TCPRECORD *sess, struct TCP_STREAM *to_server, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned state = to_server->parse.state;
	struct StringReassembler *ymsg_packet = to_server->str+0;

	frame->layer7_protocol = LAYER7_YMSG;

	while (offset < length)
	switch (state) {
	case 0:
		strfrag_init(ymsg_packet);
		/* fall through */
	case 1: case 2: case 3:
		if (px[offset] == "YMSG"[state])
			state++;
		else
			state = 0;
		offset++;
		break;
	case 4: case 5: 
		to_server->app.ymsg.version <<= 8;
		to_server->app.ymsg.version &= 0xffff;
		to_server->app.ymsg.version |= px[offset];
		offset++;
		state++;
		break;
	case 6: case 7:
		offset++;
		state++;
		break;
	case 8: case 9:
		to_server->parse.remaining <<= 8;
		to_server->parse.remaining &= 0xFFFF;
		to_server->parse.remaining |= px[offset];
		offset++;
		state++;
		break;
	case 10: case 11:
		to_server->app.ymsg.service <<= 8;
		to_server->app.ymsg.service &= 0xFFFF;
		to_server->app.ymsg.service |= px[offset];
		offset++;
		state++;
		break;
	case 12: case 13: case 14: case 15:
		to_server->app.ymsg.status <<= 8;
		to_server->app.ymsg.status &= 0xFFFFffff;
		to_server->app.ymsg.status |= px[offset];
		offset++;
		state++;
		break;
	case 16: case 17: case 18: case 19:
		to_server->app.ymsg.session_id <<= 8;
		to_server->app.ymsg.session_id &= 0xFFFFffff;
		to_server->app.ymsg.session_id |= px[offset];
		offset++;
		state++;
		break;
	case 20:
		{
			unsigned chunk_len = to_server->parse.remaining;
			if (chunk_len > length-offset)
				chunk_len = length-offset;
		
			strfrag_append(ymsg_packet, px+offset, chunk_len);
			to_server->parse.remaining -= chunk_len;
			offset += chunk_len;

			if (to_server->parse.remaining == 0) {
				process_ymsg_client_request(sess, frame, ymsg_packet);
				strfrag_init(ymsg_packet);
				state = 0;
			}
		}
		break;
	}

	to_server->parse.state = state;
}

void stack_tcp_ymsg_server_response(struct TCPRECORD *sess, struct TCP_STREAM *from_server, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned state = from_server->parse.state;
	struct StringReassembler *ymsg_packet = from_server->str+0;

	frame->layer7_protocol = LAYER7_YMSG;

	while (offset < length)
	switch (state) {
	case 0:
		strfrag_init(ymsg_packet);
		/* fall through */
	case 1: case 2: case 3:
		if (px[offset] == "YMSG"[state])
			state++;
		else
			state = 0;
		offset++;
		break;
	case 4: case 5: 
		from_server->app.ymsg.version <<= 8;
		from_server->app.ymsg.version &= 0xffff;
		from_server->app.ymsg.version |= px[offset];
		offset++;
		state++;
		break;
	case 6: case 7:
		offset++;
		state++;
		break;
	case 8: case 9:
		from_server->parse.remaining <<= 8;
		from_server->parse.remaining &= 0xFFFF;
		from_server->parse.remaining |= px[offset];
		offset++;
		state++;
		break;
	case 10: case 11:
		from_server->app.ymsg.service <<= 8;
		from_server->app.ymsg.service &= 0xFFFF;
		from_server->app.ymsg.service |= px[offset];
		offset++;
		state++;
		break;
	case 12: case 13: case 14: case 15:
		from_server->app.ymsg.status <<= 8;
		from_server->app.ymsg.status &= 0xFFFFffff;
		from_server->app.ymsg.status |= px[offset];
		offset++;
		state++;
		break;
	case 16: case 17: case 18: case 19:
		from_server->app.ymsg.session_id <<= 8;
		from_server->app.ymsg.session_id &= 0xFFFFffff;
		from_server->app.ymsg.session_id |= px[offset];
		offset++;
		state++;
		break;
	case 20:
		{
			unsigned chunk_len = from_server->parse.remaining;
			if (chunk_len > length-offset)
				chunk_len = length-offset;
		
			strfrag_append(ymsg_packet, px+offset, chunk_len);
			from_server->parse.remaining -= chunk_len;
			offset += chunk_len;

			if (from_server->parse.remaining == 0) {
				process_ymsg_server_response(sess, frame, ymsg_packet);
				strfrag_init(ymsg_packet);
				state = 0;
			}
		}
		break;
	}

	from_server->parse.state = state;
}


