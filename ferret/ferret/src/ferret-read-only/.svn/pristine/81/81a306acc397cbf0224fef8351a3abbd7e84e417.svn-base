/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "util-base64.h"
#include "util-hamster.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>





void parse_ftp_request(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct TCP_STREAM *stream = &sess->to_server;
	struct PARSE *parse = &stream->parse;
	struct HTTPREQUEST *req = &stream->app.httpreq;

	UNUSEDPARM(req); UNUSEDPARM(parse);

	sess->layer7_proto = LAYER7_FTP;
	frame->layer7_protocol = LAYER7_FTP;
}

void parse_ftp_response(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct TCP_STREAM *stream = &sess->from_server;
	struct PARSE *parse = &stream->parse;
	struct HTTPREQUEST *req = &stream->app.httpreq;

	UNUSEDPARM(req); UNUSEDPARM(parse);

	sess->layer7_proto = LAYER7_FTP;
	frame->layer7_protocol = LAYER7_FTP;
}




