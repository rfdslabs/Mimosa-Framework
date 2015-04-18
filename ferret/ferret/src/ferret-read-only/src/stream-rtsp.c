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



void stream_rtsp_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	UNUSEDPARM(px); UNUSEDPARM(length);
	sess->layer7_proto = LAYER7_RTSP;
	frame->layer7_protocol = LAYER7_RTSP;
}

void stream_rtsp_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	UNUSEDPARM(px); UNUSEDPARM(length);
	sess->layer7_proto = LAYER7_RTSP;
	frame->layer7_protocol = LAYER7_RTSP;
}




