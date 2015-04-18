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


#define DROPDOWN(i,length,state) (state)++;if (++(i)>=(length)) break

void stream_ssh_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	UNUSEDPARM(px); UNUSEDPARM(length);
	sess->layer7_proto = LAYER7_SSH;
	frame->layer7_protocol = LAYER7_SSH;
}

void stream_ssh_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
    unsigned state = stream->parse.state;
    unsigned remaining = stream->parse.remaining;
	unsigned i;
    enum {
        S, SS, SSH, SSH_,
        BANNER,
        UNKNOWN,
    };
	sess->layer7_proto = LAYER7_SSH;
	frame->layer7_protocol = LAYER7_SSH;

    for (i=0; i<length; i++) 
    switch (state) {
    case S:
        if (px[i] != 'S') {
            state = UNKNOWN;
            break;
        }
        DROPDOWN(i,length,state);
    case SS:
        if (px[i] != 'S') {
            state = UNKNOWN;
            break;
        }
        DROPDOWN(i,length,state);

    case SSH:
        if (px[i] != 'H') {
            state = UNKNOWN;
            break;
        }
        DROPDOWN(i,length,state);

    case SSH_:
        if (px[i] != '-') {
            state = UNKNOWN;
            break;
        }
        stream->app.ssh.banner_length = 0;
        DROPDOWN(i,length,state);

    case BANNER:
        while (i<length && isprint(px[i]) && px[i] && px[i] != '\n') {
            if (stream->app.ssh.banner_length < sizeof(stream->app.ssh.banner))
                stream->app.ssh.banner[stream->app.ssh.banner_length++] = px[i];
            i++;
        }
        if (i<length) {
            //printf("SSH-%.*s\n", stream->app.ssh.banner_length, stream->app.ssh.banner);
            state = UNKNOWN;
        }
        break;
        
    case UNKNOWN:
    default:
        i = length;
    }

    stream->parse.state = state;
    stream->parse.remaining = remaining;

}

