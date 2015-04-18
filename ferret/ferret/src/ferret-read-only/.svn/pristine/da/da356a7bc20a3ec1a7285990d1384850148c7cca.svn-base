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

enum MsgType {
    type_choke = 0,
    type_unchoke = 1,
    type_interested = 2,
    type_not_interested = 3,
    type_have = 4,
    type_bitfield = 5,
    type_request = 6,
    type_piece = 7,
    type_cancel = 8,
};
void stream_bittorrent_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
    struct BITTORRENT_TCP *app = &stream->app.bittorrent;
    unsigned i;
    unsigned state = stream->parse.state;
    unsigned remaining = stream->parse.remaining;
    enum {
        EXT = 20,
        DICT = 28,
        PEER = 48,
        MSG_LEN = 68,
        MSG_TYPE = 72,
        MSG = 73,
    };

	UNUSEDPARM(px); UNUSEDPARM(length);
	sess->layer7_proto = LAYER7_BITTORRENT_TCP;
	frame->layer7_protocol = LAYER7_BITTORRENT_TCP;

    for (i=0; i<length; i++)
    switch (state) {
    case 0:
        if (px[i] == 0x13)
            state++;
        else
            state = 0xFFFFFFFF;
        break;
    case  1: case  2: case  3: case  4: 
    case  5: case  6: case  7: case  8:
    case  9: case 10: case 11: case 12:
    case 13: case 14: case 15: case 16:
    case 17: case 18: case 19:
        if (tolower(px[i]) == "bittorrent protocol"[state-1])
            state++;
        else
            state = 0xFFFFFFFF;
        break;
    case EXT +  0: case EXT +  1: case EXT +  2: case EXT +  3:
    case EXT +  4: case EXT +  5: case EXT +  6: case EXT +  7: 
        app->extensions <<= 8;
        app->extensions |= px[i];
        state++;
        break;

    case DICT +  0: case DICT +  1: case DICT +  2: case DICT +  3:
    case DICT +  4: case DICT +  5: case DICT +  6: case DICT +  7: 
    case DICT +  8: case DICT +  9: case DICT + 10: case DICT + 11:
    case DICT + 12: case DICT + 13: case DICT + 14: case DICT + 15:
    case DICT + 16: case DICT + 17: case DICT + 18: case DICT + 19:
        app->hash_dictionary[state-DICT] = px[i];
        state++;
        break;
    
    case PEER +  0: case PEER +  1: case PEER +  2: case PEER +  3:
    case PEER +  4: case PEER +  5: case PEER +  6: case PEER +  7: 
    case PEER +  8: case PEER +  9: case PEER + 10: case PEER + 11:
    case PEER + 12: case PEER + 13: case PEER + 14: case PEER + 15:
    case PEER + 16: case PEER + 17: case PEER + 18: case PEER + 19:
        app->peer_id[state-PEER] = px[i];
        state++;
        break;
    
    case MSG_LEN+0:
        remaining = 0;
        /* fall through */
    case MSG_LEN+1:
    case MSG_LEN+2:
    case MSG_LEN+3:
        remaining <<= 8;
        remaining += px[i];
        state++;
        break;
    
    case MSG_TYPE:
        if (remaining == 0) {
            /* keep alive */
            i--;
            state = MSG_LEN;
            continue;
        }
        app->msg_type = px[i];
        state++;
        remaining--;
        break;
    case MSG:
        {
            unsigned len = length-i;
            if (len > remaining)
                len = remaining;

            remaining -= len;
            i += len-1;
        }
        if (remaining == 0)
            state = MSG_LEN;
        break;

    default:
    case 0xFFFFFFFF:
        i=length;
        break;
    }

    stream->parse.state = state;
    stream->parse.remaining = remaining;
}

void stream_bittorrent_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
    stream_bittorrent_toserver(sess, stream, frame, px, length);
}




