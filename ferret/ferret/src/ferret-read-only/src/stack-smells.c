#include "stack-smells.h"
#include "ferret.h"
#include "stack-netframe.h"
#include <assert.h>


/****************************************************************************
 * These are some macros to make the transitions clear. There are different
 * types of transitions we can make, such as whether we consume the next
 * character, or transition without consuming it.
 ****************************************************************************/
#define TRANSITION_IF_MORE(new_state) if (i<length) s = new_state
#define TRANSITION(new_state) s = new_state
#define TRANSITION_PLUS(new_state,exp) s = new_state, exp

enum {
    S_START=0,
    S_YES=1,
    S_NO=2,
    S_MAYBE=3,
    S_FIRST=4,
};


/****************************************************************************
 ****************************************************************************/
int
smellslike_msrpc_toserver(struct SmellsDCERPC *smell, const unsigned char *px, unsigned length)
{
    unsigned i;
    unsigned s = smell->state;
    enum {
/*
+--------+--------+--------+--------+
| ver=5  |min=0/1 |  type  |  flags |
+----+---+--------+--------+--------+
|endn|   |        |                 |
+----+---+--------+--------+--------+
|   frag_length   |   auth_length   |
+--------+--------+--------+--------+
|           call identifier         |
+--------+--------+--------+--------+
*/
        S_VER_MAJ=S_FIRST, 
        S_VER_MIN,
        S_TYPE,
        S_BIND_FLAGS,
        S_FLAGS,
        S_ENDIAN,
        S_RESERVED1b,
        S_RESERVED2b,
        S_RESERVED3b,
        S_FRAGLEN1b,
        S_FRAGLEN2b,
        S_AUTHLEN1b,
        S_AUTHLEN2b,
        S_RESERVED1l,
        S_RESERVED2l,
        S_RESERVED3l,
        S_FRAGLEN1l,
        S_FRAGLEN2l,
        S_AUTHLEN1l,
        S_AUTHLEN2l,
        S_CALLID1,
        S_CALLID2,
        S_CALLID3,
        S_CALLID4,
        S_VARHEADER,
        S_PDU,

        /* */
        S_AUTH_START,
        S_UNKNOWN,
        S_UNTILEND, /* parse data until end of PDU */
        S_BAD_STATEX,
        S_BAD_STATE /* never leave this state */
    };

    for (i=0; i<length;)
    switch (s) {
	case S_START:
    case S_VER_MAJ:
        if (px[i++] != 0x05) {
            TRANSITION(S_NO);
            break;
        } else {
            TRANSITION(S_VER_MIN);
            break;
        }
        break;
    case S_VER_MIN:
        if (px[i++] > 0x01) {
            TRANSITION(S_NO);
            break;
        } else {
            TRANSITION(S_TYPE);
            break;
        }
        break;
    case S_TYPE:
        {
            unsigned c = px[i++];
            if ((/*0x00 <= c &&*/ c <= 0x03) || (0x0b <= c && c <= 0x13)) {
                if (c == 0x0b) {
                    TRANSITION(S_BIND_FLAGS);
                } else {
                    TRANSITION(S_FLAGS);
                }
            } else {
                TRANSITION(S_NO);
            }
        }
        break;
    case S_BIND_FLAGS:
        if (px[i++] == 0x03) {
            TRANSITION(S_ENDIAN);
        } else {
            TRANSITION(S_NO);
        }
        break;
    case S_FLAGS:
        if ((px[i++]&0xFC) == 0) {
            TRANSITION(S_ENDIAN);
        } else {
            TRANSITION(S_NO);
        }
        break;

    case S_ENDIAN:
        switch (px[i++]) {
        case 0x00:
            TRANSITION(S_RESERVED1b);
            break;
        case 0x10:
            TRANSITION(S_RESERVED1l);
            break;
        default:
            TRANSITION(S_NO);
            break;
        }
        break;
    case S_RESERVED1b:
    case S_RESERVED1l:
    case S_RESERVED2b:
    case S_RESERVED2l:
    case S_RESERVED3b:
    case S_RESERVED3l:
        if (px[i++] != 0x00) {
            TRANSITION(S_NO);
        } else {
            s++;
        }
        break;
    case S_FRAGLEN1l:
    case S_AUTHLEN1l:
        smell->len = px[i++];
        s++;
        break;
    case S_FRAGLEN2l:
        smell->len |= (px[i++]<<8);
        if (smell->len < 20 || 13000 < smell->len) {
            TRANSITION(S_NO);
        } else {
            TRANSITION(S_AUTHLEN1l);
        }
        break;
    case S_AUTHLEN2l:
        smell->len |= (px[i++]<<8);
        if (6000 < smell->len) {
            TRANSITION(S_NO);
        } else {
            TRANSITION(S_YES);
        }
        break;

    case S_FRAGLEN1b:
    case S_AUTHLEN1b:
        smell->len = (unsigned short)(px[i++]<<8);
        s++;
        break;
    case S_FRAGLEN2b:
        smell->len |= px[i++];
        if (smell->len < 20 || 6000 < smell->len) {
            TRANSITION(S_NO);
        } else {
            TRANSITION(S_AUTHLEN1l);
        }
        break;
    case S_AUTHLEN2b:
        smell->len |= px[i++];
        if (6000 < smell->len) {
            TRANSITION(S_NO);
        } else {
            TRANSITION(S_YES);
        }
        break;


    case S_YES:
		//i = length;
	    smell->state = (unsigned short)s;
		return 1;

    case S_NO:
        i = length;
        break;
    default:
        assert(!"unknown state");
        break;
    }
    smell->state = (unsigned short)s;
	return 0;
}


int
smellslike_ssl_request(const struct NetFrame *frame, struct SmellsSSL *smell, const unsigned char *px, unsigned length)
{
	unsigned state = smell->state;
	unsigned offset = 0;
#define NEXT_STATE(state, offset, lenth) if (++state == 0 || ++offset >= length) break
	while (offset < length)
	switch (state) {
	case (unsigned)-1:
		//offset = length;
		smell->state = state;
		return 0;
		break;

	case 0:
		smell->type = px[offset];
		switch (px[offset]) {
		case 22:
			NEXT_STATE(state, offset, length);
			break;
		default:
			state = (unsigned)-1;
			continue;
		}

	case 1: /*version major */
		smell->version_major = px[offset];
		switch (px[offset]) {
		case 3:
			NEXT_STATE(state, offset, length);
			break;
		default:
			state = (unsigned)-1;
			continue;
		}

	case 2: /* version minor */
		smell->version_minor = px[offset];
		NEXT_STATE(state, offset, length);

	case 3:
		smell->length = px[offset]<<8;
		NEXT_STATE(state, offset, length);

	case 4:
		smell->length |= px[offset];
		if (smell->length < 10) {
			state = (unsigned)-1;
			continue;
		}
		NEXT_STATE(state, offset, length);

	case 5:
		smell->subtype = px[offset];
		switch (px[offset]) {
		case 1:
			NEXT_STATE(state, offset, length);
			break;
		case 16:
			state = (unsigned)-1;
			continue;
		}

	case 6:
		if (px[offset] != 0) {
			state = (unsigned)-1;
			continue;
		}
		NEXT_STATE(state, offset, length);

	case 7:
		smell->inner_length = px[offset]<<8;
		NEXT_STATE(state, offset, length);

	case 8:
		smell->inner_length |= px[offset];
		if (smell->inner_length > smell->length+4) {
			state = (unsigned)-1;
			continue;
		}
		if (smell->inner_length < 10) {
			state = (unsigned)-1;
			continue;
		}
		if (smell->inner_length < smell->length - 10) {
			state = (unsigned)-1;
			continue;
		}
		NEXT_STATE(state, offset, length);

	case 9: /* Handshake: Version Major */
		if (px[offset] != smell->version_major) {
			printf("%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
				(frame->src_ipv4>>24)&0xFF,
				(frame->src_ipv4>>16)&0xFF,
				(frame->src_ipv4>> 8)&0xFF,
				(frame->src_ipv4>> 0)&0xFF,
				frame->src_port,

				(frame->dst_ipv4>>24)&0xFF,
				(frame->dst_ipv4>>16)&0xFF,
				(frame->dst_ipv4>> 8)&0xFF,
				(frame->dst_ipv4>> 0)&0xFF,
				frame->dst_port

				);
			state = (unsigned)-1;
			continue;
		}
		NEXT_STATE(state, offset, length);

	case 10: /* Handshake: Version Minor */
		NEXT_STATE(state, offset, length);



		return 1;


	}



	smell->state = state;
	return 0;
}

