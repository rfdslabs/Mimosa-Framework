#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>

#ifndef UNUSEDPARM
#define UNUSEDPARM(x) (void)x
#endif
#if defined(_MSC_VER) && !defined(inline)
#define inline __inline
#endif

#define ex32be(px)  (   *((unsigned char*)(px)+0)<<24 \
                    |   *((unsigned char*)(px)+1)<<16 \
                    |   *((unsigned char*)(px)+2)<< 8 \
                    |   *((unsigned char*)(px)+3)<< 0 )
#define ex32le(px)  (   *((unsigned char*)(px)+0)<< 0 \
                    |   *((unsigned char*)(px)+1)<< 8 \
                    |   *((unsigned char*)(px)+2)<<16 \
                    |   *((unsigned char*)(px)+3)<<24 )
#define ex16be(px)  (   *((unsigned char*)(px)+0)<< 8 \
                    |   *((unsigned char*)(px)+1)<< 0 )
#define ex16le(px)  (   *((unsigned char*)(px)+0)<< 0 \
                    |   *((unsigned char*)(px)+1)<< 8 )

#define ex24be(px)  (   *((unsigned char*)(px)+0)<<16 \
                    |   *((unsigned char*)(px)+1)<< 8 \
                    |   *((unsigned char*)(px)+2)<< 0 )
#define ex24le(px)  (   *((unsigned char*)(px)+0)<< 0 \
                    |   *((unsigned char*)(px)+1)<< 8 \
                    |   *((unsigned char*)(px)+2)<<16 )

#define ex64be(px)  ( (((uint64_t)ex32be(px))<<32L) + ((uint64_t)ex32be((px)+4)) )
#define ex64le(px)  ( ((uint64_t)ex32be(px)) + (((uint64_t)ex32be((px)+4))<<32L) )

unsigned
smellslike_bittorrent_uTP_v0(const unsigned char *px, unsigned length)
{
    unsigned type;
    unsigned extension;
    //unsigned connection_id;
    //unsigned seconds;
    //unsigned microseconds;
    unsigned difference;
    //unsigned window_size;
    //unsigned seq_nr;
    unsigned ack_nr;
    unsigned offset = 23;

    if (length < 23)
        return 0;
    type = px[18];
    if (type > 4) {
        return 0;
    }
    extension = px[17];
    if (extension > 2)
        return 0;

    //connection_id = ex32be(px+0);
    //seconds = ex32be(px+4);
    //microseconds = ex32be(px+8);
    difference = ex32be(px+12);
    //window_size = ex32be(px+16);
    //seq_nr = ex16be(px+19);
    ack_nr = ex16be(px+21);
    
    switch (type) {
    case 4:
        if (difference != 0 && difference != 0x7fffffff)
            return 0;
        if (ack_nr != 0)
            return 0;
        break;
    }

    while (extension) {
        unsigned x;
        unsigned len;
        if (offset + 2 > length)
            return 0;
        x = extension;
        extension = px[offset++];
        len = px[offset++];

        switch (x) {
        case 1: /* re-order count */
            if (len != 4)
                return 0;
            break;
        case 2: /* selective ack */
            if (len < 4)
                return 0; /* must be at least 4 */
            if (len&0x3)
                return 0; /* must be multiple of 4 */
            break;
            break;
        default:
            return 0;
        }

        offset += len;
    }

    
    return 1;
}

unsigned
smellslike_bittorrent_uTP(const unsigned char *px, unsigned length)
{
    unsigned type = (px[0]>>4);
    unsigned extension;
    //unsigned connection_id;
    //uint64_t microseconds;
    uint64_t difference;
    //unsigned window_size;
    //unsigned seq_nr;
    unsigned ack_nr;
    unsigned offset = 20;

    if (length < 20)
        return 0;
    if (type > 4)
        goto v0;
    if ((px[0] & 0xF) != 1) /*version*/
        goto v0;

    extension = px[1];
    //connection_id = ex16be(px+2);
    //microseconds = ex32be(px+4);
    difference = ex32be(px+8);
    //window_size = ex32be(px+12);
    //seq_nr = ex16be(px+16);
    ack_nr = ex16be(px+18);
    
    switch (type) {
    case 4:
        if (difference != 0 && difference != 0x7fffffff)
            goto v0;
        if (ack_nr != 0)
            goto v0;
        break;
    }

    while (extension) {
        unsigned x;
        unsigned len;
        if (offset + 2 > length)
            goto v0;
        x = extension;
        extension = px[offset++];
        len = px[offset++];

        switch (x) {
        case 1: /* re-order count */
            if (len != 4)
                goto v0;
            break;
        case 2: /* selective ack */
            if (len < 4)
                goto v0; /* must be at least 4 */
            if (len&0x3)
                goto v0; /* must be multiple of 4 */
            break;
            break;
        default:
            goto v0;
        }

        offset += len;
    }

    
    return 1;
v0:
    if (px[18] <= 4 && px[17] < 3)
        return smellslike_bittorrent_uTP_v0(px, length);
    else
        return 0;

}

