/* Copyright (c) 2007-2013 by Errata Security, All Rights Reserved
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

/*
https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4
*/
#define DROPDOWN(i,length,state) (state)++;if (++(i)>=(length)) break

/*
    FRAGMENTATION content types
    change_cipher_spec(20)
    alert(21), handshake(22),
    application_data(23), (255)
*/

/*
       struct {
            uint8 major, minor;
        } ProtocolVersion;

        enum {
            change_cipher_spec(20), alert(21), handshake(22),
            application_data(23), (255)
        } ContentType;

        struct {
            ContentType type;
            ProtocolVersion version;
            uint16 length;
            opaque fragment[SSLPlaintext.length];
        } SSLPlaintext;

    SSL 3.0 patterns
    \x20 \x03 \x00
    \x21 \x03 \x00
    \x22 \x03 \x00
    \x23 \x03 \x00

*/
extern void record_ciphersuite(struct Ferret *ferret, unsigned ciphersuite);

/****************************************************************************
       struct {
           ProtocolVersion server_version;
           Random random;
           SessionID session_id;
           CipherSuite cipher_suite;
           CompressionMethod compression_method;
       } ServerHello;
****************************************************************************/
static void
server_hello(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
    struct SSL_SERVER_HELLO *hello = &stream->app.ssl.x.server_hello;
    unsigned state = hello->state;
    unsigned remaining = hello->remaining;
	unsigned i;
    enum {
        VERSION_MAJOR, VERSION_MINOR,
        TIME0, TIME1, TIME2, TIME3,
        RANDOM,
        SESSION_LENGTH, SESSION_ID,
        CIPHER0, CIPHER1,
        COMPRESSION,
        LENGTH0, LENGTH1,
        UNKNOWN,
    };


    for (i=0; i<length; i++) 
    switch (state) {
    case VERSION_MAJOR:
        hello->version_major = px[i];
        DROPDOWN(i,length,state);

    case VERSION_MINOR:
        hello->version_minor = px[i];
        if (hello->version_major > 3 || hello->version_minor > 4) {
            state = UNKNOWN;
            break;
        }
        hello->timestamp = 0;
        DROPDOWN(i,length,state);

    case TIME0:
        hello->timestamp <<= 8;
        hello->timestamp |= px[i];
        DROPDOWN(i,length,state);
    case TIME1:
        hello->timestamp <<= 8;
        hello->timestamp |= px[i];
        DROPDOWN(i,length,state);
    case TIME2:
        hello->timestamp <<= 8;
        hello->timestamp |= px[i];
        DROPDOWN(i,length,state);
    case TIME3:
        hello->timestamp <<= 8;
        hello->timestamp |= px[i];
        remaining = 28;
        DROPDOWN(i,length,state);
    case RANDOM:
        {
            unsigned len = length-i;
            if (len > remaining)
                len = remaining;

            remaining -= len;
            i += len-1;

            if (remaining != 0) {
                break;
            }
        }
        DROPDOWN(i,length,state);

    case SESSION_LENGTH:
        remaining = px[i];
        DROPDOWN(i,length,state);

    case SESSION_ID:
        {
            unsigned len = length-i;
            if (len > remaining)
                len = remaining;

            remaining -= len;
            i += len-1;

            if (remaining != 0) {
                break;
            }
        }
        hello->cipher_suite = 0;
        DROPDOWN(i,length,state);

    case CIPHER0:
        hello->cipher_suite <<= 8;
        hello->cipher_suite |= px[i];
        DROPDOWN(i,length,state);

    case CIPHER1:
        hello->cipher_suite <<= 8;
        hello->cipher_suite |= px[i];
        record_ciphersuite(sess->eng->ferret, hello->cipher_suite);

        DROPDOWN(i,length,state);

    case COMPRESSION:
        hello->compression_method = px[i];
        DROPDOWN(i,length,state);

    case LENGTH0: 
        remaining = px[i];
        DROPDOWN(i,length,state);

    case LENGTH1:
        remaining <<= 8;
        remaining |= px[i];
        DROPDOWN(i,length,state);
        break;

    case UNKNOWN:
    default:
        i = length;
    }

    hello->state = state;
    hello->remaining = remaining;
}

/****************************************************************************
 ****************************************************************************/
void content_ssl_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
}

/****************************************************************************
 ****************************************************************************/
void content_ssl_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
    struct SSLRECORD *ssl = &stream->app.ssl;
    unsigned state = ssl->record.state;
    unsigned remaining = ssl->record.remaining;
	unsigned i;
    enum {
        START,
        LENGTH0, LENGTH1, LENGTH2,
        CONTENTS,
        UNKNOWN,
    };

    for (i=0; i<length; i++) 
    switch (state) {
    case START:
        if (px[i] & 0x80) {
            state = UNKNOWN;
            break;
        }
        remaining = 0;
        ssl->record.type = px[i];
        ssl->x.all.state = 0;
        DROPDOWN(i,length,state);

    case LENGTH0: 
        remaining = px[i];
        DROPDOWN(i,length,state);

    case LENGTH1:
        remaining <<= 8;
        remaining |= px[i];
        DROPDOWN(i,length,state);

    case LENGTH2:
        remaining <<= 8;
        remaining |= px[i];
        DROPDOWN(i,length,state);

    case CONTENTS:
        {
            unsigned len = length-i;
            if (len > remaining)
                len = remaining;

            switch (ssl->record.type) {
            case 0x02: /* server hello */
                server_hello(sess, stream, frame, px+i, len);
                break;
            }

            remaining -= len;
            i += len-1;

            if (remaining == 0)
                state = START;
        }

        break;
    case UNKNOWN:
    default:
        i = length;
    }

    ssl->record.state = state;
    ssl->record.remaining = remaining;
}

/****************************************************************************
 ****************************************************************************/
void stream_ssl_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
    unsigned state = stream->parse.state;
    unsigned remaining = stream->parse.remaining;
    struct SSLRECORD *ssl = &stream->app.ssl;
	unsigned i;
    enum {
        START,
        VERSION_MAJOR,
        VERSION_MINOR,
        LENGTH0, LENGTH1,
        CONTENTS,
        UNKNOWN,
    };
	sess->layer7_proto = LAYER7_SSL;
	frame->layer7_protocol = LAYER7_SSL;

    for (i=0; i<length; i++) 
    switch (state) {
    case START:
        if (px[i] & 0x80) {
            state = UNKNOWN;
            break;
        }
        if (ssl->content_type != px[i]) {
            ssl->content_type = px[i];
            ssl->record.state = 0;
        }
        remaining = 0;
        DROPDOWN(i,length,state);

    case VERSION_MAJOR:
        ssl->version_major = px[i];
        DROPDOWN(i,length,state);

    case VERSION_MINOR:
        ssl->version_minor = px[i];
        DROPDOWN(i,length,state);

    case LENGTH0: 
        remaining = px[i]<<8;
        DROPDOWN(i,length,state);

    case LENGTH1:
        remaining |= px[i];
        DROPDOWN(i,length,state);

    case CONTENTS:
        {
            unsigned len = length-i;
            if (len > remaining)
                len = remaining;

            content_ssl_toserver(sess, stream, frame, px+i, len);

            remaining -= len;
            i += len-1;

            if (remaining == 0)
                state = START;
        }

        break;
    case UNKNOWN:
    default:
        i = length;
    }

    stream->parse.state = state;
    stream->parse.remaining = remaining;
}

/****************************************************************************
 ****************************************************************************/
void stream_ssl_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
    /*
     * NOTE:
     * This is a copy of the stuff above
     */
    unsigned state = stream->parse.state;
    unsigned remaining = stream->parse.remaining;
    struct SSLRECORD *ssl = &stream->app.ssl;
	unsigned i;
    enum {
        START,
        VERSION_MAJOR,
        VERSION_MINOR,
        LENGTH0, LENGTH1,
        CONTENTS,
        UNKNOWN,
    };
	sess->layer7_proto = LAYER7_SSL;
	frame->layer7_protocol = LAYER7_SSL;

    for (i=0; i<length; i++) 
    switch (state) {
    case START:
        if (px[i] & 0x80) {
            state = UNKNOWN;
            break;
        }
        if (ssl->content_type != px[i]) {
            ssl->content_type = px[i];
            ssl->record.state = 0;
        }
        remaining = 0;
        DROPDOWN(i,length,state);

    case VERSION_MAJOR:
        ssl->version_major = px[i];
        DROPDOWN(i,length,state);

    case VERSION_MINOR:
        ssl->version_minor = px[i];
        DROPDOWN(i,length,state);

    case LENGTH0: 
        remaining = px[i]<<8;
        DROPDOWN(i,length,state);

    case LENGTH1:
        remaining |= px[i];
        DROPDOWN(i,length,state);

    case CONTENTS:
        {
            unsigned len = length-i;
            if (len > remaining)
                len = remaining;

            content_ssl_fromserver(sess, stream, frame, px+i, len);

            remaining -= len;
            i += len-1;

            if (remaining == 0)
                state = START;
        }

        break;
    case UNKNOWN:
    default:
        i = length;
    }

    stream->parse.state = state;
    stream->parse.remaining = remaining;
}




