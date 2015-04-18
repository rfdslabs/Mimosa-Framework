/*
    "unknown" stream

    This is the default protocol parser for everything on TCP that isn't known.
    This parser will analyze the stream with heuristics, and once it discovers
    another protocol, will replace itself with the known protocol

*/
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "util-base64.h"
#include "util-hamster.h"
#include "smack.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

enum {
    MATCH_UNKNOWN=0,
    MATCH_NOCASE=0x001,
    MATCH_ANCHORED=0x02,
    M_WHITESPACE=0x100,
    M_ISREVERSE=0x200,
};

enum {
    SMELLSLIKE_NOTHING,
    SMELLSLIKE_HTTP_TOSERVER,
    SMELLSLIKE_HTTP_FROMSERVER,
    SMELLSLIKE_YAHOO_IM,
    SMELLSLIKE_MS_IM,       /* Microsoft MSN Messenger */
    SMELLSLIKE_POP3_TOSERVER,
    SMELLSLIKE_POP3_FROMSERVER,
    SMELLSLIKE_POP3_FROMSERVER2,
    SMELLSLIKE_FTP_FROMSERVER,
    SMELLSLIKE_RTSP_TOSERVER,
	SMELLSLIKE_RTSP_FROMSERVER,
	SMELLSLIKE_SMB,
	SMELLSLIKE_SMB2,
	SMELLSLIKE_MSRPC_TOSERVER,
    SMELLSLIKE_SSL_TOSERVER,
    SMELLSLIKE_SSL_FROMSERVER,
    SMELLSLIKE_BITTORRENT,
    SMELLSLIKE_SSH,
};

/****************************************************************************
 ****************************************************************************/
struct PatternMatches {
    const char *str;
    unsigned id;
    unsigned flags;
    FERRET_PARSER toserver;
    FERRET_PARSER fromserver;
};


/****************************************************************************
 ****************************************************************************/
static const struct PatternMatches headers[] = {
    //{"\xffSMB", SMELLSLIKE_SMB,                         MATCH_ANCHORED|MATCH_NOCASE},
    //{"\xfeSMB", SMELLSLIKE_SMB2,                        MATCH_ANCHORED|MATCH_NOCASE},
    {"GET http:/",   SMELLSLIKE_HTTP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_http_toserver, stream_http_fromserver},
    {"POST http:/",  SMELLSLIKE_HTTP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_http_toserver, stream_http_fromserver},
    {"HEAD http:/",  SMELLSLIKE_HTTP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_http_toserver, stream_http_fromserver},
    {"GET /",   SMELLSLIKE_HTTP_TOSERVER,               MATCH_ANCHORED|MATCH_NOCASE,
            stream_http_toserver, stream_http_fromserver},
    {"POST /",  SMELLSLIKE_HTTP_TOSERVER,               MATCH_ANCHORED|MATCH_NOCASE,
                stream_http_toserver, stream_http_fromserver},
    {"HEAD /",  SMELLSLIKE_HTTP_TOSERVER,               MATCH_ANCHORED|MATCH_NOCASE,
                stream_http_toserver, stream_http_fromserver},
    {"SSH-1.99-OpenSSH_3.", SMELLSLIKE_SSH, MATCH_ANCHORED|MATCH_NOCASE,
            stream_ssh_toserver, stream_ssh_fromserver},
    {"SSH-1.", SMELLSLIKE_SSH, MATCH_ANCHORED|MATCH_NOCASE,
            stream_ssh_toserver, stream_ssh_fromserver},
    {"SSH-2.", SMELLSLIKE_SSH, MATCH_ANCHORED|MATCH_NOCASE,
            stream_ssh_toserver, stream_ssh_fromserver},
#if 0
    {"HTTP/1.0 1",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE,
                stream_http_toserver, stream_http_fromserver},
    {"HTTP/1.1 1",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
    {"HTTP/1.0 2",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
    {"HTTP/1.1 2",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
    {"HTTP/1.0 3",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
    {"HTTP/1.1 3",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
    {"HTTP/1.0 4",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
    {"HTTP/1.1 4",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
    {"HTTP/1.0 5",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
    {"HTTP/1.1 5",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
    {"HTTP/1.0 6",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
    {"HTTP/1.1 6",SMELLSLIKE_HTTP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
#endif
    {"RTSP/1.0 2",SMELLSLIKE_RTSP_FROMSERVER,          MATCH_ANCHORED|MATCH_NOCASE|M_ISREVERSE},
    //{"YMSG",    SMELLSLIKE_YAHOO_IM,        MATCH_ANCHORED|MATCH_NOCASE},
    //{"USR",     SMELLSLIKE_MS_IM,           MATCH_ANCHORED|MATCH_NOCASE|M_WHITESPACE},
    //{"QNG",     SMELLSLIKE_MS_IM,           MATCH_ANCHORED|MATCH_NOCASE|M_WHITESPACE},
    //{"PNG",     SMELLSLIKE_MS_IM,           MATCH_ANCHORED|MATCH_NOCASE|M_WHITESPACE},
    //{"MSG",     SMELLSLIKE_MS_IM,           MATCH_ANCHORED|MATCH_NOCASE|M_WHITESPACE},
    //{"VER",     SMELLSLIKE_MS_IM,           MATCH_ANCHORED|MATCH_NOCASE|M_WHITESPACE},
    //{"ANS",     SMELLSLIKE_MS_IM,           MATCH_ANCHORED|MATCH_NOCASE|M_WHITESPACE},
    //{"USER",    SMELLSLIKE_POP3_TOSERVER,   MATCH_ANCHORED|MATCH_NOCASE|M_WHITESPACE},
    //{"AUTH",    SMELLSLIKE_POP3_TOSERVER,   MATCH_ANCHORED|MATCH_NOCASE|M_WHITESPACE},
    //{"+OK",     SMELLSLIKE_POP3_FROMSERVER, MATCH_ANCHORED|MATCH_NOCASE|M_WHITESPACE|M_ISREVERSE},
    //{"+OK Microsoft Exchange POP3",     SMELLSLIKE_POP3_FROMSERVER2, MATCH_ANCHORED|MATCH_NOCASE|M_WHITESPACE|M_ISREVERSE},
    //{"220",     SMELLSLIKE_FTP_FROMSERVER, MATCH_ANCHORED|MATCH_NOCASE|M_WHITESPACE|M_ISREVERSE},

    {"OPTIONS rtsp:/",   SMELLSLIKE_RTSP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_rtsp_toserver, stream_rtsp_fromserver},
    {"DESCRIBE rtsp:/",   SMELLSLIKE_RTSP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_rtsp_toserver, stream_rtsp_fromserver},
    {"SETUP rtsp:/",   SMELLSLIKE_RTSP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_rtsp_toserver, stream_rtsp_fromserver},
    {"PLAY rtsp:/",   SMELLSLIKE_RTSP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_rtsp_toserver, stream_rtsp_fromserver},
    {"PAUSE rtsp:/",   SMELLSLIKE_RTSP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_rtsp_toserver, stream_rtsp_fromserver},
    {"RECORD rtsp:/",   SMELLSLIKE_RTSP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_rtsp_toserver, stream_rtsp_fromserver},
    {"ANNOUNCE rtsp:/",   SMELLSLIKE_RTSP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_rtsp_toserver, stream_rtsp_fromserver},
    {"TEARDOWN rtsp:/",   SMELLSLIKE_RTSP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_rtsp_toserver, stream_rtsp_fromserver},
    {"GET_PARAMETER rtsp:/",   SMELLSLIKE_RTSP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_rtsp_toserver, stream_rtsp_fromserver},
    {"SET_PARAMETER rtsp:/",   SMELLSLIKE_RTSP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_rtsp_toserver, stream_rtsp_fromserver},
    {"REDIRECT rtsp:/",   SMELLSLIKE_RTSP_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_rtsp_toserver, stream_rtsp_fromserver},
    {"\x16\x03\x03\x0c\x1d\x0b",   SMELLSLIKE_SSL_TOSERVER,          MATCH_ANCHORED|MATCH_NOCASE,
            stream_ssl_toserver, stream_ssl_fromserver},
#if 0
    /* MS-RPC "bind" with minor-ver=0x00-0x03 and big/little endian */
    {"\x05\x00\x0b\x03\x10\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x01\x0b\x03\x10\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x02\x0b\x03\x10\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x03\x0b\x03\x10\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x00\x0b\x03\x00\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x01\x0b\x03\x00\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x02\x0b\x03\x00\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x03\x0b\x03\x00\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    
    /* MS-RPC "call" with minor-ver=0x00-0x03 and big/little endian */
    {"\x05\x00\x00\x03\x10\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x01\x00\x03\x10\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x02\x00\x03\x10\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x03\x00\x03\x10\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x00\x00\x03\x00\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x01\x00\x03\x00\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x02\x00\x03\x00\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
    {"\x05\x03\x00\x03\x00\x00\x00\x00", SMELLSLIKE_MSRPC_TOSERVER, MATCH_ANCHORED},
#endif

    {"\x13" "BitTorrent protocol",
            SMELLSLIKE_BITTORRENT,          MATCH_ANCHORED,
            stream_bittorrent_toserver, stream_bittorrent_fromserver},
    {0,0,0},
};

struct XUnknownEngine
{
    struct SMACK *headers;
    int x;
};

/****************************************************************************
 ****************************************************************************/
void
tcpsmellslike_destroy_engine(struct XUnknownEngine *unk)
{
    if (unk == NULL)
        return;
    if (unk->headers)
        smack_destroy(unk->headers);
    free(unk);
}

/****************************************************************************
 ****************************************************************************/
struct XUnknownEngine *
tcpsmellslike_create_engine()
{
    static const char whitespace[] = 
        " "     /* space */
        "\t"    /* tab */
        "\r"    /* carriage return */
        "\n"    /* newline/line feed */
        "\v"    /* vertical tab */
        "\f";   /* form feed */
    struct XUnknownEngine *xresult;
    unsigned i;

    /*
     * Create a new subsystem structure for this protocol
     */
    xresult = (struct XUnknownEngine*)malloc(sizeof(*xresult));
    memset(xresult, 0, sizeof(*xresult));

    /*
     * Add the patterns into a DFA that can pattern match at the start
     * of the TCP string to find any easily identifiable string.
     */
    xresult->headers = smack_create("tcpunknown", SMACK_CASE_INSENSITIVE);
    for (i=0; headers[i].str; i++) {
        char buf[256];
        unsigned len;
        unsigned is_anchored = (headers[i].flags & MATCH_ANCHORED);



        /* Create a copy of the method into a buffer */
        len = (unsigned)strlen(headers[i].str);
        if (len > sizeof(buf)-2)
            continue;
        /* Kludge: MSRPC patterns have \0 in them, so strlen() don't work */
        if (headers[i].id == SMELLSLIKE_MSRPC_TOSERVER)
            len = 8;

        memcpy(buf, headers[i].str, len);
  
        if (headers[i].flags & M_WHITESPACE) {
            /* Add the pattern with trailing whitespace if the 
             * flag is set */
            unsigned j;
            for (j=0; whitespace[j]; j++) {
                buf[len] = whitespace[j];

                smack_add_pattern(
                        xresult->headers, 
						buf,                /* pattern (method+whitespace char) */
						len+1,              /* pattern length */
						headers[i].id,      /* the identifier that will be returned for the method */
                        is_anchored?SMACK_ANCHOR_BEGIN:0);

            }
        } else {
            smack_add_pattern(
                xresult->headers,
                buf,                /* pattern (method+whitespace char) */
                len,                /* pattern length */
                headers[i].id,      /* the identifier that will be returned for the method */
                is_anchored?SMACK_ANCHOR_BEGIN:0);
        }
    }

    /* Add some SSL patterns */
    {
        unsigned char buf[] = {
            0x16, 0x03, 0x01, 0x00, 0xFF, 0x01, 0x00, 0xFF, 0x03
        };
        unsigned ver;

        for (ver=0; ver<=3; ver++) {
            unsigned len;
            for (len=48; len<500; len++) {
                /* 0x16, 0x03, 0x01, 0x00, 0xXX, 0x01, 0x00, 0xXX, 0x03 0x03 */
                buf[2] = (unsigned char)ver;
                buf[3] = (unsigned char)(len>>8);
                buf[4] = (unsigned char)(len);
                buf[6] = (unsigned char)((len-4)>>8);
                buf[7] = (unsigned char)((len-4));

                smack_add_pattern(
                    xresult->headers,
                    buf,                /* pattern (method+whitespace char) */
                    9,                /* pattern length */
                    headers[i].id,      /* the identifier that will be returned for the method */
                    SMACK_ANCHOR_BEGIN);

            }
        }
}

    smack_compile(xresult->headers);

    return xresult;
}

#ifndef MIN
#define MIN(a,b) ((a<b)?(a):(b))
#endif

/****************************************************************************
 ****************************************************************************/
static unsigned
is_reversed(size_t id)
{
    unsigned i;
    for (i=0; headers[i].str; i++) {
        if (headers[i].id == id)
            return (headers[i].flags & M_ISREVERSE) != 0;
    }
    return 0;
}

/****************************************************************************
 ****************************************************************************/
void
replace_parser(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length, size_t id)
{
    struct TCP_STREAM *toserver = &sess->to_server;
    struct TCP_STREAM *fromserver = &sess->from_server; 
    struct UNKNOWN *unk_to = &toserver->app.unknown;
    struct UNKNOWN *unk_from = &fromserver->app.unknown; 
    unsigned char buf_to[STREAM_UNKNOWN_BUF_SIZE];
    unsigned char buf_from[STREAM_UNKNOWN_BUF_SIZE];
    unsigned buf_tolen = unk_to->buf_len;
    unsigned buf_fromlen = unk_from->buf_len;
    unsigned i;

    memcpy(buf_to, unk_to->buf, buf_tolen);
    memcpy(buf_from, unk_from->buf, buf_fromlen);

    /* find the matching pattern */
    for (i=0; headers[i].str; i++) {
        if (headers[i].id == id)
            break;
    }

    if (headers[i].toserver == NULL || headers[i].fromserver == NULL) {
        printf(".");
    }
    
    sess->to_server.parser = headers[i].toserver;
    sess->from_server.parser = headers[i].fromserver;
    memset(&sess->to_server.app, 0, sizeof(sess->to_server.app));
    memset(&sess->from_server.app, 0, sizeof(sess->to_server.app));

    sess->to_server.parser(sess, toserver, frame, buf_to, buf_tolen);
    sess->from_server.parser(sess, fromserver, frame, buf_from, buf_fromlen);

    if (is_reversed(id))
        sess->from_server.parser(sess, toserver, frame, px, length);
    else
        sess->to_server.parser(sess, toserver, frame, px, length);
}

extern void reverse_direction(struct TCPRECORD *sess);

/****************************************************************************
 ****************************************************************************/
void
stream_to_server_unknown(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
    struct UNKNOWN *unk = &stream->app.unknown;
    struct SMACK *smack = sess->eng->tcp_smells->headers;
    unsigned buf_remaining = sizeof(unk->buf) - unk->buf_len;
    size_t id;
    unsigned offset  = 0;


    id = smack_search_next( smack,
                            &unk->ac_state,
                            px, 
                            &offset,
                            length);

    if (id != SMACK_NOT_FOUND && id != 0) {
        if (is_reversed(id)) {
            reverse_direction(sess);
            replace_parser(sess, stream, frame, px, length, id);
        } else
            replace_parser(sess, stream, frame, px, length, id);
        return; /* MUST RETURN NOW BECAUSE OUR DATA STRUCTURE IS DIFFERENT */
    }

    
    memcpy(unk->buf, px, MIN(buf_remaining, length));
    unk->buf_len += MIN(buf_remaining, length);

	frame->layer7_protocol = sess->layer7_proto = LAYER7_UNKNOWN_TCP;
}

/****************************************************************************
 ****************************************************************************/
void
stream_from_server_unknown(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
    struct UNKNOWN *unk = &stream->app.unknown;
    struct SMACK *smack = sess->eng->tcp_smells->headers;
    unsigned buf_remaining = sizeof(unk->buf) - unk->buf_len;
    size_t id;
    unsigned offset  = 0;

    memcpy(unk->buf, px, MIN(buf_remaining, length));
    unk->buf_len += MIN(buf_remaining, length);

    id = smack_search_next( smack,
                            &unk->ac_state,
                            px, 
                            &offset,
                            length);

    if (id != SMACK_NOT_FOUND && id != 0) {
        if (is_reversed(id))
            replace_parser(sess, stream, frame, px, length, id);
        else {
            reverse_direction(sess);
            replace_parser(sess, stream, frame, px, length, id);
            printf(".");
        }
        return; /* MUST RETURN NOW BECAUSE OUR DATA STRUCTURE IS DIFFERENT */
    }
    

	frame->layer7_protocol = sess->layer7_proto = LAYER7_UNKNOWN_TCP;
}




