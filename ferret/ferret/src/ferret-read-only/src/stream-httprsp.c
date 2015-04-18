/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "util-base64.h"
#include "util-hamster.h"
#include "stream-http.h"
#include "report.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>


static void 
value_DEFAULT(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, void *vreq)
{
	struct HTTPRESPONSE *req = (struct HTTPRESPONSE *)vreq;
	unsigned offset=0;

	while (offset<length)
	switch (req->value_state) {
	case 0:
		while (offset<length && px[offset] != '\n') {
			if (req->tmp_length < sizeof(req->tmp))
				req->tmp[req->tmp_length++] = px[offset];
			offset++;
		}
		if (offset<length)
			req->value_state = 1;
		break;
	case 1:
		return;
	}
	UNUSEDPARM(frame);UNUSEDPARM(sess);
}

static void 
value_SET_COOKIE(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, void *vreq)
{
	struct HTTPRESPONSE *req = (struct HTTPRESPONSE *)vreq;
	value_DEFAULT(sess, frame, px, length, req);
	if (req->value_state) {
		const char *buf = (const char*)req->tmp;
		unsigned buf_length = req->tmp_length;

		const char *path = "/";
		unsigned path_length=1;
		const char *name;
		unsigned name_length;
		const char *value;
		unsigned value_length;
		const char *domain = NULL;
		unsigned domain_length = 0;

		unsigned i;

		/*
		 * Get the 'path' variable.
		 */
		for (i=0; i<buf_length; i++) {
			while (i<buf_length && isspace(buf[i]&0xFF))
				i++;

			if (buf_length - i > 4 && strnicmp(buf+i, "path", 4) == 0) {
				i += 4;
				while (i<buf_length && isspace(buf[i]&0xFF))
					i++;
				if (i+1 >= buf_length || buf[i] != '=')
					continue;
				i++;
				path = buf+i;
				for (path_length=0; path_length+i<buf_length && path[path_length] != ';'; path_length++)
					;
				i += path_length;
				break;
			} else {
				while (i<buf_length && buf[i] != ';')
					i++;
			}
		}

		/*
		 * Get the 'domain' variable
		 */
		for (i=0; i<buf_length; i++) {
			while (i<buf_length && isspace(buf[i]&0xFF))
				i++;

			if (buf_length - i > 4 && strnicmp(buf+i, "domain", 6) == 0) {
				i += 6;
				while (i<buf_length && isspace(buf[i]&0xFF))
					i++;
				if (i+1 >= buf_length || buf[i] != '=')
					continue;
				i++;
				domain = buf+i;
				for (domain_length=0; domain_length+i<buf_length && domain[domain_length] != ';'; domain_length++)
					;
				i += domain_length;
				break;
			} else {
				while (i<buf_length && buf[i] != ';')
					i++;
			}
		}
		if (domain == NULL) {
			struct TCP_STREAM *to_server = &sess->to_server;
			struct HTTPREQUEST *reqx = &to_server->app.httpreq;

			if (reqx->host && reqx->host->str) {
				domain = (const char*)reqx->host->str;
				domain_length = reqx->host->length;
			}
		}
		if (domain == NULL || domain_length == 0) {
			; //printf("." "%s %u", __FILE__, __LINE__); exit(1);
		}

		/*
		 * Get the name/value pairs
		 */
		i = 0;
		while (i<buf_length) {
			while (i<buf_length && isspace(buf[i]&0xFF))
				i++;

			name = buf+i;

			/* move forward to '=' sign */
			for (name_length=0; i+name_length<buf_length && name[name_length]!='=' && name[name_length]!=';'; name_length++)
				;
			i += name_length;
			while (name_length && isspace(name[name_length-1]&0xFF))
				name_length--;
			if (i<buf_length && buf[i]=='=')
				i++;
			while (i<buf_length && isspace(buf[i]&0xFF))
				i++;

			/* Get the value */
			value = buf+i;
			for (value_length=0; value_length+i<buf_length && value[value_length] != ';'; value_length++)
					;
			i += value_length;

			if (i < buf_length && buf[i] == ';')
				i++;

			if ((name_length == 4 && strnicmp(name,"path",4)==0) || (name_length==6 && strnicmp(name,"domain",6)==0))
				continue;

			if (!sess->eng->ferret->cfg.no_hamster) {

				hamster_cookie(*(unsigned*)sess->ip_dst, 
						domain, domain_length,
						path, path_length,
						name, name_length,
						value, value_length);
				hamster_set_cookie(*(unsigned*)sess->ip_dst, 
						domain, domain_length,
						path, path_length,
						name, name_length,
						value, value_length);
			}
		}
	}


	UNUSEDPARM(frame);UNUSEDPARM(sess);
}

void value_CONTENT_LENGTH(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, void *vreq)
{
	struct HTTPRESPONSE *req = (struct HTTPRESPONSE *)vreq;
	unsigned offset=0;

	UNUSEDPARM(frame);
	UNUSEDPARM(sess);

	while (offset<length)
	switch (req->value_state) {
	case 0:
		req->content_length = 0;
		req->value_state++;
		break;
	case 1:
		if (isdigit(px[offset])) {
			req->content_length *= 10;
			req->content_length += px[offset]-'0';
			offset++;
		} else {
			req->value_state++;
		}
		break;
	default:
		offset = length;
	}
}

void value_CONTENT_TYPE(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, void *vreq)
{
	struct HTTPRESPONSE *req = (struct HTTPRESPONSE *)vreq;
	unsigned offset=0;
	enum {
		STATE_START=0,
		STATE_TYPE,
		STATE_SPACE_AFTER_SEMICOLON,
		STATE_OPTIONS,
		STATE_SKIP_TO_EOL,
	};

	UNUSEDPARM(frame);
	UNUSEDPARM(sess);

	while (offset<length)
	switch (req->value_state) {
	case STATE_START:
		req->value_state++;
		break;
	case STATE_TYPE:
		/* Copy content-type either up to the semi-colon (after which options appear)
		 * or up until the end-of-line */
		while (offset<length && px[offset] != ';' && px[offset] != '\n') {
			if (req->tmp_length < sizeof(req->tmp))
				req->tmp[req->tmp_length++] = px[offset];
			offset++;
		}

		if (offset<length) {
			/* Record the content_type */
			req->content_type = stringtab_lookup(sess->eng->stringtab, req->tmp, req->tmp_length);

			req->tmp_length = 0;

			if (px[offset] == ';') {
				/* continue getting options */
				req->value_state = STATE_SPACE_AFTER_SEMICOLON;
			} else
				req->value_state = STATE_SKIP_TO_EOL;
		}
		break;
	case STATE_SPACE_AFTER_SEMICOLON:
		while (offset<length && isspace(px[offset]&0xFF) && px[offset] != '\n')
			offset++;
		if (offset < length)
			req->value_state = STATE_OPTIONS;
		break;
	case STATE_OPTIONS:
		while (offset<length && px[offset] != '\n') {
			if (req->tmp_length < sizeof(req->tmp))
				req->tmp[req->tmp_length++] = px[offset];
			offset++;
		}
			
		if (offset < length)
			req->value_state = STATE_SKIP_TO_EOL;;
		break;
	case STATE_SKIP_TO_EOL:
		while (offset<length && px[offset] != '\n')
			offset++;
		if (offset<length) {
			offset++;
			req->value_state = 0;
		}
		break;
	default:
		offset = length;
	}
}

void value_SERVER(struct TCPRECORD *sess, struct NetFrame *frame, 
    const unsigned char *px, unsigned length, void *vreq)
{
	struct HTTPRESPONSE *req = (struct HTTPRESPONSE *)vreq;
	value_DEFAULT(sess, frame, px, length, req);
	if (req->value_state) {
		const unsigned char *buf = req->tmp;
		unsigned buf_length = req->tmp_length;

		record_listening_port(
			sess->eng->ferret,
			frame->ipttl,
			frame->ipver, frame->src_ipv4, frame->src_ipv6,
			LISTENING_ON_TCP,
			frame->src_port,
			"HTTP",
			buf,
			buf_length);
	}
}

struct VALUEPARSELIST  response_header_parsers[] = {
	{"CONTENT-LENGTH", value_CONTENT_LENGTH},
	{"CONTENT-TYPE", value_CONTENT_TYPE},
	{"SET-COOKIE", value_SET_COOKIE},
	{"SERVER", value_SERVER},
	{0,0}
};



void handle_http_response(struct TCPRECORD *sess, struct NetFrame *frame, struct HTTPRESPONSE *req)
{
	UNUSEDPARM(frame);

	/* YouTube videos */
	if (match_name_t("video/flv", req->content_type)) {
		
		/* Attempt to grab the 'video_id' field from the request URL */
		if (sess->to_server.app.httpreq.youtube_video_id) {
			const struct StringT *id = sess->to_server.app.httpreq.youtube_video_id;

			sprintf_s(req->snarf_filename, sizeof(req->snarf_filename), "%08x-youtube-%.*s.flv", 
				ferret_snarf_id(sess->eng->ferret), id->length, id->str);
		}
	}

}

/**
 * Parse the HTTP content until
 */
void parse_http_response_content(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct TCP_STREAM *stream = &sess->from_server;
	struct HTTPRESPONSE *req = &stream->app.httprsp;

	if (req->snarf_filename[0]) {
		ferret_snarf(sess->eng->ferret, req->snarf_filename, px, length);
	}

	UNUSEDPARM(sess);UNUSEDPARM(frame);UNUSEDPARM(px);UNUSEDPARM(length);
}

void
stream_http_fromserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct PARSE *parse = &stream->parse;
	struct HTTPRESPONSE *req = &stream->app.httprsp;
	unsigned offset;

	enum {
	HTTP_START,
	HTTP_VERSION_PRE,
	HTTP_VERSION,
	HTTP_VERSION_AFTER,
	HTTP_RETURNCODE,
	HTTP_RETURNCODE_NONDIGIT,
	HTTP_RETURNCODE_AFTER,
	HTTP_CR,
	HTTP_LF,
	HTTP_CRLF,
	HTTP_NAME,
	HTTP_NAME_COLON,
	HTTP_NAME_AFTER,
	HTTP_VALUE,
	HTTP_CONTENT,
	HTTP_SKIP_TO_EOL,
	HTTP_DESYNCHRONIZED,
	};

	/* IF CLOSING CONNECTION */
	if (px == NULL) {
		return;
	}

	sess->eng->ferret->statistics.http++;
	frame->layer7_protocol = LAYER7_HTTP;

/*
HTTP/1.1 200 OK
Connection: close
Content-Type: video/flv
ETag: "-1058843610"
Accept-Ranges: bytes
Last-Modified: Sat, 01 Jul 2006 17:51:25 GMT
Content-Length: 17258171
Date: Sun, 11 Mar 2007 14:05:34 GMT
Server: lighttpd/1.4.11.1*/

	offset = 0;

	while (offset<length)
	switch (parse->state) {
	case HTTP_START:
		memset(req, 0, sizeof(*req));
		parse->state = HTTP_VERSION_PRE;
		
	case HTTP_VERSION_PRE:
		/* We are in the state before the HTTP header. This may be the 
		 * first state of the connection, or the state after the previous
		 * HTTP request */
		while (offset<length && isspace(px[offset]&0xFF))
			offset++;
		if (offset<length)
			parse->state = HTTP_VERSION;
		else
			break;
	case HTTP_VERSION:
		copy_until_space(req->version, sizeof(req->version), &req->version_length, px, length, &offset);
		if (offset<length && isspace(px[offset]&0xFF))
			parse->state = HTTP_VERSION_AFTER;
		else
			break;
	case HTTP_VERSION_AFTER:
		while (offset<length && isspace(px[offset]&0xFF) && px[offset] != '\n')
			offset++;
		if (offset<length) {
			req->return_code = 0;
			parse->state = HTTP_RETURNCODE;
		} else
			break;
	case HTTP_RETURNCODE:
		while (offset<length && isdigit(px[offset])) {
			req->return_code = req->return_code * 10 + px[offset]-'0';
			offset++;
		}
		if (offset<length) {
			/* REPORT: listening port */
			record_listening_port(
				sess->eng->ferret,
				frame->ipttl,
				frame->ipver, frame->src_ipv4, frame->src_ipv6,
				LISTENING_ON_TCP,
				frame->src_port,
				"HTTP",
				0,
				0);
			if (isspace(px[offset]&0xFF))
				parse->state = HTTP_RETURNCODE_AFTER;
			else {
				parse->state = HTTP_RETURNCODE_NONDIGIT;
				break;
			}
		}
		else
			break;
	case HTTP_RETURNCODE_AFTER:
	case HTTP_RETURNCODE_NONDIGIT:
		parse->state = HTTP_SKIP_TO_EOL;
		break;
	case HTTP_SKIP_TO_EOL:
		while (offset<length && px[offset] != '\n')
			offset++;
		if (offset<length) {
			offset++; /*skip the LF*/
			parse->state = HTTP_LF;
		}
		break;
	case HTTP_LF:
		while (offset<length && px[offset] == '\r')
			offset++;
		if (offset<length && px[offset] == '\n') {
			offset++;

			/*******************************************
			 * This is where whe handle the header once
			 * we have parsed it.
			 *******************************************/
			handle_http_response(sess, frame, req);
			/*******************************************
			 *******************************************/

			req->tmp_length = 0;
			req->value_state = 0;

			parse->state = HTTP_CONTENT;
		} else {
			req->tmp_length = 0;
			parse->state = HTTP_NAME;
		}
		break;
	case HTTP_NAME:
		copy_until_colon(req->tmp, sizeof(req->tmp), &req->tmp_length, px, length, &offset);
		if (offset<length)
			parse->state = HTTP_NAME_COLON;
		break;
	case HTTP_NAME_COLON:
		req->value_state = 0;
		req->value_parser = lookup_value_parser(response_header_parsers, req->tmp, req->tmp_length, value_DEFAULT);
		if (px[offset] == ':') {
			offset++;
			parse->state = HTTP_NAME_AFTER;
		} else
			parse->state = HTTP_SKIP_TO_EOL;
		break;
	case HTTP_NAME_AFTER:
		while (offset<length && isspace(px[offset]&0xFF) && px[offset] != '\n')
			offset++;
		if (offset<length) {
			parse->state = HTTP_VALUE;
			req->tmp_length = 0;
		}
		break;
	case HTTP_VALUE:
		{
			unsigned sublen=0;

			/* Find the length of the segment to send to the value parser */
			while (offset+sublen<length && px[offset+sublen] != '\n' && px[offset+sublen] != '\r')
				sublen++;

			req->value_parser(sess, frame, px+offset, sublen, req);
			offset += sublen;

			if (offset<length) {
				if (px[offset] == '\r') {
					parse->state = HTTP_VALUE;
					offset++;
				} else if (px[offset] == '\n') {
					req->value_parser(sess, frame, px+offset, 1, req);
					parse->state = HTTP_SKIP_TO_EOL;
				}
			}

		}
		break;
	case HTTP_CONTENT:
		if (req->content_length == 0)
			parse->state = 0;
		else {
			unsigned len = length-offset;

			if (len > req->content_length)
				len = req->content_length;

			parse_http_response_content(sess, frame, px+offset, len);
			offset += len;
			req->content_length -= len;
		}
		break;
	default:
		FRAMERR(frame, "bad\n");
	}
}

