/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "util-base64.h"
#include "stream-http.h"
#include "util-hamster.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

void parse_http_cookie(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *name, unsigned name_length, const unsigned char *value, unsigned value_length);
void parse_http_content_form(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length);



void copy_until_space(unsigned char *method, size_t sizeof_method, unsigned *r_method_length, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	while (*r_offset < length && !isspace(px[*r_offset])) {
		if (*r_method_length < sizeof_method)
			method[(*r_method_length)++] = px[*r_offset];
		(*r_offset)++;
	}
}
void copy_until_colon(unsigned char *name, size_t sizeof_name, unsigned *r_name_length, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	while (*r_offset < length && px[*r_offset] != ':' && px[*r_offset] != '\n') {
		if (*r_name_length < sizeof_name)
			name[(*r_name_length)++] = px[*r_offset];
		(*r_offset)++;
	}

	if (*r_offset < length) {
		/* Removing trailing whitespace from the name */
		while (*r_name_length && isspace(name[(*r_name_length)-1])) {
			(*r_name_length)--;
		}
	}
}


/**
 * Called by the other 'value' parsers to simply copy over the contents
 * into a temporary buffer
 */
static void 
value_DEFAULT(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, void *vreq)
{
	struct HTTPREQUEST *req = (struct HTTPREQUEST *)vreq;
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

/**
 * Parse the cookie into a buffer. Another large moduel will then parse interesting
 * data out of the cookie.
 */
static void 
value_COOKIE(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, void *vreq)
{
	struct HTTPREQUEST *req = (struct HTTPREQUEST *)vreq;
	value_DEFAULT(sess, frame, px, length, req);
	if (req->value_state) {
		if (req->cookie_count < sizeof(req->cookie)/sizeof(req->cookie[0])) {
			req->cookie[req->cookie_count++] = stringtab_lookup(sess->eng->stringtab, req->tmp, req->tmp_length);
		}
	}
}

/**
 * Parse the numeric content-length field to see how much data we have to parse from
 * stream after the request header.
 */
static void 
value_CONTENT_LENGTH(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, void *vreq)
{
	struct HTTPREQUEST *req = (struct HTTPREQUEST *)vreq;
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

/**
 * Parse the 'user-agent' field, which tells us what kind of web-browser the user
 * is using. */
static void 
value_USER_AGENT(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, void *vreq)
{
	struct HTTPREQUEST *req = (struct HTTPREQUEST *)vreq;
	value_DEFAULT(sess, frame, px, length, req);
	if (req->value_state) {
		req->user_agent = stringtab_lookup(sess->eng->stringtab, req->tmp, req->tmp_length);

		JOTDOWN(sess->eng->ferret,
			JOT_SRC("ID-IP", frame),
			JOT_PRINTT("User-Agent", req->user_agent),
			0);
	}
}

/**
 * Parse the 'Referer' field, which is a URL */
static void 
value_REFERER(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, void *vreq)
{
	struct HTTPREQUEST *req = (struct HTTPREQUEST *)vreq;
	value_DEFAULT(sess, frame, px, length, req);
	if (req->value_state && req->host) {
		if (!sess->eng->ferret->cfg.no_hamster)
		hamster_url(*(unsigned*)sess->ip_src,
					req->host->str, req->host->length,	/*host*/
					req->url, req->url_length,			/*url*/
					req->tmp, req->tmp_length			/*referer*/
					);
	}
}


/**
 * Parse the 'host' field from the header, which tells us which of the virtual hosts
 * on the server that the user is accessing.
 */
static void 
value_HOST(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length, void *vreq)
{
	struct HTTPREQUEST *req = (struct HTTPREQUEST *)vreq;
	value_DEFAULT(sess, frame, px, length, req);
	if (req->value_state) {
		req->host = stringtab_lookup(sess->eng->stringtab, req->tmp, req->tmp_length);

		JOTDOWN(sess->eng->ferret,
				JOT_SZ("proto","HTTP"),
				JOT_PRINT("op", req->method, req->method_length),
				JOT_PRINTT("Host", req->host),
				JOT_PRINT("URL", req->url, req->url_length),
				0);
		JOTDOWN(sess->eng->ferret,
				JOT_DST("ID-IP",frame),
				JOT_PRINTT("DNS", req->host),
				0);

		if (!sess->eng->ferret->cfg.no_hamster)
		hamster_url(*(unsigned*)sess->ip_src,
					req->host->str, req->host->length,	/*host*/
					req->url, req->url_length,			/*url*/
					"", 0								/*referer*/
					);
	}
}




static struct VALUEPARSELIST request_parsers[] = {
	{"CONTENT-LENGTH", value_CONTENT_LENGTH},
	{"COOKIE", value_COOKIE},
	{"HOST", value_HOST},
	{"USER-AGENT", value_USER_AGENT},
	{"REFERER", value_REFERER},
	{0,0}
};

/**
 * Given a 'name' from an HTTP header <name: value> field, this returns
 * a parser appropriate to parse that value field */
HTTPVALUEPARSE 
lookup_value_parser(struct VALUEPARSELIST *parsers, const unsigned char *name, unsigned name_length, HTTPVALUEPARSE def)
{
	unsigned i;


	/* Look through the parsers for the specified name */
	for (i=0; parsers[i].name; i++) {
		unsigned j;

		/* Compare name */
		for (j=0; j<name_length; j++) {
			if (toupper(name[j]) != parsers[i].name[j])
				break;
		}

		/* If the name matches, return that parser */
		if (j==name_length && parsers[i].name[j] == '\0')
			return parsers[i].parser;
	}

	return def;
}


unsigned match_name(const char *name, const unsigned char *data, unsigned data_length)
{
	unsigned i;

	for (i=0; i<data_length && name[i]; i++) {
		if (name[i] != toupper(data[i]))
			return 0;
	}
	if (name[i] == '\0' && i == data_length)
		return 1;
	return 0;
}
unsigned match_name_t(const char *name, const struct StringT *value)
{
	if (value == NULL) {
		if (name == NULL || name[0] == '\0')
			return 1;
		else
			return 0;
	}
	return match_name(name, value->str, value->length);
}


unsigned ends_with_t(const char *suffix, const struct StringT *host)
{
	const unsigned char *hostname;
	unsigned length;
	unsigned i;
	size_t suflen = strlen(suffix);

	if (host == NULL) {
		if (suffix == NULL || suffix[0] == '\0')
			return 1;
		else
			return 0;
	}

	hostname = host->str;
	length = host->length;

	if (suflen > length)
		return 0;

	for (i=0; i<suflen; i++) {
		if (toupper(suffix[i]) != toupper(hostname[i+length-suflen]))
			return 0;
	}
	return 1;
}



/**
 * This is called AFTER the HTTP request headers have been completely parsed.
 * It is at this time we pull together various bits that we found
 */
void handle_http_request(struct TCPRECORD *sess, struct NetFrame *frame, struct HTTPREQUEST *req)
{
	unsigned c;

	for (c=0; c<req->cookie_count; c++) {
		const unsigned char *cookie = req->cookie[c]->str;
		unsigned len = req->cookie[c]->length;
		unsigned i;

		/* Only print cookies when we have the verbose mode turned on */
		if (sess->eng->ferret->is_verbose)
			JOTDOWN(sess->eng->ferret,
					JOT_SZ("proto","HTTP"),
					JOT_PRINT("op", req->method, req->method_length),
					JOT_PRINTT("Host", req->host),
					JOT_PRINT("URL", req->url, req->url_length),
					JOT_PRINTT("cookie", req->cookie[c]),
					0);

		for (i=0; i<len; ) {
			unsigned j;
			const unsigned char *p_name = cookie+i;
			unsigned p_name_length;
			const unsigned char *p_value;
			unsigned p_value_length;

			for(j=i; j<len && cookie[j] != '=' && cookie[j] != ';' && cookie[j] != ','; j++)
				;
			p_name_length = j-i;

			if (j<len)
				j++;
			while (j<len && isspace(cookie[j]))
				j++;

			i=j;
			p_value = cookie+i;
			for (j=i; j<len && cookie[j] != ';'; j++)
				;
			p_value_length = j-i;

			/* remove trailing space from the value field */
			while (p_value_length && isspace(p_value[p_value_length-1]))
				p_value_length--;

			parse_http_cookie(sess, frame, p_name, p_name_length, p_value, p_value_length);

			if (req->host && !sess->eng->ferret->cfg.no_hamster)
			hamster_cookie(	*(unsigned*)sess->ip_src,				/*cookie instance ID*/
							req->host->str, req->host->length,	/*cookie domain */
							req->url, req->url_length,				/*cookie path */
							p_name, p_name_length,					/*cookie name */
							p_value, p_value_length					/*cookie value */
							);

			i=j;

			/* remove trailing ';' and whitespace */
			while (i<len && (cookie[i]==';' || isspace(cookie[i]) || cookie[j]==','))
				i++;
		}
	}

}





void parse_http_content(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	UNUSEDPARM(sess);UNUSEDPARM(frame);UNUSEDPARM(px);UNUSEDPARM(length);
}

int offset_of_char(unsigned c, const unsigned char *px, unsigned length)
{
	int i;

	for (i=0; i<(int)length; i++) {
		if (c == px[i])
			return i;
	}
	return -1;
}

/**
 * Use a state-machine to parse the request-side (browser to server) of the 
 * the TCP stream.
 */
void
stream_http_toserver(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct PARSE *parse = &stream->parse;
	struct HTTPREQUEST *req = &stream->app.httpreq;
	unsigned offset;

	enum {
	HTTP_START,
	HTTP_METHOD_PRE,
	HTTP_METHOD,
	HTTP_METHOD_AFTER,
	HTTP_URL,
	HTTP_URL_AFTER,
	HTTP_VERSION,
	HTTP_CR,
	HTTP_LF,
	HTTP_CRLF,
	HTTP_NAME,
	HTTP_NAME_COLON,
	HTTP_NAME_AFTER,
	HTTP_VALUE,
	HTTP_CONTENT,
	HTTP_CONTENT_POST,
	HTTP_SKIP_TO_EOL,
	HTTP_DESYNCHRONIZED,
	};

	/* IF CLOSING CONNECTION */
	if (px == TCP_CLOSE) {
		return;
	}

	sess->eng->ferret->statistics.http++;
	frame->layer7_protocol = LAYER7_HTTP;

	offset = 0;

	while (offset<length)
	switch (parse->state) {
	case HTTP_START:
		memset(req, 0, sizeof(*req));
		parse->state = HTTP_METHOD_PRE;
		break;
	case HTTP_METHOD_PRE:
		/* We are in the state before the HTTP header. This may be the 
		 * first state of the connection, or the state after the previous
		 * HTTP request */
		while (offset<length && isspace(px[offset]))
			offset++;
		if (offset<length)
			parse->state = HTTP_METHOD;
		break;
	case HTTP_METHOD:
		copy_until_space(req->method, sizeof(req->method), &req->method_length, px, length, &offset);
		if (offset<length && isspace(px[offset]))
			parse->state = HTTP_METHOD_AFTER;
		break;
	case HTTP_METHOD_AFTER:
		while (offset<length && isspace(px[offset]) && px[offset] != '\n')
			offset++;
		if (offset<length)
			parse->state = HTTP_URL;
		break;
	case HTTP_URL:
		copy_until_space(req->url, sizeof(req->url), &req->url_length, px, length, &offset);
		if (offset<length)
			parse->state = HTTP_URL_AFTER;
		break;
	case HTTP_URL_AFTER:
		while (offset<length && isspace(px[offset]) && px[offset] != '\n')
			offset++;
		if (offset<length)
			parse->state = HTTP_VERSION;
		break;
	case HTTP_VERSION:
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
			handle_http_request(sess, frame, req);
			/*******************************************
			 *******************************************/

			req->tmp_length = 0;
			req->value_state = 0;

			if (offset_of_char('?', req->url, req->url_length) >= 0) {
				unsigned z = offset_of_char('?', req->url, req->url_length)+1;
				parse_http_content_form(sess, frame, req->url+z, req->url_length-z);
				req->tmp_length = 0;
				req->value_state = 0;
			}

			if (match_name("POST", req->method, req->method_length)) {
				parse->state = HTTP_CONTENT_POST;
			} else
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
		req->value_parser = lookup_value_parser(request_parsers, req->tmp, req->tmp_length, value_DEFAULT);
		if (px[offset] == ':') {
			offset++;
			parse->state = HTTP_NAME_AFTER;
		} else
			parse->state = HTTP_SKIP_TO_EOL;
		break;
	case HTTP_NAME_AFTER:
		while (offset<length && isspace(px[offset]) && px[offset] != '\n')
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

			parse_http_content(sess, frame, px+offset, len);
			offset += len;
			req->content_length -= len;
		}
		break;
	case HTTP_CONTENT_POST:
		if (req->content_length == 0)
			parse->state = 0;
		else {
			unsigned len = length-offset;

			if (len > req->content_length)
				len = req->content_length;

			parse_http_content_form(sess, frame, px+offset, len);
			offset += len;
			req->content_length -= len;
		}
		break;
	default:
		FRAMERR(frame, "bad\n");
	}
}



