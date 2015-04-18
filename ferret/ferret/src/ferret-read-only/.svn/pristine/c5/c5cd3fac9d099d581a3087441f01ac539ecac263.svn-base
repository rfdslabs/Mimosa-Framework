/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "util-base64.h"
#include "stream-http.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>


/**
 * Parses the <name=value> pairs in HTTP URLs and HTTP POST content data
 */
void  http_parse_form_field(struct TCPRECORD *sess, struct NetFrame *frame,
				struct StringT *name,
				const unsigned char *value,
				unsigned value_length)
{
	struct TCP_STREAM *stream = &sess->to_server;
	struct HTTPREQUEST *req = &stream->app.httpreq;

	if (name == NULL)
		return;

	switch (toupper(name->str[0])) {
	case 'E':
		if (match_name_t("EMAIL", name)) {
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_URLENC("e-mail", value, value_length),
				0);

			if (ends_with_t(".myspace.com", req->host)) {
				req->login = stringtab_lookup(sess->eng->stringtab, value, value_length);
				if (req->password) {
					JOTDOWN(sess->eng->ferret,
						JOT_SRC("ID-IP", frame),
						JOT_URLENC("MySpace-user", req->login->str, req->login->length),
						JOT_URLENC("password", req->password->str, req->password->length),
						0);
				} else
					JOTDOWN(sess->eng->ferret,
						JOT_SRC("ID-IP", frame),
						JOT_URLENC("MySpace-user", req->login->str, req->login->length),
						0);

			}
		}
		break;
	case 'P':
		if (match_name_t("PASSWORD", name)) {
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_URLENC("form-password", value, value_length),
				0);

			if (ends_with_t(".myspace.com", req->host)) {
				req->password = stringtab_lookup(sess->eng->stringtab, value, value_length);
				if (req->login) {
					JOTDOWN(sess->eng->ferret,
						JOT_SRC("ID-IP", frame),
						JOT_URLENC("MySpace-user", req->login->str, req->login->length),
						JOT_URLENC("password", req->password->str, req->password->length),
						0);
				}
			}
		}
		if (match_name_t("PASSWD", name)) {
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_URLENC("password", value, value_length),
				0);
		}
		break;
	case 'Q':
		if (match_name_t("Q", name)) {
			if (ends_with_t(".google.com", req->host)) {
				if (!starts_with("cache:", req->url, req->url_length)) {
					JOTDOWN(sess->eng->ferret,
						JOT_SRC("IP", frame),
						JOT_URLENC("search", value, value_length),
						0);

				}
			}

		}
		break;
	case 'V':
		if (match_name_t("VIDEO_ID", name)) {
			if (ends_with_t(".youtube.com", req->host)) {
				JOTDOWN(sess->eng->ferret,
					JOT_SRC("Watches", frame),
					JOT_URLENC("YouTube", value, value_length),
					0);
				req->youtube_video_id = stringtab_lookup(sess->eng->stringtab, value, value_length);
			}
		}
		break;
	}
}

void parse_http_content_form(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct TCP_STREAM *stream = &sess->to_server;
	unsigned offset=0;
	struct HTTPREQUEST *req = &stream->app.httpreq;

	enum {
	POST_NAME_PRE,
	POST_NAME,
	POST_NAME_AFTER,
	POST_VALUE
	};


	while (offset<length)
	switch (req->value_state) {
	case POST_NAME_PRE:
		req->tmp_length = 0;
		req->value_state = POST_NAME;
		break;
	case POST_NAME:
		while (offset<length && px[offset] != '=') {
			if (req->tmp_length < sizeof(req->tmp))
				req->tmp[req->tmp_length++] = px[offset];
			offset++;
		}
		if (offset<length) {
			req->value_state = POST_NAME_AFTER;
			offset++;
			req->parm_name = stringtab_lookup(sess->eng->stringtab, req->tmp, req->tmp_length);
			req->tmp_length = 0;
		}
		break;
	case POST_NAME_AFTER:
		req->value_state = POST_VALUE;
		break;
	case POST_VALUE:
		while (offset<length && px[offset] != '&') {
			if (req->tmp_length < sizeof(req->tmp))
				req->tmp[req->tmp_length++] = px[offset];
			offset++;
		}
		if (offset<length) {
			req->value_state = POST_NAME_PRE;
			offset++;

			http_parse_form_field(sess, frame,
				req->parm_name,
				req->tmp,
				req->tmp_length
				);
		}
		break;
	}

}
