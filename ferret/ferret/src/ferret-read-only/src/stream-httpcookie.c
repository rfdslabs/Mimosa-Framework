/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"
#include "util-base64.h"
#include "util-hexval.h"
#include "stream-http.h"
#include "stack-asn1.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#ifdef WIN32
#include <malloc.h>
#endif

static unsigned
contains(const void *vsubstr, const void *vvalue, unsigned value_length)
{
	const unsigned char *substr = (const unsigned char*)vsubstr;
	const unsigned char *value = (const unsigned char*)vvalue;
	unsigned i;

	for (i=0; i<value_length; i++) {
		if (value[i] == substr[0]) {
			unsigned j;
			for (j=0; i+j<value_length && substr[j] != '\0' && substr[j] == value[i+j]; j++)
				;
			if (substr[j] == '\0')
				return 1;
		}
	}
	return 0;
}

/**
 * This code analyzes a <name=value> pair within a cookie, within the
 * context of an HTTP request, which includes relavent information
 * about the host that it comes from
 */
void parse_http_cookie(struct TCPRECORD *sess, struct NetFrame *frame, const unsigned char *name, unsigned name_length, const unsigned char *value, unsigned value_length)
{
	struct TCP_STREAM *stream = &sess->to_server;
	struct HTTPREQUEST *req = &stream->app.httpreq;
	unsigned char *dec;
	unsigned dec_length = value_length;

	if (dec_length > 1000)
		dec_length = 1000;


	switch (toupper(name[0])) {
	case 'C':
		/* MYSPACE COUNTRY CODE 
		 * Example:
		 * COUNTRYCODE=MFMGCisGAQQBgjdYA%2FmgRTBDBgorBgEEAYI3WAMBoDUwMwIDAgABAgJmAwICAMAECOOUmLvDDv%2BRBBB6gRxsNuYMZ2M7SXM7N4fdBAgyFGPRkgkD7Q%3D%3D;
		 */
		if (match_name("COUNTRYCODE", name, name_length) && ends_with_t(".myspace.com", req->host)) {
			unsigned char *dec0;
			unsigned dec0_length;
			unsigned i;

			/* First, "uudecode" this */
			dec0 = alloca(value_length);
			dec0_length = 0;
			for (i=0; i<value_length; i++) {
				if (value[i] != '%')
					dec0[dec0_length++] = value[i];
				else {
					unsigned c=0;
					i++;
					if (i<value_length && isxdigit(value[i]))
						c = hexval(value[i++])<<4;
					if (i<value_length && isxdigit(value[i]))
						c |= hexval(value[i++]);
					dec0[dec0_length++] = (unsigned char)c;
					i--;
				}
			}

			/* Second, "base64 decode" this */
			dec = alloca(dec0_length);
			dec_length = (unsigned)base64_decode(dec, dec_length, value, value_length);

			/* Third, "asn.1 decode" this */
			{
				unsigned tag, len;
				const unsigned char *px = dec;
				unsigned offset = 0;
				unsigned length = dec_length;
				unsigned max_offset;

				tag = asn1_tag(px,length,&offset);
				len = asn1_length(frame,px,length, &offset);

				/* Process the big object */
				if (tag == 0x30 && len != 0xFFFFFFFF) {
					max_offset = offset+len;

					tag = asn1_tag(px,max_offset,&offset);
					len = asn1_length(frame,px,max_offset, &offset);

					/* Process the OID */
					if (tag == 0x06) {
						JOTDOWN(sess->eng->ferret,
							JOT_SRC("ID-IP", frame),
							JOT_OID("MySpace-CountryCode", px+offset, len),
							0);
					}
					offset += len;


				}


			}
		}
		break;
	case 'D':
		/*
		 go.com (including such properties as espn.com) put in their cookies 
		 some sort of location information. Here are some examples that were googled
		 from the web:

		Z2JyO2VuZztsb25kb247YnJvYWRiYW5kOzU7NTs0Oy0xOzA1MS41MDA7LTAwMC4xMTc7ODI2OzEwMTk4OzQ3ODI7NTsK
		Z2JyO2VuZztsb25kb247YnJvYWRiYW5kOzU7NTs1Oy0xOzA1MS41MDA7LTAwMC4xMTc7ODI2OzEwMTk4OzQ3ODI7NTsK
		dXNhO21kO2NvbGxlZ2UgcGFyazt0MTs1OzQ7NDs1MTE7MDM4Ljk5NzstMDc2LjkyODs4NDA7MjE7MTU7NjsK
		dXNhO3R4O2RhbGxhczticm9hZGJhbmQ7NTs0OzQ7NjIzOzAzMi43ODc7LTA5Ni43OTk7ODQwOzQ0Ozc3OzY7Cg==
		dXNhO3R4O2RhbGxhczticm9hZGJhbmQ7NTs0OzQ7NjIzOzAzMi43ODc7LTA5Ni43OTk7ODQwOzQ0Ozc3OzY7Cg==
		dXNhO2dhO2F0bGFudGE7YnJvYWRiYW5kOzU7NTs1OzUyNDswMzMuNzQ5Oy0wODQuMzg4Ozg0MDsxMTszOzY7Cg==
		dXNhO29yO2JlYXZlcnRvbjticm9hZGJhbmQ7NTszOzM7ODIwOzA0NS40OTE7LTEyMi44MDU7ODQwOzM4OzYyOzY7Cg==
		dXNhO3R4O2RhbGxhczticm9hZGJhbmQ7NTs0OzQ7NjIzOzAzMi43ODc7LTA5Ni43OTk7ODQwOzQ0Ozc3OzY7Cg==
		dXNhO3R4O2RhbGxhczticm9hZGJhbmQ7NTs0OzM7NjIzOzAzMi43ODc7LTA5Ni43OTk7ODQwOzQ0Ozc3OzY7Cg==
		*/
		if (match_name("DE2", name, name_length) && ends_with_t(".go.com", req->host)) {
			dec = alloca(dec_length);
			dec_length = (unsigned)base64_decode(dec, dec_length, value, value_length);
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("GO-LOC", dec, dec_length),
				0);
		}
		break;
	case 'E':
		if (starts_with("EMAIL", name, name_length)) {
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("e-mail", value, value_length),
				0);
		}
		if (starts_with("E-MAIL", name, name_length)) {
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("e-mail", value, value_length),
				0);
		}
		break;

	case 'G':
		/*
		d78da8e7eb998e8f571c4c641b104c60cxsAAABVUyxnYSxsYXdyZW5jZXZpbGxlLCwsLCw1MjQ=
		bf8e3d7c0474fa9da14b6551e6846ec7cxUAAABVUyxnYSxhdGxhbnRhLCwsLCw1MjQ=

		*/
		if (match_name("GEO", name, name_length) && ends_with_t(".youtube.com", req->host)) {
			unsigned i;
			unsigned comma_count=0;
			dec = alloca(dec_length);
			dec_length = (unsigned)base64_decode(dec, dec_length, value, value_length);

			for (i=dec_length; i>0; i--) {
				if (dec[i-1] == ',') {
					/*US,ga,lawrenceville,,,,,524*/
					if (++comma_count == 7)
						break;
				}
			}
			if (i>3 && isalpha(dec[i-2]) && isalpha(dec[i-3])) {
				unsigned offset=i-3;
				while (i<dec_length && comma_count > 5) {
					if (dec[i] == ',')
						comma_count--;
					i++;
				}
				JOTDOWN(sess->eng->ferret,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("YouTube-Loc", dec+offset, i-offset-1),
					0);
			}
		}
		/*Example:
		 * gmailchat=justin.hamlin@gmail.com/769779 
		 */
		if (match_name("GMAILCHAT", name, name_length) && ends_with_t("mail.google.com", req->host)) {
			unsigned j;
			for (j=0; j<value_length && value[j] != '/'; j++)
				;
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("e-mail", value, j),
				0);
		}
		break;
	case 'I':
		if (match_name("ID", name, name_length) && ends_with_t(".doubleclick.net", req->host)) {
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("DoubleClick", value, value_length),
				0);
		}
		break;
	case 'L':
		if (match_name("LOGIN", name, name_length) || match_name("LOGIN_X", name, name_length)) {
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_URLENC("login", value, value_length),
				0);

			if (ends_with_t(".facebook.com", req->host)) {
				req->login = stringtab_lookup(sess->eng->stringtab, value, value_length);
				JOTDOWN(sess->eng->ferret,
					JOT_SRC("ID-IP", frame),
					JOT_URLENC("Facebook-user", req->login->str, req->login->length),
					0);
			}

			if (contains("@", value, value_length)) {
				JOTDOWN(sess->eng->ferret,
					JOT_SRC("ID-IP", frame),
					JOT_URLENC("e-mail", value, value_length),
					0);
			} else if (contains("%40", value, value_length)) {
				JOTDOWN(sess->eng->ferret,
					JOT_SRC("ID-IP", frame),
					JOT_URLENC("e-mail", value, value_length),
					0);
			}
		}
		break;
	case 'M':
		/*http://facebook.com
		 *m_user = warnerc2%40gpc.edu%3A71101757%3ASwUchOEuvzIbYo7E*/
		if (match_name("M_USER", name, name_length)) {
			if (ends_with_t(".facebook.com", req->host)) {
				JOTDOWN(sess->eng->ferret,
					JOT_SRC("ID-IP", frame),
					JOT_URLENC("e-mail", value, value_length),
					0);
			}
		}

		/* http://login.live.com/login.srf
		 * MSPPre=tonygauvin@hotmail.com */
		if (match_name("MSPPRE", name, name_length)) {
			if (ends_with_t(".live.com", req->host)) {
				JOTDOWN(sess->eng->ferret,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("e-mail", value, value_length),
					0);
			}
		}

		/* Canadian Broadcasting */
		if (match_name("MyCBCSignIn", name, name_length)) {
			if (ends_with_t(".cbc.ca", req->host)) {
				JOTDOWN(sess->eng->ferret,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("e-mail", value, value_length),
					0);
			}
		}
		if (match_name("ME", name, name_length)) {
			if (ends_with_t(".myspace.com", req->host)) {
				JOTDOWN(sess->eng->ferret,
					JOT_SRC("ID-IP", frame),
					JOT_URLENC("e-mail", value, value_length),
					0);
			}
		}
		 
		break;
	case 'P':
		if (starts_with("PASSWORD", name, name_length)) {
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("password", value, value_length),
				0);
		}
		break;
	case 'U':
		if (starts_with("USERNAME", name, name_length)) {
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("username", value, value_length),
				0);
		}
		break;
	case 'W':
		if (starts_with("WATCHED_VIDEO_ID_LIST_", name, name_length)) {
			size_t l = sizeof("WATCHED_VIDEO_ID_LIST_")-1;
			JOTDOWN(sess->eng->ferret,
				JOT_SRC("ID-IP", frame),
				JOT_URLENC("YouTube-ID", name+l, name_length-l),
				0);
		}
		break;
	}
}
