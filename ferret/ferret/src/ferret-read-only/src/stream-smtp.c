/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-netframe.h"
#include "ferret.h"
#include "stack-extract.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

static int is_command(const char *value, const unsigned char *name, unsigned name_length)
{
	unsigned i;

	for (i=0; i<name_length && value[i]; i++) {
		if (tolower(name[i]) != tolower(value[i]))
			return 0;
	}
	if (i != name_length || value[i] != '\0')
		return 0;

	return 1;
}

void smtp_copy(unsigned char *dst, const void *v_src, unsigned src_length)
{
	const unsigned char *src = (const unsigned char*)v_src;
	unsigned dst_length = 128;
	unsigned s,d;

	for (d=0, s=0; d<dst_length && s<src_length; d++, s++) {
		dst[d] = src[s];
		if (isspace(dst[d])) {
			dst[d] = ' ';
			while (s+1<src_length && isspace(src[s+1]))
				s++;
		}
	}

	if (d<dst_length)
		dst[d] = '\0';
	else
		dst[dst_length-1] = '\0';
}

void process_simple_smtp_response(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	frame->layer7_protocol = LAYER7_SMTP;
	UNUSEDPARM(sess);UNUSEDPARM(frame);UNUSEDPARM(px);UNUSEDPARM(length);
}

void process_simple_smtp_data(struct TCPRECORD *sess, struct TCP_STREAM *to_server, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct FerretEngine *eng = sess->eng;
	struct Ferret *ferret = eng->ferret;
	unsigned offset=0;
	unsigned command;
	unsigned command_length;
	unsigned parm;
	unsigned parm_length;

	if (sess == NULL)
		return;

	frame->layer7_protocol = LAYER7_SMTP;

	while (offset<length) {

		/* Handle end-of-email '.' issue */
		if (offset<length && px[offset] == '.') {
			if (offset+1<length && px[offset] == '\n' && offset+2<length && px[offset] == '\r' && px[offset+1] == '\n') {
				to_server->app.smtpreq.is_body = 0;
				to_server->app.smtpreq.is_data = 0;
				return;
			}
		}
		if (to_server->app.smtpreq.is_body) {
			while (offset<length && px[offset] != '\n')
				offset++;
			if (offset<length && px[offset] == '\n')
				offset++;
			continue;
		}


		while (offset<length && isspace(px[offset]) && px[offset] != '\n')
			offset++;
		command = offset;
		
		while (offset<length && px[offset] != ':' && px[offset] != '\n')
			offset++;
		command_length = offset-command;
		if (command_length == 0) {
			to_server->app.smtpreq.is_body = 1;
			continue;
		}

		while (command_length && isspace(px[offset+command_length]))
			command_length--;
		if (command_length && px[offset+command_length] == ':')
			command_length--;
		while (command_length && isspace(px[offset+command_length]))
			command_length--;
	
		while (offset<length && px[offset] == ':')
			offset++;
		while (offset<length && isspace(px[offset]) && px[offset] != '\n')
			offset++;

		parm = offset;
		if ((offset<length && px[offset] == '\n') || (offset+1<length && px[offset] == '\r' && px[offset+1] == '\n')) {
			to_server->app.smtpreq.is_body = 1;
			return;
		}
again:
		while (offset<length && px[offset] != '\n')
			offset++;
		if (offset<length && px[offset] == '\n')
			offset++;
		if (offset<length && px[offset] != '\n' && isspace(px[offset]) && (offset+1<length && px[offset] != '\r' && px[offset] != '\n'))
			goto again;
		parm_length = offset-parm;
		while (parm_length && isspace(px[parm+parm_length-1]))
			parm_length--;

		JOTDOWN(ferret,
				JOT_SZ("proto","RFC822msg"),
				JOT_PRINT("header",			 	px+command,					command_length),
				JOT_PRINT("value",			 	px+parm, parm_length),
				JOT_SRC("client", frame),
				JOT_DST("server", frame),
				0);
		if (is_command("subject", px+command, command_length)) {
			smtp_copy(to_server->app.smtpreq.subject, px+parm, parm_length);
		}
		if (is_command("X-Mailer", px+command, command_length)) {
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("X-Mailer",			   px+parm, parm_length),
				0);
		}
		if (is_command("X-MimeOLE", px+command, command_length)) {
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("X-MimeOLE",			   px+parm, parm_length),
				0);
		}
	}
}

void strip_address(const char **r_parm, unsigned *r_length)
{
	const char *parm = *r_parm;
	unsigned parm_length = *r_length;

		if (parm_length && parm[0] == '<') {
			parm++;
			parm_length--;
		}
		{
			unsigned jj;
			for (jj=0; jj<parm_length && parm[jj] != '>'; jj++)
				;


			parm_length = jj;
		}

	*r_parm = parm;
	*r_length = parm_length;
}


void process_simple_smtp_request(struct TCPRECORD *sess, struct TCP_STREAM *to_server, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct FerretEngine *eng = sess->eng;
	struct Ferret *ferret = eng->ferret;
	char command[16];
	const char *parm;
	unsigned parm_length;
	unsigned i;
	unsigned  x;

	/* IF CLOSING CONNECTION */
	if (px == NULL) {
		return;
	}

	frame->layer7_protocol = LAYER7_SMTP;

	if (to_server->app.smtpreq.is_data) {
		process_simple_smtp_data(sess, to_server, frame, px, length);
		return;
	}

	/* Remove leading whitespace */
	for (i=0; i<length && isspace(px[i]); i++)
		;

	/* Grab command. This means parsing up to the first space
	 * character, or the first ':' character in the case of 
	 * mailfrom: or rcptto: */
	x=0;
again:
	while (i<length && !isspace(px[i]) && px[i] != ':') {
		if (x < sizeof(command) -1) {
			command[x++] = (char)toupper(px[i]);
			command[x] = '\0';
		}
		i++;
	}
	if (i<length && px[i] == ':')
		i++;

	/* skip space after command */
	while (i<length && isspace(px[i]))
		i++;

	if (stricmp(command, "mail")==0 || stricmp(command, "rcpt")==0) {
		if (i >= length)
			return;
		goto again;
	}

	SAMPLE(ferret,"SMTP", JOT_SZ("command", command));

	/* Grab parm */
	parm = (const char*)px+i;
	x=i;
	while (i<length && px[i] != '\n')
		i++;
	parm_length = i-x;

	if (parm_length && parm[parm_length-1] == '\n')
		parm_length--;
	if (parm_length && parm[parm_length-1] == '\r')
		parm_length--;

	JOTDOWN(ferret,
		JOT_SZ("proto", "SMTP"),
		JOT_SZ("op", command),
		JOT_PRINT("parm", parm, parm_length),
		JOT_SRC("client", frame),
		JOT_DST("server", frame),
		0);

	/* test parms */
	if (stricmp(command, "MAILFROM")==0) {
		strip_address(&parm, &parm_length);

		if (sess)
			smtp_copy(to_server->app.smtpreq.from, parm, parm_length);

		JOTDOWN(ferret,
			JOT_SRC("IP", frame),
			JOT_PRINT("e-mail", parm, parm_length),
			0);
	}
	if (stricmp(command, "RCPTTO")==0) {
		strip_address(&parm, &parm_length);

		if (sess)
			smtp_copy(to_server->app.smtpreq.to, parm, parm_length);
		JOTDOWN(ferret,
			JOT_SRC("IP", frame),
			JOT_PRINT("friend",			   parm, parm_length),
			0);
	}

	if (stricmp(command, "DATA")==0 && sess) {
		to_server->app.smtpreq.is_data = 1;
	}
	if (stricmp(command, "RSET")==0 && sess) {
		to_server->app.smtpreq.is_data = 0;
	}


}
