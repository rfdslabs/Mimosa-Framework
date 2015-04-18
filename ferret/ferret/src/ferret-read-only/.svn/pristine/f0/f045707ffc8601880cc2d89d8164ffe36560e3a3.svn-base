/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "ferret.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "util-housekeeping.h"
#include "stack-tcpchecksum.h"
#include "stack-smells.h"
#include "report.h"

#include <ctype.h>
#include <string.h>
#include <assert.h>

static void tcp_housekeeping(struct Housekeeping *housekeeper, void *housekeeping_data, time_t now, struct NetFrame *frame);
extern void VALIDATE(int exp);

enum {
	TCP_FIN=1,
	TCP_SYN=2,
	TCP_RST=4,
	TCP_PSH=8,
	TCP_ACK=16,
	TCP_URG=32,
};

enum {
	TCP_LOOKUP,
	TCP_CREATE,
	TCP_DESTROY,
};

static void tcp_syn(struct Ferret *ferret, struct NetFrame *frame)
{
	UNUSEDPARM(ferret);UNUSEDPARM(frame);
}
static void tcp_synack(struct Ferret *ferret, struct NetFrame *frame)
{
	record_listening_port(	ferret,
							frame->ipttl,
							frame->ipver, frame->src_ipv4, frame->src_ipv6, 
							LISTENING_ON_TCP, 
							frame->src_port, 
							0, /* no proto */ 
							0, /* no banner */
							0);

	UNUSEDPARM(ferret);UNUSEDPARM(frame);
}
static void tcp_fin(struct Ferret *ferret, struct NetFrame *frame)
{
	UNUSEDPARM(ferret);UNUSEDPARM(frame);
}



/**
 * Runs a heuristic over the packet data to see if it looks like the HTTP 
 * protocol. This is because we can't rely upon HTTP running on port 80,
 * it can run on any arbitrary port */
static int 
smellslike_httprequest(const unsigned char *data, unsigned length)
{
	unsigned i;
	//unsigned method;
	//unsigned url;

	for (i=0; i<length && isspace(data[i]); i++)
		;
	//method = i;
	while (i<length && !isspace(data[i]))
		i++;
	if (i>10)
		return 0;
	while (i<length && isspace(data[i]))
		i++;
	//url = i;
	while (i<length && data[i] != '\n')
		i++;

	if (i>0 && data[i] == '\n') {
		i--;

		if (i>0 && data[i] == '\r')
			i--;

		if (i>10 && strnicmp((const char*)&data[i-7], "HTTP/1.0", 8) == 0)
			return 1;
		if (i>10 && strnicmp((const char*)&data[i-7], "HTTP/1.1", 8) == 0)
			return 1;
		if (i>10 && strnicmp((const char*)&data[i-7], "HTTP/0.9", 8) == 0)
			return 1;
		
	}

	return 0;
}
static int 
smellslike_http_response(const unsigned char *data, unsigned length)
{
	if (length >= 8) {
		if (strnicmp((const char*)&data[0], "HTTP/1.0", 8) == 0)
			return 1;
		if (strnicmp((const char*)&data[0], "HTTP/1.1", 8) == 0)
			return 1;
		if (strnicmp((const char*)&data[0], "HTTP/0.9", 8) == 0)
			return 1;
	}

	return 0;
}

int smellslike_msn_messenger(const unsigned char *data, unsigned length)
{
	unsigned i=0;
	//unsigned method;
	unsigned method_length=0;
	//unsigned parms;
	unsigned non_printable_count = 0;
	unsigned line_length;

	if (smellslike_httprequest(data, length))
		return 0;


	//method = i;
	while (i<length && !isspace(data[i]))
		i++, method_length++;;
	while (i<length && data[i] != '\n' && isspace(data[i]))
		i++;
	//parms = i;
	while (i<length && data[i] != '\n')
		i++;
	line_length = i;

	for (i=0; i<length; i++)
		if (!(isprint(data[i]) || isspace(data[i])))
			non_printable_count++;


	if (method_length == 3 && data[line_length] == '\n' && non_printable_count == 0)
		return 1;

	return 0;
}

static unsigned tcp_record_hash(struct TCPRECORD *rec)
{
	unsigned i;
	unsigned hash=0;

	for (i=0; i<16; i++) {
		hash += rec->ip_dst[i];
		hash += rec->ip_src[i];
	}
	hash += rec->tcp_dst;
	hash += rec->tcp_src;

	hash ^= (hash>>16);
	return hash;
}
static unsigned tcp_record_equals(struct TCPRECORD *left, struct TCPRECORD *right, unsigned *is_reversed)
{
	unsigned i;
	unsigned address_length;

	if (left->ip_ver != right->ip_ver)
		return 0;

	if (left->ip_ver == 0 || left->ip_ver == 4)
		address_length = 4;
	else
		address_length = 16;

	/* 
	 * Forward compare
	 */
	if (left->tcp_dst != right->tcp_dst)
		goto reverse;
	if (left->tcp_src != right->tcp_src)
		goto reverse;


	for (i=0; i<address_length; i++) {
		if (left->ip_src[i] != right->ip_src[i])
			goto reverse;
		if (left->ip_dst[i] != right->ip_dst[i])
			goto reverse;
	}

	*is_reversed = 0;
	return 1;
reverse:

	if (left->tcp_dst != right->tcp_src)
		return 0;
	if (left->tcp_src != right->tcp_dst)
		return 0;

	for (i=0; i<address_length; i++) {
		if (left->ip_src[i] != right->ip_dst[i])
			return 0;
		if (left->ip_dst[i] != right->ip_src[i])
			return 0;
	}

	*is_reversed = 1;
	return 1;
}



static struct TCPRECORD *
tcp_lookup_session(
	struct FerretEngine *eng, 
	struct NetFrame *frame, 
	unsigned ipver, 
	const void *ipsrc, const void *ipdst, 
	unsigned portsrc, unsigned portdst, 
	unsigned *is_reversed,
	unsigned is_creating)
{
	static const size_t MAX_SESSIONS = (sizeof(eng->sessions)/sizeof(eng->sessions[0]));
	struct TCPRECORD rec = {0};
	struct TCPRECORD **r_index;
	struct TCPRECORD *sess;
	unsigned h;

	/* Set the current session to NULL, in case something happens */
	eng->current = 0;

	/* TODO Add support for IPv6 later, unfortunately we are only
	 * supporting IPv4 sessions right now */
	if (ipver != 0 && ipver != 4) {
		return 0;
	}


	/* Create a pseudo-record to compare against */
	rec.ip_ver = ipver;
	memcpy(rec.ip_dst, ipdst, 4);
	memcpy(rec.ip_src, ipsrc, 4);
	rec.tcp_dst = (unsigned short)portdst;
	rec.tcp_src = (unsigned short)portsrc;

	/* Do a hash lookup */
	h = tcp_record_hash(&rec) % MAX_SESSIONS;
	r_index = &eng->sessions[h];
	sess = *r_index;

	/* Follow the linked-list from that hash point
	 * [rdg] FIXED: This was originally a normal linked list ending in
	 * a NULL pointer. However, I changed it to a doubly linked list
	 * that becomes circular. Thus, the orignal code that kept going until
	 * it hit a NULL went into an infinite loop. I changed it so that it
	 * would now stop once it reached its starting point. I think there
	 * are other bits of the code ethat likewise need to change. */
	{
		unsigned depth = 0;
		while (sess && !tcp_record_equals(sess, &rec, is_reversed)) {
			if (depth++ > 1000) {
				printf("%x: too many TCP hash collisions, %u out of %u [%u.%u.%u.%u:%u -> %u.%u.%u.%u:%u]\n", h, depth, eng->session_count,
					rec.ip_src[3], rec.ip_src[2], rec.ip_src[1], rec.ip_src[0], rec.tcp_src,
					rec.ip_dst[3], rec.ip_dst[2], rec.ip_dst[1], rec.ip_dst[0], rec.tcp_dst
						);
			}
			sess = sess->next;
			if (sess == *r_index) {
				sess = NULL;
			}
		}
	}

	if (sess == NULL) {
		if (is_creating != TCP_CREATE)
			return NULL;

		/* If not found, create the session */
		eng->session_count++;
		sess = (struct TCPRECORD*)malloc(sizeof(*sess));
		memcpy(sess, &rec, sizeof(rec));

		sess->a3 = 0xa3a4a5a6;

		/* Insert into the doubly-linked list */
		if (*r_index == NULL) {
			*r_index = sess;
			sess->next = sess;
			sess->prev = sess;
		} else {
			sess->next = (*r_index)->next;
			sess->next->prev = sess;
			sess->prev = (*r_index);
			sess->prev->next = sess;
		}

		/* Add to the housekeeping list. We'll set this to call us back in 5-minutes. */
		housekeeping_remember(eng->housekeeper, frame->time_secs+5*90, tcp_housekeeping, sess, &sess->housekeeping_entry);

	} else if (is_creating == TCP_DESTROY) {
		/*
		 * MODE: DELETE this record
		 */
		unsigned i;

		/* Unlink from the housekeeping system */
		housekeeping_remove(eng->housekeeper, &sess->housekeeping_entry);

		/* Do a "close" on the TCP connection, and the reverse connection as well */
		sess->to_server.parser(sess, &sess->to_server, frame, TCP_CLOSE, 0);
		sess->from_server.parser(sess, &sess->from_server, frame, TCP_CLOSE, 0);

		/* Remove the record from the list */
		sess->next->prev = sess->prev;
		sess->prev->next = sess->next;
		if (*r_index == sess)
			*r_index = sess->next;
		if (*r_index == sess)
			*r_index = NULL;
		sess->next = NULL;
		sess->prev = NULL;

		/* Clean up the fragmentation buffers
		 * TODO: we need to separately process these fragments */
		if (sess->to_server.segments != NULL)
			FRAMERR(frame, "%s: discarding segment data\n", "TCP");
		if (sess->from_server.segments != NULL)
			FRAMERR(frame, "%s: discarding segment data\n", "TCP");
		tcpfrag_delete_all(&sess->to_server.segments);
		tcpfrag_delete_all(&sess->from_server.segments);

		/* Free the string reassemblers */
		for (i=0; i<sizeof(sess->to_server.str)/sizeof(sess->from_server.str[0]); i++) {
			strfrag_finish(&sess->to_server.str[i]);
			strfrag_finish(&sess->from_server.str[i]);
		}

		/* Free the memory */
		if (sess->a3 != 0xa3a4a5a6)
			printf("TCP stream memory corruption, probalby exploitable\n");
		free(sess);
		sess = NULL;
		eng->session_count--;
	}


	eng->current = sess;
	return sess;
}


extern unsigned smellslike_aim_oscar(const unsigned char *px, unsigned length);


/**
 * Run various heuristics on the TCP connection in order to figure out a likely
 * protocol parser for it.
 */
unsigned
tcp_smellslike(struct TCPRECORD *sess,  const struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned src_port = frame->src_port;
	unsigned dst_port = frame->dst_port;
	struct SmellsSSL smell;
	struct SmellsDCERPC dcerpc;
	FERRET_PARSER *to_server = &sess->to_server.parser;
	FERRET_PARSER *from_server = &sess->from_server.parser;

	/* HTTP */
	if (smellslike_httprequest(px, length)) {
		*to_server = stream_http_toserver;
		*from_server = stream_http_fromserver;
		return 0;
	}
	if (smellslike_http_response(px, length)) {
		*to_server = stream_http_toserver;
		*from_server = stream_http_fromserver;
		return 1; /* reverse */
	}

	/* SSL */
	smell.state = 0;
	if (smellslike_ssl_request(frame, &smell, px, length)) {
		*to_server = stream_ssl_toserver;
		*from_server = stream_ssl_fromserver;
		return 0;
	}

	/* MSRPC */
	dcerpc.state = 0;
	if (smellslike_msrpc_toserver(&dcerpc, px, length)) {
		*to_server = stream_dcerpc_toserver;
		*from_server = stream_dcerpc_fromserver;
		return 0;
	}

	/* MSN MESSENGER */
	if ((src_port == 1863 || dst_port == 1863)
		&& smellslike_msn_messenger(px, length)) {
		*to_server = process_simple_msnms_client_request;
		*from_server = process_msnms_server_response;
		return (src_port == 1863);
	}

	/* AIM OSCAR */
	if (length > 6 && px[0] == 0x2a && 1 <= px[1] && px[1] <= 5) {
		if (src_port == 5190) {
			*to_server = parse_aim_oscar_to_server;
			*from_server = parse_aim_oscar_from_server;
			return 1;
		} else if (dst_port == 5190) {
			*to_server = parse_aim_oscar_to_server;
			*from_server = parse_aim_oscar_from_server;
			return 0;
		}
	}

	/* I'm not sure why, but I saw AIM traffic across port 443, but not SSL
	 * encrypted. I assume that the AIM client does this in order to avoid
	 * being firewalled. */
	if ((src_port == 443 || dst_port == 443) && length > 6 && px[0] == 0x2a && 1 <= px[1] && px[1] <= 5 && smellslike_aim_oscar(px, length)) {
		if (src_port == 5190) {
			*to_server = parse_aim_oscar_to_server;
			*from_server = parse_aim_oscar_from_server;
			return 1;
		} else if (dst_port == 5190) {
			*to_server = parse_aim_oscar_to_server;
			*from_server = parse_aim_oscar_from_server;
			return 0;
		}
	}

	/* Yahoo Msg */
	if ((dst_port == 5050) || (src_port == 5050 && length > 4 && memcmp(px, "YMSG", 4))) {
		*to_server = stack_tcp_ymsg_client_request;
		*from_server = stack_tcp_ymsg_server_response;
		return (src_port == 5050);
	}

	/* SSL */
	if (src_port > 1024)
	switch (dst_port) {
	case 443: case 465:	case 993: case 995:
			*to_server = stream_ssl_toserver;
			*from_server = stream_ssl_fromserver;
			return 0;
	}
	if (src_port > 1024)
	switch (dst_port) {
	case 443: case 465:	case 993: case 995:
			*to_server = stream_ssl_toserver;
			*from_server = stream_ssl_fromserver;
			return 1;
	}

	/* SSH */
	if (dst_port == 22 || src_port == 22) {
		*to_server = stream_ssh_toserver;
		*from_server = stream_ssh_fromserver;
		return (src_port == 22);
	}


	/* SMTP */
	if (dst_port == 25 || src_port == 25) {
		*to_server = process_simple_smtp_request;
		*from_server = process_simple_smtp_response;
		return (src_port == 25);
	}

	/* RDP - remote desktop protocol from Microsoft */
	if (dst_port == 3389 || src_port == 3389) {
		*to_server = parse_rdp_request;
		*from_server = parse_rdp_response;
		return (src_port == 3389);
	}

	/* POP3 email */
	if (dst_port == 110 || src_port == 110) {
		*to_server = parse_pop3_request;
		*from_server = parse_pop3_response;
		return (src_port == 110);
	}

	/* SMB */
	if (dst_port == 139 || src_port == 139) {
		*to_server = parse_smb_request;
		*from_server = parse_smb_response;
		return (src_port == 139);
	}
	if (dst_port == 445 || src_port == 445) {
		*to_server = parse_smb_request;
		*from_server = parse_smb_response;
		return (src_port == 445);
	}

	/* DCE RPC */
	if (dst_port == 135 || src_port == 135) {
		*to_server = stream_dcerpc_toserver;
		*from_server = stream_dcerpc_fromserver;
		return (src_port == 135);
	}

	if (dst_port == 80 || src_port == 80) {
		*to_server = stream_http_toserver;
		*from_server = stream_http_fromserver;
		return (src_port == 80);
	}


	/*
	 * Default
	 */
	*to_server =  stream_to_server_unknown;
	*from_server = stream_from_server_unknown;

	return 0;
}


/**
 * This is called every 5-minutes on a TCP connection in order to clean up
 * closed or inactive connections.
 */
static void 
tcp_housekeeping(struct Housekeeping *housekeeper, void *housekeeping_data, time_t now, struct NetFrame *frame)
{
	struct TCPRECORD *sess = (struct TCPRECORD*)housekeeping_data;
	unsigned is_reversed = 0;

	/* If there has been activity since the last housekeeping check,
	 * then re-register this to be 5 minutes from the last activity */
	if (sess->last_activity + 5*60 > now) {
		housekeeping_remember(housekeeper, sess->last_activity + 5*60, tcp_housekeeping, sess, &sess->housekeeping_entry);
		return;
	}
	
	/* Free the TCP connections */
	tcp_lookup_session(sess->eng, frame, sess->ip_ver, sess->ip_src, sess->ip_dst, sess->tcp_src, sess->tcp_dst, &is_reversed, TCP_DESTROY);
}


/**
 * This function processes acknowledgements. The primary idea behind this
 * function is to see if we've missed any packets on a TCP connection,
 * such as when monitoring wireless networks. When we miss packets,
 * we have to figure out how to repair our TCP state. One easy
 * way is to simply delete the connect and start over again.
 */
static void 
tcp_ack_data(struct TCPRECORD *sess, unsigned is_reversed, struct NetFrame *frame, unsigned ackno)
{
	unsigned seqno;

	if (sess == NULL)
		return;

	/* Get the 'seqno' from the opposite side of the TCP connection to match the ACK number */
	if (is_reversed)
		seqno = sess->to_server.seqno;
	else
		seqno = sess->from_server.seqno;


	if ((int)(ackno - seqno) > 0) {
		/* We have experienced a dropped packet on the other side of the connection */
		/*printf("TCP DROPPED PACKET EVENT\n");
		printf("Session: %u.%u.%u.%u : %u  ->  %u.%u.%u.%u : %u\n",
			(unsigned char)(sess->ip_src[3]),
			(unsigned char)(sess->ip_src[2]),
			(unsigned char)(sess->ip_src[1]),
			(unsigned char)(sess->ip_src[0]),
			sess->tcp_src,

			(unsigned char)(sess->ip_dst[3]),
			(unsigned char)(sess->ip_dst[2]),
			(unsigned char)(sess->ip_dst[1]),
			(unsigned char)(sess->ip_dst[0]),
			sess->tcp_dst
			);*/

	}
}

/**
 *
 */
static void
tcp_data_parse(struct TCPRECORD *sess, struct TCP_STREAM *stream, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned seqno, unsigned is_frag)
{
	unsigned i;
	
	/*
	 * MISSING FRAGMENT
	 * 
	 * This tests to see if there is a discontinuity. If the current seqno
	 * is greater than the next-expected-seqno, then we have a missing
	 * fragment somewhere. Therefore, we need to add the fragment to the 
	 * queue to be processed when (if ever) the missing fragment arrives
	 */
	if (SEQ_FIRST_BEFORE_SECOND(stream->seqno, seqno)) {

		if (SEQ_FIRST_BEFORE_SECOND(stream->seqno+1999000, seqno)) {
			/* This fragment is too far in the future, so discard it */
			FRAMERR(frame, "tcp: orphan fragment\n");
			/* defcon2008/dump002.pcap(93562)
			 * This packet goes over 100,000 bytes in the future passed
			 * missed fragment before retransmitting it */
			return;
		}

		/* Don't remember this fragment if it's coming from the remembered
		 * fragment queue */
		if (is_frag)
			return;

		/* Remeber this segment so that we can process it later when we 
		 * get something appropriate. */
		tcpfrag_add(&(stream->segments), px, length, seqno);
		return;

	}
	
	
	/* 
	 * PREVIOUS FRAGMENT and RETRANSMISSION
	 *
	 * This tests to see end of this fragment is a sequence number that
	 * we've already processed. This will be the case on repeated
	 * transmissions of the same packet as well.
	 */
	if (SEQ_FIRST_BEFORE_SECOND(seqno+length, stream->seqno) || seqno+length == stream->seqno) {
		/* This fragment is completely before the current one, therefore
		 * we can completely ignore it */
		return;
	}


	/* 
	 * OVERLAPPING FRAGMENT 
	 *
	 * This tests the case where the current fragment starts somewhere
	 * in the middle of something we've already processed. There is still
	 * some new data, so we just ignore the old bit.
	 */
	if (SEQ_FIRST_BEFORE_SECOND(seqno, stream->seqno)) {
		/* Regress: ferret-regress-00001-tcp-overlap.pcap frame 20 */
		unsigned sublen = stream->seqno - seqno;
		seqno += sublen;
		length -= sublen;
		px += sublen;
	}


	/* TEMP: change this to an assert */
	if (stream->seqno != seqno)
		FRAMERR(frame, "programming error\n");

	/*
	 * PARSE THE DATA WITH A PROTOCOL PARSER
	 */
	stream->parser(sess, stream, frame, px, length);
	stream->seqno = seqno+length;

	/* STRING RE-ASSEMBLER:
	 *	If we are in the middle of parsing a string from the packet,
	 *  then it's currently pointing into the packet that's about to
	 *	disappear. Therefore, we need to allocate a backing store
	 *	for it that will be preserved along with the TCP stream so
	 *	that the packet can disappear */
	for (i=0; i<sizeof(stream->str)/sizeof(stream->str[0]); i++) {
		if (stream->str[i].length && stream->str[i].backing_store == NULL)
			strfrag_force_backing_store(&stream->str[i]);
	}

	if (sess->layer7_proto == 0)
		sess->layer7_proto = frame->layer7_protocol;
}


void swap(const void *lhs, const void *rhs, size_t length)
{
	unsigned char *p_lhs = (unsigned char *)lhs;
	unsigned char *p_rhs = (unsigned char *)rhs;
	size_t i;

	for (i=0; i<length; i++) {
		p_lhs[i] ^= p_rhs[i];
	}
	for (i=0; i<length; i++) {
		p_rhs[i] ^= p_lhs[i];
	}
	for (i=0; i<length; i++) {
		p_lhs[i] ^= p_rhs[i];
	}
}

/**
 * Called when we've discovered that the session is going the wrong way, 
 * that it's going FROM the server rather than TO the server.
 */
void reverse_direction(struct TCPRECORD *sess)
{
	swap(&sess->tcp_src, &sess->tcp_dst, sizeof(sess->tcp_src));
	swap(&sess->ip_src, &sess->ip_dst, sizeof(sess->ip_src));
	swap(&sess->to_server, &sess->from_server, sizeof(sess->to_server));
}

/**
 * This is the primary function called to analyze a bit of data from a 
 * TCP connection.
 */
static void 
tcp_data(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned seqno, unsigned ackno)
{
	struct TCPRECORD *sess;
	struct TCP_STREAM *stream;
	struct FerretEngine *eng = ferret->eng[ferret->engine_count - 1];
	unsigned i;
	unsigned is_reversed = 0;

	/*
	 * Lookup (or create) a TCP session object. This is an object in a
	 * SINGLE direction of a TCP flow.
	 */
	/* Look for the session in one of our eng instances */
	sess = NULL;
	for (i=0; i<ferret->engine_count; i++) {
		sess = tcp_lookup_session(ferret->eng[i], 
						frame, frame->ipver, 
						&frame->src_ipv4, &frame->dst_ipv4, 
						frame->src_port, frame->dst_port, 
						&is_reversed,
						TCP_LOOKUP);
		if (sess != NULL) {
			eng = ferret->eng[i];
			break;
		}
	}

	/* If not found, create it in the newest instance */
	if (sess == NULL) {
		
		/* Create a new TCP session record */
		sess = tcp_lookup_session(
					ferret->eng[ferret->engine_count-1], 
					frame, frame->ipver, 
					&frame->src_ipv4, &frame->dst_ipv4, 
					frame->src_port, frame->dst_port, 
					&is_reversed, TCP_CREATE);
		sess->eng = eng;
		frame->sess = sess;


		sess->to_server.seqno = seqno;
		sess->to_server.ackno = seqno;
		sess->from_server.seqno = ackno;
		sess->from_server.ackno = ackno;

		is_reversed = tcp_smellslike(sess, frame, px, length);
		if (is_reversed) {
			swap(&sess->to_server.parser, &sess->from_server.parser, sizeof(sess->to_server.parser));
			reverse_direction(sess);
		}
	}

	/* If it's still NULL, we got a problem */
	if (!sess)
		return; /* TODO: handle packets that cannot be assigned a state object */

    /* Record the last time we saw a data packet. We will use this value
	 * in order to determine when we should age out the TCP connection,
	 * where the oldest inactive connections will be those that get aged out
	 * first. */
	sess->last_activity = frame->time_secs;

	/* Get the 'stream' */
	if (is_reversed)
		stream = &sess->from_server;
	else
		stream = &sess->to_server;

	/*
	 * Now parse the data
	 */
	tcp_data_parse(sess, stream, frame, px, length, seqno, 0);

	assert(frame->sess);

	/*
	 * Take care of remaining fragments that attach to this one
	 */
	while (stream->segments && (int)(stream->seqno - stream->segments->seqno)>=0) {
		/* Regress: ferret-regress-00002-tcp-missing.pcap
		 *  the case where a saved fragment overlaps with existing fragment */
		px = stream->segments->px;
		length = stream->segments->length;
		seqno = stream->segments->seqno;

		tcp_data_parse(sess, stream, frame, px, length, seqno, 1);

		tcpfrag_delete(&stream->segments);
	}
	
	/* Now forget the current processor */
	eng->current = 0;
}

void process_tcp(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned is_reversed = 0;
	struct {
		unsigned src_port;
		unsigned dst_port;
		unsigned seqno;
		unsigned ackno;
		unsigned header_length;
		unsigned flags;
		unsigned window;
		unsigned checksum;
		unsigned urgent;
	} tcp;

	ferret->statistics.tcp++;
	frame->layer4_protocol = LAYER4_TCP;

	if (length == 0) {
		FRAMERR(frame, "tcp: frame empty\n");
		frame->layer4_protocol = LAYER4_TCP_CORRUPT;
		return;
	}
	if (length < 20) {
		FRAMERR(frame, "tcp: frame too short\n");
		frame->layer4_protocol = LAYER4_TCP_CORRUPT;
		return;
	}

/*
	    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

	tcp.src_port = ex16be(px+0);
	tcp.dst_port = ex16be(px+2);
	tcp.seqno = ex32be(px+4);
	tcp.ackno = ex32be(px+8);
	tcp.header_length = px[12]>>2;
	tcp.flags = px[13];
	tcp.window = ex16be(px+14);
	tcp.checksum = ex16be(px+16);
	tcp.urgent = ex16be(px+18);

	frame->src_port = tcp.src_port;
	frame->dst_port = tcp.dst_port;

	if (tcp.header_length < 20) {
		/* Regress: defcon2008\dump027.pcap(39901) */
		//FRAMERR(frame, "tcp: header too short, expected length=20, found length=%d\n", tcp.header_length);
		frame->layer4_protocol = LAYER4_TCP_CORRUPT;
		return;
	}
	if (tcp.header_length > length) {
		//FRAMERR(frame, "tcp: header too short, expected length=%d, found length=%d\n", tcp.header_length, length);
		frame->layer4_protocol = LAYER4_TCP_CORRUPT;
		return;
	}
	if ((tcp.flags & 0x20) && tcp.urgent > 0) {
		FRAMERR(frame, "tcp: found %d bytes of urgent data\n", tcp.urgent);
		frame->layer4_protocol = LAYER4_TCP_CORRUPT;
		return;
	}

	/* Check the checksum */
	if (0) if (!validate_tcp_checksum(px, length, frame->src_ipv4, frame->dst_ipv4)) {
		/* Regress: defcon2008-msnmsgr.pcap(24066) */
		ferret->statistics.errs_tcp_checksum++;		
		frame->layer4_protocol = LAYER4_TCP_XSUMERR;
		return;
	}

	/*TODO: need to check checksum */

	if (tcp.header_length > 20) {
		unsigned o = 20;
		unsigned max = tcp.header_length;

		while (o < tcp.header_length) {
			unsigned tag = px[o++];
			unsigned len;

			if (tag == 0)
				break;
			if (tag == 1)
				continue;

			if (o >= max) {
				FRAMERR(frame, "tcp: options too long\n");
				break;
			}
			len = px[o++];

			if (len < 2) {
				FRAMERR(frame, "tcp: invalid length field\n");
				break;
			}
			if (o+len-2 > max) {
				FRAMERR(frame, "tcp: options too long\n");
				break;
			}

			switch (tag) {
			case 0x02: /* max seg size */
				if (len != 4)
					FRAMERR(frame, "tcp: unknown length: option=%d, length=%d\n", tag, len);
				break;
			case 0x04: /* SACK permitted */
				if (len != 2)
					FRAMERR(frame, "tcp: unknown length: option=%d, length=%d\n", tag, len);
				break;
			case 0x05: /* SACK */
				break;
			case 0x08: /*timestamp*/
				break;
			case 0x03: /*window scale*/
				break;
			default:
				FRAMERR(frame, "tcp: unknown option=%d, length=%d\n", tag, len);
			}

			o += len-2;
		}
	}


	SAMPLE(ferret,"TCP", JOT_NUM("flags", tcp.flags));

	frame->sess = tcp_lookup_session(ferret->eng[0], 
									frame, 
									frame->ipver, 
									&frame->src_ipv4, 
									&frame->dst_ipv4, 
									frame->src_port, 
									frame->dst_port, 
									&is_reversed,
									TCP_LOOKUP);
	if (frame->sess && frame->sess->layer7_proto)
		frame->layer7_protocol = frame->sess->layer7_proto;
	else {
		if (tcp.src_port == 80 || tcp.dst_port == 80)
			frame->layer7_protocol = LAYER7_HTTP;
		else if (tcp.src_port == 443 || tcp.dst_port == 443)
			frame->layer7_protocol = LAYER7_SSL;
		else if (tcp.src_port == 25 || tcp.dst_port == 25)
			frame->layer7_protocol = LAYER7_SMTP;
		else if (tcp.src_port == 139 || tcp.dst_port == 139)
			frame->layer7_protocol = LAYER7_SMB;
		else if (tcp.src_port == 445 || tcp.dst_port == 445)
			frame->layer7_protocol = LAYER7_SMB;
		else if (tcp.src_port == 110 || tcp.dst_port == 110)
			frame->layer7_protocol = LAYER7_POP3;
		else if (tcp.src_port == 135 || tcp.dst_port == 135)
			frame->layer7_protocol = LAYER7_DCERPC;
	}

	/* Process an "acknowledgement". Among other things, this will identify
	 * when packets have been missed: if the other side claims to have
	 * received a packet, but we never saw it, then we know that it was
	 * dropped somewhere on the network (probably because we are getting
	 * a weak signal via wireless). */
	if ((tcp.flags & TCP_ACK) && frame->sess) {
		tcp_ack_data(frame->sess, is_reversed, frame, tcp.ackno);
	}

	switch (tcp.flags & 0x3F) {
	case TCP_SYN:
		tcp_syn(ferret, frame);
		break;
	case TCP_SYN|TCP_ACK:
		tcp_synack(ferret, frame);
		break;
	case TCP_FIN:
	case TCP_FIN|TCP_ACK:
	case TCP_FIN|TCP_ACK|TCP_PSH:
		tcp_fin(ferret, frame);
		break;
	case TCP_ACK:
	case TCP_ACK|TCP_PSH:
		if (length > tcp.header_length) {
			tcp_data(ferret, frame, px+tcp.header_length, length-tcp.header_length, tcp.seqno, tcp.ackno);
		}
		break;
	case TCP_RST:
	case TCP_RST|TCP_ACK:
		break;
	case 0x40|TCP_ACK:
		break;
	case TCP_RST|TCP_ACK|TCP_FIN:
	case TCP_RST|TCP_ACK|TCP_PSH:
		break;
	default:
		FRAMERR(frame, "tcp: unexpected combo of flags: 0x%03x\n", tcp.flags);
	}

	/*
	 * KLUDGE:
	 */
	if (frame->layer7_protocol == 0) {
		if (frame->dst_port == 443 || frame->src_port == 443)
			frame->layer7_protocol = LAYER7_SSL;
		if ((frame->dst_port == 3260 && frame->src_port > 1024)
		 || (frame->src_port == 3260 && frame->dst_port > 1024))
			frame->layer7_protocol = LAYER7_ISCSI;
		if ((frame->dst_port == 21 && frame->src_port > 1024)
		 || (frame->src_port == 21 && frame->dst_port > 1024))
			frame->layer7_protocol = LAYER7_FTP;
		if ((frame->dst_port == 143 && frame->src_port > 1024)
		 || (frame->src_port == 143 && frame->dst_port > 1024))
			frame->layer7_protocol = LAYER7_IMAP;
	}
}

void strfrag_xfer(struct StringReassembler *dst, struct StringReassembler *src)
{
	/* Transfer from one string to another. We often call this when the
	 * we really just want to re-use one of the string reassembly buffers
	 * on the connection to store data across packets. */
	if (dst->length)
		strfrag_init(dst);
	memcpy(dst, src, sizeof(*dst));
	memset(src, 0, sizeof(*src));
}
void strfrag_copy(struct StringReassembler *dst, struct StringReassembler *src)
{
	/* Make a copy of one string to another.
	 * If they both point into the current packet, then we don't need to
	 * allocate memory. Otherwise, we need to duplicate the backing-store */
	if (dst->length)
		strfrag_init(dst);
	strfrag_append(dst, src->the_string, src->length);
	if (src->backing_store)
		strfrag_force_backing_store(dst);
}

void strfrag_init(struct StringReassembler *strfrag)
{
	if (strfrag->backing_store)
		free(strfrag->backing_store);
	memset(strfrag, 0, sizeof(*strfrag));

	/* TODO: we should just set the ->length field to zero to
	 * improve performance */
}

void strfrag_finish(struct StringReassembler *strfrag)
{
	if (strfrag->backing_store)
		free(strfrag->backing_store);
	memset(strfrag, 0, sizeof(*strfrag));
}

void strfrag_append(struct StringReassembler *strfrag, const unsigned char *px, size_t length)
{
	if (length == 0)
		return;

	if (strfrag->length == 0) {
		/* Initial condition: we create the first object by pointing
		 * into the packet */
		strfrag->the_string = px;
		strfrag->length = (unsigned)length;

		assert(strfrag->backing_store == 0);
		return;
	}

	if (strfrag->backing_store) {
		/* We have a backing store, so we need to re-alloc the memory and
		 * copy the new data onto the end of it, then reset the string
		 * point to the newly allocated memory */
		unsigned char *new_store = (unsigned char *)malloc(length + strfrag->length + 1);

		/* Copy the old string */
		memcpy(	new_store, 
				strfrag->the_string, 
				strfrag->length);

		/* Append the new string */
		memcpy(	new_store + strfrag->length,
				px,
				length);

		/* Nul-terminate just to make debugging easier */
		new_store[strfrag->length + length] = '\0';

		/* Now free the old string and replace it with the new string, including
		 * making the static pointer point to the new string */
		free(strfrag->backing_store);
		strfrag->backing_store = new_store;
		strfrag->the_string = new_store;
		strfrag->length += (unsigned)length;
		return;
	}


	if (strfrag->the_string + strfrag->length != px) {
		/* WHOOPS. This shouldn't happen, but it looks like a programmer
		 * is combining multiple un-connected segments together.
		 * This forces us to create a backing store to combine the 
		 * disconnected fragments into a single string */
		strfrag_force_backing_store(strfrag);
		strfrag_append(strfrag, px, length);
		return;
	}

	/* It looks like we are still pointing to the same packet. Therefore, 
	 * all we have to do is just increase the length of the string
	 * that we are already pointing to */
	strfrag->length += (unsigned)length;
}

void strfrag_force_backing_store(struct StringReassembler *strfrag)
{
	/* This is likely called AFTER we have parsed a TCP application,
	 * but aren't through parsing a string. Therefore, we need to
	 * copy the fragment of the string out of the current packet and
	 * place it into a allocated memory. */

	/* If we already have a backing-store, then do nothing. This means
	 * the process is 'idempotent': we can repeatedly call this function
	 * without worrying if it's already been called */
	if (strfrag->backing_store)
		return;

	/* Allocate memory for the store. I'm going to allocate an extra byte
	 * for a nul-terminator, not because any of the parsers rely upon 
	 * nul terminated strings, but because it makes debugging easier.
	 */
	strfrag->backing_store = (unsigned char*)malloc(strfrag->length+1);

	/* Copy over the string from the current packet */
	memcpy(strfrag->backing_store, strfrag->the_string, strfrag->length);

	/* Nul-terminate */
#if RELEASE
	strfrag->backing_store[strfrag->length] = 'Q'; /*force non-nul termination to detect bugs*/
#else
	strfrag->backing_store[strfrag->length] = '\0';
#endif

	/* Change the pointer from pointing into the packet to now point to
	 * the allocated string */
	strfrag->the_string = strfrag->backing_store;
}

