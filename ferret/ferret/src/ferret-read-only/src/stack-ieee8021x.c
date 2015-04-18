/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "stack-parser.h"
#include "stack-extract.h"
#include "stack-netframe.h"
#include "ferret.h"
#include <string.h>
#include <stdio.h>

struct LEAPtransaction {
	time_t timestamp;
	unsigned id;
	unsigned char src_mac[6];
	unsigned char dst_mac[6];
	unsigned char identity[100];
	unsigned identity_length;
	unsigned char challenge[8];
	unsigned char response[24];
	unsigned status;

	/* use a simple linked-list, because there shouldn't be
	 * too many LEAP transactions open at any point in time */
	struct LEAPtransaction *next;
};

struct LEAP {
	struct LEAPtransaction *transactions;
};

/**
 * Called whenever we see an EAPOL-Start or EAPOL-Logoff to make
 * sure that we remove any partially seen authentication
 */
void
xleap_destroy(struct Ferret *ferret, const unsigned char *src_mac, const unsigned char *dst_mac)
{
	struct LEAP *leap = ferret->leap;
	struct LEAPtransaction **r_trans;

	if (leap == NULL)
		return;


	for (r_trans=&leap->transactions; *r_trans; r_trans=&(*r_trans)->next) {
		struct LEAPtransaction *trans = *r_trans;

		if (memcmp(trans->src_mac, src_mac, 6) == 0 && memcmp(trans->dst_mac, dst_mac, 6) == 0) {
			/* Remove from the list */
			*r_trans = trans->next;
			/* Free the memory */
			free(trans);
			break;
		}
	}

	if (leap->transactions == NULL) {
		free(leap);
		ferret->leap = NULL;
	}
}

void xleap_destroy_all(struct LEAP *leap)
{
	if (leap == NULL)
		return;
	while (leap->transactions) {
		struct LEAPtransaction *trans = leap->transactions;
		leap->transactions = trans->next;
		free(trans);
	}
	free(leap);
}

struct LEAPtransaction *
xleap_lookup(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *src_mac, const unsigned char *dst_mac, unsigned do_create)
{
	struct LEAP *leap;
	struct LEAPtransaction **r_trans;
	struct LEAPtransaction *trans;
	unsigned done_a_time_out = 0;


	/* If our structure doesn't already exist, then create it */
	if (ferret->leap == NULL) {
		ferret->leap = (struct LEAP*)malloc(sizeof(*ferret->leap));
		memset(ferret->leap, 0, sizeof(*ferret->leap));
		ferret->leap_free = xleap_destroy_all;
	}

	leap = ferret->leap;

	/* See if it already exists */
	for (r_trans=&leap->transactions; *r_trans; r_trans=&(*r_trans)->next) {
		struct LEAPtransaction *trans = *r_trans;

		/* HOUSEKEEPING: we are shoving some housekeeping code here to
		 * get rid of old entries. We want to delete entries older than
		 * 5-minutes. However, we don't want a situation where we send 
		 * a bunch of requests, then wait 5mins, and then go through
		 * the huge list and delete them. Therefore, every time we do
		 * a lookup, we will only delete a single timed-out entry 
		 * CHANGE: 2-minutes */
		if (frame->time_secs > trans->timestamp + (unsigned)(2*60) && !done_a_time_out) {
			*r_trans = trans->next;
			free(trans);
			done_a_time_out = 1;
			if (*r_trans == NULL)
				break;
			trans = *r_trans;
		}

		if (memcmp(trans->src_mac, src_mac, 6) == 0 && memcmp(trans->dst_mac, dst_mac, 6) == 0) {
			return trans;
		}

	}

	if (!do_create)
		return NULL;

	/* If not found, then create */
	trans = (struct LEAPtransaction*)malloc(sizeof(*trans));
	memset(trans, 0, sizeof(*trans));
	trans->timestamp = frame->time_secs;
	memcpy(trans->src_mac, src_mac, 6);
	memcpy(trans->dst_mac, dst_mac, 6);
	
	/* Insert into head of linked list */
	trans->next = leap->transactions;
	leap->transactions = trans;
	
	return trans;
}

extern void DesEncrypt(const unsigned char *in, const unsigned char *key, unsigned char *out);


int brute_force_final_2bytes_of_ntlm_hash(struct LEAPtransaction *trans, unsigned char endofhash[2])
{

	unsigned i;
	unsigned char deskey[7] = { 0, 0, 0, 0, 0, 0, 0 };
	unsigned char cipher[8];

	if (memcmp(trans->challenge, "\0\0\0\0\0\0\0\0", 8) == 0)
		return 0;
	if (memcmp(trans->response, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 24) == 0)
		return 0;
	for (i = 0; i <= 0xffff; i++) {
		deskey[0] = (unsigned char)(i >> 8);
		deskey[1] = (unsigned char)(i & 0xff);

		DesEncrypt(trans->challenge, deskey, cipher);
		if (memcmp(cipher, trans->response + 16, 8) == 0) {
			/* Success in calculating the last 2 of the hash */
			/* debug - printf("%2x%2x\n", deskey[0], deskey[1]); */
			endofhash[0] = deskey[0];
			endofhash[1] = deskey[1];
			return 1;
		}
	}

	return 0;
}




static void
copy_identity(struct LEAPtransaction *trans, const unsigned char *px, unsigned length)
{
	unsigned len = length;
	if (len > sizeof(trans->identity)-1)
		len = sizeof(trans->identity)-1;
	memcpy(trans->identity, px, len);
	trans->identity[len] = '\0';
	trans->identity_length = len;
}

void process_eap_identity(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	struct LEAPtransaction *trans;

	/* remove the leading nul Cisco puts on their access points */
	if (length > 1 && px[0] == '\0') {
		px++;
		length--;
	}

	JOTDOWN(ferret, 
		JOT_MACADDR("ID-MAC", frame->src_mac),
		JOT_PRINT("LEAP-Username",	px, length),
		0);

	/* Create a LEAP transaction entry remembering this. First
	 * destroy any existing entries */
	xleap_destroy(ferret, frame->src_mac, frame->dst_mac);
	trans = xleap_lookup(ferret, frame, frame->src_mac, frame->dst_mac, 1);
	if (trans) {
		copy_identity(trans, px, length);
	}
}


void process_leap_challenge_request(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned id)
{
	struct LEAPtransaction *trans;
	unsigned version;
	unsigned challenge_length;
	const unsigned char *challenge;
	
	/* Validate the packet length */
	if (length < 3+8) {
		FRAMERR(frame, "LEAP: challenge header too short\n");
		return;
	}

	/* Validate the version number, we only support version 1,
	 * and there is no newer version as far as we know */
	version = px[0];
	if (version != 1) {
		FRAMERR(frame, "LEAP: unexpected version %d\n", version);
		return;
	}

	/* Grab the 8 byte challenge */
	challenge_length = px[2];
	if (challenge_length != 8) {
		FRAMERR(frame, "LEAP: unexpected challenge length %d\n", challenge_length);
	}
	challenge = px+3;

	/* Skip all the fields up to this point, the remainder should only be
	 * the Identity field */
	px += 3+8;
	length -= 3+8;

	/* Create a LEAP transaction entry remembering this */
	trans = xleap_lookup(ferret, frame, frame->dst_mac, frame->src_mac, 1);
	if (trans) {
		trans->id = id;
		memcpy(trans->challenge, challenge, 8);
		if (length)
			copy_identity(trans, px, length);

		JOTDOWN(ferret, 
			JOT_MACADDR("ID-MAC", frame->dst_mac),
			JOT_PRINT("LEAP-Username",	trans->identity, trans->identity_length),
			JOT_HEXSTR("Challenge", trans->challenge, 8),
			0);
	}
}

void process_leap_challenge_response(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned id)
{
	struct LEAPtransaction *trans;
	unsigned version;
	unsigned challenge_length;
	const unsigned char *challenge;
	
	if (length < 3+8) {
		FRAMERR(frame, "LEAP: challenge response header too short\n");
		return;
	}

	version = px[0];
	if (version != 1) {
		FRAMERR(frame, "LEAP: unexpected version %d\n", version);
		return;
	}

	challenge_length = px[2];
	if (challenge_length != 24) {
		FRAMERR(frame, "LEAP: unexpected challenge response length %d\n", challenge_length);
	}
	challenge = px+3;

	px += 3+24;
	length -= 3+24;

	/* Create a LEAP transaction entry remembering this */
	trans = xleap_lookup(ferret, frame, frame->src_mac, frame->dst_mac, 1);
	if (trans) {
		if (id != trans->id && trans->id != 0) {
			xleap_destroy(ferret, frame->src_mac, frame->dst_mac);
			trans = xleap_lookup(ferret, frame, frame->src_mac, frame->dst_mac, 1);

			/* ID mismatch */
			FRAMERR(frame, "LEAP: ID mismatch\n");
		}

		memcpy(trans->response, challenge, 24);
		if (length)
			copy_identity(trans, px, length);


		JOTDOWN(ferret, 
			JOT_MACADDR("ID-MAC", frame->dst_mac),
			JOT_PRINT("LEAP-Username",	trans->identity, trans->identity_length),
			JOT_HEXSTR("Challenge", trans->challenge, 8),
			JOT_HEXSTR("Response", trans->response, 24),
			0);
		if (memcmp(frame->src_mac,frame->bss_mac,6)==0) {
			JOTDOWN(ferret, 
				JOT_MACADDR("ID-MAC", frame->dst_mac),
				JOT_PRINT("LEAP-Username",	trans->identity, trans->identity_length),
				JOT_HEXSTR("Challenge", trans->challenge, 8),
				JOT_HEXSTR("Response", trans->response, 24),
				JOT_SZ("Side", "server"),
				0);
		}

		/*if (1) {
			unsigned char endofhash[2];
			if (brute_force_final_2bytes_of_ntlm_hash(trans, endofhash)) {
				JOTDOWN(ferret, 
					JOT_MACADDR("ID-MAC", frame->dst_mac),
					JOT_PRINT("LEAP-Username",	trans->identity, trans->identity_length),
					JOT_HEXSTR("Challenge", trans->challenge, 8),
					JOT_HEXSTR("Response", trans->response, 24),
					JOT_HEXSTR("NTLM-Hint", endofhash, 2),
					0);
			}
		}*/

	}
}
void process_leap_success_failure(struct Ferret *ferret, struct NetFrame *frame, unsigned id, unsigned code)
{
	struct LEAPtransaction *trans;

	trans = xleap_lookup(ferret, frame, frame->dst_mac, frame->src_mac, 0);
	if (trans) {
		if (id != trans->id && id != trans->id+1 && trans->id != 0) {
			/* ID mismatch */
			FRAMERR(frame, "LEAP: ID mismatch\n");
			return;
		}

		JOTDOWN(ferret, 
			JOT_MACADDR("ID-MAC", frame->dst_mac),
			JOT_PRINT("LEAP-Username",	trans->identity, trans->identity_length),
			JOT_HEXSTR("Challenge", trans->challenge, 8),
			JOT_HEXSTR("Response", trans->response, 24),
			JOT_SZ("Result", ((code==3)?"Success":"Failure")),
			0);
	}
}

void process_eap(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned code;
	unsigned id;
	unsigned remaining;
	unsigned offset = 0;
	unsigned type = 0;
	if (length < 4) {
		FRAMERR(frame, "EAP: truncated\n");
		return;
	}

	/* parse header */
	code = px[0];
	id = px[1];
	remaining = ex16be(px+2);
	if (length < remaining) {
		FRAMERR(frame, "EAP: truncated\n");
	}
	if (length > remaining)
		length = remaining;
	offset += 4;
	if (code == 1 || code == 2) {
		if (length < offset + 1) {
			FRAMERR(frame, "EAP: truncated\n");
		}
		type = px[offset];
		offset++;
	}

	switch (code) {
	case 1: /* Request */
		switch (type) {
		case 1: /* Identity */
			/* Regress: asleap/data/leap.dump(334)*/
			process_eap_identity(ferret, frame, px+offset, length-offset);
			break;
		case 17: /* Cisco LEAP */
			process_leap_challenge_request(ferret, frame, px+offset, length-offset, id);
			break;
		default:
			FRAMERR(frame, "EAP: unknown request %d\n", type);
		}
		break;
	case 2: /* Response */
		switch (type) {
		case 1: /* Identity */
			process_eap_identity(ferret, frame, px+offset, length-offset);
			break;
		case 17: /* Cisco LEAP */
			process_leap_challenge_response(ferret, frame, px+offset, length-offset, id);
			break;
		default:
			FRAMERR(frame, "EAP: unknown request %d\n", px[offset]);
		}
		break;
	case 3: /* Success */
	case 4: /* Failure */
		process_leap_success_failure(ferret, frame, id, code);
		break;
	default:
		FRAMERR(frame, "EAP: unknown code %d\n", code);
	}
	
}


void process_802_1x_auth(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned type;
	
	UNUSEDPARM(ferret);

	if (length < 4) {
		FRAMERR(frame, "802.1x: truncated\n");
		return;
	}

	switch (px[0]) {
	case 1: /*version = 1*/
		type = px[1];

		SAMPLE(ferret,"IEEE802.11", JOT_NUM("auth", type));
		switch (type) {
		case 0: /* EAP */
			process_eap(ferret, frame, px+4, length-4);
			break;
		case 1: /* EAPOL start */
			xleap_destroy(ferret, frame->src_mac, frame->dst_mac);
			xleap_destroy(ferret, frame->dst_mac, frame->src_mac);			
			break;
		case 2: /* EAPPOL Logoff */
			xleap_destroy(ferret, frame->src_mac, frame->dst_mac);
			xleap_destroy(ferret, frame->dst_mac, frame->src_mac);			
			break;
		case 3: /* KEY */
			//FRAMERR(frame, "802.1x: unknown\n");
			break;
		default:
			FRAMERR(frame, "802.1x: unknown\n");
		}
		break;
	default:
		FRAMERR(frame, "802.1x: unknown\n");
		break;
	}
	
	
}

