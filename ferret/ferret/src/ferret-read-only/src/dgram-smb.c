/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*

  SERVER MESSAGE BLOCK - DATAGRAM

  SMB is the primary Microsoft Windows networking protocol that
  all their applications are based upon.

  One feature of SMB runs over UDP, the other over TCP. The UDP
  datagram service is used primarily for broadcasts where 
  Windows tries to discovers the local network.

  Two of the main protocols we are interested in are the BROWSE
  protocol that helps us find servers on a network, and the NETLOGON
  protocol that tells us about the 'domain' that a machine belongs
  to and some of the user account information.

  Reference
	title: "SMB Traffic During Windows NT Domain Logon"
	urrl:  http://support.microsoft.com/kb/139608
*/



#include "stack-parser.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "ferret.h"

#include <ctype.h>
#include <string.h>
#include <stdio.h>

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

struct SMBdgm_transact
{
	unsigned word_count;
	unsigned total_parm_count;
	unsigned total_data_count;
	unsigned max_parm_count;
	unsigned max_data_count;
	unsigned max_setup_count;
	unsigned flags;
	unsigned timeout;
	unsigned parm_count;
	unsigned parm_offset;
	unsigned data_count;
	unsigned data_offset;
	unsigned setup_count;
	unsigned byte_count;
	unsigned setup_offset;
	unsigned extra_offset;
	unsigned extra_length;
};
struct SMBdgm
{
	unsigned command;
	unsigned err;
	unsigned errcode;
	unsigned flags;
	unsigned flags2;
	unsigned process_id_high;
	unsigned process_id;
	unsigned char signature[8];
	unsigned tree_id;
	unsigned user_id;
	unsigned multiplex_id;

	union {
		struct SMBdgm_transact trans;
	} dgm;

	struct MailSlot {
		unsigned opcode;
		unsigned priority;
		unsigned clss;
		const unsigned char *name;
		unsigned name_length;
	} mailslot;

};

static unsigned get_byte(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result;
	unsigned offset = *r_offset;
	
	if (offset > length)
		return 0;
	if (offset == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	result = px[offset];
	
	(*r_offset)++;
	return result;
}
static unsigned get_word(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result;
	unsigned offset = *r_offset;
	
	if (offset > length)
		return 0;
	if (offset == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	if (offset+1 == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	result = ex16le(px+offset);
	
	(*r_offset) += 2;
	return result;
}
static unsigned get_dword(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset)
{
	unsigned result;
	unsigned offset = *r_offset;
	
	if (offset > length)
		return 0;
	if (offset == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	if (offset+1 == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	if (offset+2 == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	if (offset+3 == length) {
		FRAMERR(frame, "smb: truncated\n");
		return 0;
	}
	result = ex32le(px+offset);
	
	(*r_offset) += 4;
	return result;
}

static int path_equals(const unsigned char *name, unsigned name_length, const char *value)
{
	unsigned i;

	for (i=0; i<name_length && value[i]; i++)
		if (tolower(name[i]) != tolower(value[i]))
			return 0;
	if (i==name_length && value[i] == '\0')
		return 1;
	else 
		return 0;
}

static size_t cleanse_netbios_name(const char *name)
{
	size_t length = strlen(name);

	if (length>4 && name[length-1] == '>') {
		if (isdigit(name[length-2]) && isdigit(name[length-3]) && name[length-4] == '<')
			length-=4;
	}
	while (length && isspace(name[length-1]))
		length--;
	return length;
}
void process_BROWSE(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct SMBdgm *smb)
{
	unsigned cmd;

	UNUSEDPARM(smb);UNUSEDPARM(length);

	cmd = px[offset]; /*get_byte(frame, px, length, &offset);*/

	switch (cmd) {
	case 15: /*Local Master Announcement*/
	case 9: /* Get Backup List Request*/
	case 8: /* Browser election Request */
	case 2: /* Request Announcement */
		break;
	case 12: /*0x0c - Domain/Workgroup Announcement */
		{
			const unsigned char *workgroup = px+offset+6;
			unsigned workgroup_length;
			const char *hostname = frame->netbios_source;
			size_t hostname_length = cleanse_netbios_name(hostname);

			/* find nul terminator */
			for (workgroup_length=0; workgroup_length<16 && workgroup[workgroup_length]; workgroup_length++)
				;

			JOTDOWN(ferret,
				JOT_SZ("proto","MS-BROWSE"),
				JOT_SZ("op","domain"),
				JOT_PRINT("domain",	 	workgroup,					workgroup_length),
				JOT_PRINT("hostname",	 	hostname,					hostname_length),
				JOT_SRC("ip.src", frame),
				0);
		}
		break;
	case 1: /*0x01 - Host Announcement */
		{
			const unsigned char *netbios;
			unsigned netbios_length;
			unsigned major, minor;
			const unsigned char *comment;
			unsigned comment_length;
			char winver[64];

			if (offset + 22 > length) {
				FRAMERR(frame, "MS-BROWSE: truncated\n");
				break;
			}
			offset += 6;

			netbios = px+offset;

			/* find nul terminator */
			for (netbios_length=0; offset+netbios_length<length && netbios_length<16 && netbios[netbios_length]; netbios_length++)
				;


			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("netbios",	 	netbios,					netbios_length),
				0);

			offset += 16;

			if (offset + 2 > length) {
				FRAMERR(frame, "MS-BROWSE: truncated\n");
				break;
			}

			major = px[offset];
			minor = px[offset+1];
			sprintf_s(winver, sizeof(winver), "Windows/%d.%d", major, minor);

			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_SZ("os",winver),
				0);

			offset += 10;


			comment = px+offset;
			for (comment_length=0; offset+comment_length<length && comment[comment_length]; comment_length++)
				;
			if (comment_length)
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("comment",	 	comment,					comment_length),
				0);

		}
		break;
	case 10: /* get backup list response */
		break;
	case 11: /*0x0b - Become Backup Brwoser */
		break;
	default:
		FRAMERR(frame, "MSBROWSE: unknown command %d\n", cmd);
	}
}
void process_LANMAN(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct SMBdgm *smb)
{
	unsigned cmd;

	UNUSEDPARM(smb);UNUSEDPARM(length);

	cmd = px[offset]; /*get_byte(frame, px, length, &offset);*/

	switch (cmd) {
	case 1: /*0x01 - Host Announcement */
		{
			const unsigned char *netbios;
			unsigned netbios_length;
			unsigned major, minor;
			const unsigned char *comment;
			unsigned comment_length;
			char winver[64];

			if (offset + 22 > length) {
				FRAMERR(frame, "MS-BROWSE: truncated\n");
				break;
			}
			offset += 6;

			/* Windows Version */
			major = px[offset];
			minor = px[offset+1];
			sprintf_s(winver, sizeof(winver), "Windows/%d.%d", major, minor);
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_SZ("os",winver),
				0);
			offset += 2;
			

			/* Update Periodicity */
			offset += 2;


			/* Hostname */
			netbios = px+offset;
			for (netbios_length=0; offset+netbios_length<length && netbios_length<16 && netbios[netbios_length]; netbios_length++)
				;
			if (netbios_length)
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("hostname", netbios, netbios_length),
				JOT_SZ("type", "LANMAN"),
				0);
			offset += netbios_length+1;

			/* comment */
			comment = px+offset;
			for (comment_length=0; offset+comment_length<length && comment[comment_length]; comment_length++)
				;
			if (comment_length)
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("comment",	 	comment,					comment_length),
				0);

		}
		break;
	default:
		FRAMERR(frame, "%s: unknown command %d\n", "LANMAN", cmd);
	}
}
void process_NETLOGON(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct SMBdgm *smb)
{
	unsigned cmd;

	UNUSEDPARM(smb);UNUSEDPARM(length);

	cmd = px[offset]; /*get_byte(frame, px, length, &offset);*/

	switch (cmd) {
	case 0x12: /*0x12 - Domain/Workgroup Announcement */
		{
			unsigned name_offset;
			unsigned name_length;

			offset += 4;

			/* Find the length of the machine name */
			name_offset = offset;
			while (offset+1 < length && !(px[offset]==0 && px[offset+1] == 0))
				offset++;
			name_length = offset-name_offset;

			/* TODO: the name is unicode, we need to convert it to UTF-8 */
			/* Record the name */
			if (name_length)
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("hostname", px+name_offset, name_length),
				JOT_SZ("proto", "NETLOGON"),
				0);

			/* Find the length of the machine name */
			name_offset = offset;
			while (offset+1 < length && !(px[offset]==0 && px[offset+1] == 0))
				offset++;
			name_length = offset-name_offset;

			/* TODO: the name is unicode, we need to convert it to UTF-8 */
			/* Record the name */
			if (name_length)
			JOTDOWN(ferret,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("username", px+name_offset, name_length),
				JOT_SZ("proto", "NETLOGON"),
				0);
		}
		break;
	default:
		FRAMERR(frame, "%s: unknown command %d\n", "NETLOGON", cmd);
	}
}

void process_smb_mailslot(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct SMBdgm *smb)
{
	unsigned offset_max;
	unsigned i;

	offset = smb->dgm.trans.setup_offset;

	if (smb->dgm.trans.setup_count != 3)
		FRAMERR(frame, "smb: corrupt\n");
	smb->mailslot.opcode = get_word(frame, px, length, &offset);
	smb->mailslot.priority = get_word(frame, px, length, &offset);
	smb->mailslot.clss = get_word(frame, px, length, &offset);

	smb->mailslot.name = px+smb->dgm.trans.extra_offset;
	for (i=0; i<length; i++)
		if (smb->mailslot.name[i] == '\0')
			break;
	smb->mailslot.name_length = i;

	switch (smb->mailslot.opcode) {
	case 1: /* write mail slot */
		offset = smb->dgm.trans.data_offset;
		offset_max = smb->dgm.trans.data_count;
		if (path_equals(smb->mailslot.name, smb->mailslot.name_length, "\\MAILSLOT\\BROWSE"))
			process_BROWSE(ferret, frame, px, MIN(length, offset+offset_max), offset, smb);
		else if (path_equals(smb->mailslot.name, smb->mailslot.name_length, "\\MAILSLOT\\LANMAN"))
			process_LANMAN(ferret, frame, px, MIN(length, offset+offset_max), offset, smb);
		else if (path_equals(smb->mailslot.name, smb->mailslot.name_length, "\\MAILSLOT\\NET\\NETLOGON"))
			process_NETLOGON(ferret, frame, px, MIN(length, offset+offset_max), offset, smb);
		else
			FRAMERR(frame, "smb: unknown mailslot=%.*s\n", smb->mailslot.name_length, smb->mailslot.name);
		break;
	default:
		FRAMERR(frame, "smb: corrupt\n");
	}

}

void process_smb_dgm_transaction(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct SMBdgm *smb)
{
	//unsigned reserved;

	smb->dgm.trans.word_count		= get_byte(frame, px, length, &offset);
	smb->dgm.trans.total_parm_count = get_word(frame, px, length, &offset);
	smb->dgm.trans.total_data_count = get_word(frame, px, length, &offset);
	smb->dgm.trans.max_parm_count	= get_word(frame, px, length, &offset);
	smb->dgm.trans.max_data_count	= get_word(frame, px, length, &offset);
	smb->dgm.trans.max_setup_count	= get_byte(frame, px, length, &offset);
	/*reserved						=*/  get_byte(frame, px, length, &offset);
	smb->dgm.trans.flags			= get_word(frame, px, length, &offset);
	smb->dgm.trans.timeout			= get_dword(frame, px, length, &offset);
	/* reserved						=*/ get_word(frame, px, length, &offset);
	smb->dgm.trans.parm_count		= get_word(frame, px, length, &offset);
	smb->dgm.trans.parm_offset		= get_word(frame, px, length, &offset);
	smb->dgm.trans.data_count		= get_word(frame, px, length, &offset);
	smb->dgm.trans.data_offset		= get_word(frame, px, length, &offset);
	smb->dgm.trans.setup_count		= get_byte(frame, px, length, &offset);
	/*reserved						=*/  get_byte(frame, px, length, &offset);
	smb->dgm.trans.setup_offset		= offset;
	offset += smb->dgm.trans.setup_count*2;
	smb->dgm.trans.byte_count		= get_word(frame, px, length, &offset);
	smb->dgm.trans.extra_offset			= offset;
	
	if (offset+10 < length && strnicmp((const char*)px+offset, "\\MAILSLOT\\", 10)==0)
		process_smb_mailslot(ferret, frame, px, length, offset, smb);
	else
		FRAMERR(frame, "smb: unknow transact command\n");

}

void process_smb_dgm(struct Ferret *ferret, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	struct SMBdgm smb;
	//unsigned reserved;

	if (length < 28) {
		FRAMERR(frame, "smb: truncated\n");
		return;
	}
	offset = 4;

	smb.command			= get_byte(frame, px, length, &offset);
	smb.err				= get_byte(frame, px, length, &offset);
	/*reserved			=*/ get_byte(frame, px, length, &offset);
	smb.errcode			= get_word(frame, px, length, &offset);
	smb.flags			= get_byte(frame, px, length, &offset);
	smb.flags2			= get_word(frame, px, length, &offset);
	smb.process_id_high = get_word(frame, px, length, &offset);
	memcpy(smb.signature, px+offset, 8);
	offset += 8;
	/*reserved			= */ get_word(frame, px, length, &offset);
	smb.tree_id			= get_word(frame, px, length, &offset);
	smb.process_id		= get_word(frame, px, length, &offset);
	smb.user_id			= get_word(frame, px, length, &offset);
	smb.multiplex_id	= get_word(frame, px, length, &offset);

	frame->layer7_protocol = LAYER7_SMB_DGM;

	switch (smb.command) {
	case 0x25: /* Transaction Request*/
		process_smb_dgm_transaction(ferret, frame, px, length, offset, &smb);
		break;
	default:
		FRAMERR(frame, "smb: unknow dgm command\n");
	}

}

