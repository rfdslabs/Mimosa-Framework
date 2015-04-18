/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*

	JOT DOWN

  This is the module where we "jot down" or "take note of" or "record"
  all the bits of information that we find on the network.

  When a protocol-parser finds something interesting, it fills in a 
  "vector" of information. This "vector" is a list of all the bits
  related to the essential piece that we found.

  That vector is first formatted into a string form. The biggest 
  code here is this formatting. As we add protocol parsers, we find
  new ways that we want to format data.

  We then test that vector for uniqueness. If it's a copy of an existing
  vector, we drop it. If it's a new vector, then we output it.

  The output of the vectors is just to the command-line.

  [code review]
	If you are looking for vulnerabilities in this module, you likely
	find them in the string formatting function. That's were we do
	the most buffer copies, and we are constantly adding more as we
	find more interesting ways of formatting data.

	The reason this is dangerous is because the protocol-parsers themselves
	generally don't format strings. For example, the SNMP OIDs are formatted
	here rather than SNMP. Thus, we've taken the dangerous bits from all 
	over the code and concentrated them into one highly dangerous function.
	
	Also, look at the output from this function. You might find a way
	to output data that compromises a Unix terminal using special codes,
	or a database using SQL injection. In theory, the formatting code
	will cleanse the output of offensive characters, but you can never
	be certain.
*/
#include "ferret.h"
#include "out-jotdown.h"
#include "stack-netframe.h"
#include "stack-extract.h"
#include "util-hamster.h"
#include "platform.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>



/**
 * A stupid way to calculate the number of digits in an Integer
 * because I'm too lazy to think of a more elegant way.
 */
static unsigned count_digits(uint64_t n)
{
	unsigned i=0;
	for (i=0; n; i++)
		n = n/10;
	return i;
}


/**
 * This function formats an unsigned number, possibly 64-bits in length.
 */
static void 
format_unsigned(char *buf, unsigned length, size_t *r_offset, uint64_t num)
{
	unsigned digits = count_digits(num);
	size_t new_offset;

	if (*r_offset >= length)
		return;
	if (*r_offset + 1 >= length) {
		buf[(*r_offset)++] = '\0';
		return;
	}

	if (digits == 0) {
		buf[(*r_offset)++] = '0';
		buf[(*r_offset)] = '\0';
	} else {
		if (*r_offset + digits >= length) {
			memset(buf+*r_offset, '0', length-*r_offset);
			buf[length-1] = '\0';
			*r_offset = length;
			return;
		}

		buf[*r_offset+digits] = '\0';
		new_offset = *r_offset + digits;

		while (num) {
			buf[*r_offset + --digits] = (num%10)["01234567890"];
			num = num / 10;
		}
		
		*r_offset = new_offset;
	}
}

/**
 * TODO: implement this function so that we can 'sift' traffic.
 */
void process_sample(struct Ferret *ferret, ...)
{
	UNUSEDPARM(ferret);
}

void append_hexdigit(char *valbuf, size_t sizeof_valbuf, size_t *r_vallen, unsigned n)
{
	if (n && *r_vallen + 1 < sizeof_valbuf)
		valbuf[(*r_vallen)++] = "0123456789ABCDEF"[n];
}

/**
 * Formats in traditional IPv6 format, something like [FFFF:FFFF:FFFF:FFFF]
 */
void format_ipv6(char *valbuf, size_t sizeof_valbuf, size_t *r_vallen, const unsigned char *value)
{
	unsigned i;
	unsigned nulls=0;
	size_t vallen = *r_vallen;

	valbuf[vallen++] = '[';
	
	/* Loop through all 8 bytes, formatting each one */
	for (i=0; i<8; i++) {
		const unsigned n = ex16be(value+i*2);

		if (n == 0) {
			if (nulls == 0) {
				if (vallen+2<sizeof(valbuf))
					valbuf[vallen++] = ':';
				nulls = 1;
			} else if (nulls == 1)
				;
			else if (vallen + 7 < sizeof_valbuf) {
				valbuf[vallen++] = ':';
				append_hexdigit(valbuf, sizeof_valbuf, &vallen, (n>>12)&0xF);
				append_hexdigit(valbuf, sizeof_valbuf, &vallen, (n>> 8)&0xF);
				append_hexdigit(valbuf, sizeof_valbuf, &vallen, (n>> 4)&0xF);
				append_hexdigit(valbuf, sizeof_valbuf, &vallen, (n>> 0)&0xF);
			}
		} else {
			if (nulls == 1)
				nulls = 2;
			if (i != 0)
				valbuf[vallen++] = ':';
			append_hexdigit(valbuf, sizeof_valbuf, &vallen, (n>>12)&0xF);
			append_hexdigit(valbuf, sizeof_valbuf, &vallen, (n>> 8)&0xF);
			append_hexdigit(valbuf, sizeof_valbuf, &vallen, (n>> 4)&0xF);
			append_hexdigit(valbuf, sizeof_valbuf, &vallen, (n>> 0)&0xF);
		}
	}
	valbuf[vallen++] = ']';
	valbuf[vallen] = '\0';
	*r_vallen = vallen;
}

/**
 * Format a "printable" string. The characters are assumed to be printable 
 * ones. Binary-characters are converted to hex representation.
 */
static void 
format_printable(char *valbuf, size_t sizeof_valbuf, size_t *r_vallen, const void *v_value, size_t length)
{
	const unsigned char *value = (const unsigned char *)v_value;
	size_t i;
	size_t vallen = *r_vallen;


	if (value == 0)
		value = (const unsigned char*)"";


	if (vallen < sizeof_valbuf)
		valbuf[vallen++] = '\"';

	for (i=0; vallen+6<sizeof_valbuf && i<length; i++) {
		if (isprint(value[i]) && value[i] != '\"' && value[i] != '\\') {
			valbuf[vallen++] = (char)value[i];
		} else {
			valbuf[vallen++] = '\\';
			valbuf[vallen++] = 'x';
			valbuf[vallen++] = "0123456789ABCDEF"[(value[i]>>4)&0x0F];
			valbuf[vallen++] = "0123456789ABCDEF"[(value[i]>>0)&0x0F];
		}
	}
	if (vallen < sizeof_valbuf-1) {
		valbuf[vallen++] = '\"';
		valbuf[vallen] = '\0';
	}
	valbuf[sizeof_valbuf-1] = '\0';
	*r_vallen = vallen;
}

static void 
format_url_recoded(char *valbuf, size_t sizeof_valbuf, size_t *r_vallen, const void *v_value, size_t length)
{
	const unsigned char *value = (const unsigned char *)v_value;
	size_t i;
	size_t vallen = *r_vallen;


	if (value == 0)
		value = (const unsigned char*)"";


	if (vallen < sizeof_valbuf)
		valbuf[vallen++] = '\"';

	for (i=0; vallen+6<sizeof_valbuf && i<length; i++) {
		unsigned char c = value[i];

		if (c == '%') {
			if (i<length && isdigit(value[i+1]))
				c = (unsigned char)((value[++i]-'0')<<4);
			if (i<length && isdigit(value[i+1]))
				c |= (unsigned char)((value[++i]-'0'));
		}

		if (isprint(c) && c != '\"' && c != '\\' && c != '%' && c != '=' && c != '&') {
			valbuf[vallen++] = (char)c;
		} else {
			valbuf[vallen++] = '%';
			valbuf[vallen++] = "0123456789ABCDEF"[(c>>4)&0x0F];
			valbuf[vallen++] = "0123456789ABCDEF"[(c>>0)&0x0F];
		}
	}
	if (vallen < sizeof_valbuf-1) {
		valbuf[vallen++] = '\"';
		valbuf[vallen] = '\0';
	}
	valbuf[sizeof_valbuf-1] = '\0';
	*r_vallen = vallen;
}


struct Jotdown *
jotdown_create()
{
	struct Jotdown *jot;

	jot = (struct Jotdown *)malloc(sizeof(*jot));
	memset(jot, 0, sizeof(*jot));

	return jot;
}

/*
static void 
jot_destroy_names(struct SeapName *name);

static void 
jot_destroy_values(struct SeapValue *value)
{
	while (value) {
		struct SeapValue *next_value = value->next;

		if (value->length)
			free(value->value);

		jot_destroy_names(value->names);

		free(value);

		value = next_value;
	}

}
static void 
jot_destroy_names(struct SeapName *name)
{
	while (name) {
		struct SeapName *next_name = name->next;

		jot_destroy_values(name->values);

		free(name);
		name = next_name;
	}

}
*/

/*ID-IP=[10.1.5.8]*/
struct BinChild *
bintree_lookup(struct BinChild *binchild, const char *data, unsigned data_length)
{
	struct BinTree *bt;
	unsigned min, max, mid;

	/* Must point to structure */
	if (binchild == NULL)
		return 0;

	/* See if this is a new entry */
	if (binchild->next == NULL) {
		return 0;
	}

	bt = binchild->next;

	min = 0;
	max = bt->m_count;

	while (min<max) {
		int c;
		unsigned len;
		
		mid = (min+max)/2;

		len = data_length;
		if (len > bt->m_list[mid].m_data_length)
			len = bt->m_list[mid].m_data_length;

		c = memcmp(bt->m_list[mid].m_data, data, len);
		if (c == 0 && data_length == bt->m_list[mid].m_data_length)
			return &bt->m_list[mid];

		if (c > 0 || (c == 0 && len < data_length)) {
			max = mid;
		} else
			min = mid+1;
	}

	return 0;
}


struct BinChild *
bintree_insert(struct BinChild *binchild, const char *data, unsigned data_length, unsigned *r_new)
{
	struct BinTree *bt;
	unsigned min, max, mid;

	/* Must point to structure */
	if (binchild == NULL)
		return 0;

	/* See if this is a new entry */
	if (binchild->next == NULL) {
		binchild->next = (struct BinTree *)malloc(sizeof(struct BinTree));
		bt = binchild->next;
		bt->m_count = 1;
		bt->m_max = 1;
		bt->m_list = (struct BinChild*)malloc(sizeof(bt->m_list[0]));
		bt->m_list[0].m_data = (char*)malloc(data_length+1);
		memcpy(bt->m_list[0].m_data, data, data_length);
		bt->m_list[0].m_data[data_length] = '\0'; /* NUL terminate for debugging */
		bt->m_list[0].m_data_length = data_length;
		bt->m_list[0].next = NULL;
		*r_new = 1;
		return &bt->m_list[0];
	}

	bt = binchild->next;

	min = 0;
	max = bt->m_count;

	while (min<max) {
		int c;
		unsigned len;
		
		mid = (min+max)/2;

		len = data_length;
		if (len > bt->m_list[mid].m_data_length)
			len = bt->m_list[mid].m_data_length;

		c = memcmp(bt->m_list[mid].m_data, data, len);
		if (c == 0 && data_length == bt->m_list[mid].m_data_length)
			return &bt->m_list[mid];

		if (c > 0 || (c == 0 && len < data_length)) {
			max = mid;
		} else
			min = mid+1;
	}

	/* Insert a new record where "min" points to */
	mid = min;
	if (bt->m_count+1 >= bt->m_max) {
		unsigned new_max = bt->m_max*2+1;
		struct BinChild *new_list = (struct BinChild*)malloc(sizeof(new_list[0])*new_max);
		memcpy(new_list, bt->m_list, sizeof(new_list[0])*bt->m_count);

		free(bt->m_list);
		bt->m_list = new_list;
		bt->m_max = new_max;
	}

	/* Move everything over to the right at this position */
	if (mid < bt->m_count)
		memmove(&bt->m_list[mid+1], &bt->m_list[mid], (bt->m_count-mid)*sizeof(bt->m_list[0]));

	/* Create the new entry at this postion */
	bt->m_list[mid].m_data = (char*)malloc(data_length+1);
	memcpy(bt->m_list[mid].m_data, data, data_length);
	bt->m_list[mid].m_data[data_length] = '\0';
	bt->m_list[mid].m_data_length = data_length;
	bt->m_list[mid].next = 0;
	*r_new = 1;
	bt->m_count++;
	return &bt->m_list[mid];
}

void bintree_print(struct BinChild *bc, unsigned depth)
{
	unsigned i;
	unsigned d;
	struct BinTree *bt;

	if (bc == NULL)
		return;

	bt = bc->next;
	if (bt == NULL)
		return;

	for (i=0; i<bt->m_count; i++) {
		for (d=0; d<depth; d++)
			printf("  ");
		printf("%.*s\n", bt->m_list[i].m_data_length, bt->m_list[i].m_data);
		bintree_print(&bt->m_list[i], depth+1);
	}	
}

void bintree_destroy(struct BinChild *bc)
{
	unsigned i;
	struct BinTree **bt;

	if (bc == NULL)
		return;
	if (bc->m_data != NULL) {
		free(bc->m_data);
		bc->m_data = 0;
		bc->m_data_length = 0;
	}

	bt = &bc->next;

	if (*bt == NULL)
		return;

	for (i=0; i<(*bt)->m_count; i++) {
		bintree_destroy(&((*bt)->m_list[i]));
	}

	free((*bt)->m_list);
	free(*bt);

	*bt = NULL;
}

void 
jotdown_destroy(struct Jotdown *jot)
{
	//jot_destroy_names(jot->records);
	bintree_destroy(&jot->records);
	free(jot);
}

static unsigned
is_user_id(const char *name)
{
	static const char *user_ids[] = {
		"username", "MSN-usernmae", "POP3-user", "computername",
		"e-mail", "AIM-Screen-Name", "hostname", "passport",
			0};
	unsigned i;

	for (i=0; user_ids[i]; i++) {
		if (stricmp(name, user_ids[i]) == 0)
			return 1;
	}
	return 0;
}

extern void hamster_icon(const void *vid_ip, unsigned id_ip_length,
					const void *vuserid, unsigned userid_length
					);

void hamster_sift(unsigned record_count, struct BinChild **bc_vector)
{
	unsigned i;
	char *id_ip="";
	unsigned id_ip_length=0;

	for (i=0; i<record_count; i++) {
		char *name = bc_vector[i*2+0]->m_data;
		/*unsigned name_length = bc_vector[i*2+0]->m_data_length;*/
		char *value = bc_vector[i*2+1]->m_data;
		unsigned value_length = bc_vector[i*2+1]->m_data_length;

		if (stricmp(name, "ID-IP") == 0) {
			id_ip = value;
			id_ip_length = value_length;
			continue;
		}
		if (is_user_id(name)) {
			if (id_ip_length == 0)
				return;
			hamster_userid(id_ip, id_ip_length, value, value_length);
		}

		if (strcmp(name, "icon") == 0 && id_ip_length)  {
			hamster_icon(id_ip, id_ip_length, value, value_length);
		}
	}

}

void print_ip_id(struct Ferret *ferret, unsigned ip)
{
	char buf[16+4];
	unsigned buflen;
	struct BinChild *bc;
	struct BinTree *bt;
	unsigned is_new_entry = 0;
	unsigned i;

	/*
	 * Format a pseudo entry
	 */
	sprintf_s(buf, sizeof(buf), "[%d.%d.%d.%d]",
		(ip>>24)&0xFF,
		(ip>>16)&0xFF,
		(ip>> 8)&0xFF,
		(ip>> 0)&0xFF
		);
	buflen = (unsigned)strlen(buf);

	bc = &ferret->jot->records;

	bc = bintree_insert(bc, "ID-IP", 5, &is_new_entry);
	bc = bintree_insert(bc, buf, buflen, &is_new_entry);

	bt = bc->next;
	for (i=0; bt && i<bt->m_count; i++) {
		struct BinChild *bc2 = &bt->m_list[i];
		struct BinTree *bt2 = bc2->next;
		unsigned j;

		for (j=0; j<bt2->m_count; j++) {
			struct BinChild *bc3 = &bt2->m_list[j];
			
			printf("%.*s=%.*s ", bc2->m_data_length, bc2->m_data,
								bc3->m_data_length, bc3->m_data);
		}
	}
}

/**
 * This is the primay function that records a piece of 
 * information found by Ferret.
 */
static void vJOTDOWN(struct Ferret *ferret, va_list marker)
{
	enum {MAX_RECORDS=100};
	int record_count;
	unsigned is_new_entry = 0;
	struct BinChild *bc;
	struct BinChild *bc_vector[MAX_RECORDS*2];

	if (ferret->jot == NULL)
		return;

	if (ferret->cfg.quiet)
		return;

	bc = &ferret->jot->records;

	for (record_count=0; record_count<MAX_RECORDS; record_count++) {
		const char *name;
		const unsigned char *value;
		int fmt;
		unsigned length;
		char valbuf[1024];
		size_t vallen=0;
		
		name = va_arg(marker, char *);
		if (name == 0 /*kludge*/ || ((unsigned)(size_t)name) == 0)
			break;

		fmt = va_arg(marker, int);
		
		value = va_arg(marker, unsigned char *);
		length = va_arg(marker, unsigned);


		/*
		 * If doing frame addresses, extract the appropariate address
		 */
		if (fmt==REC_FRAMESRC || fmt==REC_FRAMEDST) {
			struct NetFrame *frame = (struct NetFrame *)value;

			/* TEMP: this should be removed if you are reading this */
			if (frame == NULL)
				return;

			switch (frame->ipver) {
			case ADDRESS_IP_v6:
				length = 16;
				if (fmt == REC_FRAMESRC)
					value = &frame->src_ipv6[0];
				else
					value = &frame->dst_ipv6[0];
				fmt = REC_IPv6;
				break;
			case ADDRESS_IP_v4:
				length = 4;
				if (fmt == REC_FRAMESRC)
					value = (const unsigned char*)&frame->src_ipv4;
				else
					value = (const unsigned char*)&frame->dst_ipv4;
				fmt = REC_IPv4;
				break;
			case ADDRESS_ATALK_EDDP:
				length = 4;
				if (fmt == REC_FRAMESRC)
					value = (const unsigned char*)&frame->src_ipv4;
				else
					value = (const unsigned char*)&frame->dst_ipv4;
				fmt = REC_ATALKADDR;
				break;
			case ADDRESS_IPX:
				length = 10;
				if (fmt == REC_FRAMESRC)
					value = &frame->src_ipv6[0];
				else
					value = &frame->dst_ipv6[0];
				fmt = REC_IPXADDR;
				break;
			default:
				FRAMERR(frame, "unknown\n");
				return;
			}
		}

		switch (fmt) {
		case REC_SZ:			/* zero-terminated string, length should be -1 */
			vallen=0;
			format_printable(valbuf, sizeof(valbuf), &vallen, value, strlen((const char*)value));
			break;
		case REC_PRINTABLE:	/* printable string, length should be length of the string */
			vallen=0;
			format_printable(valbuf, sizeof(valbuf), &vallen, value, length);
			break;
		case REC_URLENCODE:
			vallen=0;
			format_url_recoded(valbuf, sizeof(valbuf), &vallen, value, length);
			break;
		case REC_STRING_T:	/* printable string, length should be length of the string */
			vallen=0;
			if (value == NULL)
				format_printable(valbuf, sizeof(valbuf), &vallen, "", 0);
			else {
				struct StringT *t = (struct StringT *)value;
				format_printable(valbuf, sizeof(valbuf), &vallen, t->str, t->length);
			}
			break;
		case REC_HEXSTRING:	/* printable string, length should be length of the string */
			{
				unsigned i;

				if (value == 0)
					value = (const unsigned char*)"";
				vallen=0;
				valbuf[vallen++] = '$';

				for (i=0; vallen<sizeof(valbuf)-6 && i<length; i++) {
					valbuf[vallen++] = "0123456789ABCDEF"[(value[i]>>4)&0x0F];
					valbuf[vallen++] = "0123456789ABCDEF"[(value[i]>>0)&0x0F];
				}
				valbuf[vallen] = '\0';
			}
			break;
		case REC_OID: /* asn.1 object identifer */
			{
				unsigned i=0;

				vallen = 0;
				while (vallen < sizeof(valbuf)-2 && i<length) {
					uint64_t id=0;

					/* Grab the next id */
					while (i<length && value[i]&0x80) {
						id |= value[i]&0x7F;
						id <<= 7;
						i++;
					}
					id |= value[i++];

					/* Format the integer */
					if (vallen == 0) {
						format_unsigned(valbuf, sizeof(valbuf), &vallen, id/40);
						valbuf[vallen++] = '.';
						format_unsigned(valbuf, sizeof(valbuf), &vallen, id%40);
					} else {
						valbuf[vallen++] = '.';
						format_unsigned(valbuf, sizeof(valbuf), &vallen, id);
					}
				}
			}
			break;
		case REC_MACADDR:	/* MAC address, length should be 6 */
			if (value == NULL)
				sprintf_s(valbuf, sizeof(valbuf), "(null)");
			else
			sprintf_s(valbuf, sizeof(valbuf), "[%02x:%02x:%02x:%02x:%02x:%02x]",
				value[0],
				value[1],
				value[2],
				value[3],
				value[4],
				value[5]
				);
			vallen = strlen(valbuf);
			break;
		case REC_IPv4:
			if (length == sizeof(unsigned)) {
				unsigned ip = *(unsigned*)value;
				sprintf_s(valbuf, sizeof(valbuf), "[%d.%d.%d.%d]",
					(ip>>24)&0xFF,
					(ip>>16)&0xFF,
					(ip>> 8)&0xFF,
					(ip>> 0)&0xFF
					);
				vallen = strlen(valbuf);
			} else {
				fprintf(stderr, "unknown integer size");
				break;
			}
			break;
		case REC_IPXADDR:
			if (length == 10) {
				sprintf_s(valbuf, sizeof(valbuf), "[0x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x]",
					value[0], value[1], value[2], value[3], 
					value[4], value[5], value[6], value[7], value[8], value[9] ); 
				vallen = strlen(valbuf);
			} else {
				fprintf(stderr, "unknown integer size");
				break;
			}
			break;
		case REC_ATALKADDR:
			if (length == sizeof(unsigned)) {
				unsigned ip = *(unsigned*)value;
				sprintf_s(valbuf, sizeof(valbuf), "[@%d.%d]",
					(ip>>8)&0xFFFF,
					(ip>>0)&0xFF
					);
				vallen = strlen(valbuf);
			} else {
				fprintf(stderr, "unknown integer size");
				break;
			}
			break;
		case REC_IPv6:
			assert(length==16);
			format_ipv6(valbuf, sizeof(valbuf), &vallen, value);
			break;
		case REC_UNSIGNED:
			if (length == sizeof(unsigned)) {
				sprintf_s(valbuf, sizeof(valbuf), "%u", *(unsigned*)value);
				vallen = strlen(valbuf);
			} else {
				fprintf(stderr, "unknown integer size");
				break;
			}
			break;
		case REC_HEX24:
			if (length == sizeof(unsigned)) {
				sprintf_s(valbuf, sizeof(valbuf), "0x%03x", *(unsigned*)value);
				vallen = strlen(valbuf);
			} else {
				fprintf(stderr, "unknown integer size");
				break;
			}
			break;
		default:
			fprintf(stderr, "unknown record type=%u, count=%u type=0x%llx\n", fmt, record_count,
				(long long unsigned)fmt
				/*name, fmt, value, length*/);
			printf("name = [0x%llx]\n", (unsigned long long)(size_t)name);
			printf("name = %s\n", name);
			break;
		}
		

		/* Insert record into list */
		bc = bintree_insert(bc, (const char*)name, (unsigned)strlen(name), &is_new_entry);
		bc_vector[record_count*2 + 0] = bc;
		bc = bintree_insert(bc, (const char *)valbuf, (unsigned)vallen, &is_new_entry);
		bc_vector[record_count*2 + 1] = bc;
	}

	if (is_new_entry) {
		int i;

		/* Indicate that something new was found in the frame. This is 
		 * useful for the 'sift' feature, that saves all those packets
		 * that have something new in them */
		ferret->something_new_found = 1;

		/* Print the vector to the command-line */
		if (!ferret->cfg.no_vectors) {
			for (i=0; i<record_count; i++) {
				if (i>0)
					printf(", ");
				printf("%s=%.*s", bc_vector[i*2+0]->m_data, bc_vector[i*2+1]->m_data_length, bc_vector[i*2+1]->m_data);
				
			}
			printf("\n");
		}

		if (!ferret->cfg.no_hamster)
			hamster_sift(record_count, bc_vector);
	}

}


/**
 * This is the primary function called by protocol parsers as they discover
 * interesting information.
 */
void JOTDOWN(struct Ferret *ferret, ...)
{
	va_list marker;

	va_start(marker, ferret);
	vJOTDOWN(ferret, marker);
	va_end(marker);

}

