/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __JOTDOWN_H
#define __JOTDOWN_H
#ifdef __cplusplus
extern "C" {
#endif

enum RECORD_FORMAT {
	REC_END,
	REC_SZ,			/* zero-terminated string, length should be -1 */
	REC_PRINTABLE,	/* printable string, length should be length of the string */
	REC_STRING_T,
	REC_MACADDR,	/* MAC address, length should be 6 */
	REC_UNSIGNED,
	REC_HEX24,
	REC_IPv4,		/* IP address in decimal-dot notation, such as [192.168.10.3] */
	REC_IPv6,
	REC_ATALKADDR,	/* AppleTalk DDP address */
	REC_IPXADDR,	/* Novel IPX address, which is a 4-byte network followed by 6-byte host */
	REC_FRAMESRC,
	REC_FRAMEDST,
	REC_OID,		/* ASN.1 OBJECT IDENTIFIER */
	REC_HEXSTRING,
	REC_URLENCODE
};

#define JOT_NUM(name,val) name,REC_UNSIGNED,&val,(unsigned)sizeof(val)
#define JOT_SZ(name,val) name,REC_SZ,val,(unsigned)-1
#define JOT_SRC(name,val) name,REC_FRAMESRC,val,(unsigned)-1
#define JOT_DST(name,val) name,REC_FRAMEDST,val,(unsigned)-1
#define JOT_PRINT(name,val,val_len) name,REC_PRINTABLE,val,(unsigned)(val_len)
#define JOT_PRINTT(name,val) name,REC_STRING_T,val,(unsigned)-1
#define JOT_HEXSTR(name,val,val_len) name,REC_HEXSTRING,val,(unsigned)(val_len)
#define JOT_OID(name,val,val_len) name,REC_OID,val,(unsigned)(val_len)
#define JOT_IPv4(name,val) name,REC_IPv4,&val,((unsigned)(sizeof(val)))
#define JOT_IPv6(name,val,val_len) name,REC_IPv6,val,(unsigned)(val_len)
#define JOT_MACADDR(name,val) name,REC_MACADDR,val,(unsigned)6
#define JOT_HEX24(name,val) name,REC_HEX24,&val,(unsigned)sizeof(val)
#define JOT_URLENC(name,val,val_len) name,REC_URLENCODE,val,(unsigned)(val_len)


//#define SAMPLE process_sample (proto,name,type,data,sizes) process_sample(ferret, name, valname,type,data,sizes)
#define SAMPLE process_sample
void jtree_dump(struct Ferret *ferret, const char *capfilename);

void JOTDOWN(struct Ferret *ferret, ...);
void process_sample(struct Ferret *ferret, ...);

/*
struct SeapName
{
	char *name;
	struct SeapValue *values;
	struct SeapName *next;
};

struct SeapValue
{
	char *value;
	size_t length;

	struct SeapName *names;
	struct SeapValue *next;
};
*/

struct BinTree;

struct BinChild
{
	char *m_data;
	unsigned m_data_length;
	struct BinTree *next;
};
struct BinTree
{
	struct BinChild *m_list;
	unsigned m_count;
	unsigned m_max;
};

struct Jotdown {
	//struct SeapName *records;
	struct BinChild records;
};

struct Jotdown *jotdown_create();
void jotdown_destroy(struct Jotdown *jot);

#ifdef __cplusplus
}
#endif
#endif /*__JOTDOWN_H*/
