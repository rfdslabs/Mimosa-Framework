/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __TCPFRAG_H
#define __TCPFRAG_H
#ifdef __cplusplus
extern "C" {
#endif


struct TCP_segment {
	unsigned seqno;
	unsigned offset;
	unsigned length;
	struct TCP_segment *next;
	unsigned char *px;
};


unsigned SEQ_FIRST_BEFORE_SECOND(unsigned seqno1, unsigned seqno2);
unsigned SEQ_FIRST_GTE_SECOND(unsigned seqno1, unsigned seqno2);

void
tcpfrag_add(struct TCP_segment **r_frag, const unsigned char *px, unsigned length, unsigned seqno);

void tcpfrag_delete(struct TCP_segment **r_frag);
void tcpfrag_delete_all(struct TCP_segment **r_frag);

/** Returns the maximum contiguous seqno */
unsigned tcpfrag_max_contiguous(struct TCP_segment *frag, unsigned seqno);



#ifdef __cplusplus
}
#endif
#endif /*__TCPFRAG_H*/
