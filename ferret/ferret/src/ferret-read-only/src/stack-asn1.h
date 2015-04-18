/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __ASN1_H
#define __ASN1_H
#ifdef __cplusplus
extern "C" {
#endif


unsigned 
asn1_tag(const unsigned char *px, unsigned length, unsigned *r_offset);

#define asn1_enumerated asn1_integer
#define asn1_boolean asn1_integer

void
asn1_string(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset, const unsigned char **r_str, unsigned *r_str_length);

unsigned 
asn1_length(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset);


unsigned 
asn1_integer(struct NetFrame *frame, const unsigned char *px, unsigned length, unsigned *r_offset);



#ifdef __cplusplus
}
#endif
#endif /*__ASN1_H*/
