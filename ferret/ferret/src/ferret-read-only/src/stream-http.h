/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __HTTP_H
#define __HTTP_H
#ifdef __cplusplus
extern "C" {
#endif



unsigned match_name(const char *name, const unsigned char *data, unsigned data_length);
unsigned match_name_t(const char *name, const struct StringT *value);
unsigned ends_with_t(const char *suffix, const struct StringT *host);
void copy_until_space(unsigned char *method, size_t sizeof_method, unsigned *r_method_length, const unsigned char *px, unsigned length, unsigned *r_offset);
void copy_until_colon(unsigned char *name, size_t sizeof_name, unsigned *r_name_length, const unsigned char *px, unsigned length, unsigned *r_offset);

struct VALUEPARSELIST {
	const char *name;
	HTTPVALUEPARSE parser;
};

HTTPVALUEPARSE lookup_value_parser(struct VALUEPARSELIST *parsers, const unsigned char *name, unsigned name_length, HTTPVALUEPARSE default_parser);


#ifdef __cplusplus
}
#endif
#endif /*__HTTP_H*/
