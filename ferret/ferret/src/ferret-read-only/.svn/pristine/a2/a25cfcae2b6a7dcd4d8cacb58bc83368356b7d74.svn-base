/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	BASE 64 encoding of binary data in text

  BASE64 is a way of encoding binary data within text. A lot of 
  protocols use BASE64. Some examples are:

  - HTTP authentication field
  - E-mail attachments
  - some HTTP cookies

*/

#include "util-base64.h"



size_t base64_decode(unsigned char *dst, size_t sizeof_dst, const unsigned char *src, size_t sizeof_src)
{
	static const unsigned char rstr[] = {
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,	62,		0xFF,   0xFF,   0xFF,	63,
		52,		53,		54,		55,		56,		57,		58,		59,		60,		61,		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0,		1,		2,		3,		4,		5,		6,		7,		8,		9,		10,		11,		12,		13,		14,
		15,		16,		17,		18,		19,		20,		21,		22,		23,		24,		25,		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,	26,		27,		28,		29,		30,		31,		32,		33,		34,		35,		36,		37,		38,		39,		40,
		41,		42,		43,		44,		45,		46,		47,		48,		49,		50,		51,		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
		0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,   0xFF,
	};
    size_t i = 0;
    size_t d = 0;


	while (i < sizeof_src) {
        unsigned b;
		unsigned c=0;

		/* byte#1 */
		while (i<sizeof_src && (c = rstr[src[i]]) > 64)
			i++;
		if (src[i] == '=' || i++ >= sizeof_src)
			break;
		b = (c << 2) & 0xfc;
	
		while (i<sizeof_src && (c = rstr[src[i]]) > 64)
			i++;
		if (src[i] == '=' || i++ >= sizeof_src)
			break;
		b |= (c>>4) & 0x03;
		if (d<sizeof_dst)
			dst[d++] = (unsigned char)b;
		if (i>=sizeof_src)
			break;

		/* byte#2 */
		b = (c<<4) & 0xF0;
		while (i<sizeof_src && src[i] != '=' && (c = rstr[src[i]]) > 64)
			;
		if (src[i] == '=' || i++ >= sizeof_src)
			break;
		b |= (c>>2) & 0x0F;
		if (d<sizeof_dst)
			dst[d++] = (unsigned char)b;
		if (i>=sizeof_src)
			break;

		/* byte#3*/
		b = (c<<6) & 0xC0;
		while (i<sizeof_src && src[i] != '=' && (c = rstr[src[i]]) > 64)
			;
		if (src[i] == '=' || i++ >= sizeof_src)
			break;
		b |= c;
		if (d<sizeof_dst)
			dst[d++] = (unsigned char)b;
		if (i>=sizeof_src)
			break;
	}

	if (d<sizeof_dst)
		dst[d] = '\0';
	return d;
}

/****************************************************************************

  MODULETEST

  This code is designed to regression test this module. It is only included
  when this file is compiled as a standalone program.

 ****************************************************************************/
#ifdef MODULETEST
#include <ctype.h>
#include <stdlib.h>

const char testcase1[] = 
"Z2JyO2VuZztsb25kb247YnJvYWRiYW5kOzU7NTs0Oy0xOzA1MS41MDA7LTAwMC4xMTc7ODI2OzEwMTk4OzQ3ODI7NTsK\0"
"gbr;eng;london;broadband;5;5;4;-1;051.500;-000.117;826;10198;4782;5;\0"
"\0"
"Z2JyO2VuZztsb25kb247YnJvYWRiYW5kOzU7NTs1Oy0xOzA1MS41MDA7LTAwMC4xMTc7ODI2OzEwMTk4OzQ3ODI7NTsK\0"
"dXNhO21kO2NvbGxlZ2UgcGFyazt0MTs1OzQ7NDs1MTE7MDM4Ljk5NzstMDc2LjkyODs4NDA7MjE7MTU7NjsK\0"
"dXNhO29yO2JlYXZlcnRvbjticm9hZGJhbmQ7NTszOzM7ODIwOzA0NS40OTE7LTEyMi44MDU7ODQwOzM4OzYyOzY7Cg==\0"
"dXNhO2dhO2F0bGFudGE7YnJvYWRiYW5kOzU7NTs1OzUyNDswMzMuNzQ5Oy0wODQuMzg4Ozg0MDsxMTszOzY7Cg==\0"
"dXNhO3R4O2RhbGxhczticm9hZGJhbmQ7NTs0OzQ7NjIzOzAzMi43ODc7LTA5Ni43OTk7ODQwOzQ0Ozc3OzY7Cg==\0"
"dXNhO3R4O2RhbGxhczticm9hZGJhbmQ7NTs0OzQ7NjIzOzAzMi43ODc7LTA5Ni43OTk7ODQwOzQ0Ozc3OzY7Cg==\0"
"dXNhO3R4O2RhbGxhczticm9hZGJhbmQ7NTs0OzM7NjIzOzAzMi43ODc7LTA5Ni43OTk7ODQwOzQ0Ozc3OzY7Cg==\0"
"\0";

static void 
run_test(const char *test)
{
	unsigned i;
	char result[1000];
	unsigned result_length;

	for (i=0; test[i]; ) {
		unsigned j;
		unsigned length = 0;

		while (test[i+length])
			length++;

		result_length = base64_decode(result, result_length, test+i, length);

		i+=length+1;
		if (test[i] == '\0')
			break;

		for (j=0; j<result_length+1; j++) {
			if (result[j] != test[i+j]) {
				printf("test failure\n");
				return;

			}
		}

		i += j;
		printf("%s\n", result);

		if (test[i] == '\0')
			break;

	}
}


void main(int argc, char *argv[1])
{
	unsigned i;

	printf("-- MODULE TEST START: %s\n", "stringtab.c");
	run_test(testcase1);

	srand(0);
	for (i=0; i<100000; i++) {
		char buf[16000];
		unsigned j;

		for (j=0; j<sizeof(buf); j++) {
			buf[j] = "ABCDEFG "[rand()&0x7];
		}
		buf[sizeof(buf)-1] = '\0';

		printf("%.*s", 70, buf);
		run_test(buf);
	}
	printf("-- MODULE TEST END: %s\n\n", "stringtab.c");
}

#endif /* MODULETEST */
