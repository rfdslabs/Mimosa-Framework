/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	STRING TABLE

  This module implements a "table of strings". As we parse packets,
  we find that we want to keep track of strings for a period of time.
  This module is used to make that easier.

  TODO: This module is currently broken. It relies upon the 'engine' 
  object to regularly release the resources, but we arenn't doing that
  yet (2007-03-29).


*/
#include "util-stringtab.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int stringtab_compare(struct StringT *t, const unsigned char *str, unsigned length)
{
	unsigned i;

	for (i=0; i<t->length && i<length; i++) {
		if (t->str[i] < str[i])
			return -1;
		if (t->str[i] > str[i])
			return 1;
	}

	if (t->length == length)
		return 0;
	if (t->length < length)
		return -1;
	return 1;
}

/**
 * Get a pointer to a stored copy of a string, or if not found,
 * then create an entry in the table, and return that entry. */
struct StringT *
stringtab_lookup(struct StringTable *stringtab, const unsigned char *str, unsigned length)
{
	/* We store the strings in a binary-lookup table */
	unsigned min = 0;
	unsigned max = stringtab->count;
	unsigned half = (min+max)/2;
	struct StringT *t;

	if (str == NULL)
		str = (const unsigned char*)"";

	/* Lookup the entry */
	while (min<max)
	{
		int c;
		
		half = (min+max)/2;
		
		c = stringtab_compare(stringtab->strings[half], str, length);

		if (c == 0)
			return stringtab->strings[half];
		if (c == -1)
			min = half+1;
		if (c == 1)
			max = half;
	}

	half = (min+max)/2;

	/* Add a new string entry */
	if (stringtab->count+1 >= stringtab->max) {
		struct StringT **newstr;
		
		/* Roughly double the size of the table */
		stringtab->max = stringtab->max*2 + 1;
		
		/* Create the bigger table */
		newstr = (struct StringT**)malloc(sizeof(*newstr)*stringtab->max);
		memset(newstr, 0, sizeof(*newstr)*stringtab->max);
		
		/* Copy the old to the new */
		if (stringtab->count)
			memcpy(newstr, stringtab->strings, sizeof(*newstr)*stringtab->count);
		if (stringtab->strings)
			free(stringtab->strings);
		stringtab->strings = newstr;
	}

	/* Create a new entry */
	t = (struct StringT*)malloc(sizeof(*t) + length + 1);
	t->length = length;
	t->str = ((unsigned char*)t)+sizeof(*t);
	memcpy((char*)t->str, str, length);
	((char*)(t->str))[t->length] = '\0';


	/* Make space at this place in the table */
	memmove(stringtab->strings+half+1, stringtab->strings+half, sizeof(*stringtab->strings)*(stringtab->count-half));
	stringtab->count++;

	/* Insert at this location */
	stringtab->strings[half] = t;

	return t;
}

/**
 * Clear the entries in the string table. Only call this when you have 
 * cleared all the instance data that refers to these strings */
void stringtab_clear(struct StringTable *stringtab)
{
	unsigned i;

	for (i=0; i<stringtab->count; i++)
		free(stringtab->strings[i]);

	if (stringtab->strings)
		free(stringtab->strings);

	memset(stringtab, 0, sizeof(*stringtab));
}


/****************************************************************************

  MODULETEST

  This code is designed to regression test this module. It is only included
  when this file is compiled as a standalone program.

 ****************************************************************************/
#ifdef MODULETEST
#include <ctype.h>

/* Explanation:
 * LOREM IPSUM has been the printing-press standard sample text since the
 * 1500s. It's a good choice for random text to here */
const char testcase1[] = 
	"Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do "
	"eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut "
	"enim ad minim veniam, quis nostrud exercitation ullamco laboris "
	"nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor "
	"in reprehenderit in voluptate velit esse cillum dolore eu fugiat "
	"nulla pariatur. Excepteur sint occaecat cupidatat non proident, "
	"sunt in culpa qui officia deserunt mollit anim id est laborum. " ;


static unsigned
is_valid(struct StringTable *stringtab)
{
	unsigned i;
	if (stringtab->count <= 1)
		return 1;

	for (i=0; i<stringtab->count-1; i++) {
		int c;
		c = stringtab_compare(stringtab->strings[i], 
				stringtab->strings[i+1]->str, stringtab->strings[i+1]->length);
		if (c != -1) {
			printf("%.*s < %.*s\n", stringtab->strings[i]->length, stringtab->strings[i]->str, stringtab->strings[i+1]->length, stringtab->strings[i+1]->str);
			return 0;
		}
	}
	return 1;
}

static void 
run_test(const char *test)
{
	unsigned i;
	struct StringTable stringtab[1];
	memset(stringtab, 0, sizeof(*stringtab));

	for (i=0; test[i]; ) {
		unsigned length = 0;

		while (test[i+length] && !isspace(test[i+length]))
			length++;

		stringtab_lookup(stringtab, test+i, length);

		while (test[i+length] && isspace(test[i+length]))
			length++;

		i += length;

		if (!is_valid(stringtab)) {
			printf("test error\n");
			break;
		}
	}

	printf("  %d\n", stringtab->count);
	stringtab_clear(stringtab);

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
