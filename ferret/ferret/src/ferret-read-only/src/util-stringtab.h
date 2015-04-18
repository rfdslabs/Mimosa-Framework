/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __STRINGTAB
#define __STRINGTAB
#ifdef __cplusplus
extern "C" {
#endif

struct StringT
{
	const unsigned char *str;
	unsigned length;
};
struct StringTable
{
	struct StringT **strings;
	unsigned count;
	unsigned max;
};

/**
 * Get a pointer to a stored copy of a string, or if not found,
 * then create an entry in the table, and return that entry. */
struct StringT *stringtab_lookup(struct StringTable *stringtab, const unsigned char *str, unsigned length);

/**
 * Clear the entries in the string table. Only call this when you have 
 * cleared all the instance data that refers to these strings */
void stringtab_clear(struct StringTable *stringtab);


#ifdef __cplusplus
}
#endif
#endif /*__STRINGTAB*/
