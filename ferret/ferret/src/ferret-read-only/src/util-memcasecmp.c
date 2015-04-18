#include "util-memcasecmp.h"
#include <ctype.h>

int memcasecmp(const void *lhs, const void *rhs, size_t length)
{
	size_t i;

	for (i=0; i<length; i++) {
		char l = ((const char *)lhs)[i];
		char r = ((const char *)rhs)[i];

		if (tolower(l) != tolower(r))
			return 1;
	}

	return 0;
}



