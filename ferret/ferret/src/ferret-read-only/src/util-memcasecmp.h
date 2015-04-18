#ifndef UTIL_MEMCASECMP_C
#define UTIL_MEMCASECMP_C
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int memcasecmp(const void *lhs, const void *rhs, size_t length);

#ifdef WIN32
#define strcasecmp _stricmp
#endif

#endif
