#ifndef BASE32_H
#define BASE32_H

#include <assert.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef INT32_MAX
#define INT32_MAX 0x7fffffff
#endif

#ifndef INT64_MAX
#define INT64_MAX 0x7fffffffffffffffll
#endif

#define SIZEOF_SIZE_T sizeof(size_t)

#ifndef SSIZE_MAX
#if (SIZEOF_SIZE_T == 4)
#define SSIZE_MAX INT32_MAX
#elif (SIZEOF_SIZE_T == 8)
#define SSIZE_MAX INT64_MAX
#else
#error "Can't define SSIZE_MAX"
#endif
#endif

#define SIZE_T_CEILING  ((size_t)(SSIZE_MAX-16))
#define BASE32_CHARS "abcdefghijklmnopqrstuvwxyz234567"


void base32_encode(char *dest, size_t destlen, unsigned char *src, size_t srclen);
int base32_decode(unsigned char *dest, size_t destlen, const char *src, size_t srclen);

#endif
