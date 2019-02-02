#ifndef LOR_UTILS_H
#define LOR_UTILS_H


#include <ctype.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#define MIN(a,b) ((a)<(b)?(a):(b))
#define MEMBER_SIZE(type, member) sizeof(((type *)0)->member)


void lor_str2hex( unsigned char *hex, char *str );
void lor_ntop4( uint32_t ip, char *ip_str );
uint32_t lor_pton4( char *ip_str );
void lor_pton4_selftest();
int lor_dump_var( void *data, size_t size );
void lor_log( const char* format, ... );

#endif
