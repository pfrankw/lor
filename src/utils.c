#include "lor/utils.h"

void lor_str2hex( unsigned char *hex, char *str ){
	int i, k, len;
	char tmp[4];

	len = strlen(str);

	for(i=0, k=0; i<len; i+=2, k++){
		memcpy( tmp, str+i, 2 );
		tmp[2] = 0;
		hex[k] = strtoul( tmp, 0, 16 );
	}

}


void lor_ntop4( uint32_t ip, char *ip_str ){
	sprintf( ip_str, "%u.%u.%u.%u", *(((uint8_t*)&ip)+0), *(((uint8_t*)&ip)+1), *(((uint8_t*)&ip)+2), *(((uint8_t*)&ip)+3) );
}

uint32_t lor_pton4( char *ip_str ){

	int i, k, len;
	uint32_t ip;
	char *c;
	char tmp[4];

	c = ip_str;
	for(i=0; i<4; i++){

		memset( tmp, 0, sizeof(tmp) );
		k=0;
		len=0;
		while( isdigit(c[k++]) && len<3 ) len++;

		strncpy( tmp, c, len );

		*((uint8_t*)(&ip)+i) = strtoul( tmp, 0, 10 );

		if( i+1 < 4 ){
			if( !( c = strstr( c, "." ) ) )
				return 0;

			c++;
		}

	}

	return (ip);

}


void lor_pton4_selftest(){

	char *ip = "212.33.1.124";
	char ip_str[20];
	uint32_t ip_n;

	ip_n = lor_pton4( ip );
	assert( ip != 0 );
	lor_ntop4( ip_n, ip_str );
	assert( strcmp(ip_str, ip) == 0 );


}


int lor_dump_var( void *data, size_t size ){

  size_t i;
  unsigned char *c = data;
  for(i=0; i<size; i++){
    printf("%02X ", c[i]);
    if( (i+1) % 16 == 0 )
      printf("\n");
  }

  printf("\n");
  fflush(stdout);

  return 0;
}


void lor_log( const char* format, ... ){

	va_list args;
  va_start( args, format );
  vfprintf( stdout, format, args );
  fprintf( stdout, "\n" );
	fflush( stdout );
  va_end( args );

}
