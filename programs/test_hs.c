#include <lor/lor.h>

#define LOR_TEST_HOST "insertyouraddr.onion"
#define LOR_CACHED_DIR_FILE "/tmp/testlor"

int main( int argc, char **argv ){

  int rr, r=-1;
  lor_sha_t *sha = 0;
  lor_context_t *lor_ctx = 0;
  lor_opts_t lor_opts;
  lor_socket_t *sock = 0;
  unsigned char buffer[4096];
  char *c = 0;

  memset( &lor_opts, 0, sizeof(lor_opts_t) );
  memset( buffer, 0, sizeof(buffer) );

  strcpy( lor_opts.dir_file, LOR_CACHED_DIR_FILE );

  if( (lor_ctx = lor_new( 0 )) == 0 )
    goto exit;

  if( (sock = lor_connect( lor_ctx, LOR_TEST_HOST, 8080 )) == 0 )
    goto exit;

  sprintf( (char*)buffer, "GET /test.data HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", LOR_TEST_HOST );

  if( lor_send( sock, buffer, strlen((char*)buffer) ) <= 0 )
    goto exit;

  if( (rr=lor_recv( sock, buffer, sizeof(buffer) )) <= 0 )
    goto exit;

  buffer[rr] = 0;

  if( (c=strstr( (char*)buffer, "\r\n\r\n" )) == 0 )
    goto exit;

  c+= 4;
  sha = lor_sha_new();
  lor_sha_update( sha, c, rr-(c-(char*)buffer) );

  while( (rr=lor_recv( sock, buffer, sizeof(buffer) )) > 0 ){
    lor_sha_update( sha, buffer, rr );
  }

  lor_sha_digest( sha, buffer );

  fprintf( stdout, "\nThe SHA digest is: ");
  for( rr=0; rr<LOR_DIGEST_LEN; rr++ ){
    fprintf( stdout, "%02x", buffer[rr] );
  }
  fprintf( stdout, "\n" );

  r=0;
 exit:

  lor_sha_free( sha );
  lor_close( sock );
  lor_free( lor_ctx );


  return r;
}
