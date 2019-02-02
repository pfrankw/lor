#include "lor/hs.h"


int lor_hs_calc_desc_id( char *onion, char replica, unsigned char *desc_id ){

  lor_sha_t *sha = 0;
  uint32_t time_period = 0;
  unsigned char perm_id[10];
  unsigned char digest[LOR_DIGEST_LEN];

  assert( onion );
  assert( desc_id );

  memset( perm_id, 0, sizeof(perm_id) );
  memset( digest, 0, sizeof(digest) );

  if( base32_decode( perm_id, 10, onion, 16 ) != 0 )
    return -1;

  time_period = (time(0) + ((uint8_t) perm_id[0]) * 86400 / 256 ) / 86400;
  time_period = htobe32( time_period );

  sha = lor_sha_new();
  lor_sha_update( sha, &time_period, sizeof(time_period) );
  lor_sha_update( sha, &replica, sizeof(replica) );
  lor_sha_digest( sha, digest );
  lor_sha_free( sha );

  sha = lor_sha_new();
  lor_sha_update( sha, perm_id, sizeof(perm_id) );
  lor_sha_update( sha, digest, sizeof(digest) );
  lor_sha_digest( sha, digest );
  lor_sha_free( sha );

  memcpy( desc_id, digest, LOR_DIGEST_LEN );

  return 0;
}


int lor_hs_parse_desc_message( char *message, lor_hs_intro_t *intro ){

  int r=-1;
  char *decoded = 0;
  char *c;
  int i, len;

  assert( message );
  assert( intro );

  if( (len=strstr( message, "-----END MESSAGE-----" ) - message) < 0 )
    goto exit;

  decoded = malloc( len );

  if( lor_base64_decode( message, len, (unsigned char*)decoded, len, 1 ) != 0 )
    goto exit;

  c = decoded;
  for(i=0; i<3; i++){

    if( !(c=strstr( c, "introduction-point")) )
      goto exit;
    c+=19;

    if( (len=strstr(c, "\n") - c) < 0 )
      goto exit;

    if( base32_decode( intro[i].fp, sizeof(intro[i].fp), c, len ) != 0 )
      goto exit;

    if( !(c=strstr( c, "ip-address")) )
      goto exit;
    c+=11;

    if( (len=strstr( c, "\n" ) - c) < 0 )
      goto exit;
    c[len] = 0;

    if( (intro[i].ip = lor_pton4( c )) == 0 )
      goto exit;

    intro[i].ip = htobe32(intro[i].ip);

    c+=len+1;

    if( !(c=strstr( c, "onion-port")) )
      goto exit;
    c+=11;

    intro[i].port = strtoul( c, 0, 10 );

    if( !(c=strstr( c, "onion-key")) )
      goto exit;
    c+=10;

    if( (len=strstr( c, "-----END RSA PUBLIC KEY-----")+28 - c) <0 )
      goto exit;

    strncpy( intro[i].onion_key, c, len );

    if( !(c=strstr( c, "service-key")) )
      goto exit;
    c+=12;

    if( (len=strstr( c, "-----END RSA PUBLIC KEY-----")+28 - c) <0 )
      goto exit;

    strncpy( intro[i].service_key, c, len );

    c+=len;
  }

  r = 0;
 exit:
  free( decoded );
  return r;
}

int lor_hs_parse_desc( char *desc, lor_hs_desc_t *desc_out ){

  int r = -1;
  char *c;
  int copylen;

  assert( desc );
  assert( desc_out );

  memset( desc_out, 0, sizeof(lor_hs_desc_t) );

  if( !(c = strstr( desc, "-----END SIGNATURE-----" )) )
    goto exit;

  if( !(c = strstr( desc, "rendezvous-service-descriptor" )) )
    goto exit;
  c+=30;


  if( (copylen=strstr( c, "\n" ) - c) < 0 )
    goto exit;

  if( base32_decode( desc_out->id, sizeof(desc_out->id), c, copylen ) != 0 )
    goto exit;


  if( !(c = strstr( desc, "permanent-key" )) )
    goto exit;
  c+=14;

  if( (copylen=strstr( c, "-----END RSA PUBLIC KEY-----" ) + 28 - c) < 0 )
    goto exit;

  strncpy( desc_out->permanent_key, c, copylen );

  if( !(c = strstr( desc, "-----BEGIN MESSAGE-----" )) )
    goto exit;
  c+=24;

  if( lor_hs_parse_desc_message( c, desc_out->intro ) != 0 )
    goto exit;

  if( !(c = strstr( desc, "-----BEGIN SIGNATURE-----" )) )
    goto exit;

  if( (copylen=strstr( c, "-----END SIGNATURE-----" ) + 23 - c) < 0 )
    goto exit;

  strncpy( desc_out->signature, c, copylen );

  r = 0;
 exit:
  return r;
}
