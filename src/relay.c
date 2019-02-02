#include "lor/relay.h"


void lor_relay_init( lor_relay_t *relay, unsigned char *Df, unsigned char *Db, unsigned char *Kf, unsigned char *Kb ){

  assert( relay );
  assert( Df );
  assert( Db );
  assert( Kf );
  assert( Kb );

  memset( relay, 0, sizeof(lor_relay_t) );
  relay->Df = lor_sha_new();
  lor_sha_update( relay->Df, Df, LOR_DIGEST_LEN );

  relay->Db = lor_sha_new();
  lor_sha_update( relay->Db, Db, LOR_DIGEST_LEN );

  relay->Kf = lor_aes_new( 128, Kf, 0 );
  relay->Kb = lor_aes_new( 128, Kb, 0 );

}

void lor_relay_free( lor_relay_t *relay ){

  if( !relay )
    return;
  lor_sha_free( relay->Df );
  lor_sha_free( relay->Db );
  lor_aes_free( relay->Kf );
  lor_aes_free( relay->Kb );

  memset( relay, 0, sizeof(lor_relay_t) );
}

void lor_relay_crypt_forward( lor_relay_t *relay, void *data, size_t len ){
  assert( relay );
  assert( data );

  lor_aes_crypt( relay->Kf, data, data, len );
}

void lor_relay_crypt_backward( lor_relay_t *relay, void *data, size_t len ){
  assert( relay );
  assert( data );

  lor_aes_crypt( relay->Kb, data, data, len );
}

void lor_relay_digest_forward( lor_relay_t *relay, void *data, size_t len, unsigned char *digest ){
  assert( relay );
  assert( data );
  assert( digest );

  lor_sha_update( relay->Df, data, len );
  lor_sha_digest( relay->Df, digest );
}

void lor_relay_digest_backward( lor_relay_t *relay, void *data, size_t len, unsigned char *digest ){
  assert( relay );
  assert( data );
  assert( digest );

  lor_sha_update( relay->Db, data, len );
  lor_sha_digest( relay->Db, digest );
}

void lor_relay_digest_rcell_forward( lor_relay_t *relay, lor_rcell_t *rcell ){

  unsigned char digest[LOR_DIGEST_LEN];
  assert( relay );
  assert( rcell );

  memset( rcell->digest, 0, sizeof(rcell->digest) );
  lor_relay_digest_forward( relay, rcell, sizeof(lor_rcell_t), digest );
  memcpy( rcell->digest, digest, sizeof(rcell->digest) );
}

int lor_relay_digest_rcell_backward( lor_relay_t *relay, lor_rcell_t *rcell ){

  unsigned char rcell_digest[sizeof(rcell->digest)];
  unsigned char digest[LOR_DIGEST_LEN];
  assert( relay );
  assert( rcell );

  memcpy( rcell_digest, rcell->digest, sizeof(rcell->digest) );
  memset( rcell->digest, 0, sizeof(rcell->digest) );
  lor_relay_digest_backward( relay, rcell, sizeof(lor_rcell_t), digest );
  if( memcmp( rcell_digest, digest, sizeof(rcell->digest) )!= 0 )
    return -1;
  return 0;
}
