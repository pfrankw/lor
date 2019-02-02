#include <lor/crypto.h>
#include <mbedtls/hmac_drbg.h>

char *rfc2409_p = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"\
              "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"\
              "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"\
              "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"\
              "49286651ECE65381FFFFFFFFFFFFFFFF";

int lor_hybrid_encrypt( lor_rsa_t *onion_key, unsigned char *key, void *in, void *out, size_t len ){

  int r=-1;
  lor_aes_t *aes = 0;
  int pklen = 0, outpklen = 0, symlen = 0;
  unsigned char buffer[128-LOR_PKCS1_OAEP_PADDING_OVERHEAD];

  assert( onion_key );
  assert( key );
  assert( in );
  assert( out );

  memset( buffer, 0, sizeof(buffer) );

  aes = lor_aes_new( 128, key, 0 );

  pklen = 128;
  if( pklen != 128 )
    goto exit;

  memcpy( buffer, key, LOR_CIPHER_KEY_LEN );
  memcpy( buffer+LOR_CIPHER_KEY_LEN, in, sizeof(buffer)-LOR_CIPHER_KEY_LEN );

  symlen = len - (sizeof(buffer)-LOR_CIPHER_KEY_LEN);

  outpklen = lor_rsa_pub_encrypt( onion_key, buffer, out, pklen - LOR_PKCS1_OAEP_PADDING_OVERHEAD );
  if( outpklen != pklen )
    goto exit;

  lor_aes_crypt( aes, in+(len-symlen), out+outpklen, symlen );

  r = 0;
 exit:
  lor_aes_free( aes );
  return r;
}

int lor_create_tap_onion_skin( lor_rsa_t *onion_key, lor_dh_t *dh_out, unsigned char *onion_skin_out ){

  unsigned char ckey[LOR_CIPHER_KEY_LEN];
  unsigned char challenge[LOR_DH_BYTES];

  assert( onion_key );
  assert( dh_out );
  assert( onion_skin_out );

  lor_dh_t dh;
  int r = -1;

  if( lor_dh_init( &dh ) != 0 )
    goto exit;

  lor_dh_get_public( &dh, challenge );

  lor_rand_bytes( ckey, sizeof(ckey) );

  if( lor_hybrid_encrypt( onion_key, ckey, challenge, onion_skin_out, sizeof(challenge) ) != 0 )
    goto exit;

  r = 0;

 exit:

  if( r == 0 ){
    *dh_out = dh;
  } else {
    lor_dh_free( &dh );
  }

  return r;
}

int lor_create_ntor_onion_skin( unsigned char *fp, unsigned char *ntor_key, lor_ecdh_t **ecdh_out, unsigned char *ntor_onion_skin_out ){

  int r = -1;
  lor_ecdh_t *ecdh = 0;
  unsigned char public_key[LOR_CURVE25519_PUBKEY_LEN];
  unsigned char *nos = ntor_onion_skin_out;

  if( (ecdh=lor_ecdh_new()) == 0 )
    goto exit;

  if( lor_ecdh_get_public( ecdh, public_key ) != LOR_CURVE25519_PUBKEY_LEN )
    goto exit;

  memcpy( nos, fp, LOR_DIGEST_LEN ); nos += LOR_DIGEST_LEN;
  memcpy( nos, ntor_key, LOR_CURVE25519_PUBKEY_LEN ); nos += LOR_CURVE25519_PUBKEY_LEN;
  memcpy( nos, public_key, LOR_CURVE25519_PUBKEY_LEN ); nos += LOR_CURVE25519_PUBKEY_LEN;

  assert( nos == ntor_onion_skin_out + LOR_NTOR_ONIONSKIN_LEN );

  r = 0;
 exit:
  if( r == 0 ){
    *ecdh_out = ecdh;
  } else {
    lor_ecdh_free( ecdh );
  }
  return r;
}

int lor_expand_key_material_rfc5869_sha256(
                                    const uint8_t *key_in, size_t key_in_len,
                                    const uint8_t *salt_in, size_t salt_in_len,
                                    const uint8_t *info_in, size_t info_in_len,
                                    uint8_t *key_out, size_t key_out_len)
{
  uint8_t prk[LOR_DIGEST256_LEN];
  uint8_t tmp[LOR_DIGEST256_LEN + 128 + 1];
  uint8_t mac[LOR_DIGEST256_LEN];
  int i;
  uint8_t *outp;
  size_t tmp_len;

  /*crypto_hmac_sha256((char*)prk,
                     (const char*)salt_in, salt_in_len,
                     (const char*)key_in, key_in_len);
*/

  //mbedtls_sha256_hmac(salt_in, salt_in_len, key_in, key_in_len, prk, 0);
  mbedtls_md_hmac( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), salt_in, salt_in_len, key_in, key_in_len, prk );


  /* If we try to get more than this amount of key data, we'll repeat blocks.*/
  assert(key_out_len <= LOR_DIGEST256_LEN * 256);
  assert(info_in_len <= 128);
  memset(tmp, 0, sizeof(tmp));
  outp = key_out;
  i = 1;

  while (key_out_len) {
    size_t n;
    if (i > 1) {
      memcpy(tmp, mac, LOR_DIGEST256_LEN);
      memcpy(tmp+LOR_DIGEST256_LEN, info_in, info_in_len);
      tmp[LOR_DIGEST256_LEN+info_in_len] = i;
      tmp_len = LOR_DIGEST256_LEN + info_in_len + 1;
    } else {
      memcpy(tmp, info_in, info_in_len);
      tmp[info_in_len] = i;
      tmp_len = info_in_len + 1;
    }
    //mbedtls_sha256_hmac(prk, LOR_DIGEST256_LEN, tmp, tmp_len, mac, 0);
    mbedtls_md_hmac( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), prk, LOR_DIGEST256_LEN, tmp, tmp_len, mac );


    /*crypto_hmac_sha256((char*)mac,
                       (const char*)prk, DIGEST256_LEN,
                       (const char*)tmp, tmp_len); */

    n = key_out_len < LOR_DIGEST256_LEN ? key_out_len : LOR_DIGEST256_LEN;
    memcpy(outp, mac, n);
    key_out_len -= n;
    outp += n;
    ++i;
  }

  memset(tmp, 0, sizeof(tmp));
  memset(mac, 0, sizeof(mac));
  return 0;
}

/* KDF-TOR */
int lor_expand_key_material_tap( unsigned char *secret, uint32_t secret_len, unsigned char *secret_out, uint32_t secret_out_len ){

  int i, r=-1;
  unsigned char *cp, *tmp = malloc( secret_len + 1 );
  unsigned char digest[LOR_DIGEST_LEN];

  assert( secret_out_len <= LOR_DIGEST_LEN*256 );

  memcpy( tmp, secret, secret_len );
  for(cp = secret_out, i = 0; cp < secret_out + secret_out_len; i++, cp += LOR_DIGEST_LEN ){
      tmp[secret_len] = i;
      //if( !SHA1( tmp, secret_len + 1, digest ) )
      //  goto exit;
      lor_sha( tmp, secret_len +1, digest );
      memcpy( cp, digest, MIN( LOR_DIGEST_LEN, secret_out_len - ( cp - secret_out ) ) );
  }

  r = 0;
  memset( tmp, 0, secret_len + 1 );
  free( tmp );
  memset( digest, 0, LOR_DIGEST_LEN );
  return r;

}
/* TAP Client handshake */
int lor_client_tap_handshake( lor_dh_t *dh, unsigned char *server_handshake, unsigned char *Df, unsigned char *Db, unsigned char *Kf, unsigned char *Kb ){

  int r=-1;
  unsigned char derivation[(LOR_DIGEST_LEN*3) + (LOR_CIPHER_KEY_LEN*2)];
  unsigned char secret_tmp[LOR_DH_BYTES];
  int dh_result;

  assert( dh );
  assert( server_handshake );
  assert( Df );
  assert( Db );
  assert( Kf );
  assert( Kb );

  dh_result = lor_dh_compute_secret( dh, server_handshake, secret_tmp );
  if( dh_result < 0 )
    goto exit;


  if( lor_expand_key_material_tap( secret_tmp, dh_result, derivation, sizeof(derivation) ) != 0 )
    goto exit;

  if( memcmp( server_handshake + LOR_DH_BYTES, derivation, LOR_DIGEST_LEN ) != 0 )
    goto exit;

  memcpy( Df, derivation+LOR_DIGEST_LEN, LOR_DIGEST_LEN );
  memcpy( Db, derivation+(LOR_DIGEST_LEN*2), LOR_DIGEST_LEN );
  memcpy( Kf, derivation+(LOR_DIGEST_LEN*3), LOR_CIPHER_KEY_LEN );
  memcpy( Kb, derivation+(LOR_DIGEST_LEN*3)+LOR_CIPHER_KEY_LEN, LOR_CIPHER_KEY_LEN );

  r = 0;
 exit:
  memset( secret_tmp, 0, sizeof(secret_tmp) );
  return r;
}

int lor_client_ntor_handshake( lor_ecdh_t *ecdh, unsigned char *server_handshake, unsigned char *fp, unsigned char *ntor_onion_key, unsigned char *Df, unsigned char *Db, unsigned char *Kf, unsigned char *Kb ){

  int r = -1;
  unsigned char secret_input[LOR_SECRET_INPUT_LEN];
  unsigned char auth_input[LOR_AUTH_INPUT_LEN];
  unsigned char *si = secret_input;
  unsigned char *ai = auth_input;
  unsigned char my_public[LOR_CURVE25519_PUBKEY_LEN];
  unsigned char verify[LOR_DIGEST256_LEN];
  unsigned char auth[LOR_DIGEST256_LEN];
  unsigned char derivation[(LOR_DIGEST_LEN*2) + (LOR_CIPHER_KEY_LEN*2)];
  unsigned char *d = derivation;

  assert( ecdh );
  assert( server_handshake );
  assert( Df );
  assert( Db );
  assert( Kf );
  assert( Kb );

  if( lor_ecdh_compute_secret( ecdh, server_handshake, si ) != 0 )
    goto exit;

  si += LOR_CURVE25519_OUTPUT_LEN;

  if( lor_ecdh_compute_secret( ecdh, ntor_onion_key, si ) != 0 )
    goto exit;

  si += LOR_CURVE25519_OUTPUT_LEN;

  memcpy( si, fp, LOR_DIGEST_LEN ); si += LOR_DIGEST_LEN;
  memcpy( si, ntor_onion_key, LOR_CURVE25519_PUBKEY_LEN ); si += LOR_CURVE25519_PUBKEY_LEN;
  if( lor_ecdh_get_public( ecdh, my_public ) != LOR_CURVE25519_PUBKEY_LEN )
    goto exit;
  memcpy( si, my_public, LOR_CURVE25519_PUBKEY_LEN ); si += LOR_CURVE25519_PUBKEY_LEN;
  memcpy( si, server_handshake, LOR_CURVE25519_PUBKEY_LEN ); si += LOR_CURVE25519_PUBKEY_LEN;
  memcpy( si, LOR_PROTOID, LOR_PROTOID_LEN ); si += LOR_PROTOID_LEN;

  assert( si == secret_input + sizeof(secret_input) );

  //mbedtls_sha256_hmac( (unsigned char*)LOR_T_VERIFY, strlen(LOR_T_VERIFY), secret_input, sizeof(secret_input), verify, 0 );
  mbedtls_md_hmac( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), (unsigned char*)LOR_T_VERIFY, strlen(LOR_T_VERIFY), secret_input, sizeof(secret_input), verify );

  memcpy( ai, verify, LOR_DIGEST256_LEN ); ai += LOR_DIGEST256_LEN;
  memcpy( ai, fp, LOR_DIGEST_LEN ); ai += LOR_DIGEST_LEN;
  memcpy( ai, ntor_onion_key, LOR_CURVE25519_PUBKEY_LEN ); ai += LOR_CURVE25519_PUBKEY_LEN;
  memcpy( ai, server_handshake, LOR_CURVE25519_PUBKEY_LEN ); ai += LOR_CURVE25519_PUBKEY_LEN;
  memcpy( ai, my_public, LOR_CURVE25519_PUBKEY_LEN ); ai += LOR_CURVE25519_PUBKEY_LEN;
  memcpy( ai, LOR_PROTOID, LOR_PROTOID_LEN ); ai += LOR_PROTOID_LEN;
  memcpy( ai, "Server", 6 ); ai += 6;

  assert( ai == auth_input + sizeof(auth_input) );

  //mbedtls_sha256_hmac( (unsigned char*)LOR_T_MAC, strlen(LOR_T_MAC), auth_input, sizeof(auth_input), auth, 0 );
  mbedtls_md_hmac( mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), (unsigned char*)LOR_T_MAC, strlen(LOR_T_MAC), auth_input, sizeof(auth_input), auth );

  if( memcmp( auth, server_handshake + LOR_CURVE25519_PUBKEY_LEN, LOR_DIGEST256_LEN ) != 0 )
    goto exit;

  if( lor_expand_key_material_rfc5869_sha256( secret_input, sizeof(secret_input), (unsigned char*)LOR_T_KEY, strlen(LOR_T_KEY), (unsigned char*)LOR_M_EXPAND, strlen(LOR_M_EXPAND), derivation, sizeof(derivation)) != 0 )
    goto exit;

  memcpy( Df, d, LOR_DIGEST_LEN ); d+= LOR_DIGEST_LEN;
  memcpy( Db, d, LOR_DIGEST_LEN ); d+= LOR_DIGEST_LEN;
  memcpy( Kf, d, LOR_CIPHER_KEY_LEN ); d+= LOR_CIPHER_KEY_LEN;
  memcpy( Kb, d, LOR_CIPHER_KEY_LEN ); d+= LOR_CIPHER_KEY_LEN;

  r = 0;
 exit:
  return r;
}

int lor_client_fast_handshake( unsigned char *X, unsigned char *server_handshake, unsigned char *Df, unsigned char *Db, unsigned char *Kf, unsigned char *Kb ){

  int r=-1;
  unsigned char derivation[(LOR_DIGEST_LEN*3) + (LOR_CIPHER_KEY_LEN*2)];
  unsigned char secret_tmp[LOR_DIGEST_LEN * 2];

  assert( server_handshake );
  assert( Df );
  assert( Db );
  assert( Kf );
  assert( Kb );


  memcpy( secret_tmp, X, LOR_DIGEST_LEN );
  memcpy( secret_tmp+LOR_DIGEST_LEN, server_handshake, LOR_DIGEST_LEN );

  if( lor_expand_key_material_tap( secret_tmp, sizeof(secret_tmp), derivation, sizeof(derivation) ) != 0 )
    goto exit;

  if( memcmp( server_handshake + LOR_DIGEST_LEN, derivation, LOR_DIGEST_LEN ) != 0 )
    goto exit;

  memcpy( Df, derivation+LOR_DIGEST_LEN, LOR_DIGEST_LEN );
  memcpy( Db, derivation+(LOR_DIGEST_LEN*2), LOR_DIGEST_LEN );
  memcpy( Kf, derivation+(LOR_DIGEST_LEN*3), LOR_CIPHER_KEY_LEN );
  memcpy( Kb, derivation+(LOR_DIGEST_LEN*3)+LOR_CIPHER_KEY_LEN, LOR_CIPHER_KEY_LEN );
  r = 0;
 exit:
  memset( secret_tmp, 0, sizeof(secret_tmp) );
  return r;
}


/* AES Functions */
lor_aes_t* lor_aes_new( int bits, unsigned char *key, unsigned char *iv ){

  lor_aes_t *aes;

  assert( key );

  aes = malloc( sizeof(lor_aes_t) );
  memset( aes, 0, sizeof(lor_aes_t) );
  mbedtls_aes_init( &aes->aes_ctx );

  switch( bits ){
    case 128:
      mbedtls_aes_setkey_enc( &aes->aes_ctx, key, 128 );
    break;

    default:
      assert( 0 );
    break;
  }



  return aes;
}

void lor_aes_crypt( lor_aes_t *aes, void *input, void *output, size_t len ){

  assert( aes );
  assert( input );
  assert( output );
  assert( len < INT_MAX );

  mbedtls_aes_crypt_ctr( &aes->aes_ctx, len, &aes->nc_off, aes->nonce_counter, aes->stream_block, input, output );
}

void lor_aes_free( lor_aes_t *aes ){

  if( !aes )
    return;

  mbedtls_aes_free( &aes->aes_ctx );
  memset( aes, 0, sizeof(lor_aes_t) );
  free( aes );
}

/* SHA Functions */
void lor_sha( void *data, size_t len, unsigned char *md ){
  assert( data );
  assert( md );

  mbedtls_sha1( data, len, md );
}

lor_sha_t* lor_sha_new(){

  lor_sha_t *sha;

  sha = malloc( sizeof(lor_sha_t) );
  mbedtls_sha1_init( &sha->sha_ctx );
  mbedtls_sha1_starts( &sha->sha_ctx );

  return sha;

}

void lor_sha_update( lor_sha_t *sha, void *data, size_t len ){

  assert( sha );
  assert( data );

  mbedtls_sha1_update( &sha->sha_ctx, data, len );
}

void lor_sha_digest( lor_sha_t *sha, unsigned char *md ){

  lor_sha_t *sha_cp;

  assert( sha );
  assert( md );

  sha_cp = malloc( sizeof(lor_sha_t) );

  memcpy( sha_cp, sha, sizeof(lor_sha_t) ); /* Copy the ctx because SHA1_Final frees it */

  mbedtls_sha1_finish( &sha_cp->sha_ctx, md );

  free( sha_cp );
}

void lor_sha_free( lor_sha_t *sha ){

  if( !sha )
    return;

  mbedtls_sha1_free( &sha->sha_ctx );
  memset( sha, 0, sizeof(lor_sha_t) );
  free( sha );
}

/* X509 Functions */

int lor_x509_init_x509( lor_x509_t *x509, const mbedtls_x509_crt *crt ){

    assert( x509 );
    assert( crt );

    lor_x509_init_der( x509, crt->raw.p, crt->raw.len );
    return 0;

}

int lor_x509_init_der( lor_x509_t *x509, unsigned char *dercrt, size_t len ){

    assert( x509 );
    assert( dercrt );

    mbedtls_x509_crt_init( &x509->crt );

    if( mbedtls_x509_crt_parse_der( &x509->crt, dercrt, len ) != 0 )
      return LOR_ERR_GENERIC;
    return 0;

}

void lor_x509_free( lor_x509_t *x509 ){

  if( !x509 )
    return;

  mbedtls_x509_crt_free( &x509->crt );
  memset( x509, 0, sizeof(lor_x509_t) );
}

int lor_x509_get_rsa_pubkey( lor_x509_t *x509, lor_rsa_t **rsa ){

  int r = -1;
  lor_rsa_t *lrsa;

  if( (lrsa = lor_rsa_new_pk( &x509->crt.pk )) == 0 )
    goto exit;

  *rsa = lrsa;

  r=0;
 exit:
  return r;
}

int lor_x509_to_der( lor_x509_t *x509, unsigned char *der, size_t len ){
  return -1;
}

int lor_x509_digest( lor_x509_t *x509, unsigned char *digest ){

  assert( x509 );
  assert( digest );

  if( !x509->crt.raw.p || x509->crt.raw.len == 0 )
    return -1;

  lor_sha( x509->crt.raw.p, x509->crt.raw.len, digest );

  return 0;
}


/* RSA Functions */
lor_rsa_t* lor_rsa_new_pk( mbedtls_pk_context *pk ){

  int r=-1;
  lor_rsa_t *rsa = 0;
  unsigned char der[500];

  assert( pk );

  /* ---- BEGIN HACK ---- */
  if( lor_rsa_to_der( (lor_rsa_t*)pk, der, sizeof(der) ) == 0 )
    goto exit;
  /* ---- END HACK ---- */

  if( (rsa=lor_rsa_new_der( der, sizeof(der) )) == 0 )
    goto exit;

  mbedtls_rsa_set_padding( mbedtls_pk_rsa( rsa->pk_ctx ), MBEDTLS_RSA_PKCS_V15, 0 );

  r = 0;
 exit:
  if( r == 0 )
    return rsa;

  return 0;
}

lor_rsa_t* lor_rsa_new_pem( char *pemkey ){

  int r = -1;
  lor_rsa_t *rsa = 0;
  unsigned char der[500];

  assert( pemkey );

  pemkey += strlen("-----BEGIN RSA PUBLIC KEY-----")+1;
  if( lor_base64_decode( pemkey, strstr( pemkey, "-----END RSA PUBLIC KEY-----") - pemkey , der, 500, 1) != 0 )
    goto exit;

  if( (rsa = lor_rsa_new_der( der, sizeof(der) )) == 0 )
    goto exit;

  r = 0;
 exit:
  if( r == 0 )
    return rsa;

  return 0;
}

lor_rsa_t* lor_rsa_new_der( unsigned char *der, size_t len ){

  int r=-1;
  lor_rsa_t *rsa = 0;
  mbedtls_rsa_context *rsa_ctx;

  assert( der );

  rsa = malloc( sizeof(lor_rsa_t) );
  memset( rsa, 0, sizeof(lor_rsa_t) );

  mbedtls_entropy_init( &rsa->entropy );
  mbedtls_ctr_drbg_init( &rsa->ctr_drbg );
  mbedtls_pk_init( &rsa->pk_ctx );

  if( mbedtls_ctr_drbg_seed( &rsa->ctr_drbg, mbedtls_entropy_func, &rsa->entropy, 0, 0 ) != 0 )
    goto exit;

  if( mbedtls_pk_setup( &rsa->pk_ctx, mbedtls_pk_info_from_type( MBEDTLS_PK_RSA ) ) != 0 )
    goto exit;

  rsa_ctx = mbedtls_pk_rsa( rsa->pk_ctx );

  if( mbedtls_mpi_read_binary( &rsa_ctx->N, der+6, 129 ) != 0 )
    goto exit;

  if( mbedtls_mpi_read_binary( &rsa_ctx->E, der+6+129+2, 3 ) != 0 )
    goto exit;

  rsa_ctx->len = ( mbedtls_mpi_bitlen( &rsa_ctx->N ) + 7 ) >> 3;

  mbedtls_rsa_set_padding( mbedtls_pk_rsa( rsa->pk_ctx ), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1 );

  r = 0;
 exit:
  if( r == 0 )
    return rsa;

  free( rsa );
  return 0;
}

int lor_rsa_to_der( lor_rsa_t *rsa, unsigned char *der, size_t len ){

  int llen;

  assert( rsa );
  assert( der );

  mbedtls_rsa_context *rsa_ctx = mbedtls_pk_rsa( rsa->pk_ctx );

  llen = 6 + 129 + 2 + 3;
  if( llen > len )
    return -1;

  memcpy( der, "\x30\x81\x89\x02\x81\x81", 6 );
  if( mbedtls_mpi_write_binary( &rsa_ctx->N, der+6, 129 ) != 0 )
    return -1;

  memcpy( der+6+129, "\x02\x03", 2 );
  if( mbedtls_mpi_write_binary( &rsa_ctx->E, der+6+129+2, 3 ) != 0 )
    return -1;

  return llen;
}

int lor_rsa_pub_encrypt( lor_rsa_t *rsa, unsigned char *input, unsigned char *output, size_t len ){

  /*rsa_pkcs1_encrypt( pk_rsa( rsa->pk_ctx ), ctr_drbg_random, &rsa->ctr_drbg, RSA_PUBLIC, len, input, output );*/
  /*rsa_rsaes_oaep_encrypt( pk_rsa( rsa->pk_ctx ), ctr_drbg_random, &rsa->ctr_drbg, RSA_PUBLIC, "", 0, len, input, output );
  return 128;*/

  mbedtls_pk_encrypt( &rsa->pk_ctx, input, len, output, &len, 128, mbedtls_ctr_drbg_random, &rsa->ctr_drbg );
  return len;
}

int lor_rsa_verify( lor_rsa_t *rsa, unsigned char *msg_digest, size_t msg_len, unsigned char *sig, size_t siglen ){
  return mbedtls_pk_verify( &rsa->pk_ctx, MBEDTLS_MD_SHA1, msg_digest, msg_len, sig, siglen );
}



int lor_rsa_digest( lor_rsa_t *rsa, unsigned char *digest ){

  unsigned char derrsa[500];
  int len, r=-1;

  assert( rsa );
  assert( digest );

  if( (len=lor_rsa_to_der( rsa, derrsa, sizeof(derrsa))) <= 0  )
    goto exit;

  lor_sha( derrsa, len, digest );

  r = 0;
 exit:
  return r;
}

void lor_rsa_free( lor_rsa_t *rsa ){

  if( !rsa )
    return;

  mbedtls_pk_free( &rsa->pk_ctx );
  mbedtls_ctr_drbg_free( &rsa->ctr_drbg );
  mbedtls_entropy_free( &rsa->entropy );
  memset( rsa, 0, sizeof(lor_rsa_t) );
  free( rsa );
}

int lor_dh_init( lor_dh_t *dh ){

  int r = -1;
  size_t olen;
  unsigned char buf[2048];

  assert( dh );

  memset( dh, 0, sizeof(lor_dh_t) );

  mbedtls_dhm_init( &dh->dhm );
  mbedtls_entropy_init( &dh->entropy );
  mbedtls_ctr_drbg_init( &dh->ctr_drbg );
  if( mbedtls_ctr_drbg_seed( &dh->ctr_drbg, mbedtls_entropy_func, &dh->entropy, 0, 0 ) != 0 )
    goto exit;

  if( mbedtls_mpi_read_string( &dh->dhm.P, 16, rfc2409_p ) != 0 )
    goto exit;

  if( mbedtls_mpi_read_string( &dh->dhm.G, 10, "2" ) != 0 )
    goto exit;

  if( mbedtls_dhm_make_params( &dh->dhm, mbedtls_mpi_size( &dh->dhm.P ), buf, &olen, mbedtls_ctr_drbg_random, &dh->ctr_drbg ) != 0 )
    goto exit;

  if( mbedtls_dhm_make_public( &dh->dhm, dh->dhm.len, dh->challenge, mbedtls_mpi_size( &dh->dhm.P ), mbedtls_ctr_drbg_random, &dh->ctr_drbg ) != 0 )
    goto exit;

  r = 0;
 exit:
  if( r != 0 ){
    mbedtls_dhm_free( &dh->dhm );
  }
  return r;
}

void lor_dh_free( lor_dh_t *dh ){
  assert( dh );

  mbedtls_dhm_free( &dh->dhm );
}

void lor_dh_get_public( lor_dh_t *dh, unsigned char *public ){

  assert( dh );
  assert( public );

  memcpy( public, dh->challenge, sizeof(dh->challenge) );

}

int lor_dh_compute_secret( lor_dh_t *dh, unsigned char *pubkey, unsigned char *secret ){

  int r=-1;
  size_t olen;

  assert( dh );
  assert( pubkey );
  assert( secret );

  if( mbedtls_dhm_read_public( &dh->dhm, pubkey, LOR_DH_BYTES) != 0 )
    goto exit;

  olen = dh->dhm.len;
  if( mbedtls_dhm_calc_secret( &dh->dhm, secret, LOR_DH_BYTES, &olen, mbedtls_ctr_drbg_random, &dh->ctr_drbg) != 0 )
    goto exit;

  r = olen;
 exit:
  return r;
}

lor_ecdh_t* lor_ecdh_new(){

  int r = -1;
  lor_ecdh_t *ecdh = 0;

  ecdh = malloc( sizeof(lor_ecdh_t) );
  memset( ecdh, 0, sizeof(lor_ecdh_t) );

  mbedtls_ecdh_init( &ecdh->ctx );
  mbedtls_entropy_init( &ecdh->entropy );
  mbedtls_ctr_drbg_init( &ecdh->ctr_drbg );
  mbedtls_ecp_group_init( &ecdh->ctx.grp );

  if( mbedtls_ctr_drbg_seed( &ecdh->ctr_drbg, mbedtls_entropy_func, &ecdh->entropy, 0, 0 ) != 0 )
    goto exit;

  if( mbedtls_ecp_group_load( &ecdh->ctx.grp, MBEDTLS_ECP_DP_CURVE25519 ) != 0 )
    goto exit;

  if( mbedtls_ecdh_gen_public( &ecdh->ctx.grp, &ecdh->ctx.d, &ecdh->ctx.Q, mbedtls_ctr_drbg_random, &ecdh->ctr_drbg ) != 0 )
    goto exit;

  r = 0;
 exit:

  if( r == 0 )
    return ecdh;

  lor_ecdh_free( ecdh );
  return 0;
}

int lor_ecdh_get_public( lor_ecdh_t *ecdh, unsigned char *public ){

  size_t olen = 0;
  unsigned char public_tmp[LOR_CURVE25519_PUBKEY_LEN+1];

  assert( ecdh );
  assert( public );

  if( mbedtls_ecp_point_write_binary( &ecdh->ctx.grp, &ecdh->ctx.Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, public_tmp, sizeof(public_tmp) ) != 0 )
    return -1;

  memcpy( public, public_tmp+1, LOR_CURVE25519_PUBKEY_LEN );
  lor_reverse_buffer( public, LOR_CURVE25519_PUBKEY_LEN );
  return olen-1;
}

int lor_ecdh_compute_secret( lor_ecdh_t *ecdh, unsigned char *public, unsigned char *secret ){

  int r = -1;
  mbedtls_mpi z;
  unsigned char peer_public[LOR_CURVE25519_PUBKEY_LEN];

  assert( ecdh );
  assert( public );
  assert( secret );

  memcpy( peer_public, public, sizeof(peer_public) );
  lor_reverse_buffer( peer_public, sizeof(peer_public) );
  mbedtls_mpi_init( &z );

  mbedtls_mpi_read_binary( &ecdh->ctx.Qp.X, peer_public, LOR_CURVE25519_PUBKEY_LEN );
  mbedtls_mpi_lset( &ecdh->ctx.Qp.Z, 1 );

  if( mbedtls_ecdh_compute_shared( &ecdh->ctx.grp, &z, &ecdh->ctx.Qp, &ecdh->ctx.d, mbedtls_ctr_drbg_random, &ecdh->ctr_drbg ) != 0 )
    goto exit;

  if( mbedtls_mpi_write_binary( &z, secret, LOR_CURVE25519_OUTPUT_LEN ) != 0 )
    goto exit;

  lor_reverse_buffer( secret, LOR_CURVE25519_OUTPUT_LEN );

  r = 0;
 exit:
  mbedtls_mpi_free( &z );
  return r;
}

void lor_ecdh_free( lor_ecdh_t *ecdh ){

  if( !ecdh )
    return;

  mbedtls_ctr_drbg_free( &ecdh->ctr_drbg );
  mbedtls_entropy_free( &ecdh->entropy );
  mbedtls_ecdh_free( &ecdh->ctx );
  memset( ecdh, 0, sizeof(lor_ecdh_t) );
  free( ecdh );
}


void lor_rand_bytes( void *bytes, size_t len ){

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_entropy_init( &entropy );
  mbedtls_ctr_drbg_init( &ctr_drbg );
  if( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, 0, 0 ) != 0 )
    goto exit;

  if( mbedtls_ctr_drbg_random( &ctr_drbg, bytes, len ) != 0 )
    goto exit;

 exit:
  mbedtls_ctr_drbg_free( &ctr_drbg );
  mbedtls_entropy_free( &entropy );

}

uint32_t lor_rand_int( uint32_t min, uint32_t max ){

  uint32_t r;
  lor_rand_bytes( &r, sizeof(r) );
  return (r % (max-min)) + min;

}

void lor_base64_encode( char *str, size_t str_len, unsigned char *data, size_t data_len ){

  assert( str );
  assert( data );

  mbedtls_base64_encode( (unsigned char*)str, str_len, &str_len, data, data_len );

  return;
}

int lor_base64_decode( char *str, size_t str_len, unsigned char *data, size_t data_len, int nl ){

  if( mbedtls_base64_decode( data, data_len, &data_len, (unsigned char*)str, str_len ) != 0 )
    return -1;
  return 0;

}

void lor_reverse_buffer( unsigned char *buf, size_t size ){

  size_t i, k;
  unsigned char tmp = 0;

  for(i=size-1, k=0; k<size/2; i--, k++){
    tmp = buf[i];
    buf[i] = buf[k];
    buf[k] = tmp;
  }

}
