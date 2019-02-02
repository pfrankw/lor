#ifndef LOR_CRYPTO_H
#define LOR_CRYPTO_H

#include <time.h>
#include <limits.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include <mbedtls/bignum.h>
#include <mbedtls/base64.h>

#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_crl.h>

#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/dhm.h>
#include <mbedtls/pk.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>


#include <lor/utils.h>
#include <lor/err.h>


typedef struct _lor_aes_t {
  mbedtls_aes_context aes_ctx;
  size_t nc_off;
  unsigned char nonce_counter[16];
  unsigned char stream_block[16];
} lor_aes_t;

typedef struct _lor_sha_t {
  mbedtls_sha1_context sha_ctx;
} lor_sha_t;

typedef struct _lor_x509_t {
  mbedtls_x509_crt crt;
} lor_x509_t;

typedef struct _lor_rsa_t {
  mbedtls_pk_context pk_ctx;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
} lor_rsa_t;

typedef struct _lor_dh_t {
  mbedtls_dhm_context dhm;
  unsigned char challenge[128];
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
} lor_dh_t;

typedef struct _lor_ecdh_t {
  /*ecp_group grp;
  mpi d;
  ecp_point Q;
  ecp_point Qp;*/
  mbedtls_ecdh_context ctx;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
} lor_ecdh_t;

/* tap handshake */
#define LOR_DIGEST_LEN 20
#define LOR_DIGEST256_LEN 32
#define LOR_PKCS1_OAEP_PADDING_OVERHEAD 42
#define LOR_DH_BYTES (1024/8)
#define LOR_DH_PRIVATE_KEY_BITS 320
#define LOR_CIPHER_KEY_LEN 16
#define LOR_ONION_SKIN_CHALLENGE_LEN LOR_PKCS1_OAEP_PADDING_OVERHEAD + LOR_CIPHER_KEY_LEN + LOR_DH_BYTES
#define LOR_HYBRID_ENCRYPT_OVERHEAD LOR_PKCS1_OAEP_PADDING_OVERHEAD + LOR_CIPHER_KEY_LEN

#define LOR_PROTOID "ntor-curve25519-sha256-1"
#define LOR_T_MAC (LOR_PROTOID ":mac")
#define LOR_T_KEY (LOR_PROTOID ":key_extract")
#define LOR_T_VERIFY (LOR_PROTOID ":verify")
#define LOR_M_EXPAND (LOR_PROTOID ":key_expand")

#define LOR_PROTOID_LEN 24
#define LOR_SERVER_STR_LEN 6
#define LOR_CURVE25519_PUBKEY_LEN 32
#define LOR_CURVE25519_OUTPUT_LEN 32
#define LOR_SECRET_INPUT_LEN  ( (LOR_CURVE25519_PUBKEY_LEN * 3) + \
                              (LOR_CURVE25519_OUTPUT_LEN * 2) + \
                              LOR_DIGEST_LEN + LOR_PROTOID_LEN)

#define LOR_AUTH_INPUT_LEN    (LOR_DIGEST256_LEN + LOR_DIGEST_LEN + \
                              LOR_CURVE25519_PUBKEY_LEN * 3 +       \
                              LOR_PROTOID_LEN + LOR_SERVER_STR_LEN)

#define LOR_NTOR_ONIONSKIN_LEN LOR_DIGEST_LEN+LOR_CURVE25519_PUBKEY_LEN+LOR_CURVE25519_PUBKEY_LEN

/* ntor handshake */
#define CURVE25519_PUBKEY_LEN 32
#define CURVE25519_SECKEY_LEN 32
typedef uint8_t u8;


int lor_hybrid_encrypt( lor_rsa_t *onion_key, unsigned char *key, void *in, void *out, size_t len );
int lor_create_tap_onion_skin( lor_rsa_t *onion_key, lor_dh_t *dh_out, unsigned char *onion_skin_out );
int lor_create_ntor_onion_skin( unsigned char *fp, unsigned char *ntor_key, lor_ecdh_t **ecdh_out, unsigned char *ntor_onion_skin_out );

int lor_client_tap_handshake( lor_dh_t *dh, unsigned char *server_handshake, unsigned char *Df, unsigned char *Db, unsigned char *Kf, unsigned char *Kb );
int lor_client_ntor_handshake( lor_ecdh_t *ecdh, unsigned char *server_handshake, unsigned char *fp, unsigned char *ntor_onion_key, unsigned char *Df, unsigned char *Db, unsigned char *Kf, unsigned char *Kb );
int lor_client_fast_handshake( unsigned char *X, unsigned char *server_handshake, unsigned char *Df, unsigned char *Db, unsigned char *Kf, unsigned char *Kb );


/* AES Functions */
lor_aes_t* lor_aes_new( int bits, unsigned char *key, unsigned char *iv );
void lor_aes_crypt( lor_aes_t *aes, void *input, void *output, size_t len );
void lor_aes_free( lor_aes_t *aes );

/* SHA Functions */
void lor_sha( void *data, size_t len, unsigned char *md );
lor_sha_t* lor_sha_new();
void lor_sha_update( lor_sha_t *sha, void *data, size_t len );
void lor_sha_digest( lor_sha_t *sha, unsigned char *md );
void lor_sha_free( lor_sha_t *sha );

/* X509 Functions */
int lor_x509_init_x509( lor_x509_t *x509, const mbedtls_x509_crt *crt );
int lor_x509_init_der( lor_x509_t *x509, unsigned char *dercrt, size_t len );
void lor_x509_free( lor_x509_t *x509 );
int lor_x509_get_rsa_pubkey( lor_x509_t *x509, lor_rsa_t **rsa );
int lor_x509_digest( lor_x509_t *x509, unsigned char *digest );

/* RSA Functions */
lor_rsa_t* lor_rsa_new_pk( mbedtls_pk_context *pk );
lor_rsa_t* lor_rsa_new_pem( char *pemkey );
lor_rsa_t* lor_rsa_new_der( unsigned char *der, size_t len );
int lor_rsa_to_der( lor_rsa_t *rsa, unsigned char *der, size_t len );
int lor_rsa_digest( lor_rsa_t *rsa, unsigned char *digest );
int lor_rsa_pub_encrypt( lor_rsa_t *rsa, unsigned char *input, unsigned char *output, size_t len );
int lor_rsa_verify( lor_rsa_t *rsa, unsigned char *msg_digest, size_t msg_len, unsigned char *sig, size_t siglen );
void lor_rsa_free( lor_rsa_t *rsa );

/* DH Functions */
int lor_dh_init( lor_dh_t *dh );
void lor_dh_free( lor_dh_t *dh );
void lor_dh_get_public( lor_dh_t *dh, unsigned char *publickey );
int lor_dh_compute_secret( lor_dh_t *dh, unsigned char *pubkey, unsigned char *secret );

lor_ecdh_t* lor_ecdh_new();
lor_ecdh_t* lor_ecdh_new_b64();
int lor_ecdh_get_public( lor_ecdh_t *ecdh, unsigned char *publickey );
int lor_ecdh_compute_secret( lor_ecdh_t *ecdh, unsigned char *publickey, unsigned char *secret );
void lor_ecdh_free( lor_ecdh_t *ecdh );

/* RAND Functions */
void lor_rand_bytes( void *bytes, size_t len );
uint32_t lor_rand_int( uint32_t min, uint32_t max );


/* Base64 Functions */
void lor_base64_encode( char *str, size_t str_len, unsigned char *data, size_t data_len ); // NEVER TESTED MAY BE SHIT
int lor_base64_decode( char *str, size_t str_len, unsigned char *data, size_t data_len, int nl );


/* Helpers */
void lor_reverse_buffer( unsigned char *buf, size_t size );

#endif
