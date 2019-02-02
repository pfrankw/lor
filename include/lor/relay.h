#ifndef LOR_RELAY_H
#define LOR_RELAY_H

#include <lor/rcell.h>
#include <lor/crypto.h>

typedef struct _lor_relay_t {

  lor_sha_t *Df, *Db; /* Digests */
  lor_aes_t *Kf, *Kb; /* Ciphers */
} lor_relay_t;


void lor_relay_init( lor_relay_t *relay, unsigned char *Df, unsigned char *Db, unsigned char *Kf, unsigned char *Kb );
void lor_relay_free( lor_relay_t *relay );
void lor_relay_crypt_forward( lor_relay_t *relay, void *data, size_t len );
void lor_relay_crypt_backward( lor_relay_t *relay, void *data, size_t len );

void lor_relay_digest_forward( lor_relay_t *relay, void *data, size_t len, unsigned char *digest );
void lor_relay_digest_backward( lor_relay_t *relay, void *data, size_t len, unsigned char *digest );

void lor_relay_digest_rcell_forward( lor_relay_t *relay, lor_rcell_t *rcell );
int lor_relay_digest_rcell_backward( lor_relay_t *relay, lor_rcell_t *rcell );

#endif
