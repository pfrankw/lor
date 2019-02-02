#ifndef LOR_NET_H
#define LOR_NET_H

#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

#if ( !defined(_WIN32) )
#include <netinet/in.h>
#endif

#include "portable_endian.h"

#include <mbedtls/ssl.h>
#include <mbedtls/net.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include <lor/cell.h>
#include <lor/rcell.h>
#include <lor/relay.h>
#include <lor/crypto.h>
#include "lor/utils.h"

#if ( !defined(NDEBUG) )
  #define LOR_CONNECTION_TIMEOUT 7
#else
  #define LOR_CONNECTION_TIMEOUT 7
#endif
#define LOR_MAX_PAYLOAD_LEN 0xFFFF

typedef struct _lor_conn_t {

  int initialized;
  int connected;
  mbedtls_net_context fd;
  uint32_t own_ip;

  mbedtls_ssl_context ssl;
  mbedtls_ssl_config ssl_config;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  lor_x509_t peer_crt;
  lor_x509_t link_crt; /* Should be same as peer crt */
  lor_x509_t id_crt;

  unsigned char id_digest[LOR_DIGEST_LEN];

} lor_conn_t;

int lor_net_init( lor_conn_t *conn, unsigned char *id_digest );

int lor_net_read( lor_conn_t *conn, void *buf, size_t size );
int lor_net_write( lor_conn_t *conn, unsigned char *buf, size_t size );

void lor_net_tls_free( lor_conn_t *conn );
int lor_net_tls_connect( lor_conn_t *conn, uint32_t ip, uint16_t port );


/* Helpers */
int lor_net_write_padding_cell( lor_conn_t *conn );
int lor_net_read_cell( lor_conn_t *conn, lor_cell_header *cell, void *payload );
int lor_net_write_cell( lor_conn_t *conn, uint32_t circ_id, uint8_t command, uint16_t length, void *payload );

/* Functions */
int lor_net_negotiate_versions( lor_conn_t *conn );
int lor_net_handshake( lor_conn_t *conn );



/* External */
int
curve25519_donna(u8 *mypublic, const u8 *secret, const u8 *basepoint);

#endif
