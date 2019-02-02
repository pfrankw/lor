#ifndef LOR_CIRCUIT_H
#define LOR_CIRCUIT_H


#include "lor/relay.h"
#include "lor/net.h"
#include "lor/utils.h"

#define LOR_CIRCUIT_MAX_HOPS 3
#define LOR_STREAM_WINDOW_SIZE 500
#define LOR_CIRCUIT_WINDOW_SIZE 1000

#define LOR_CIRCUIT_OP_SEND 0
#define LOR_CIRCUIT_OP_RECV 1


#define LOR_REND_COOKIE_LEN 20

typedef struct _lor_window_t {
  uint16_t s_s; /* Stream send */
  uint16_t s_r; /* Stream recv */
  uint16_t c_s; /* Circuit send */
  uint16_t c_r; /* Circuit recv */

} lor_window_t;

typedef struct _lor_circuit_t {

  lor_conn_t conn;
  uint32_t id;
  int hops;
  uint16_t stream_id;

  unsigned char recv_buffer[MEMBER_SIZE(lor_rcell_t, data)-1];
  uint16_t recv_buffer_len;

  lor_window_t window;
  lor_relay_t relay[LOR_CIRCUIT_MAX_HOPS+1]; /* The last one is Bob */

} lor_circuit_t;

int lor_circuit_init( lor_circuit_t *circ, uint32_t circ_id, uint32_t ip, uint16_t port, unsigned char *id_digest );
void lor_circuit_free( lor_circuit_t *circ );

/* Circuit control functions */
int lor_circuit_create( lor_circuit_t *circ, lor_rsa_t *onion_key );
int lor_circuit_create2( lor_circuit_t *circ, uint16_t htype, uint16_t hlen, unsigned char *hdata, unsigned char *payload_out );
int lor_circuit_create2_ntor( lor_circuit_t *circ, unsigned char *fp, unsigned char *ntor_onion_key );
int lor_circuit_create_fast( lor_circuit_t *circ );
int lor_circuit_extend( lor_circuit_t *circ, uint32_t ip, uint16_t port, lor_rsa_t *onion_key, unsigned char *id_digest );
int lor_circuit_extend2( lor_circuit_t *circ, uint32_t ip, uint16_t port, unsigned char *fp, uint16_t htype, uint16_t hlen, unsigned char *hdata, unsigned char *payload_out );
int lor_circuit_extend2_ntor( lor_circuit_t *circ, uint32_t ip, uint16_t port, unsigned char *ntor_onion_key, unsigned char *fp );
int lor_circuit_introduce( lor_circuit_t *circ, lor_circuit_t *rend_circ, lor_rsa_t *service_key,
  uint32_t rend_ip, uint16_t rend_port, unsigned char *rend_fp, void *rend_key, uint16_t rend_key_len, void *rend_cookie );

/* Stream commands functions */
int lor_circuit_begin( lor_circuit_t *circ, char *host_port );
int lor_circuit_begin_dir( lor_circuit_t *circ );
int lor_circuit_begin_rend( lor_circuit_t *circ, unsigned char *cookie );


/* Generic functions */
int lor_circuit_recv_rcell( lor_circuit_t *circ, lor_rcell_t *rcell );
int lor_circuit_send_rcell( lor_circuit_t *circ, lor_rcell_t *rcell, int early );

int lor_circuit_send( lor_circuit_t *circ, void *data, int len );
int lor_circuit_recv( lor_circuit_t *circ, void *data, int len );

#endif
