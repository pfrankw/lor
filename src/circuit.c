#include "lor/circuit.h"
#include "lor/authorities.h"

#define MIN(a,b) ((a)<(b)?(a):(b))


int lor_circuit_init( lor_circuit_t *circ, uint32_t circ_id, uint32_t ip, uint16_t port, unsigned char *id_digest ){

  int r = -1;
  assert( circ );
  assert( circ_id );
  assert( ip );
  assert( port );
  assert( id_digest );

  #if (!defined(NDEBUG))
    lor_log( "%s: Initializing circuit %u ip=%u port=%u", __FUNCTION__, circ_id, ip, port );
  #endif

  memset( circ, 0, sizeof(lor_circuit_t) );
  circ->id = circ_id;

  if( lor_net_init( &circ->conn, id_digest ) != 0 )
    goto exit;

  if( lor_net_tls_connect( &circ->conn, ip, port ) != 0 )
    goto exit;

  if( lor_net_handshake( &circ->conn ) != 0 )
    goto exit;

  r = 0;
 exit:
 if( r != 0 ){
   #if (!defined(NDEBUG))
     lor_log( "%s: Failed to initialize circuit %u ip=%u port=%u", __FUNCTION__, circ_id, ip, port );
   #endif
   lor_net_tls_free( &circ->conn );
 }
 return r;

}

void lor_circuit_free( lor_circuit_t *circ ){

  int i;
  unsigned char payload[LOR_PAYLOAD_LEN];
  lor_rcell_t rcell;

  if( !circ || circ->id == 0 ) /* If circ->id is == 0 the ctx was not initialized */
    return;

  memset( &rcell, 0, sizeof(lor_rcell_t) );
  memset( payload, 0, sizeof(payload) );

  if( circ->stream_id ){
    rcell.command = LOR_RELAY_END;
    rcell.length = 1;
    rcell.stream_id = circ->stream_id;
    rcell.data[0] = 1; /* REASON_MISC */
    lor_circuit_send_rcell( circ, &rcell, 0 );
  }

  lor_net_write_cell( &circ->conn, circ->id, LOR_CELL_DESTROY, LOR_PAYLOAD_LEN, payload );
  lor_net_tls_free( &circ->conn );

  for(i=0; i<circ->hops; i++ )
    lor_relay_free( &circ->relay[i] );

  memset( circ, 0, sizeof(lor_circuit_t) );
}

int lor_circuit_send_rcell( lor_circuit_t *circ, lor_rcell_t *rcell, int early ){

  int i, h;
  assert( circ );
  assert( rcell );

  if( circ->window.s_s <= 0 || circ->window.c_s); /* To be finished */
  h = circ->hops;
  if( h == 0 )
    return -1;

  for(i=h; i>0; i--){
    if( i == h )
      lor_relay_digest_rcell_forward( &circ->relay[i-1], rcell );

    lor_relay_crypt_forward( &circ->relay[i-1], rcell, sizeof(lor_rcell_t) );
  }

  if( lor_net_write_cell( &circ->conn, circ->id, early ? LOR_CELL_RELAY_EARLY : LOR_CELL_RELAY, LOR_PAYLOAD_LEN, rcell ) != 0 )
    return -2;

  if( rcell->stream_id )
    circ->window.s_s--;
  circ->window.c_s--;
  return 0;

}


int lor_circuit_recv_rcell( lor_circuit_t *circ, lor_rcell_t *rcell ){

  lor_rcell_t rcellw;
  lor_cell_header cell;
  unsigned char *payload = 0;
  int r=-1, i, h;
  assert( circ );
  assert( rcell );
  h = circ->hops;

  if( h == 0 )
    return -1;

  payload = malloc( LOR_MAX_PAYLOAD_LEN );
  memset( payload, 0, LOR_MAX_PAYLOAD_LEN );
  memset( &cell, 0, sizeof(lor_cell_header) );
  memset( rcell, 0, sizeof(lor_rcell_t) ); /* Thanks valgrind */

  if( lor_net_read_cell( &circ->conn, &cell, payload ) != 0 )
    goto exit;

  if( cell.command != LOR_CELL_RELAY ){
     if( cell.command == LOR_CELL_DESTROY ){
      //assert( !("Protocol violation") );
      #if (!defined(NDEBUG))
        lor_log( "%s: CELL_DESTROY from %u payload = %u", __FUNCTION__, circ->id, payload[0] );
      #endif
    }
    goto exit;
  }

  memcpy( rcell, payload, sizeof(lor_rcell_t) );
  for(i=0; i<h; i++){
    lor_relay_crypt_backward( &circ->relay[i], rcell, sizeof(lor_rcell_t) );
    if( i == h-1 )
      if( lor_relay_digest_rcell_backward( &circ->relay[i], rcell ) != 0 ){
        #if (!defined(NDEBUG))
          lor_log( "%s: Bad rcell digest from %u", __FUNCTION__, circ->id );
        #endif
        goto exit;
      }
  }

  rcell->length = be16toh( rcell->length );

  if( rcell->length > sizeof( rcell->data ) ) /* BOF */
    goto exit;

  if( rcell->stream_id )
    circ->window.s_r--; /* Decreasing windows sizes by 1 as we receive data */
  circ->window.c_r--;

  if( circ->window.s_r < (LOR_STREAM_WINDOW_SIZE-(LOR_STREAM_WINDOW_SIZE/10)) ){ /* If this window is less than its 90% */

    memset( &rcellw, 0, sizeof(rcellw) );
    rcellw.command = LOR_RELAY_SENDME;
    rcellw.stream_id = rcell->stream_id;

    if( lor_circuit_send_rcell( circ, &rcellw, 0 ) != 0 )
      goto exit;

    circ->window.s_r += (LOR_STREAM_WINDOW_SIZE/10); /* +50 */

  }

  if ( circ->window.c_r < (LOR_CIRCUIT_WINDOW_SIZE - (LOR_CIRCUIT_WINDOW_SIZE/10)) ){

    memset( &rcellw, 0, sizeof(rcellw) );
    rcellw.command = LOR_RELAY_SENDME;

    if( lor_circuit_send_rcell( circ, &rcellw, 0 ) != 0 )
      goto exit;

    circ->window.c_r += (LOR_CIRCUIT_WINDOW_SIZE/10); /* +100 */
  }

  r = 0;

 exit:

  free( payload );
  if( rcell->command == LOR_RELAY_SENDME ){
    if( rcell->stream_id )
      circ->window.s_s += (LOR_STREAM_WINDOW_SIZE/10); /* +50 */
    circ->window.c_s += (LOR_CIRCUIT_WINDOW_SIZE/10); /* +100 */
    return lor_circuit_recv_rcell( circ, rcell );
  } else if (rcell->command == LOR_RELAY_END){
    #if (!defined(NDEBUG))
      lor_log( "%s: RELAY_END Received from %u", __FUNCTION__, circ->id );
    #endif

    circ->window.s_s = LOR_STREAM_WINDOW_SIZE;
    circ->window.s_r = LOR_STREAM_WINDOW_SIZE;
    circ->stream_id = 0;
  }

  if( r == 0 ){

  } else {
    lor_circuit_free( circ );
  }
  return r;
}

void lor_circuit_reset_windows( lor_circuit_t *circ ){
  assert( circ );

  circ->window.s_s = LOR_STREAM_WINDOW_SIZE;
  circ->window.s_r = LOR_STREAM_WINDOW_SIZE;
  circ->window.c_s = LOR_CIRCUIT_WINDOW_SIZE;
  circ->window.c_r = LOR_CIRCUIT_WINDOW_SIZE;

}

int lor_circuit_send( lor_circuit_t *circ, void *data, int len ){

  int r = -1;
  uint32_t i=0;
  uint32_t n_rcell;
  lor_rcell_t rcell;

  assert( circ );
  assert( data );


  n_rcell = (len+sizeof(rcell.data)-1) / sizeof( rcell.data ); /* Ninja */

  for(i=0; i<n_rcell; i++){
    uint16_t rcell_length = MIN( sizeof(rcell.data), len - (i*sizeof(rcell.data) ) );
    memset( &rcell, 0, sizeof(rcell) );
    rcell.command = LOR_RELAY_DATA;
    rcell.stream_id = circ->stream_id;
    rcell.length = htobe16( rcell_length );
    memcpy( rcell.data, data+(i*sizeof(rcell.data)), rcell_length );
    if( lor_circuit_send_rcell( circ, &rcell, 0 ) != 0 )
      goto exit;
    r += rcell_length;
  }

 exit:
  if( r > -1 ) r++; // r=-1 at start
  return r;
}

int lor_circuit_recv( lor_circuit_t *circ, void *data, int len ){

  int r = 0;
  uint32_t n_rcell;
  uint32_t i=0;
  lor_rcell_t rcell;

  assert( circ );
  assert( data );

  if( circ->recv_buffer_len > 0 ){ /* Formula magica */

    memcpy( data, circ->recv_buffer, MIN(len, circ->recv_buffer_len) );
    r += MIN(len, circ->recv_buffer_len);
    circ->recv_buffer_len -= r;

    if( circ->recv_buffer_len > 0 ){ /* If len wasn't big enough to contain all the recv_buffer data */
      unsigned char tmp_buffer[MEMBER_SIZE(lor_rcell_t, data)];
      memcpy( tmp_buffer, circ->recv_buffer+r, circ->recv_buffer_len );
      memcpy( circ->recv_buffer, tmp_buffer, circ->recv_buffer_len );
    }

  }

  if( !circ->stream_id )
    goto exit;

  n_rcell = (len-r+MEMBER_SIZE(lor_rcell_t, data)-1) / sizeof( rcell.data );

  for(i=0; i<n_rcell; i++){

    if( lor_circuit_recv_rcell( circ, &rcell ) != 0 || rcell.command != LOR_RELAY_DATA )
      goto exit;

    if( r+rcell.length > len ){ /* Formula magica */

      memcpy( data + r, rcell.data, len-r );
      memcpy( circ->recv_buffer, rcell.data+len-r, rcell.length - (len-r) );
      circ->recv_buffer_len = rcell.length - (len-r);

      r += len-r;

    } else {
      memcpy( data + r , rcell.data, rcell.length );
      r += rcell.length;
    }
  }

 exit:
  if( r == 0 ) r = -1;
  return r;
}

int lor_circuit_create( lor_circuit_t *circ, lor_rsa_t *onion_key ){

  unsigned char Df[LOR_DIGEST_LEN], Db[LOR_DIGEST_LEN], Kf[LOR_CIPHER_KEY_LEN], Kb[LOR_CIPHER_KEY_LEN];
  lor_cell_header cell;
  lor_dh_t dh;
  unsigned char *payload = 0;
  int r = -1;

  assert( circ );
  assert( onion_key );

  if( circ->hops > 0 ) /* Only create if not circuit has been created */
    return -1;

  payload = malloc( LOR_MAX_PAYLOAD_LEN ); /* Max payload length */
  memset( payload, 0, LOR_MAX_PAYLOAD_LEN );

  lor_create_tap_onion_skin( onion_key, &dh, payload );

  if( lor_net_write_cell( &circ->conn, circ->id, LOR_CELL_CREATE, LOR_PAYLOAD_LEN, payload ) != 0 ) /* Sending the onion skin */
    goto exit;

  if( lor_net_read_cell( &circ->conn, &cell, payload ) != 0 )
    goto exit;

  if( cell.command != LOR_CELL_CREATED )
    goto exit;

  if( lor_client_tap_handshake( &dh, payload, Df, Db, Kf, Kb ) != 0 )
    goto exit;

  lor_relay_init( &circ->relay[0], Df, Db, Kf, Kb );
  circ->hops = 1;
  lor_circuit_reset_windows( circ );

  r = 0;
 exit:

  lor_dh_free( &dh );
  free( payload );
  return r;
}

int lor_circuit_create2( lor_circuit_t *circ, uint16_t htype, uint16_t hlen, unsigned char *hdata, unsigned char *payload_out ){

  int r = -1;
  lor_cell_header cell;
  unsigned char *payload = 0;

  assert( circ );
  assert( hdata );

  payload = malloc( LOR_MAX_PAYLOAD_LEN ); /* Max payload length */
  memset( payload, 0, LOR_MAX_PAYLOAD_LEN );

  htype = htobe16( htype );
  hlen = htobe16( hlen );
  memcpy( payload, &htype, sizeof(htype) );
  memcpy( payload+2, &hlen, sizeof(hlen) );
  memcpy( payload+4, hdata, be16toh(hlen) );

  if( lor_net_write_cell( &circ->conn, circ->id, LOR_CELL_CREATE2, LOR_PAYLOAD_LEN, payload ) != 0 ) /* Sending the onion skin */
    goto exit;

  if( lor_net_read_cell( &circ->conn, &cell, payload ) != 0 )
    goto exit;

  if( cell.command != LOR_CELL_CREATED2 )
    goto exit;

  memcpy( payload_out, payload, LOR_MAX_PAYLOAD_LEN );

  r = 0;
 exit:
  free( payload );
  return r;
}

int lor_circuit_create2_ntor( lor_circuit_t *circ, unsigned char *fp, unsigned char *ntor_onion_key ){

  int r = -1;
  unsigned char Df[LOR_DIGEST_LEN], Db[LOR_DIGEST_LEN], Kf[LOR_CIPHER_KEY_LEN], Kb[LOR_CIPHER_KEY_LEN];
  lor_ecdh_t *ecdh = 0;
  unsigned char ntor_onion_skin[LOR_NTOR_ONIONSKIN_LEN];
  unsigned char *payload = 0;

  assert( circ );
  assert( fp );
  assert( ntor_onion_key );

  payload = malloc( LOR_MAX_PAYLOAD_LEN ); /* Max payload length */
  memset( payload, 0, LOR_MAX_PAYLOAD_LEN );

  if( lor_create_ntor_onion_skin( fp, ntor_onion_key, &ecdh, ntor_onion_skin) != 0 )
    goto exit;

  if( lor_circuit_create2( circ, 2, LOR_NTOR_ONIONSKIN_LEN, ntor_onion_skin, payload ) != 0 )
    goto exit;

  if( lor_client_ntor_handshake( ecdh, payload+2, fp, ntor_onion_key, Df, Db, Kf, Kb ) != 0 )
    goto exit;

  lor_relay_init( &circ->relay[0], Df, Db, Kf, Kb );
  circ->hops = 1;
  lor_circuit_reset_windows( circ );

  r = 0;
 exit:
  lor_ecdh_free( ecdh );
  free( payload );
  return r;
}


int lor_circuit_create_fast( lor_circuit_t *circ ){

  unsigned char Df[LOR_DIGEST_LEN], Db[LOR_DIGEST_LEN], Kf[LOR_CIPHER_KEY_LEN], Kb[LOR_CIPHER_KEY_LEN];
  lor_cell_header cell;
  unsigned char X[LOR_PAYLOAD_LEN];
  unsigned char *payload = 0;
  int r = -1;

  assert( circ );

  if( circ->hops > 0 ) /* Only create if not circuit has been created */
    return -1;

  payload = malloc( LOR_MAX_PAYLOAD_LEN ); /* Max payload length */
  memset( payload, 0, LOR_MAX_PAYLOAD_LEN );
  memset( X, 0, sizeof(X) );

  lor_rand_bytes( X, LOR_DIGEST_LEN );

  if( lor_net_write_cell( &circ->conn, circ->id, LOR_CELL_CREATE_FAST, LOR_PAYLOAD_LEN, X ) != 0 ) /* Sending the onion skin */
    goto exit;

  if( lor_net_read_cell( &circ->conn, &cell, payload ) != 0 )
    goto exit;

  if( cell.command != LOR_CELL_CREATED_FAST )
    goto exit;

  if( lor_client_fast_handshake( X, payload, Df, Db, Kf, Kb ) != 0 )
    goto exit;

  lor_relay_init( &circ->relay[0], Df, Db, Kf, Kb );
  circ->hops = 1;
  lor_circuit_reset_windows( circ );

  r = 0;
 exit:

  free( payload );
  return r;

}

int lor_circuit_extend( lor_circuit_t *circ, uint32_t ip, uint16_t port, lor_rsa_t *onion_key, unsigned char *id_digest ){

  lor_dh_t dh;
  lor_rcell_t rcell;
  unsigned char onion_skin[LOR_ONION_SKIN_CHALLENGE_LEN];
  unsigned char Df[LOR_DIGEST_LEN], Db[LOR_DIGEST_LEN], Kf[LOR_CIPHER_KEY_LEN], Kb[LOR_CIPHER_KEY_LEN];

  int r = -1;

  assert( circ );
  assert( ip );
  assert( port );
  assert( onion_key );
  assert( id_digest );

  if( circ->hops == 0 || circ->hops >= LOR_CIRCUIT_MAX_HOPS )
    return -1;

  memset( &rcell, 0, sizeof(lor_rcell_t) );

  if( lor_create_tap_onion_skin( onion_key, &dh, onion_skin ) != 0 )
    goto exit;

  rcell.command = LOR_RELAY_EXTEND;
  rcell.length = htobe16(4+2+sizeof(onion_skin)+LOR_DIGEST_LEN);
  ip = htobe32(ip);
  port = htobe16(port);
  memcpy( rcell.data, &ip, 4 );
  memcpy( rcell.data+4, &port, 2 );
  memcpy( rcell.data+4+2, onion_skin, sizeof(onion_skin) );
  memcpy( rcell.data+4+2+sizeof(onion_skin), id_digest, LOR_DIGEST_LEN );

  if( lor_circuit_send_rcell( circ, &rcell, 1 ) != 0 )
    goto exit;

  if( lor_circuit_recv_rcell( circ, &rcell ) != 0 )
    goto exit;

  if( lor_client_tap_handshake( &dh, rcell.data, Df, Db, Kf, Kb ) != 0 )
    goto exit;

  lor_relay_init( &circ->relay[circ->hops], Df, Db, Kf, Kb );
  circ->hops++;
  lor_circuit_reset_windows( circ );
  r = 0;

 exit:
  lor_dh_free( &dh );
  return r;
}

int lor_circuit_extend2( lor_circuit_t *circ, uint32_t ip, uint16_t port, unsigned char *fp, uint16_t htype, uint16_t hlen, unsigned char *hdata, unsigned char *payload_out ){

  int r = -1;
  lor_rcell_t rcell;

  assert( circ );
  assert( hdata );
  assert( payload_out );

  memset( &rcell, 0, sizeof(lor_rcell_t) );

  ip = htobe32(ip);
  port = htobe16(port);
  htype = htobe16(htype);
  hlen = htobe16(hlen);

  rcell.command = LOR_RELAY_EXTEND2;
  rcell.length = htobe16( 35 + be16toh(hlen) );

  rcell.data[0] = 2; /* NSPEC */

  rcell.data[1] = 0; /* LSTYPE */
  rcell.data[2] = 6; /* LSLEN */
  memcpy( rcell.data+3, &ip, sizeof(ip) ); /* IP */
  memcpy( rcell.data+7, &port, sizeof(port) ); /* ORPORT */

  rcell.data[9] = 2; /* LSTYPE */
  rcell.data[10] = LOR_DIGEST_LEN; /* LSLEN */
  memcpy( rcell.data+11, fp, LOR_DIGEST_LEN ); /* FP */

  memcpy( rcell.data+31, &htype, sizeof(htype) );
  memcpy( rcell.data+33, &hlen, sizeof(hlen) );
  memcpy( rcell.data+35, hdata, be16toh(hlen) );

  if( lor_circuit_send_rcell( circ, &rcell, 1 ) != 0 )
    goto exit;

  if( lor_circuit_recv_rcell( circ, &rcell ) != 0 )
    goto exit;

  memcpy( payload_out, rcell.data, rcell.length );

  r = 0;
 exit:

  return r;
}

int lor_circuit_extend2_ntor( lor_circuit_t *circ, uint32_t ip, uint16_t port, unsigned char *ntor_onion_key, unsigned char *fp ){

  int r = -1;
  unsigned char Df[LOR_DIGEST_LEN], Db[LOR_DIGEST_LEN], Kf[LOR_CIPHER_KEY_LEN], Kb[LOR_CIPHER_KEY_LEN];
  lor_ecdh_t *ecdh = 0;
  unsigned char ntor_onion_skin[LOR_NTOR_ONIONSKIN_LEN];

  unsigned char *payload = 0;

  assert( circ );
  assert( ntor_onion_key );
  assert( fp );

  payload = malloc( LOR_MAX_PAYLOAD_LEN );
  memset( payload, 0, LOR_MAX_PAYLOAD_LEN );

  if( lor_create_ntor_onion_skin( fp, ntor_onion_key, &ecdh, ntor_onion_skin ) != 0 )
    goto exit;

  if( lor_circuit_extend2( circ, ip, port, fp, 2, LOR_NTOR_ONIONSKIN_LEN, ntor_onion_skin, payload ) != 0 )
    goto exit;

  if( lor_client_ntor_handshake( ecdh, payload+2, fp, ntor_onion_key, Df, Db, Kf, Kb ) != 0 )
    goto exit;

  lor_relay_init( &circ->relay[circ->hops], Df, Db, Kf, Kb );
  circ->hops++;
  lor_circuit_reset_windows( circ );

  r = 0;
 exit:
  free( payload );
  lor_ecdh_free( ecdh );
  return r;
}

int lor_circuit_introduce( lor_circuit_t *circ, lor_circuit_t *rend_circ, lor_rsa_t *service_key,
  uint32_t rend_ip, uint16_t rend_port, unsigned char *rend_fp, void *rend_key, uint16_t rend_key_len, void *rend_cookie ){

  unsigned char Df[LOR_DIGEST_LEN], Db[LOR_DIGEST_LEN], Kf[LOR_CIPHER_KEY_LEN], Kb[LOR_CIPHER_KEY_LEN];
  int r=-1;
  unsigned char *intro_cell = 0, *ic;
  int intro_cell_len;
  uint32_t timestamp;
  lor_dh_t dh;
  unsigned char dh_public[LOR_DH_BYTES];
  unsigned char ckey[LOR_CIPHER_KEY_LEN];
  lor_rcell_t rcell;
  uint16_t stream_id;


  assert( circ );
  assert( service_key );
  assert( rend_fp );
  assert( rend_key );
  assert( rend_cookie );

  if( circ->hops != LOR_CIRCUIT_MAX_HOPS )
    return -1;

  stream_id = lor_rand_int( 1, 0xFFFF );
  timestamp = htobe32(time(0));

  if( lor_dh_init( &dh ) != 0 )
    goto exit;

  lor_dh_get_public( &dh, dh_public );

  intro_cell_len = 20 + 1 + 1 + 4 + 4 + 2 + LOR_DIGEST_LEN + 2 + rend_key_len + 20 + LOR_DH_BYTES;
  intro_cell = malloc( intro_cell_len );

  lor_rsa_digest( service_key, intro_cell ); /* Bob's PK identifier */

  ic = intro_cell + 20;
  ic[0] = 3; ic++; /* Version */
  ic[0] = 0; ic++; /* Auth method */
  memcpy( ic, &timestamp, sizeof(timestamp) ); ic+=sizeof(timestamp); /* Timestamp */

  rend_ip = htobe32( rend_ip );
  rend_port = htobe16( rend_port );
  rend_key_len = htobe16( rend_key_len );
  memcpy( ic, &rend_ip, sizeof(rend_ip) ); ic+=sizeof(rend_ip); /* Rendezvous IP */
  memcpy( ic, &rend_port, sizeof(rend_port) ); ic+=sizeof(rend_port); /* Rendezvous Port */
  memcpy( ic, rend_fp, LOR_DIGEST_LEN ); ic+=LOR_DIGEST_LEN; /* Rendezvous FP */
  memcpy( ic, &rend_key_len, sizeof(rend_key_len) ); ic+=sizeof(rend_key_len); /* Rendezvous key length */
  memcpy( ic, rend_key, be16toh(rend_key_len) ); ic+=be16toh(rend_key_len); /* Rendezvous onion key */
  memcpy( ic, rend_cookie, LOR_DIGEST_LEN ); ic+=LOR_DIGEST_LEN; /* Rendezvous cookie */
  memcpy( ic, dh_public, LOR_DH_BYTES ); ic+=LOR_DH_BYTES; /* DH g^x */

  memset( &rcell, 0, sizeof(rcell) );
  rcell.command = LOR_RELAY_ESTABLISH_INTRODUCE1;
  rcell.stream_id = stream_id;
  rcell.length = htobe16( intro_cell_len + LOR_HYBRID_ENCRYPT_OVERHEAD );

  memcpy( rcell.data, intro_cell, LOR_DIGEST_LEN ); /* Copy only Bob's PK identifier */

  lor_rand_bytes( ckey, LOR_CIPHER_KEY_LEN );

  if( lor_hybrid_encrypt( service_key, ckey, intro_cell+20, rcell.data+20, intro_cell_len - 20 ) != 0 )
    goto exit;

  if( lor_circuit_send_rcell( circ, &rcell, 0 ) != 0 )
    goto exit;

  if( lor_circuit_recv_rcell( circ, &rcell ) != 0 )
    goto exit;

  if( rcell.command != LOR_RELAY_INTRODUCE_ACK || rcell.data[0] != 0 )
    goto exit;

  if( lor_circuit_recv_rcell( rend_circ, &rcell) != 0 )
    goto exit;

  if( rcell.command != LOR_RELAY_ESTABLISH_RENDEZVOUS2 )
    goto exit;

  if( lor_client_tap_handshake( &dh, rcell.data, Df, Db, Kf, Kb ) != 0 )
    goto exit;

  rend_circ->stream_id = 0;
  lor_relay_init( &rend_circ->relay[rend_circ->hops++], Df, Db, Kf, Kb );
  lor_circuit_reset_windows( rend_circ );

  r = 0;
 exit:
  lor_dh_free( &dh );
  free( intro_cell );
  return r;
}

int lor_circuit_begin( lor_circuit_t *circ, char *host_port ){

  int r=-1;
  lor_rcell_t rcell;
  uint16_t stream_id;

  assert( circ );
  assert( host_port );
  assert( strlen(host_port) <= (sizeof(rcell.data) - 1 - 4) );

  if( circ->stream_id )
    return -1;

  memset( &rcell, 0, sizeof(lor_rcell_t) );
  stream_id = lor_rand_int( 1, 0xFFFF );

  rcell.command = LOR_RELAY_BEGIN;
  rcell.length = htobe16( strlen( host_port ) + 1 + 4 ); /* strlen host_port + 1 '\0' + 4 flags */
  rcell.stream_id = stream_id;

  memcpy( rcell.data, host_port, strlen(host_port) );

  if( lor_circuit_send_rcell( circ, &rcell, 0 ) != 0 )
    goto exit;

  if( lor_circuit_recv_rcell( circ, &rcell ) != 0 )
    goto exit;

  if( rcell.command != LOR_RELAY_CONNECTED )
    goto exit;

  circ->stream_id = stream_id;

  r = 0;
 exit:

  return r;
}

int lor_circuit_begin_rend( lor_circuit_t *circ, unsigned char *cookie ){

  int r=-1;
  lor_rcell_t rcell;
  uint16_t stream_id;

  assert( circ );

  if( circ->stream_id )
    return -1;

  memset( &rcell, 0, sizeof(rcell) );

  stream_id = lor_rand_int( 1, 0xFFFF );

  rcell.command = LOR_RELAY_ESTABLISH_RENDEZVOUS;
  rcell.stream_id = stream_id;

  memcpy( rcell.data, cookie, LOR_REND_COOKIE_LEN );
  rcell.length = htobe16(LOR_REND_COOKIE_LEN);

  if( lor_circuit_send_rcell( circ, &rcell, 0 ) != 0 )
    goto exit;

  if( lor_circuit_recv_rcell( circ, &rcell ) != 0 )
    goto exit;

  if( rcell.command != LOR_RELAY_RENDEZVOUS_ESTABLISHED )
    goto exit;

  circ->stream_id = stream_id;

  r = 0;
 exit:
  return r;
}


int lor_circuit_begin_dir( lor_circuit_t *circ ){

  int r=-1;
  lor_rcell_t rcell;
  uint16_t stream_id;

  assert( circ );

  if( circ->stream_id )
    goto exit;

  memset( &rcell, 0, sizeof(rcell) );

  stream_id = lor_rand_int( 1, 0xFFFF );

  rcell.command = LOR_RELAY_BEGIN_DIR;
  rcell.stream_id = stream_id;

  if( lor_circuit_send_rcell( circ, &rcell, 0 ) != 0 )
    goto exit;

  if( lor_circuit_recv_rcell( circ, &rcell ) != 0 )
    goto exit;

  if( rcell.command != LOR_RELAY_CONNECTED )
    goto exit;

  circ->stream_id = stream_id;

  r = 0;
 exit:
  return r;

}
