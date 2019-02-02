#include <lor/net.h>

int lor_net_init( lor_conn_t *conn, unsigned char *id_digest ){

  assert( conn );
  assert( id_digest );

  memset( conn, 0, sizeof(lor_conn_t) );
  memcpy( conn->id_digest, id_digest, sizeof(conn->id_digest) );
  conn->initialized = 1;

  return 0;
}

int lor_net_read( lor_conn_t *conn, void *buf, size_t size ){

  int r, tr = 0;

  if( !conn->connected )
    return -1;

  while( tr < size ){

    r = mbedtls_ssl_read( &conn->ssl, buf+tr, size-tr );
    if( r <= 0 )
      return -1;

    tr += r;
  }

  return tr;

}

int lor_net_write( lor_conn_t *conn, unsigned char *buf, size_t size ){
  if( !conn->connected )
    return -1;
  return mbedtls_ssl_write( &conn->ssl, buf, size ) ;
}

void lor_net_tls_free( lor_conn_t *conn ){

  assert(conn);

  if( !conn )
    return;

  if( !conn->initialized )
    return;

  lor_x509_free( &conn->id_crt );
  lor_x509_free( &conn->link_crt );
  lor_x509_free( &conn->peer_crt );

  #if (!defined(NDEBUG))
    lor_log( "%s: Closing connection", __FUNCTION__);
  #endif

  mbedtls_ssl_close_notify( &conn->ssl );
  mbedtls_ssl_free( &conn->ssl );
  mbedtls_ssl_config_free( &conn->ssl_config );
  mbedtls_ctr_drbg_free( &conn->ctr_drbg );
  mbedtls_entropy_free( &conn->entropy );
  mbedtls_net_free( &conn->fd );

  memset( conn, 0, sizeof(lor_conn_t) );

}

int lor_net_tls_connect( lor_conn_t *conn, uint32_t ip, uint16_t port ){

  int hr, r=-1;
  char str_ip[100], str_port[20];

  assert( conn );
  assert( ip );
  assert( port );

  ip = htobe32( ip );
  lor_ntop4( ip, str_ip );
  snprintf(str_port, sizeof(str_port), "%u", port);

  #if (!defined(NDEBUG))
    lor_log( "%s: Connecting to ip=%s port=%u", __FUNCTION__, str_ip, port );
  #endif

  if( mbedtls_net_connect( &conn->fd, str_ip, str_port, MBEDTLS_NET_PROTO_TCP ) != 0 )
    goto exit;

  mbedtls_net_set_nonblock( &conn->fd );

  mbedtls_entropy_init( &conn->entropy );
  mbedtls_ctr_drbg_init( &conn->ctr_drbg );
  mbedtls_ssl_init( &conn->ssl );
  mbedtls_ssl_config_init( &conn->ssl_config );

  if( mbedtls_ssl_config_defaults( &conn->ssl_config,
    MBEDTLS_SSL_IS_CLIENT,
    MBEDTLS_SSL_TRANSPORT_STREAM,
    MBEDTLS_SSL_PRESET_DEFAULT ) != 0 )
      goto exit;

  if( mbedtls_ctr_drbg_seed( &conn->ctr_drbg, mbedtls_entropy_func, &conn->entropy, 0, 0 ) != 0 )
    goto exit;

  mbedtls_ssl_conf_rng( &conn->ssl_config, mbedtls_ctr_drbg_random, &conn->ctr_drbg );
  mbedtls_ssl_conf_authmode( &conn->ssl_config, MBEDTLS_SSL_VERIFY_NONE );
  mbedtls_ssl_conf_read_timeout( &conn->ssl_config, LOR_CONNECTION_TIMEOUT * 1000 );
  mbedtls_ssl_set_bio( &conn->ssl, &conn->fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout );

  if( mbedtls_ssl_setup( &conn->ssl, &conn->ssl_config ) != 0 )
    goto exit;

  while( ( hr = mbedtls_ssl_handshake( &conn->ssl ) ) != 0 )
    if( hr != MBEDTLS_ERR_SSL_WANT_READ && hr != MBEDTLS_ERR_SSL_WANT_WRITE )
      goto exit;

  if( mbedtls_ssl_get_peer_cert( &conn->ssl ) == 0 )
    goto exit;

  lor_x509_init_x509( &conn->peer_crt, mbedtls_ssl_get_peer_cert( &conn->ssl ) );

  conn->connected = 1;

  r = 0;
 exit:
  if( r != 0 ){
    #if (!defined(NDEBUG))
      lor_log( "%s: Failed connection to ip=%s port=%u", __FUNCTION__, str_ip, port );
    #endif
  }
  return r;
}

int lor_net_read_cell( lor_conn_t *conn, lor_cell_header *cell, void *payload ){

  int r = -1;

  assert( conn );
  assert( cell );
  assert( payload );

  memset( cell, 0, sizeof(lor_cell_header) );

  if( lor_net_read( conn, cell, sizeof(cell->circ_id) + sizeof(cell->command) ) <= 0 ) /* CIRCUIT ID + COMMAND READ*/
    goto exit;

  cell->circ_id = be32toh( cell->circ_id );
  if( cell->command > 127 ){  /* Variable length CELL */

    if( lor_net_read( conn, &cell->length, sizeof(cell->length) ) <= 0 ) /* LENGTH */
      goto exit;

    cell->length = be16toh( cell->length );

  } else {
    cell->length = LOR_PAYLOAD_LEN;
  }

  if( lor_net_read( conn, payload, cell->length ) < 0 ) /* PAYLOAD */
    goto exit;

  r = 0;
 exit:
  return r;
}

int lor_net_write_cell( lor_conn_t *conn, uint32_t circ_id, uint8_t command, uint16_t length, void *payload ){

  int r = -1;
  lor_cell_header cell;

  assert( conn );
  assert( payload );

  cell.circ_id = htobe32( circ_id );
  cell.command = command;
  cell.length = htobe16( length );

  if( !conn->connected )
    goto exit;

  if( lor_net_write( conn, (unsigned char*)&cell.circ_id, sizeof(cell.circ_id) ) <= 0 ) /* CIRCUIT ID */
    goto exit;

  if( lor_net_write( conn, (unsigned char*)&cell.command, sizeof(cell.command) ) <= 0 ) /* COMMAND */
    goto exit;

  if( command > 127 ){ /* Variable length CELL */
    if( lor_net_write( conn, (unsigned char*)&cell.length, sizeof(cell.length) ) <= 0 ) /* LENGTH */
      goto exit;
  }

  if( lor_net_write( conn, payload, length ) <= 0 )
    goto exit;

  r = 0;
 exit:
  return r;
}

int lor_net_negotiate_versions( lor_conn_t *conn ){

  int r = -1;
  lor_cell_header_v3 cell;
  uint16_t versions[10];
  int i;

  assert( conn );

  if( lor_net_write( conn, (unsigned char *)"\x00\x00\x07\x00\x02", 5 ) <= 0 ) /* CIRC_ID 0, CELL TYPE 7, LENGTH 2 */
    goto exit;

  if( lor_net_write( conn, (unsigned char*)"\x00\x04", 2 ) <= 0 )
    goto exit;

  if( lor_net_read( conn, (unsigned char*)&cell, sizeof(cell) ) <= 0 )
    goto exit;

  cell.length = be16toh(cell.length);
  if( cell.length > 10 * sizeof(uint16_t) )
    goto exit;

  if( lor_net_read( conn, (unsigned char*)versions, cell.length  ) <= 0 )
    goto exit;

  if( cell.command != LOR_CELL_VERSIONS )
    goto exit;

  for(i=0; i<cell.length; i++)
    if( be16toh(versions[i]) == 4 ){
      r = 0;
      break;
    }

 exit:
  return r;
}

int lor_send_netinfo_cell( lor_conn_t *conn, uint32_t *other_ip, uint32_t *this_ip ){

  uint32_t timestamp;
  unsigned char payload[LOR_PAYLOAD_LEN];

  assert( conn );
  assert( other_ip );
  assert( this_ip );

  timestamp = htobe32( time(0) );
  *other_ip = htobe32( *other_ip );
  *this_ip = htobe32( *this_ip );

  memcpy( payload, &timestamp, 4 ); /* Big-endian timestamp */
  memcpy( payload+4, "\x04\x04", 2 ); /* IPv4 */
  memcpy( payload+6, other_ip, 4 ); /* Other IP */
  payload[10] = 0x01; /* One IP */
  memcpy( payload+11, "\x04\x04", 2 ); /* IPv4 */
  memcpy( payload+13, this_ip, 4 ); /* My IP */
  memset( payload+17, 0, LOR_PAYLOAD_LEN-17 ); /* Clean the payload buffer */

  *other_ip = be32toh( *other_ip );
  *this_ip = be32toh( *this_ip );


  if( lor_net_write_cell( conn, 0, LOR_CELL_NETINFO, LOR_PAYLOAD_LEN, payload ) != 0 ){
    return -1;
  }

  return 0;
}

int lor_parse_netinfo_cell( unsigned char *payload, uint32_t *timestamp, uint32_t *other_ip, uint32_t *this_ip ){

  unsigned char *next_ip;
  int i;

  if( !payload )
    return -1;

  if( timestamp ){
    memcpy( timestamp, payload, sizeof(uint32_t) );
    *timestamp = be32toh( *timestamp );
  }

  if( payload[4] != 4 || payload[5] != 4 ) /* My IP is of course IPv4 */
    return -3;


  if( other_ip ){
    memcpy( other_ip, payload+6, sizeof(uint32_t) );
    *other_ip = be32toh( *other_ip );
  }

  if( this_ip ){
    next_ip = payload + 11;
    for(i=0; i<payload[10]; i++){
      if( next_ip[0] == 4 ){
        memcpy( this_ip, next_ip+2, sizeof(uint32_t) );
        *this_ip = be32toh( *this_ip );
        break;
      } else if( next_ip[0] == 6 ) {
        next_ip += 2 + 16; /* Advance by 18 bytes */
      } else {
        next_ip += 2 + next_ip[1]; /* Advance by "length" bytes */
      }
    }
  }

  return 0;
}

int lor_parse_certs_cell( unsigned char *payload, uint16_t length, lor_x509_t *link_crt, lor_x509_t *id_crt, lor_x509_t *auth_crt ){

  unsigned char *p;
  int i;

  if( !payload )
    return -1;

  p = payload + 1;

  if( payload[0] < 2 )
    return -1;

  for(i=0; i<payload[0]; i++){

    uint16_t clen;
    lor_x509_t *crt = 0;

    switch( p[0] /* CertType */ ){

      case 1:
        crt = link_crt;
      break;

      case 2:
        crt = id_crt;
      break;

      case 3:
        crt = auth_crt;
      break;

      default:
        return -1;
      break;
    }

    p++; /* CLEN */
    memcpy( &clen, p, 2 );
    clen = be16toh( clen );
    p+=2; /* Certificate */
    if( crt )
      if( lor_x509_init_der( crt, p, clen ) != 0 )
        return -1;

    p+=clen;

  }

  return 0;

}

int lor_net_handshake( lor_conn_t *conn ){

  int r=-1;
  unsigned char id_rsa_digest[LOR_DIGEST_LEN], link_digest[LOR_DIGEST_LEN], peer_digest[LOR_DIGEST_LEN];
  unsigned char peer_sign[LOR_DIGEST_LEN];
  unsigned char *payload = 0;
  lor_cell_header cell;
  uint32_t this_ip, other_ip;
  lor_rsa_t *id_rsa = 0;
  mbedtls_x509_crl cacrl;

  assert( conn );

  payload = malloc( LOR_MAX_PAYLOAD_LEN );
  memset( payload, 0, LOR_MAX_PAYLOAD_LEN );
  memset( &cacrl, 0, sizeof(mbedtls_x509_crl) );

  if( lor_net_negotiate_versions( conn ) != 0 )
    goto exit;

  if( lor_net_read_cell( conn, &cell, payload ) != 0 ) /* CERTS */
    goto exit;

  if( lor_parse_certs_cell( payload, cell.length, &conn->link_crt, &conn->id_crt, 0 ) != 0 )
    goto exit;

  if( lor_x509_get_rsa_pubkey( &conn->id_crt, &id_rsa) != 0 )
    goto exit;

  if( lor_rsa_digest( id_rsa, id_rsa_digest ) != 0 )
    goto exit;

  if( lor_x509_digest( &conn->link_crt, link_digest ) != 0 )
    goto exit;

  if( lor_x509_digest( &conn->peer_crt, peer_digest ) != 0 )
    goto exit;

  if( memcmp( id_rsa_digest, conn->id_digest, LOR_DIGEST_LEN) != 0 )
    goto exit;

  if( memcmp( link_digest, peer_digest, LOR_DIGEST_LEN) != 0 )
    goto exit;

  /* ---- BEGIN HACK ---- */
  lor_sha( conn->peer_crt.crt.tbs.p, conn->peer_crt.crt.tbs.len, peer_sign );

  if( lor_rsa_verify( id_rsa, peer_sign, sizeof(peer_sign), conn->peer_crt.crt.sig.p, conn->peer_crt.crt.sig.len ) != 0 )
    goto exit;
  /* ---- END HACK ---- */

  if( lor_net_read_cell( conn, &cell, payload ) != 0 ) /* AUTH_CHALLENGE */
    goto exit;

  if( lor_net_read_cell( conn, &cell, payload ) != 0 )
    goto exit;

  if( lor_parse_netinfo_cell( payload, 0, &this_ip, &other_ip ) != 0 ) /* NETINFO */
    goto exit;

  conn->own_ip = this_ip;

  if( lor_send_netinfo_cell( conn, &other_ip, &this_ip ) != 0 ) /* NETINFO RESPONSE */
    goto exit;

  r = 0;
 exit:
  lor_rsa_free( id_rsa );

  free( payload );

  return r;
}
