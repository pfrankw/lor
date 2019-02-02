#include "lor/autocircuit.h"

lor_autocircuit_t* lor_autocircuit_new(){

  int r = -1;
  lor_autocircuit_t *ac = 0;

  ac = (lor_autocircuit_t*) malloc( sizeof(lor_autocircuit_t) );
  memset( ac, 0, sizeof(lor_autocircuit_t) );

  if( (ac->dir = lor_dir_new()) == 0 )
    goto exit;

  r = 0;
 exit:

  if( r == 0 )
    return ac;

  lor_dir_free( ac->dir );
  free( ac );
  return 0;

}

void lor_autocircuit_free( lor_autocircuit_t *ac ){

  if( !ac )
    return;

  lor_dir_free( ac->dir );
  memset( ac, 0, sizeof(lor_autocircuit_t) );
  free( ac );
}

int lor_autocircuit_dir_update( lor_autocircuit_t *ac ){

  int r = -1, rt = 0;;
  lor_circuit_t c_circ, m_circ; /* Consensus Circuit, Microdescriptor circuit */
  uint32_t i = 0;

  assert( ac );

  memset( &c_circ, 0, sizeof(lor_circuit_t) );
  memset( &m_circ, 0, sizeof(lor_circuit_t) );

  if( time(0) - ac->dir->created < 60*60 && ac->dir->ne > 0 ){
    r = 0;
    goto exit;
  }

  #if (!defined(NDEBUG))
    lor_log("%s: Building circuit to auth", __FUNCTION__);
  #endif

  lor_dir_free( ac->dir );
  ac->dir = 0;

  if( lor_autocircuit_build_dir_auth( &c_circ ) != 0 )
    goto exit;

  if( (ac->dir = lor_dir_new()) == 0 )
    goto exit;

  if( lor_autocircuit_fetch_consensus( ac, &c_circ ) != 0 )
    goto exit;

  lor_circuit_free( &c_circ );

  for(i=0; i<ac->dir->ne && rt < LOR_DIR_FETCH_MAX_RETRY ; ){

    if( lor_autocircuit_build_dir( ac, &m_circ ) != 0 )
      goto retry;

    #if (!defined(NDEBUG))
      lor_log("%s: Fetching microdesc %d", __FUNCTION__, i);
    #endif

    if( lor_autocircuit_fetch_microdesc( ac, &m_circ, i, MIN(ac->dir->ne - i, LOR_DIR_FETCH_N) ) != 0 ){
      #if (!defined(NDEBUG))
        lor_log("%s: lor_autocircuit_fetch_microdesc failed", __FUNCTION__);
      #endif
      lor_circuit_free( &m_circ );
      goto retry;
    }

    lor_circuit_free( &m_circ );
    i+=LOR_DIR_FETCH_N;
    continue;
 retry:
    rt++;
    continue;
  }

  if( rt == LOR_DIR_FETCH_MAX_RETRY )
    goto exit;

  r = 0;
 exit:
  lor_circuit_free( &c_circ );
  lor_circuit_free( &m_circ );

  if( r != 0 ){
    lor_dir_free( ac->dir );
    ac->dir = 0;
  }
  
  return r;

}

int lor_autocircuit_fetch_consensus( lor_autocircuit_t *ac, lor_circuit_t *circ ){

  int r=-1, rr = 0;
  char *http_req = "GET /tor/status-vote/current/consensus-microdesc HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  char buffer[LOR_PAYLOAD_LEN-11];
  uint32_t c_offset = 0;
  char *consensus = 0;

  assert( ac );

  memset( buffer, 0, sizeof(buffer) );

  if( lor_circuit_send( circ, http_req, strlen(http_req) ) < 0 )
    goto exit;

  while( (rr=lor_circuit_recv( circ, buffer, sizeof(buffer) )) > 0 ){
    c_offset += rr;

    consensus = realloc( consensus, c_offset + 1);

    memcpy( consensus+c_offset-rr, buffer, rr );
  }

  if( !consensus )/* Extra fail */
    goto exit;

  consensus[c_offset] = 0;

  if( lor_dir_parse_consensus( ac->dir, consensus ) != 0 )
    goto exit;

  r = 0;
 exit:

  free(consensus);
  return r;

}

int lor_autocircuit_fetch_microdesc( lor_autocircuit_t *ac, lor_circuit_t *circ, uint32_t offset, uint32_t n ){

  uint32_t i;
  int r=-1, rr;
  char *http_req_init = "GET /tor/micro/d/";
  char *http_req_end = " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  char *http_req_buffer = 0;
  char buffer[MEMBER_SIZE(lor_rcell_t, data)+1];
  char *microdesc = 0;
  uint32_t m_offset = 0;

  assert( offset + n <= ac->dir->ne );
  assert( ac );

  http_req_buffer = malloc( strlen(http_req_init) +  (MEMBER_SIZE(lor_dir_entry_t, microdesc_hash) * n) + strlen(http_req_end) + 10 );

  assert( http_req_buffer );

  sprintf( http_req_buffer, "%s", http_req_init );
  for(i=0; i<n; i++){
    if(i+1<n)
      sprintf( http_req_buffer, "%s%s-", http_req_buffer, ac->dir->entry[offset+i].microdesc_hash );
    else
      sprintf( http_req_buffer, "%s%s", http_req_buffer, ac->dir->entry[offset+i].microdesc_hash );
  }

  sprintf( http_req_buffer, "%s%s", http_req_buffer, http_req_end );

  if( lor_circuit_send( circ, http_req_buffer, strlen(http_req_buffer) ) < 0 )
    goto exit;

  while( (rr=lor_circuit_recv( circ, buffer, sizeof(buffer)-1 )) > 0 ){
    m_offset += rr;

    microdesc = realloc( microdesc, m_offset+1 );

    memcpy( microdesc+m_offset-rr, buffer, rr );
  }

  if( !microdesc ) /* Extra fail */
    goto exit;

  microdesc[m_offset] = 0;

  if( lor_dir_parse_microdesc( ac->dir, microdesc ) != 0 )
    goto exit;

  r = 0;
 exit:

  //lor_circuit_free( &circ );

  free( http_req_buffer );
  free( microdesc );
  return r;

}


int lor_autocircuit_get_hsdesc( lor_autocircuit_t *ac, char *onion, lor_hs_desc_t *hs_desc ){

  int i, k, rr, r=-1;

  lor_dir_entry_t *resp_hsdir[3];

  lor_circuit_t hsdir_circ;
  unsigned char hsdesc_id[LOR_DIGEST_LEN];
  char hsdesc_id_base32[100];
  char *hsdir_http_req = "GET /tor/rendezvous2/%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
  char buffer[4096];

  assert( ac );
  assert( hs_desc );

  memset( &hsdir_circ, 0, sizeof(lor_circuit_t) );
  memset( hsdesc_id_base32, 0, sizeof(hsdesc_id_base32) );
  memset( buffer, 0, sizeof(buffer) );

  for(i=0; i<2; i++){ /* MAX REPLICAS */

    int b_offset = 0;

    if( lor_hs_calc_desc_id( onion, (char)i, hsdesc_id ) != 0 )
      goto loopexit;

    base32_encode( hsdesc_id_base32, sizeof(hsdesc_id_base32), hsdesc_id, sizeof(hsdesc_id) );

 #if (!defined(NDEBUG))
      lor_log("%s: Getting responsible HSDirs for #%d replica", __FUNCTION__, i);
 #endif

    if( lor_dir_get_responsible_hsdir( ac->dir, hsdesc_id, resp_hsdir ) != 0 )
      goto loopexit;

    for(k=0; k<3; k++){

 #if (!defined(NDEBUG))
        lor_log("%s: Building a circuit to the #%d responsible HSDir", __FUNCTION__, k);
 #endif

      if( lor_autocircuit_build_fp( ac, &hsdir_circ, resp_hsdir[k]->fp, 0 ) == 0 ){

        sprintf( buffer, hsdir_http_req, hsdesc_id_base32 );

        if( lor_circuit_begin_dir( &hsdir_circ ) != 0 )
          goto kloopexit;

 #if (!defined(NDEBUG))
          lor_log("%s: Requesting the HS Descriptor", __FUNCTION__);
 #endif

        if( lor_circuit_send( &hsdir_circ, buffer, strlen(buffer) ) < 0 )
          goto kloopexit;

        while( b_offset+MEMBER_SIZE(lor_rcell_t, data) < sizeof(buffer) && (rr=lor_circuit_recv( &hsdir_circ, buffer+b_offset, MEMBER_SIZE(lor_rcell_t, data) )) > 0 ){
          b_offset += rr;
        }
        buffer[b_offset] = 0;
        b_offset = 0;

 #if (!defined(NDEBUG))
          lor_log("%s: Parsing the HS Descriptor", __FUNCTION__);
 #endif

        if( lor_hs_parse_desc( buffer, hs_desc ) != 0 )
          goto kloopexit;

        r = 0;
        lor_circuit_free( &hsdir_circ );
        break;
      }

 kloopexit:
      lor_circuit_free( &hsdir_circ );
    }

loopexit:
    if( r == 0 ) /* If the HS Descriptor was found */
      break;
  }

  return r;
}

int lor_autocircuit_build_fp( lor_autocircuit_t *ac, lor_circuit_t *circ, unsigned char *fp, int fast ){

  int r = -1;
  lor_dir_entry_t *end_hop;
  lor_rsa_t *onion_key = 0;

  assert( ac );
  assert( circ );
  assert( fp );

  end_hop = lor_dir_get_entry_by_fp( ac->dir, fp );
  if( !end_hop )
    goto exit;

  if( !fast ){

    if( (onion_key=lor_rsa_new_pem( end_hop->onion_key )) == 0 )
      goto exit;

    if( lor_autocircuit_build( ac, circ, end_hop->ip, end_hop->port, end_hop->ntor_onion_key, onion_key, end_hop->fp ) != 0 )
      goto exit;

  } else {

    if( lor_autocircuit_build_fast( ac, circ, end_hop->ip, end_hop->port, end_hop->fp ) != 0 )
      goto exit;

  }

  r = 0;
 exit:
  if( r != 0 )
    lor_circuit_free( circ );

  lor_rsa_free( onion_key );

  return r;
}

int lor_autocircuit_build_fast( lor_autocircuit_t *ac, lor_circuit_t *circ, uint32_t ip, uint16_t port, unsigned char *fp ){

  int r = -1;
  uint32_t circ_id;

  assert( ac );
  assert( circ );
  assert( fp );

  circ_id = lor_rand_int( 0x80000000, 0xFFFFFFFF );

  if( lor_circuit_init( circ, circ_id, ip, port, fp ) != 0 )
    goto exit;

  if( lor_circuit_create_fast( circ ) != 0  )
    goto exit;

  r = 0;
 exit:
  if( r != 0 )
    lor_circuit_free( circ );

  return r;
}

int lor_autocircuit_build( lor_autocircuit_t *ac, lor_circuit_t *circ, uint32_t ip, uint16_t port, unsigned char *ntor_onion_key, lor_rsa_t *onion_key, unsigned char *fp ){

  int i, retries = 0, r = -1;
  char flags[MEMBER_SIZE(lor_dir_entry_t, flags)];
  uint32_t circ_id;

  assert( ac );
  assert( circ );
  assert( fp );

  circ_id = lor_rand_int( 0x80000000, 0xFFFFFFFF );
  for(i=0; i<LOR_CIRCUIT_MAX_HOPS-1; i++){

    lor_rsa_t *relay_onion_key = 0;
    lor_dir_entry_t *relay = 0;

    memset( flags, 0, sizeof(flags) );

    flags[LOR_DIR_FLAG_FAST] = 1;
    flags[LOR_DIR_FLAG_STABLE] = 1;

    if( i == 0 )
      flags[LOR_DIR_FLAG_GUARD] = 1;

    if( lor_dir_random_entry( ac->dir, flags, &relay ) != 0 )
      goto loopretry;

    if( (relay_onion_key=lor_rsa_new_pem( relay->onion_key )) == 0 )
      goto loopretry;

    if( i == 0 ){

      if( lor_circuit_init( circ, circ_id, relay->ip, relay->port, relay->fp ) != 0 )
        goto loopretry;

      if( lor_circuit_create2_ntor( circ, relay->fp, relay->ntor_onion_key ) != 0 )
        if( lor_circuit_create( circ, relay_onion_key ) != 0 )
          goto loopretry;

    } else {

      if( lor_circuit_extend2_ntor( circ, relay->ip, relay->port, relay->ntor_onion_key, relay->fp ) != 0 )
        if( lor_circuit_extend( circ, relay->ip, relay->port, relay_onion_key, relay->fp ) != 0 )
          goto loopretry;

    }

    lor_rsa_free( relay_onion_key );
    relay_onion_key = 0;
    continue;
 loopretry:
    if( i == 0 ) /* If it was our first hop we have to free the circuit */
      lor_circuit_free( circ );

    i--;
    retries++;
    lor_rsa_free( relay_onion_key );
    relay_onion_key = 0;
    if( retries == LOR_AUTOCIRCUIT_MAX_BUILD_RETRY )
      goto exit;
  }

  if( !ntor_onion_key || lor_circuit_extend2_ntor( circ, ip, port, ntor_onion_key, fp ) != 0 )
    if( lor_circuit_extend( circ, ip, port, onion_key, fp ) != 0 )
      goto exit;

  r = 0;
 exit:
  if( r != 0 )
    lor_circuit_free( circ );

  return r;
}


int lor_autocircuit_build_dir( lor_autocircuit_t *ac, lor_circuit_t *circ ){

  int r = -1;
  lor_dir_entry_t *dir;
  char flags[MEMBER_SIZE(lor_dir_entry_t, flags)];

  assert( ac );
  assert( circ );

  memset( flags, 0, sizeof(flags) );
  flags[LOR_DIR_FLAG_FAST] = 1;
  flags[LOR_DIR_FLAG_STABLE] = 1;
  flags[LOR_DIR_FLAG_V2DIR] = 1;

  if( lor_dir_random_entry( ac->dir, flags, &dir ) != 0 )
    goto exit;

  if( lor_autocircuit_build_fp( ac, circ, dir->fp, 1 ) != 0 )
    goto exit;

  if( lor_circuit_begin_dir( circ ) != 0 )
    goto exit;

  r = 0;
 exit:

  if( r != 0 )
    return lor_autocircuit_build_dir_auth( circ );

  return r;

}

int lor_autocircuit_build_dir_auth( lor_circuit_t *circ ){

  int r = -1;
  uint32_t circ_id = 0;
  char *auth = 0, *c = 0; /* Positioning-purpose pointers */
  unsigned char fp_digest[LOR_DIGEST_LEN];
  uint32_t ip = 0;
  uint16_t port = 0;
  char tmp[100];
  int8_t n_auth = 0;

  assert( circ );

  memset( fp_digest, 0, sizeof(fp_digest) );
  memset( tmp, 0, sizeof(tmp) );

  circ_id = lor_rand_int( 0x80000000, 0xFFFFFFFF );

  n_auth = lor_rand_int( 0, LOR_AUTH_LEN-1 );
  auth = AUTHORITIES[n_auth];

  /* Fingerprint */
  strncpy( tmp, auth, LOR_DIGEST_LEN*2 );
  tmp[LOR_DIGEST_LEN*2] = 0;
  lor_str2hex( fp_digest, tmp );

  /* IP */
  c = strstr( auth, " " ) + 1;
  strncpy( tmp, c, strstr( c, " " ) - c );
  tmp[ strstr( c, " " ) - c  ] = 0;
  //inet_pton( AF_INET, tmp, &ip );
  ip = lor_pton4( tmp );

  /* ORPort */
  c = strstr( c, " " ) + 1;
  strncpy( tmp, c, strstr( c, " " ) - c );
  tmp[ strstr( c, " " ) - c  ] = 0;
  port = strtoul( tmp, 0, 10 );


  if( lor_circuit_init( circ, circ_id, be32toh(ip), port, fp_digest ) != 0 )
    goto exit;

  if( lor_circuit_create_fast( circ ) != 0 )
    goto exit;

  if( lor_circuit_begin_dir( circ ) != 0 )
    goto exit;

  r = 0;
exit:

  if( r != 0 )
    lor_circuit_free( circ );

  return r;

}

int lor_autocircuit_build_hs( lor_autocircuit_t *ac, char *onion, uint16_t port, lor_circuit_t *rend_circ ){

  int i, r=-1;
  char flags[MEMBER_SIZE(lor_dir_entry_t, flags)];
  lor_dir_entry_t *rend;

  lor_circuit_t intro_circ;
  lor_hs_desc_t hs_desc;

  lor_rsa_t *rend_key_tmp = 0;
  lor_rsa_t *intro_onion_key = 0;
  lor_rsa_t *service_key = 0;

  unsigned char rend_key_der[300];
  int rend_key_der_len;
  unsigned char rend_cookie[LOR_DIGEST_LEN];

  char host_port[MEMBER_SIZE(lor_rcell_t, data)];

  assert( ac );
  assert( rend_circ );

  memset( rend_circ, 0, sizeof(lor_circuit_t) );
  memset( &intro_circ, 0, sizeof(lor_circuit_t) );

  #if (!defined(NDEBUG))
    lor_log("%s: Fetching HS Descriptor", __FUNCTION__);
  #endif

  if( lor_autocircuit_get_hsdesc( ac, onion, &hs_desc) != 0 )
    goto exit;

  memset( flags, 0, sizeof(flags) );
  flags[LOR_DIR_FLAG_FAST] = 1;
  flags[LOR_DIR_FLAG_STABLE] = 1;


  if( lor_dir_random_entry( ac->dir, flags, &rend ) != 0 )
    goto exit;

  #if (!defined(NDEBUG))
    lor_log("%s: Building rendezvous circuit", __FUNCTION__);
  #endif

  if( lor_autocircuit_build_fp( ac, rend_circ, rend->fp, 0 ) != 0 )
    goto exit;

  lor_rand_bytes( rend_cookie, sizeof(rend_cookie) );

  if( lor_circuit_begin_rend( rend_circ, rend_cookie ) != 0 )
    goto exit;

  for(i=0; i<3; i++){ /* Try to use every introduction point */

    if( (intro_onion_key=lor_rsa_new_pem( hs_desc.intro[i].onion_key )) == 0 )
      goto loopexit;

    #if (!defined(NDEBUG))
      lor_log("%s: Building a circuit to the #%d introduction point", __FUNCTION__, i+1);
    #endif

    if( lor_autocircuit_build( ac, &intro_circ, hs_desc.intro[i].ip, hs_desc.intro[i].port, 0, intro_onion_key, hs_desc.intro[i].fp ) != 0 )
      goto loopexit;

    if( (service_key=lor_rsa_new_pem( hs_desc.intro[i].service_key )) == 0 )
      goto loopexit;

    break;
 loopexit:
    lor_rsa_free( intro_onion_key );
    lor_rsa_free( service_key );
    intro_onion_key = 0;
    service_key = 0;
  }

  if( !intro_onion_key || !service_key )
    goto exit;

  if( (rend_key_tmp=lor_rsa_new_pem( rend->onion_key )) == 0 )
    goto exit;

  if( ( rend_key_der_len = lor_rsa_to_der( rend_key_tmp, rend_key_der, sizeof(rend_key_der) ) ) == 0 )
    goto exit;

  #if (!defined(NDEBUG))
    lor_log("%s: Sending introduce instructions", __FUNCTION__);
  #endif

  if( lor_circuit_introduce( &intro_circ, rend_circ, service_key, rend->ip, rend->port, rend->fp, rend_key_der, rend_key_der_len, rend_cookie ) != 0 )
    goto exit;

  sprintf( host_port, ":%u", port );

  #if (!defined(NDEBUG))
    lor_log("%s: Beginning rendezvous", __FUNCTION__);
  #endif

  if( lor_circuit_begin( rend_circ, host_port ) != 0 )
    goto exit;

  r = 0;
 exit:
  if( r != 0 ){

    #if (!defined(NDEBUG))
      lor_log("%s: There was an error", __FUNCTION__);
    #endif

    lor_circuit_free( rend_circ );
  }
  lor_rsa_free( intro_onion_key );
  lor_rsa_free( service_key );
  lor_rsa_free( rend_key_tmp );
  lor_circuit_free( &intro_circ );

  return r;

}
