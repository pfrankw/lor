#include "lor/dir.h"



lor_dir_t * lor_dir_new(){

  lor_dir_t *dir = 0;

  dir = malloc( sizeof(lor_dir_t) );
  memset( dir, 0, sizeof(lor_dir_t) );

  dir->entry = 0;
  dir->created = time(0);

  return dir;

}

void lor_dir_free( lor_dir_t *dir ){

  if( !dir )
    return;

  free( dir->entry );
  free( dir );

}

int lor_dir_load_buffer( lor_dir_t *dir, unsigned char *buffer, size_t len ){

  assert( dir );
  assert( buffer );

  if( !len || len%sizeof(lor_dir_entry_t) != 0 )
    return -1;

  len -= sizeof(dir->created);
  dir->entry = malloc( len );
  memcpy( &dir->created, buffer, sizeof(dir->created) );
  memcpy( dir->entry, buffer + sizeof(dir->created), len );
  dir->ne = len / sizeof(lor_dir_entry_t);

  return 0;
}

int lor_dir_save_buffer( lor_dir_t *dir, unsigned char *buffer, size_t *len ){

  size_t t_len;

  assert( dir );

  t_len = dir->ne * sizeof(lor_dir_entry_t);

  if( !buffer ){
    *len = t_len;
    return 0;
  }

  if( *len < t_len )
    return -1;

  memcpy( buffer, &dir->created, sizeof(dir->created) );
  memcpy( buffer+sizeof(dir->created), dir->entry, t_len );
  *len = t_len;

  return 0;

}

int lor_dir_load_file( lor_dir_t *dir, FILE *fp ){

  uint32_t i=0;
  lor_dir_entry_t tmp_entry;

  assert( dir );
  assert( fp );

  rewind( fp );

  if( dir->entry ){
    free( dir->entry );
    dir->entry = 0;
    dir->ne = 0;
  }

  fread( &dir->created, 1, sizeof(dir->created), fp );
  while( fread( &tmp_entry, sizeof(lor_dir_entry_t), 1, fp ) > 0 ){
    i++;
    dir->entry = realloc( dir->entry, sizeof(lor_dir_entry_t) * i );
    memcpy( &dir->entry[i-1], &tmp_entry, sizeof(lor_dir_entry_t) );
  }
  dir->ne = i;
  return 0;

}

int lor_dir_save_file( lor_dir_t *dir, FILE *fp ){

  uint32_t i = 0;
  assert( dir );
  assert( fp );

  if( !dir->entry )
    return -1;

  fwrite( &dir->created, 1, sizeof(dir->created), fp );
  for(i=0; i<dir->ne; i++){
    fwrite( &dir->entry[i], sizeof(lor_dir_entry_t), 1, fp );
  }

  return 0;

}

int lor_dir_parse_consensus( lor_dir_t *dir, char *consensus ){

  int r = -1;
  char *c = 0, *c2 = 0;
  char tmp[200];
  lor_dir_entry_t tmp_entry;

  while( (consensus=strstr(consensus, "\nr ")) ){

    // R NAME FP DATE TIME IP PORT DIRPORT
    // M MHASH
    // S FLAGS

    memset( &tmp_entry, 0, sizeof(lor_dir_entry_t) );

    //c = strstr( consensus )

    c = consensus + 3;/* [>NAME] */


    if( !(c = strstr( c, " " )) ) goto exit; /* [NAME<] */
    c = c + 1; /* [NAME <] [>FP] */
    if( !(c2 = strstr( c, " " )) ) goto exit; /* [FP<] */
    if( c2-c > sizeof(tmp)-2 ) goto exit; /* Size of FP - Bug or attack */

    memset( tmp, 0, sizeof(tmp) );
    strncpy( tmp, c, c2-c );
    strcat( tmp, "=" );

    if( lor_base64_decode( tmp, strlen(tmp), tmp_entry.fp, sizeof(tmp_entry.fp), 0 ) != 0 )
      goto exit;

    c = c2 + 1; /* [FP <] [>DATE] */
    if( !(c = strstr( c, " " )) ) goto exit; /* [DATE<] */
    c = c + 1; /* [DATE <] [>TIME] */
    if( !(c = strstr( c, " " )) ) goto exit; /* [TIME<] */
    c = c + 1; /* [TIME <] [>IP] */
    if( !(c2 = strstr( c, " " )) ) goto exit; /* [IP<] */
    if( c2-c > sizeof(tmp)-1 ) goto exit; /* Size of IP - Bug or attack */

    memset( tmp, 0, sizeof(tmp) );
    strncpy( tmp, c, c2-c );

    tmp_entry.ip = be32toh( lor_pton4( tmp ) );

    c = c2 + 1; /* [IP <] [>PORT] */
    if( !(c2 = strstr( c, " " )) ) goto exit; /* [PORT<] */
    if( c2-c > 5 ) goto exit; /* Size of PORT - Bug or attack */

    memset( tmp, 0, sizeof(tmp) );
    strncpy( tmp, c, c2-c );

    tmp_entry.port = strtoul( tmp, 0, 10 );

    c = c2 + 1; /* [PORT <] [>DIRPORT] */
    if( !(c2 = strstr( c, "\n" )) ) goto exit; /* [DIRPORT<] */
    if( c2-c > 5 ) goto exit; /* Size of DIRPORT - Bug or attack */

    memset( tmp, 0, sizeof(tmp) );
    strncpy( tmp, c, c2-c );

    tmp_entry.dirport = strtoul( tmp, 0, 10 );

    if( !(c = strstr( c, "\nm " )) ) goto exit; /* [>\nM] */
    c = c + 3; /* [M <] [>MHASH] */
    if( !(c2 = strstr( c, "\n" )) ) goto exit; /* [MHASH<] */
    if( c2-c > sizeof(tmp)-1 ) goto exit; /* Size of MHASH - Bug or attack */

    memset( tmp, 0, sizeof(tmp) );
    strncpy( tmp, c, c2-c );

    strncpy( tmp_entry.microdesc_hash, tmp, sizeof(tmp_entry.microdesc_hash) );

    if( !(c = strstr( c, "\ns " )) ) goto exit; /* [>\nS] */
    c = c + 3; /* [S <] [>FLAGS] */
    if( !(c2 = strstr( c, "\n" )) ) goto exit; /* [FLAGS<] */
    if( c2-c > sizeof(tmp)-1 ) goto exit; /* Size of FLAGS - Bug or attack */

    memset( tmp, 0, sizeof(tmp) );
    strncpy( tmp, c, c2-c );

    if( strstr(tmp, "Exit") ) tmp_entry.flags[LOR_DIR_FLAG_EXIT] = 1;

    if( strstr(tmp, "BadExit") ) tmp_entry.flags[LOR_DIR_FLAG_EXIT] = 0; /* Avoid BadExit */

    if( strstr(tmp, "Fast") ) tmp_entry.flags[LOR_DIR_FLAG_FAST] = 1;

    if( strstr(tmp, "Guard") ) tmp_entry.flags[LOR_DIR_FLAG_GUARD] = 1;

    if( strstr(tmp, "HSDir") ) tmp_entry.flags[LOR_DIR_FLAG_HSDIR] = 1;

    if( strstr(tmp, "Running") ) tmp_entry.flags[LOR_DIR_FLAG_RUNNING] = 1;

    if( strstr(tmp, "Stable") ) tmp_entry.flags[LOR_DIR_FLAG_STABLE] = 1;

    if( strstr(tmp, "V2Dir") ) tmp_entry.flags[LOR_DIR_FLAG_V2DIR] = 1;

    if( strstr(tmp, "Valid") ) tmp_entry.flags[LOR_DIR_FLAG_VALID] = 1;

    dir->ne++;
    dir->entry = realloc( dir->entry, sizeof(lor_dir_entry_t) * (dir->ne) );
    memcpy( &dir->entry[dir->ne-1], &tmp_entry, sizeof(lor_dir_entry_t) );


    consensus += 3;
  }

  r = 0;
 exit:
  return r;
}

int lor_dir_parse_microdesc( lor_dir_t *dir, char *microdesc ){

  int r = -1;
  char *m, *m2;
  char onion_key[MEMBER_SIZE(lor_dir_entry_t, onion_key)];
  char ntor_onion_key[50];
  char fp_b64[100];
  unsigned char fp[MEMBER_SIZE(lor_dir_entry_t, fp)];
  lor_dir_entry_t *entry = 0;

  memset( ntor_onion_key, 0, sizeof(ntor_onion_key) );

  while( (microdesc=strstr(microdesc, "onion-key\n-----BEGIN RSA PUBLIC KEY-----")) ){

    // ONIONKEY
    // KEY
    // NTOKEY KEY
    // IDR FP

    m = microdesc + 10; /* [>KEY] */

    if( !(m2=strstr(m, "-----END RSA PUBLIC KEY-----")) ) goto exit; /* [KE>Y] */
    m2 = m2 + 28; /* [KEY<] */
    if( m2-m > sizeof(onion_key)-1 ) goto exit; /* Size of KEY - Bug or attack */

    memset( onion_key, 0, sizeof(onion_key) );
    strncpy( onion_key, m, m2-m );

    if( !(m2=strstr(m, "\nntor-onion-key ")) ) goto parsefp; /* [>\nNTOKEY] */

    m = m2 + 16; /* [NTOKEY <][>KEY] */
    if( !(m2=strstr(m, "\n")) ) goto exit; /* [KEY<] */
    if( m2-m > sizeof(ntor_onion_key)-2 ) goto exit; /* Size of KEY - Bug or attack */

    memset( ntor_onion_key, 0, sizeof(ntor_onion_key) );
    strncpy( ntor_onion_key, m, m2-m );

    if( lor_base64_decode( ntor_onion_key, strlen(ntor_onion_key), (unsigned char*)ntor_onion_key, LOR_CURVE25519_PUBKEY_LEN, 0 ) != 0 ) goto exit; /* Ninja */
    //lor_swap_buffer( ntor_onion_key, LOR_CURVE25519_PUBKEY_LEN );

  parsefp:
    if( !(m=strstr(m, "\nid rsa1024 ")) ) goto exit; /* [>\nIDR] */
    m = m + 12; /* [IDR <] [>FP] */
    if( !(m2=strstr(m, "\n")) ) goto exit; /* [FP<] */
    if( m2-m > sizeof(fp_b64)-2 ) goto exit; /* Size of FP - Bug or attack */

    memset( fp_b64, 0, sizeof(fp_b64) );
    strncpy( fp_b64, m, m2-m );
    strcat( fp_b64, "=" );

    if( lor_base64_decode(fp_b64, strlen(fp_b64), fp, sizeof(fp), 0 ) != 0 )
      goto exit;

    if( ( entry=lor_dir_get_entry_by_fp( dir, fp ) ) == 0 )
      goto exit;

    memcpy( entry->onion_key, onion_key, sizeof(onion_key) );
    memcpy( entry->ntor_onion_key, ntor_onion_key, LOR_CURVE25519_PUBKEY_LEN );
    microdesc = m;


  }

  r = 0;
 exit:
  return r;
}

int lor_dir_random_entry( lor_dir_t *dir, char *flags, lor_dir_entry_t **entry ){

  int r = -1;
  uint32_t n = 0;
  lor_dir_entry_t **arr_entry = 0;

  assert( dir );
  assert( flags );

  arr_entry = malloc( sizeof(lor_dir_entry_t*) * dir->ne );

  n = lor_dir_get_entry( dir, flags, arr_entry, dir->ne );
  if( n == 0 )
    goto exit;

  n = lor_rand_int( 0, n );
  *entry = arr_entry[n];

  r = 0;
 exit:
  free( arr_entry );
  return r;

}

uint32_t lor_dir_get_entry( lor_dir_t *dir, char *flags, lor_dir_entry_t **entry, uint32_t len ){

  uint32_t i, k, t;

  assert( dir );
  assert( flags );
  assert( entry );

  t=0;
  for(i=0; i<dir->ne && t<len; i++){

    int fok = 1;
    for(k=0; k<MEMBER_SIZE(lor_dir_entry_t, flags); k++){
      if(flags[k] && !dir->entry[i].flags[k] ){
        fok = 0;
        break;
      }
    }

    if( fok ){
      entry[t] = &dir->entry[i];
      t++;
    }

  }

  return t;
}

lor_dir_entry_t* lor_dir_get_entry_by_fp( lor_dir_t *dir, unsigned char *fp ){

  uint32_t i;

  assert( dir );
  assert( fp );

  for(i=0; i<dir->ne; i++){
    if( memcmp( dir->entry[i].fp, fp, sizeof(dir->entry[i].fp) ) == 0 ){
        return &dir->entry[i];
    }
  }

  return 0;
}

int lor_dir_get_responsible_hsdir( lor_dir_t *dir, unsigned char *desc_id, lor_dir_entry_t *entry[3] ){

  int r = -1;
  lor_dir_entry_t **arr_entry;
  char flags[MEMBER_SIZE(lor_dir_entry_t, flags)];
  uint32_t i, n_hs;
  uint32_t cd, ce; /* Compare digest, compare entry */

  assert( dir );
  assert( desc_id );
  assert( entry );

  arr_entry = malloc( sizeof(lor_dir_entry_t*) * dir->ne );
  memset( flags, 0, sizeof(flags) );

  /* Copying the first 32bit of digest into cd */
  memcpy( &cd, desc_id, sizeof(cd) );
  cd = htobe32(cd);

  flags[LOR_DIR_FLAG_HSDIR] = 1;

  n_hs = lor_dir_get_entry( dir, flags, arr_entry, dir->ne );
  if( n_hs < 3 )
    goto exit;

  for(i=0; i<n_hs; i++){
    memcpy( &ce, arr_entry[i]->fp, sizeof(ce) );
    ce = htobe32(ce);
    if( ce > cd ){
      entry[0] = arr_entry[++i==n_hs?(i=0):i-1]; /* If ++i == n_hs (end of array) then i = 0, else current i */
      entry[1] = arr_entry[++i==n_hs?(i=0):i-1];
      entry[2] = arr_entry[++i==n_hs?(i=0):i-1];
      r = 0;
      break;
    }

  }

 exit:
  free( arr_entry );
  return r;
}
