#ifndef LOR_HS_H
#define LOR_HS_H

#include <lor/crypto.h>
#include <lor/base32.h>
#include <lor/dir.h>

#include "lor/portable_endian.h"

typedef struct _lor_hs_intro_t {
  unsigned char fp[LOR_DIGEST_LEN];
  uint32_t ip;
  uint16_t port;
  char onion_key[260];
  char service_key[260];

} lor_hs_intro_t;

typedef struct _lor_hs_desc_t {

  unsigned char id[LOR_DIGEST_LEN];
  char permanent_key[260];
  lor_hs_intro_t intro[3];
  char signature[260];

} lor_hs_desc_t;


int lor_hs_calc_desc_id( char *onion, char replica, unsigned char *desc_id );
int lor_hs_parse_desc( char *desc, lor_hs_desc_t *desc_out );

#endif
