#ifndef LOR_DIR_H
#define LOR_DIR_H

#include <time.h>

#include <lor/crypto.h>
#include <lor/portable_endian.h>
#include <lor/utils.h>

#define LOR_DIR_FLAG_EXIT 0
#define LOR_DIR_FLAG_FAST 1
#define LOR_DIR_FLAG_GUARD 2
#define LOR_DIR_FLAG_HSDIR 3
#define LOR_DIR_FLAG_RUNNING 4
#define LOR_DIR_FLAG_STABLE 5
#define LOR_DIR_FLAG_V2DIR 6
#define LOR_DIR_FLAG_VALID 7


typedef struct _lor_dir_entry_t {

  unsigned char fp[LOR_DIGEST_LEN];
  uint32_t ip;
  uint16_t port;
  uint16_t dirport;
  char microdesc_hash[50];

  char flags[8];

  char onion_key[260];
  unsigned char ntor_onion_key[LOR_CURVE25519_PUBKEY_LEN];

} lor_dir_entry_t;


typedef struct _lor_dir_t {
  lor_dir_entry_t *entry;
  uint32_t ne; /* N entries */

  time_t created;
} lor_dir_t;


/* Standard functions */
lor_dir_t* lor_dir_new();
void lor_dir_free( lor_dir_t *dir );

/* lor_dir_t loading functions */
int lor_dir_load_buffer( lor_dir_t *dir, unsigned char *buffer, size_t len );
int lor_dir_save_buffer( lor_dir_t *dir, unsigned char *buffer, size_t *len );
int lor_dir_load_file( lor_dir_t *dir, FILE *fp );
int lor_dir_save_file( lor_dir_t *dir, FILE *fp );

/* Parsing functions */
int lor_dir_parse_consensus( lor_dir_t *dir, char *consensus );
int lor_dir_parse_microdesc( lor_dir_t *dir, char *microdesc );

/* Query functions */
uint32_t lor_dir_get_entry( lor_dir_t *dir, char *flags, lor_dir_entry_t **entry, uint32_t len );
lor_dir_entry_t* lor_dir_get_entry_by_fp( lor_dir_t *dir, unsigned char *fp );
int lor_dir_random_entry( lor_dir_t *dir, char *flags, lor_dir_entry_t **entry );
int lor_dir_is_fetched( lor_dir_t *dir, uint32_t i );
int lor_dir_get_responsible_hsdir( lor_dir_t *dir, unsigned char *desc_id, lor_dir_entry_t *entry[3] );

#endif
