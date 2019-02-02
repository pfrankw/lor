#ifndef LOR_H
#define LOR_H

#include <lor/autocircuit.h>

#define LOR_CONNECT_MAX_RETRIES 10

typedef struct _lor_opts_t {

  char dir_file[250];
  unsigned char *dirdata;
  size_t dirdata_len;

} lor_opts_t;

typedef struct _lor_socket_t {
  lor_circuit_t circ;
  int connected;
} lor_socket_t;

typedef struct _lor_context_t {

  lor_autocircuit_t *ac;
  lor_opts_t opts;

} lor_context_t;



lor_context_t* lor_new( lor_opts_t* opts );
void lor_free( lor_context_t* ctx );
int lor_save_dir_buffer( lor_context_t *ctx, unsigned char *buffer, size_t *len );
int lor_load_dir_buffer( lor_context_t *ctx, unsigned char *buffer, size_t len );
int lor_save_dir_file( lor_context_t *ctx );
int lor_load_dir_file( lor_context_t *ctx );


lor_socket_t* lor_connect( lor_context_t *ctx, char *host, uint16_t port );
int lor_send( lor_socket_t *sock, void *data, size_t len );
int lor_recv( lor_socket_t *sock, void *data, size_t len );
void lor_close( lor_socket_t *sock );



#endif
