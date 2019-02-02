#include "lor/lor.h"


lor_context_t* lor_new( lor_opts_t *opts ){

  int r=-1;
  lor_context_t *ctx = 0;


  ctx = malloc( sizeof(lor_context_t) );
  memset( ctx, 0, sizeof(lor_context_t) );

  ctx->ac = lor_autocircuit_new();
  if( !ctx->ac )
    goto exit;

  if( opts ){
    memcpy( &ctx->opts, opts, sizeof(lor_opts_t) );
  }

  if( lor_load_dir_file( ctx ) != 0 ){
    // Do nothing
  }

  if( lor_autocircuit_dir_update( ctx->ac ) != 0 ){
    goto exit;
  }

  lor_save_dir_file( ctx );

  r = 0;
 exit:
  if( r == 0 )
    return ctx;

  lor_free( ctx );
  return 0;
}

void lor_free( lor_context_t *ctx ){

  if( !ctx )
    return;

  lor_autocircuit_free( ctx->ac );
  memset( ctx, 0, sizeof(lor_context_t) );
  free( ctx );

}

int lor_save_dir_buffer( lor_context_t *ctx, unsigned char *buffer, size_t *len ){

  assert( ctx );
  assert( len );

  return lor_dir_save_buffer( ctx->ac->dir, buffer, len );
}

int lor_load_dir_file( lor_context_t *ctx ){

  int r = -1;
  FILE *fp = 0;

  assert( ctx );

  fp = fopen( ctx->opts.dir_file, "rb" );
  if( !fp )
    goto exit;

  if( lor_dir_load_file( ctx->ac->dir, fp ) != 0 )
    goto exit;

  if( ctx->ac->dir->ne < 10 )
    goto exit;

  r = 0;
 exit:
  if(fp) fclose( fp );
  return r;
}

int lor_save_dir_file( lor_context_t *ctx ){

  int r=-1;
  FILE *fp = 0;

  assert( ctx );

  fp = fopen( ctx->opts.dir_file, "wb" );
  if( !fp )
    goto exit;

  if( lor_dir_save_file( ctx->ac->dir, fp ) != 0 )
    goto exit;

  r = 0;
 exit:
  if(fp) fclose( fp );
  return r;
}

int lor_load_dir_buffer( lor_context_t *ctx, unsigned char *buffer, size_t len ){

  assert( ctx );
  assert( buffer );

  return lor_dir_load_buffer( ctx->ac->dir, buffer, len );

}

lor_socket_t* lor_connect( lor_context_t *ctx, char *host, uint16_t port ){

  int retries = LOR_CONNECT_MAX_RETRIES;
  int r=-1;
  lor_socket_t *sock = 0;
  int hostlen = 0;
  time_t last_update;

  assert( ctx );
  assert( host );

  sock = malloc( sizeof(lor_socket_t) );
  memset( sock, 0, sizeof(lor_socket_t) );

  last_update = ctx->ac->dir->created;

  if( lor_autocircuit_dir_update( ctx->ac ) != 0 )
    goto exit;

  if( ctx->ac->dir->created != last_update )
    lor_save_dir_file( ctx );

  if( (hostlen=strlen(host)) < 5 )
    goto exit;

  if( strcmp( host+hostlen-6, ".onion" )  == 0 ){

    char host_no_onion[hostlen];

    strncpy( host_no_onion, host, hostlen-6 );
    host_no_onion[hostlen-6] = 0;

    while( retries > 0 && lor_autocircuit_build_hs( ctx->ac, host_no_onion, port, &sock->circ ) != 0 )
      retries--;

    if( retries == 0 )
      goto exit;

  } else {
    goto exit; /* Not supported */
  }

  sock->connected = 1;
  r = 0;
 exit:
  if( r == 0 )
    return sock;

  lor_close( sock );
  return 0;
}

int lor_send( lor_socket_t *sock, void *data, size_t len ){
  return lor_circuit_send( &sock->circ, data, len );
}

int lor_recv( lor_socket_t *sock, void *data, size_t len ){
  int r = lor_circuit_recv( &sock->circ, data, len );
  sock->connected = sock->circ.stream_id ? 1 : 0;
  return r;
}

void lor_close( lor_socket_t *sock ){

  if( !sock )
    return;

  lor_circuit_free( &sock->circ );
  memset( sock, 0, sizeof(lor_socket_t) );
  free( sock );

}
