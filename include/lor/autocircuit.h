#ifndef LOR_AUTOCIRCUIT_H
#define LOR_AUTOCIRCUIT_H

#include <lor/authorities.h>
#include <lor/dir.h>
#include <lor/circuit.h>
#include <lor/hs.h>

#define LOR_DIR_FETCH_MAX_RETRY 100
#define LOR_DIR_FETCH_N 128

#define LOR_AUTOCIRCUIT_MAX_BUILD_RETRY 10

typedef struct _lor_autocircuit_t {
  lor_dir_t *dir;
} lor_autocircuit_t;


/* Standard functions */
lor_autocircuit_t* lor_autocircuit_new();
void lor_autocircuit_free( lor_autocircuit_t *ac );

/* Hidden service helpers */
int lor_autocircuit_get_hsdesc( lor_autocircuit_t *ac, char *onion, lor_hs_desc_t *hs_desc );

/* Directory functions */
int lor_autocircuit_dir_update( lor_autocircuit_t *ac );
int lor_autocircuit_fetch_consensus( lor_autocircuit_t *ac, lor_circuit_t *circ );
int lor_autocircuit_fetch_microdesc( lor_autocircuit_t *ac, lor_circuit_t *circ, uint32_t offset, uint32_t n );


/* Circuit building functions */
int lor_autocircuit_build_fp( lor_autocircuit_t *ac, lor_circuit_t *circ, unsigned char *fp, int fast );
int lor_autocircuit_build_dir( lor_autocircuit_t *ac, lor_circuit_t *circ );
int lor_autocircuit_build_dir_auth( lor_circuit_t *circ );

int lor_autocircuit_build_rend( lor_autocircuit_t *ac, lor_circuit_t *circ );
int lor_autocircuit_build_hs( lor_autocircuit_t *ac, char *onion, uint16_t port, lor_circuit_t *rend_circ );
int lor_autocircuit_build_fast( lor_autocircuit_t *ac, lor_circuit_t *circ, uint32_t ip, uint16_t port, unsigned char *fp );
int lor_autocircuit_build( lor_autocircuit_t *ac, lor_circuit_t *circ, uint32_t ip, uint16_t port, unsigned char *ntor_onion_key, lor_rsa_t *onion_key, unsigned char *fp );

#endif
