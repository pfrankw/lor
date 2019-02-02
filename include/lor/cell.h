#ifndef LOR_CELL_H
#define LOR_CELL_H

#include <stdint.h>

/* Fixed length CELLs */
#define LOR_CELL_PADDING 0
#define LOR_CELL_CREATE 1
#define LOR_CELL_CREATED 2
#define LOR_CELL_RELAY 3
#define LOR_CELL_DESTROY 4
#define LOR_CELL_CREATE_FAST 5
#define LOR_CELL_CREATED_FAST 6
#define LOR_CELL_NETINFO 8
#define LOR_CELL_NETINFO_SIZE 60
#define LOR_CELL_RELAY_EARLY 9
#define LOR_CELL_CREATE2 10
#define LOR_CELL_CREATED2 11

/* Variable length CELLs */
#define LOR_CELL_VERSIONS 7
#define LOR_CELL_VPADDING 128
#define LOR_CELL_CERTS 129
#define LOR_CELL_AUTH_CHALLENGE 130
#define LOR_CELL_AUTHENTICATE 131
#define LOR_CELL_AUTHORIZE 132

#define LOR_PAYLOAD_LEN 509

typedef struct __attribute__((__packed__)) _lor_cell_header_v3 {
  uint16_t circ_id;
  uint8_t command;
  uint16_t length;
} lor_cell_header_v3;

typedef struct __attribute__((__packed__)) _lor_cell_header {
  uint32_t circ_id;
  uint8_t command;
  uint16_t length;
} lor_cell_header;


#endif
