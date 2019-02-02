#ifndef LOR_RCELL_H
#define LOR_RCELL_H

#include <stdint.h>

#include <lor/cell.h>

#define LOR_RELAY_BEGIN 1
#define LOR_RELAY_DATA 2
#define LOR_RELAY_END 3
#define LOR_RELAY_CONNECTED 4
#define LOR_RELAY_SENDME 5
#define LOR_RELAY_EXTEND 6
#define LOR_RELAY_EXTENDED 7
#define LOR_RELAY_TRUNCATE 8
#define LOR_RELAY_TRUNCATED 9
#define LOR_RELAY_DROP 10
#define LOR_RELAY_RESOLVE 11
#define LOR_RELAY_RESOLVED 12
#define LOR_RELAY_BEGIN_DIR 13
#define LOR_RELAY_EXTEND2 14
#define LOR_RELAY_EXTENDED2 15

#define LOR_RELAY_ESTABLISH_INTRO 32
#define LOR_RELAY_ESTABLISH_RENDEZVOUS 33
#define LOR_RELAY_ESTABLISH_INTRODUCE1 34
#define LOR_RELAY_ESTABLISH_INTRODUCE2 35
#define LOR_RELAY_ESTABLISH_RENDEZVOUS1 36
#define LOR_RELAY_ESTABLISH_RENDEZVOUS2 37
#define LOR_RELAY_INTRO_ESTABLISHED 38
#define LOR_RELAY_RENDEZVOUS_ESTABLISHED 39
#define LOR_RELAY_INTRODUCE_ACK 40

typedef struct __attribute__((__packed__)) _lor_rcell_t {
  uint8_t command;
  uint16_t recognized;
  uint16_t stream_id;
  uint8_t digest[4];
  uint16_t length;
  unsigned char data[LOR_PAYLOAD_LEN-11];
} lor_rcell_t;

#endif
