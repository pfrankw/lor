#include "lor/base32.h"

void base32_encode(char *dest, size_t destlen, unsigned char *src, size_t srclen)
{
  unsigned int i, v, u;
  size_t nbits = srclen * 8, bit;

  assert(srclen < SIZE_T_CEILING/8);
  assert((nbits%5) == 0); /* We need an even multiple of 5 bits. */
  assert((nbits/5)+1 <= destlen); /* We need enough space. */
  assert(destlen < SIZE_T_CEILING);

  for (i=0,bit=0; bit < nbits; ++i, bit+=5) {
    /* set v to the 16-bit value starting at src[bits/8], 0-padded. */
    v = ((uint8_t)src[bit/8]) << 8;
    if (bit+5<nbits) v += (uint8_t)src[(bit/8)+1];
    /* set u to the 5-bit value at the bit'th bit of src. */
    u = (v >> (11-(bit%8))) & 0x1F;
    dest[i] = BASE32_CHARS[u];
  }
  dest[i] = '\0';
}

/** Implements base32 decoding as in RFC 4648.  Limitation: Requires
 * that srclen*5 is a multiple of 8. Returns 0 if successful, -1 otherwise.
 */
int base32_decode(unsigned char *dest, size_t destlen, const char *src, size_t srclen)
{
  /* XXXX we might want to rewrite this along the lines of base64_decode, if
   * it ever shows up in the profile. */
  unsigned int i;
  size_t nbits, j, bit;
  char *tmp;
  nbits = srclen * 5;

  assert(srclen < SIZE_T_CEILING / 5);
  assert((nbits%8) == 0); /* We need an even multiple of 8 bits. */
  assert((nbits/8) <= destlen); /* We need enough space. */
  assert(destlen < SIZE_T_CEILING);

  memset(dest, 0, destlen);

  /* Convert base32 encoded chars to the 5-bit values that they represent. */
  tmp = malloc(srclen);
  memset( tmp, 0, srclen );
  for (j = 0; j < srclen; ++j) {
    if (src[j] > 0x60 && src[j] < 0x7B) tmp[j] = src[j] - 0x61;
    else if (src[j] > 0x31 && src[j] < 0x38) tmp[j] = src[j] - 0x18;
    else if (src[j] > 0x40 && src[j] < 0x5B) tmp[j] = src[j] - 0x41;
    else {
      free(tmp);
      return -1;
    }
  }

  /* Assemble result byte-wise by applying five possible cases. */
  for (i = 0, bit = 0; bit < nbits; ++i, bit += 8) {
    switch (bit % 40) {
    case 0:
      dest[i] = (((uint8_t)tmp[(bit/5)]) << 3) +
                (((uint8_t)tmp[(bit/5)+1]) >> 2);
      break;
    case 8:
      dest[i] = (((uint8_t)tmp[(bit/5)]) << 6) +
                (((uint8_t)tmp[(bit/5)+1]) << 1) +
                (((uint8_t)tmp[(bit/5)+2]) >> 4);
      break;
    case 16:
      dest[i] = (((uint8_t)tmp[(bit/5)]) << 4) +
                (((uint8_t)tmp[(bit/5)+1]) >> 1);
      break;
    case 24:
      dest[i] = (((uint8_t)tmp[(bit/5)]) << 7) +
                (((uint8_t)tmp[(bit/5)+1]) << 2) +
                (((uint8_t)tmp[(bit/5)+2]) >> 3);
      break;
    case 32:
      dest[i] = (((uint8_t)tmp[(bit/5)]) << 5) +
                ((uint8_t)tmp[(bit/5)+1]);
      break;
    }
  }

  memset(tmp, 0, srclen); /* on the heap, this should be safe */
  free(tmp);
  tmp = NULL;
  return 0;
}
