#include <sys/types.h>
#include <string.h>
#include "base32.h"
#include "byte.h"
#include "uint_t.h"
#include "errno.h"

/* DNSCurve uses its own sophomoric base32 implementation:

 1. base32_encode: used for DNS labels
 2. base32_clientkey: used for client key generation only
 3. base32_serverkey: used for server key generation only
 3. base32_decode: additional 'mode' to decode all 

 Note: This implementation is neither RFC 3548 nor 4684 compatible!
*/

/*
  Algorithm & Alfabet:

  base32_char = '0123456789bcdfghjklmnpqrstuvwxyz'
  ','.join('%2d' % base32_char.find(chr(x).lower()) for x in xrange(256))
  x < 128; otherwise invalid
*/

static const char base32_char[32] = "0123456789bcdfghjklmnpqrstuvwxyz";

static const uint8 base32_map[128] = { 
//   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99, // 0
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99, // 1
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99, // 2
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,99,99,99,99,99,99, // 3
    99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99, // 4
    21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99, // 5
    99,99,10,11,12,99,13,14,15,99,16,17,18,19,20,99, // 6
    21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99  // 7
};

unsigned int base32_bytessize(unsigned int len)
{
  len = (8 * len + 4) / 5;
  return len + (len + 49) / 50;
}
 
unsigned int base32_decode(uint8 *out,const char *in,unsigned int len,int mode)
{
  unsigned int i;
  unsigned int j;
  unsigned int v;
  unsigned int bits;
  uint8 x;

  i = j = v = bits = 0;

  for (i = 0; i < len; ++i) {
    if (in[i] & 0x80) return 0;
    x = base32_map[(uint8) in[i]];
    if (x > 31) return 0;
    v |= ((unsigned) x) << bits;
    bits += 5;

    if (bits >= 8) {
      out[j++] = v;
      v >>= 8;
      bits -= 8;
    }
  }
  if (mode && bits) {
    out[j++] = v;
  } else if (bits >= 5 || v)
    return 0;

  return j;
}

void base32_encode(uint8 *out,const char *in,unsigned int len)
{
  unsigned int i;
  unsigned int x;
  unsigned int v;
  unsigned int bits;
 
  x = v = bits = 0;

  for (i = 0; i < len; ++i) {
    v |= ((unsigned int) (uint8) in[i]) << bits;
    bits += 8;

    do {
      out[++x] = base32_char[v & 31];
      v >>= 5;
      bits -= 5;
      if (x == 50) {  // new label 
        *out = x;
        out += 1 + x;
        x = 0;
      }   
    } while (bits >= 5); 
  }

  if (bits) out[++x] = base32_char[v & 31];
  if (x) *out = x;
}

void base32_clientkey(uint8 *out,const char *key)
{ 
  unsigned int i;
  unsigned int v;  
  unsigned int bits;

  byte_copy(out,4,"\66x1a");
  out += 4;
  v = bits = 0;

  for (i = 0; i < 32; ++i) {
    v |= ((unsigned int) (uint8) key[i]) << bits;
    bits += 8;
    do {
      *out++ = base32_char[v & 31];
      v >>= 5;
      bits -= 5;
    } while (bits >= 5); 
  }
}

unsigned int base32_serverkey(uint8 *out,const char *in,unsigned int len) 
{
  unsigned int i = 0;
  unsigned int j = 0;
  unsigned int v = 0;
  unsigned int bits = 0;

  while (j < len) {
    v |= ((uint8) in[j++]) << bits;
    bits += 8;

    while (bits >= 5) {
      out[i++] = base32_char[v & 31];
      bits -= 5;
      v >>= 5;
    }
  }

  if (bits) 
    out[i++] = base32_char[v & 31];

  return i;
}
