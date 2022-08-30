#include <string.h>
#include "byte.h"
#include "uint_t.h"

int char2hex(char in,uint8 *out) 
{
  if ((in >= '0') && (in <= '9')) {
    *out = in - '0';
    return 1;
  } else if ((in >= 'a') && (in <= 'f')) {
    *out = 10 + (in - 'a');
    return 1;
  } else if ((in >= 'A') && (in <= 'F')) {
    *out = 10 + (in - 'A');
    return 1;
  } else {
    return 0;
  }
}

int hex2char(uint8 in,char *out) 
{
  if (in < 10) *out = in + '0';
  else if (in < 16) *out = (in - 10) + 'a';
  else return 0;

  return 1;
}

int hex_decode(const char *src,uint8 *dst) 
{
 uint8 v1, v2; 

  while (*src) {
    if (!char2hex(*src++,&v1)) return 0;
    if (!char2hex(*src++,&v2)) return 0;
    *dst++ = (v1 << 4) | v2; 
  }
  return 1;
}

int hex_encode(const uint8 *src,int srclen,char *dst,int dstlen) 
{
  int i;

  byte_zero(dst,dstlen);
  if ((srclen * 2) < dstlen) return 0;

  for (i = 0; i < srclen; i++) {
    if (!hex2char(src[i] >> 4,dst)) return 0;
    dst++;
    if (!hex2char(src[i] & 0xf,dst)) return 0;
    dst++;
  }
  return 1;
}
