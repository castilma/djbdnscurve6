#ifndef _BASE32_H
#define _BASE32_H
#include "uint_t.h"

unsigned int base32_bytessize(unsigned int);
unsigned int base32_decode(uint8 *,const char *,unsigned int,int);
unsigned int base32_serverkey(uint8 *,const char *,unsigned int);
void base32_encode(uint8 *,const char *,unsigned int);
void base32_clientkey(uint8 *,const char *);

/* hex.c */

int hex_encode(const uint8 *,int,char *,int);
int hex_decode(const char *,uint8 *);

#endif
