#ifndef HEXMISC_H
#define HEXMISC_H

#include "unit_t.h"

int char2hex(char,uint8 *);
int hex2char(uint8,char *);
int hex_decode(const char *,uint8 *);
int hex_encode(const uint8 *,int,char *,int);

#endif
