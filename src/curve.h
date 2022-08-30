#ifndef CURVE_H
#define CURVE_H

#include "uint_t.h"

 /* NACL routines */
 
#include "crypto_box.h"

#define crypto_scalarmult_base crypto_scalarmult_curve25519_base
#define crypto_box_keypair crypto_box_curve25519xsalsa20poly1305_keypair
#define crypto_box_beforenm crypto_box_curve25519xsalsa20poly1305_beforenm

#define crypto_box_afternm crypto_box_curve25519xsalsa20poly1305_afternm
#define crypto_box_open_afternm crypto_box_curve25519xsalsa20poly1305_open_afternm

extern int flagcurved;

void curve_nonce(uint8 [12]);

int dns_curve_query(const char *,const unsigned int,const unsigned int);
int dns_curve_pubkey(uint8 *,const char *,const unsigned int);
int dns_curve_nonce(uint8 *,const char *,const unsigned int);
int dns_curve_cryptobox(uint8 *,const char *,const unsigned int,const unsigned int);

int dns_curve_txtquery(const char *,unsigned int,unsigned int);
int dns_curve_txtqname(uint8 *,const char *,const unsigned int);
int dns_curve_txtpubkey(uint8 *,const char *,const unsigned int);
int dns_curve_txtnonce(uint8 *,const unsigned char *);

int response_stream(const uint8 *,const uint8 *);
int response_alttxt(const uint8 *,const uint8 *,const char [2],const unsigned char *,const unsigned int,const int);

/* dns_random.c */

void surf(void);
void dns_random_init(const char [12]);
unsigned int dns_random(unsigned int);
void randombytes(uint8 *,unsigned long long);
int crypto_random_init(void);

#endif
