#ifndef CURVEDNS_H
#define CURVEDNS_H

#include "alloc.h"
#include "ip.h"
#include "socket_if.h"
#include "dns.h"
#include "query.h"

#define DNSPORT 53

extern unsigned int fallback;
extern unsigned int flagedserver;

/* NACL routines */

#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "crypto_scalarmult_curve25519.h"

#define crypto_scalarmult_base crypto_scalarmult_curve25519_base
#define crypto_box_beforenm crypto_box_curve25519xsalsa20poly1305_beforenm

#define crypto_box_afternm crypto_box_curve25519xsalsa20poly1305_afternm
#define crypto_box_open_afternm crypto_box_curve25519xsalsa20poly1305_open_afternm

/* dnscache genuine Curved caching NS routines */

void cns_query(struct dns_transmit *);
void dns_basequery(struct dns_transmit *,char *); 
int cns_addns(struct query *,const char *,int,const char *);
void cns_sortns(char *,char *,unsigned int);
void cns_nonce(char [12]);
int cns_pubkey(const char *,char [32]);
int cns_uncurve(const struct dns_transmit *,char *,unsigned int *); 
int cns_transmit_start(struct dns_transmit *,const char [512],int,const char *,const char [2], \
                       const char [16],const char [1024],const char [32],const char *);

#endif
