/* cns_transmit_start returns DNS_COM */

#include <stdio.h>
#include "alloc.h"
#include "byte.h"
#include "uint_t.h"
#include "case.h" 
#include "dns.h"
#include "curvedns.h"
#include "base32.h"
#include "query.h"
#include "socket_if.h"
#include "ip.h"
#include "error.h"
#include "serverok.h"
#include "log.h"

#define SET_EDNS0 2
#define SET_DNSSEC 0
#define OPT_RR 41

unsigned int flagedserver;
unsigned int fallback;

void cns_nonce(char nonce[12])
{
  int i; 

  for (i = 0; i < 12; i++)
    nonce[i] = dns_random(256);
}

/* Generate standard DNS query message */

void dns_basequery(struct dns_transmit *d,char *query)
{
  unsigned int len;

  len = dns_domain_length(d->name);

  byte_copy(query,2,d->nonce + 8);      
  /*                  Parameter Mapping:     1: Query;  1: #Queries; 1: #AddSec */
  byte_copy(query + 2,10,d->flagrecursive ? "\1\0\0\1\0\0\0\0\0\0" : \
                                            "\0\0\0\1\0\0\0\0\0\0gcc-bug-workaround");
  byte_copy(query + 12,len,d->name);
  byte_copy(query + 12 + len,2,d->qtype);
  byte_copy(query + 14 + len,2,DNS_C_IN);
}

/* Generate DNSCurve format query message */

void cns_query(struct dns_transmit *d)
{
  unsigned int len;
  char nonce[24];
  const char *key;
  unsigned int m;
  unsigned int suffixlen;

  cns_nonce(d->nonce);

  if (!d->keys) {
    byte_copy(d->query + 2,2,d->nonce + 8);
    return;
  }

  len = dns_domain_length(d->name);

  byte_copy(nonce,12,d->nonce);
  byte_zero(nonce + 12,12);
  key = d->keys + 32 * d->curserver;

  byte_zero(d->query,32);
  dns_basequery(d,d->query + 32);

  crypto_box_afternm((unsigned char *) d->query,(const unsigned char *) d->query,len + 48, \
                     (const unsigned char *) nonce,(const unsigned char *) key);

  if (!d->suffix) {
    byte_copyr(d->query + 54,len + 32,d->query + 16);
    uint16_pack_big(d->query,len + 84);
    byte_copy(d->query + 2,8,"Q6fnvWj8");
    byte_copy(d->query + 10,32,d->pubkey);
    byte_copy(d->query + 42,12,nonce);
    return;
  }

  byte_copyr(d->query + d->querylen - len - 32,len + 32,d->query + 16);
  byte_copy(d->query + d->querylen - len - 44,12,nonce);

  suffixlen = dns_domain_length(d->suffix);
  m = base32_bytessize(len + 44);

  uint16_pack_big(d->query,d->querylen - 2);
  d->query[2] = dns_random(256);
  d->query[3] = dns_random(256);
  byte_copy(d->query + 4,10,"\0\0\0\1\0\0\0\0\0\0");
  base32_encode(d->query + 14,d->query + d->querylen - len - 44,len + 44);
  base32_clientkey(d->query + 14 + m,d->pubkey);
  byte_copy(d->query + 69 + m,suffixlen,d->suffix);
  byte_copy(d->query + 69 + m + suffixlen,4,DNS_T_TXT DNS_C_IN);
}

int cns_uncurve(const struct dns_transmit *d,char *buf,unsigned int *lenp)
{
  const char *key;
  char nonce[24];
  unsigned int len;
  char out[16];
  unsigned int pos;
  uint16 datalen;
  unsigned int i;
  unsigned int j;
  char ch;
  unsigned int txtlen;
  unsigned int namelen;

  if (!d->keys) return 0;

  key = d->keys + 32 * d->curserver;
  len = *lenp;

  if (!d->suffix) {
    if (len < 48) return 1;
    if (byte_diff(buf,8,"R6fnvWJ8")) return 1;
    if (byte_diff(buf + 8,12,d->nonce)) return 1;
    byte_copy(nonce,24,buf + 8);
    byte_zero(buf + 16,16);

    if (crypto_box_open_afternm((uint8 *) buf + 16,(const uint8 *) buf + 16,len - 16, \
                                (const uint8 *) nonce,(const uint8 *) key)) return 1;
    byte_copy(buf,len - 48,buf + 48);
    *lenp = len - 48;
    return 0;
  }

  /* XXX: be more leniant? */

  pos = dns_packet_copy(buf,len,0,out,12); if (!pos) return 1;
  if (byte_diff(out,2,d->query + 2)) return 1;
  if (byte_diff(out + 2,10,"\204\0\0\1\0\1\0\0\0\0")) return 1;

  /* query name might be >255 bytes, so can't use dns_packet_getname */
  namelen = dns_domain_length(d->query + 14);
  pos += namelen;

  pos = dns_packet_copy(buf,len,pos,out,16); if (!pos) return 1;
  if (byte_diff(out,14,"\0\20\0\1\300\14\0\20\0\1\0\0\0\0")) return 1;
  uint16_unpack_big(out + 14,&datalen);
  if (datalen > len - pos) return 1;

  j = 4;
  txtlen = 0;
  for (i = 0; i < datalen; ++i) {
    ch = buf[pos + i];
    if (!txtlen)
     txtlen = (unsigned char) ch;
    else {
      --txtlen;
      buf[j++] = ch;
    }
  }
  if (txtlen) return 1;

  if (j < 32) return 1;
  byte_copy(nonce,12,d->nonce);
  byte_copy(nonce + 12,12,buf + 4);
  byte_zero(buf,16);

  if (crypto_box_open_afternm((unsigned char *) buf,(const unsigned char *) buf,j, \
                              (const unsigned char *) nonce,(const unsigned char *) key)) return 1;
  byte_copy(buf,j - 32,buf + 32);
  *lenp = j - 32;

  return 0;
}

int cns_pubkey(const char *dn,char key[32])
{
  unsigned char c;

  while ((c = *dn++)) {
    if (c == 54)
      if (!case_diffb(dn,3,"uz5")) 
        if (base32_decode(key,dn + 3,51,1) == 32)
          return 1;
    dn += (unsigned int) c;
  }
  return 0;
}

void cns_sortns(char *s,char *t,unsigned int n)
{
  unsigned int i;
  char tmp[32];

  /* s = ipaddres, t = pubkey, n = #NS */

  while (n > 1) {
    i = dns_random(n);
    --n;
    byte_copy(tmp,16,s + (i << 4));
    byte_copy(s + (i << 4),16,s + (n << 4));
    byte_copy(s + (n << 4),16,tmp);

    byte_copy(tmp,32,t + (i << 5));
    byte_copy(t + (i << 5),32,t + (n << 5));
    byte_copy(t + (n << 5),32,tmp);
  }
}

int cns_addns(struct query *z,const char *addr,int flagnskey,const char *key)
{
  int k;
  int flagns = 0;

  if (flagedserver) {
    flagns = serverok(addr);
    if (flagns == 1) return 1; 
    if (flagns == -1) flagnskey = 0;
  }

  if (z->flagnskeys[z->level - 1]) {
    if (!flagnskey) goto IPONLY;
  } else if (flagnskey) {
    byte_zero(z->servers[z->level - 1],QUERY_MAXIPLEN);
    byte_zero(z->keys[z->level - 1],1024);
    z->flagnskeys[z->level - 1] = 1;
  }

  IPONLY:

  for (k = 0; k < QUERY_MAXIPLEN; k += 16) {
    if (byte_equal(z->servers[z->level - 1] + k,16,addr)) return flagns;
    if (byte_equal(z->servers[z->level - 1] + k,16,V6localnet)) {
      byte_copy(z->servers[z->level - 1] + k,16,addr);
      if (flagnskey) byte_copy(z->keys[z->level - 1] + 2 * k,32,key);

      break;
    }
  }

  return flagns;  
}

int cns_transmit_start(struct dns_transmit *d,const char servers[QUERY_MAXIPLEN], \
                       int flagrecursive,const char *q,const char qtype[2], \
                       const char localip[16],\
                       const char keys[1024],const char pubkey[32],const char *suffix)
{
  unsigned int len;
  unsigned int suffixlen;
  unsigned int m;

  dns_transmit_free(d);
  errno = EIO;
  len = dns_domain_length(q);

  if (!keys) {
    d->querylen = len + 18; 
  } else if (!suffix)
    d->querylen = len + 86;
  else {
    suffixlen = dns_domain_length(suffix);
    m = base32_bytessize(len + 44);
    d->querylen = m + suffixlen + 73;
  }

  d->query = alloc(d->querylen);
  if (!d->query) return DNS_MEM;

  d->name = q;
  byte_copy(d->qtype,2,qtype);
  d->servers = servers;
  byte_copy(d->localip,16,localip);
  d->flagrecursive = flagrecursive;
  d->keys = keys;
  d->pubkey = pubkey;
  d->suffix = suffix;

  if (!d->keys) {
    uint16_pack_big(d->query,len + 16); 
    dns_basequery(d,d->query + 2);
    d->name = d->query + 14; /* keeps dns_transmit_start backwards compatible */
  }
  d->udploop = flagrecursive ? 1 : 0;

  if (len > MSGSIZE - 16) return firsttcp(d);

  return firstudp(d);
}
