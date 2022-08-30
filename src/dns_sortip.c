#include "byte.h"
#include "ip.h"
#include "dns.h"

/* XXX: sort servers by configurable notion of closeness? */
/* XXX: pay attention to competence of each server? */
/* XXX: pay attention to qualification (DNSSec, DNSCurve) of each server? */
/* YYY: we use a randomly sorted list of NS; not depending on answer */

void dns_sortip4(char *s,unsigned int n)
{
  unsigned int i;
  char tmp[4];

  n >>= 2;	/* 4 byte per IPv4 address */
  while (n > 1) {
    i = dns_random(n);
    --n;
    byte_copy(tmp,4,s + (i << 2));
    byte_copy(s + (i << 2),4,s + (n << 2));
    byte_copy(s + (n << 2),4,tmp);
  }
}

void dns_sortip6(char *s,unsigned int n)
{
  unsigned int i;
  char tmp[16];

  n >>= 4;	/* 16 byte per IPv4 address */
  while (n > 1) {
    i = dns_random(n);
    --n;
    byte_copy(tmp,16,s + (i << 4));
    byte_copy(s + (i << 4),16,s + (n << 4));
    byte_copy(s + (n << 4),16,tmp);
  }
}
