#include "uint_t.h"
#include "buffer.h"
#include "scan.h"
#include "str.h"
#include "byte.h"
#include "logmsg.h"
#include "printpacket.h"
#include "parsetype.h"
#include "dns.h"
#include "exit.h"
#include "base32.h"

#define WHO "dnsqr"

void usage(void)
{
  logmsg(WHO,100,USAGE,"type name");
}
void oops(void)
{
  logmsg(WHO,111,FATAL,"unable to parse");
}

char type[2];
static char *q;

static stralloc out;

static char seed[128];

int main(int argc,char **argv)
{
  uint16 u16;

  dns_random_init(seed);

  if (!*argv) usage();
  if (!*++argv) usage();
  if (!parsetype(*argv,type)) usage();

  if (!*++argv) usage();
  if (dns_domain_fromdot(&q,*argv,str_len(*argv)) <= 0) oops();

  if (*++argv) usage();

  if (!stralloc_copys(&out,"")) oops();
  uint16_unpack_big(type,&u16);
  if (!stralloc_catulong0(&out,u16,0)) oops();
  if (!stralloc_cats(&out," ")) oops();
  if (dns_domain_todot_cat(&out,q) <= 0) oops();
  if (!stralloc_cats(&out,":\n")) oops();

  if (dns_resolve(q,type) < 0) {
    if (!stralloc_cats(&out,errstr(errno))) oops();
    if (!stralloc_cats(&out,"\n")) oops();
  }
  else {
    if (dns_resolve_tx.packetlen < 4) oops();
    dns_resolve_tx.packet[2] &= ~1;
    dns_resolve_tx.packet[3] &= ~128;
    if (!printpacket_cat(&out,dns_resolve_tx.packet,dns_resolve_tx.packetlen)) oops();
  }

  buffer_putflush(buffer_1,out.s,out.len);
  _exit(0);
}
