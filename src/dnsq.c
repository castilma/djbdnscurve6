#include "uint_t.h"
#include "logmsg.h"
#include "buffer.h"
#include "scan.h"
#include "str.h"
#include "byte.h"
#include "ip.h"
#include "iopause.h"
#include "printpacket.h"
#include "parsetype.h"
#include "dns.h"
#include "ip.h"
#include "exit.h"
#include "curvedns.h"

#define WHO "dnsq"

void usage(void)
{
  logmsg(WHO,100,USAGE,"type name server");
}
void oops(void)
{
  logmsg(WHO,111,FATAL,"unable to parse");
}

static struct dns_transmit tx;

int resolve(char *q,char qtype[2],char servers[QUERY_MAXIPLEN])
{
  struct taia stamp;
  struct taia deadline;
  iopause_fd x[1];
  int r;

  if (cns_transmit_start(&tx,servers,0,q,qtype,V6any,0,0,0) < 0) return DNS_COM;

  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline,120);
    taia_add(&deadline,&deadline,&stamp);
    dns_transmit_io(&tx,x,&deadline);
    iopause(x,1,&deadline,&stamp);
    r = dns_transmit_get(&tx,x,&stamp);
    if (r < 0) return DNS_ERR;
    if (r == 1) break;
  }

  return 0;
}

char servers[QUERY_MAXIPLEN];
static stralloc ip;
static stralloc fqdn;

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

  if (!*++argv) usage();
  if (!stralloc_copys(&out,*argv)) oops();
  if (dns_ip_qualify(&ip,&fqdn,&out) < 0) oops();
  if (ip.len >= QUERY_MAXIPLEN) ip.len = QUERY_MAXIPLEN;
  byte_zero(servers,QUERY_MAXIPLEN);
  byte_copy(servers,ip.len,ip.s);

  if (!stralloc_copys(&out,"")) oops();
  uint16_unpack_big(type,&u16);
  if (!stralloc_catulong0(&out,u16,0)) oops();
  if (!stralloc_cats(&out," ")) oops();
  if (dns_domain_todot_cat(&out,q) <= 0) oops();
  if (!stralloc_cats(&out,":\n")) oops();

  if (resolve(q,type,servers) < 0) {
    if (!stralloc_cats(&out,errstr(errno))) oops();
    if (!stralloc_cats(&out,"\n")) oops();
  }
  else {
    if (!printpacket_cat(&out,tx.packet,tx.packetlen)) oops();
  }

  buffer_putflush(buffer_1,out.s,out.len);
  _exit(0);
}
