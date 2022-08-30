#include "str.h"
#include "byte.h"
#include "scan.h"
#include "exit.h"
#include "stralloc.h"
#include "buffer.h"
#include "logmsg.h"
#include "uint_t.h"
#include "response.h"
#include "case.h"
#include "printpacket.h"
#include "parsetype.h"
#include "ip.h"
#include "dns.h"

extern int respond(char *,char *,char *);
int rename(const char *,const char *);  // keep compiler silent

#define WHO "tinydns-get "

void usage(void)
{
  logmsg(WHO,100,USAGE,"tinydns-get type name [ip]");
}
void oops(void)
{
  logmsg(WHO,111,FATAL,"unable to parse");
}

static char ip[16];
static char type[2];
static char *q;

static stralloc out;

int main(int argc,char **argv)
{
  uint16 u16;

  if (!*argv) usage();

  if (!*++argv) usage();
  if (!parsetype(*argv,type)) usage();

  if (!*++argv) usage();
  if (dns_domain_fromdot(&q,*argv,str_len(*argv)) <= 0) oops();

  if (*++argv) 
    if (!ip6_scan(*argv,ip)) usage();

  if (!stralloc_copys(&out,"")) oops();
  uint16_unpack_big(type,&u16);
  if (!stralloc_catulong0(&out,u16,0)) oops();
  if (!stralloc_cats(&out," ")) oops();
  if (dns_domain_todot_cat(&out,q) <= 0) oops();
  if (!stralloc_cats(&out,":\n")) oops();

  if (!response_query(q,type,DNS_C_IN)) oops();
  response[3] &= ~128;
  response[2] &= ~1;
  response[2] |= 4;
  case_lowerb(q,dns_domain_length(q));

  if (byte_equal(type,2,DNS_T_AXFR)) {
    response[3] &= ~15;
    response[3] |= 4;
  }
  else
    if (!respond(q,type,ip)) goto DONE;

  if (!printpacket_cat(&out,response,response_len)) oops();

  DONE:
  buffer_putflush(buffer_1,out.s,out.len);
  _exit(0);
}
