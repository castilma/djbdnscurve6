#include <unistd.h>
#include "str.h"
#include "byte.h"
#include "ip.h"
#include "open.h"
#include "env.h"
#include "cdbread.h"
#include "dns.h"
#include "dd.h"
#include "response.h"
#include "logmsg.h"
#include "uint_t.h"
#include "scan.h"

#define WHO "rbldns"
const char *fatal = "rbldns";
int flagcurved;

static char *base;

static struct cdb c;
static char data[100 + IP6_FMT];

static int doit(char *q,char qtype[2])
{
  int flaga;
  int flaga4;
  int flagtxt;
  int flagip6;
  char ch;
  char reverseip4[4];
  char reverseip6[16];
  char ip4[4];	
  char ip5[16]; /* aehm */
  char ip6[16];
  uint32 ipnum4;
  uint64 ipnum5; /* aehm */
  struct uint128_t ipnum6;
  uint32 dlen;
  int r;
  int i;
  stralloc ipstring = {0};
  stralloc tmp = {0};

  flaga = byte_equal(qtype,2,DNS_T_A);
  flaga4 = byte_equal(qtype,2,DNS_T_AAAA);
  flagtxt = byte_equal(qtype,2,DNS_T_TXT);
  if (byte_equal(qtype,2,DNS_T_ANY)) flaga = flaga4 = flagtxt = 1;
  if (!(flaga || flaga4) && !flagtxt) goto REFUSE;

  if (flaga || flagtxt) {
    r = dd4(q,base,reverseip4);
    if (r < 0) goto IPV6;
    if (r != 4) goto REFUSE;
    uint32_unpack(reverseip4,&ipnum4);
    uint32_pack_big(ip4,ipnum4);
    if (ip4_bytestring(&ipstring,ip4,32)) return 0;

    for (i = 32; i > 0; --i) {
      if (!stralloc_copys(&tmp,"")) return 0;
      if (!stralloc_catb(&tmp,ipstring.s,i)) return 0;
      r = cdb_find(&c,tmp.s,i);
      if (r == -1) return 0;
      if (r) goto BASE;
    }
    if (!r) { response_nxdomain(); return 1; }
  }


  IPV6:
  if (flaga4 || flagtxt) {
    flagip6 = 1;
    if (dd6(q,base,reverseip6) != 16) goto REFUSE;

    uint128_unpack(reverseip6,&ipnum6);	// IPv6 incl. link token 
    uint128_pack_big(ip6,ipnum6);
    if (ip6_bytestring(&ipstring,ip6,128)) return 0;
    if (!stralloc_copys(&tmp,"^")) return 0;
    if (!stralloc_catb(&tmp,ipstring.s,128)) return 0;
    r = cdb_find(&c,tmp.s,129);
    if (r) goto BASE;

    uint64_unpack(reverseip6+8,&ipnum5); // IPv6 net-id only
    uint64_pack_big(ip5,ipnum5);
    if (ip6_bytestring(&ipstring,ip5,64)) return 0;

    for (i = 64; i > 0; --i) {
      if (!stralloc_copys(&tmp,"^")) return 0;
      if (!stralloc_catb(&tmp,ipstring.s,i)) return 0;
      r = cdb_find(&c,tmp.s,i);
      if (r == -1) return 0;
      if (r) goto BASE;
    }
    if (!r) { response_nxdomain(); return 1; }
  } 


  BASE:  
  r = cdb_find(&c,"",0);
  if (r == -1) return 0;
  if (r && ((dlen = cdb_datalen(&c)) >= 4)) {
    if (dlen > 256) dlen = 256;
    if (cdb_read(&c,data,dlen,cdb_datapos(&c)) == -1) return 0;
  }
  else {
    dlen = 12;
    byte_copy(data,dlen,"\177\0\0\2Listed $");
  }

  if ((dlen >= 5) && (data[dlen - 1] == '$')) {
    --dlen;
    if (flagip6) 
      dlen += ip6_fmt(data + dlen,ip6);
    else 
      dlen += ip4_fmt(data + dlen,ip4);
  }

  if (flaga) {
    if (!response_rstart(q,DNS_T_A,2048)) return 0;
    if (!response_addbytes(data,4)) return 0;
    response_rfinish(RESPONSE_ANSWER);
  }
  if (flaga4) {
    if (!response_rstart(q,DNS_T_AAAA,2048)) return 0;
    if (!response_addbytes(data,16)) return 0;
    response_rfinish(RESPONSE_ANSWER);
  }
  if (flagtxt) {
    if (!response_rstart(q,DNS_T_TXT,2048)) return 0;
    ch = dlen - 4;
    if (!response_addbytes(&ch,1)) return 0;
    if (!response_addbytes(data + 4,dlen - 4)) return 0;
    response_rfinish(RESPONSE_ANSWER);
  }

  return 1;


  REFUSE:
  response[2] &= ~4;
  response[3] &= ~15;
  response[3] |= 5;
  return 1;
}

int respond(char *q,char qtype[2],char ip[16])
{
  int fd;
  int result;

  fd = open_read("data.cdb");
  if (fd == -1) return 0;
  cdb_init(&c,fd);
  result = doit(q,qtype);
  cdb_free(&c);
  close(fd);
  return result;
}

const char *starting = "starting rbldns ";

void init_server(void)
{
  char *x;

  x = env_get("BASE");
  if (!x)
    logmsg(WHO,111,ERROR,"$BASE not set");
  if (dns_domain_fromdot(&base,x,str_len(x)) <= 0)
    logmsg(WHO,111,FATAL,"unable to parse $BASE"); 
}
