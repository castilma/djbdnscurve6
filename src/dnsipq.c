#include "buffer.h"
#include "exit.h"
#include "logmsg.h"
#include "ip.h"
#include "dns.h"

#define WHO "dnsipq"

static char seed[128];

static stralloc in;
static stralloc fqdn;
static stralloc out;
char ip4[IP4_FMT];
char ip6[IP6_FMT];

int main(int argc,char **argv)
{
  int i;

  dns_random_init(seed);

  if (*argv) ++argv;

  while (*argv) {
    if (!stralloc_copys(&in,*argv))
      logmsg(WHO,111,FATAL,"out of memory");

    if (dns_ip6_qualify(&out,&fqdn,&in) < 0)
      logmsg(WHO,111,FATAL,B("unable to find IPv6 address for: ",*argv));

    buffer_put(buffer_1,fqdn.s,fqdn.len);
    buffer_puts(buffer_1,"\n");

    for (i = 0; i + 16 <= out.len; i += 16) {
      if (ip6_isv4mapped(out.s + i)) continue;
      buffer_put(buffer_1,ip6,ip6_fmt(ip6,out.s + i));
      buffer_puts(buffer_1," ");
    }
    buffer_puts(buffer_1,"\n");

    if (dns_ip4_qualify(&out,&fqdn,&in) < 0)
      logmsg(WHO,111,FATAL,B("unable to find IPv4 address for: ",*argv));

    for (i = 0; i + 4 <= out.len; i += 4) {
      buffer_put(buffer_1,ip4,ip4_fmt(ip4,out.s + i));
      buffer_puts(buffer_1," ");
    }
    buffer_puts(buffer_1,"\n");

    ++argv;
  }

  buffer_flush(buffer_1);
  _exit(0);
}
