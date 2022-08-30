#include "buffer.h"
#include "exit.h"
#include "logmsg.h"
#include "ip.h"
#include "dns.h"

#define WHO "dnsip"

static char seed[128];

static stralloc fqdn;
static stralloc out;

int main(int argc,char **argv)
{
  int i;
  char ip4str[IP4_FMT];
  char ip6str[IP6_FMT];

  dns_random_init(seed);

  if (*argv) ++argv;

  while (*argv) {
    if (!stralloc_copys(&fqdn,*argv))
      logmsg(WHO,111,FATAL,"out of memory");

    if ((i = dns_ip6(&out,&fqdn)) > 0) {
      for (i = 0; i + 16 <= out.len; i += 16) {
        if (ip6_isv4mapped(out.s + i)) continue;
        buffer_put(buffer_1,ip6str,ip6_fmt(ip6str,out.s + i));
        buffer_puts(buffer_1," ");
      }
    }

    if ((i = dns_ip4(&out,&fqdn)) > 0)
      for (i = 0; i + 4 <= out.len; i += 4) {
        buffer_put(buffer_1,ip4str,ip4_fmt(ip4str,out.s + i));
        buffer_puts(buffer_1," ");
      }

    ++argv;
    buffer_puts(buffer_1,"\n");
  }

  buffer_flush(buffer_1);
  _exit(0);
}
