#include "buffer.h"
#include "exit.h"
#include "logmsg.h"
#include "dns.h"

#define WHO "dnstxt"

static char seed[128];

static stralloc fqdn;
static stralloc out;

int main(int argc,char **argv)
{
  dns_random_init(seed);

  if (*argv) ++argv;

  while (*argv) {
    if (!stralloc_copys(&fqdn,*argv))
      logmsg(WHO,111,FATAL,"out of memory");
    if (dns_txt(&out,&fqdn) > 0) {
      buffer_put(buffer_1,out.s,out.len);
      buffer_puts(buffer_1,"\n");
    }
    ++argv;
  }

  buffer_flush(buffer_1);
  _exit(0);
}
