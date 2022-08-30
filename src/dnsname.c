#include "buffer.h"
#include "exit.h"
#include "logmsg.h"
#include "ip.h"
#include "dns.h"
#include "str.h"

#define WHO "dnsname"

static char seed[128];

char ip4[4];
char ip6[16];
static stralloc out;

int main(int argc,char **argv)
{
  dns_random_init(seed);

  if (*argv) ++argv;

  while (*argv) {
    if (str_chr(*argv,':') < str_len(*argv)) {
      if (ip6_scan(*argv,ip6)) dns_name6(&out,ip6);
    } else 
      if (ip4_scan(*argv,ip4)) dns_name4(&out,ip4);

    buffer_put(buffer_1,out.s,out.len);
    buffer_puts(buffer_1,"\n");
    ++argv;
  }

  buffer_flush(buffer_1);
  _exit(0);
}
