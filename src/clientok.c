#include <sys/types.h>
#include <sys/stat.h>
#include "str.h"
#include "ip.h"
#include "byte.h"
#include "clientok.h"

static char fnaccept[3 + IPFMT];
static char fnreject[4 + IPFMT];

int clientok(char ip[16])
{
  struct stat st;
  int i;
  char sep;

  fnaccept[0] = fnreject[0] = 'i'; 
  fnaccept[1] = fnreject[1] = 'p';
  fnaccept[2] = fnreject[2] = '/';
  fnreject[3] = '#';

  if (byte_equal(ip,12,V4mappedprefix)) {
    fnaccept[3 + ip4_fmt(fnaccept + 3,ip + 12)] = 0;
    fnreject[4 + ip4_fmt(fnreject + 4,ip + 12)] = 0;
    sep='.';
  } else {
    fnaccept[3 + ip6_fmt(fnaccept + 3,ip)] = 0;
    fnreject[4 + ip6_fmt(fnreject + 4,ip)] = 0;
    sep=':';
  }

  /* Bad guys first */

  for (;;) { 
    if (!fnreject[3]) break; 
    if (stat(fnreject,&st) == 0) return 0;
    i = str_rchr(fnreject,sep);
    if (i && fnreject[i] == sep) 
      fnreject[i] = 0;
    else
      break;
  }

  /* Good guys next */

  for (;;) {
    if (!fnaccept[3]) return 0;
    if (stat(fnaccept,&st) == 0) return 1;
    /* treat temporary error as rejection */
    i = str_rchr(fnaccept,sep);
    if (!fnaccept[i]) return 0;
    fnaccept[i] = 0;
  }
}
