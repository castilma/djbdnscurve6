#include <sys/types.h>
#include <sys/stat.h>
#include "ip.h"
#include "byte.h"
#include "stralloc.h"
#include "serverok.h"

static char fnserver[4 + IPFMT];
static char fncurve[4 + IPFMT];

/* -1 no curve server
    1 omitt server */

int serverok(char ip[16])
{
  struct stat st;

  fnserver[0] = fncurve[0] = 'i';
  fnserver[1] = fncurve[1] = 'p';
  fnserver[2] = fncurve[2] = '/';
  fnserver[3] = '%';	
  fncurve[3] = '-';	

  if (byte_equal(ip,12,V4mappedprefix)) {
    fnserver[4 + ip4_fmt(fnserver + 4,ip + 12)] = 0;
    fncurve[4 + ip4_fmt(fncurve + 4,ip + 12)] = 0;
  } else {
    fnserver[4 + ip6_fmt(fnserver + 4,ip)] = 0;
    fncurve[4 + ip6_fmt(fncurve + 4,ip)] = 0;
  }

  if (stat(fnserver,&st) == 0) return 1;
  if (stat(fncurve,&st) == 0) return -1;

  return 0;
}
