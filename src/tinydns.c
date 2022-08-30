#include "dns.h"
#include "curve.h"

#define WHO = "tinydns "

const char *fatal = "tinydns";
const char *starting = "starting tinydns ";

int flagcurved;

static char seed[128];

void init_server(void)
{
  dns_random_init(seed);
}
