#include <unistd.h>
#include "open.h"
#include "error.h"
#include "str.h"
#include "byte.h"
#include "error.h"
#include "direntry.h"
#include "ip.h"
#include "dns.h"
#include "readclose.h"
#include "roots.h"
#include "socket_if.h"
#include "dns.h"

static stralloc data;
static stralloc ifname = {0};

static int roots_find(char *q)
{
  int i;
  int j;

  i = 0;
  while (i < data.len) {
    j = dns_domain_length(data.s + i);
    if (dns_domain_equal(data.s + i,q)) return i + j;
    i += j;
    i += 512;
  }
  return -1;
}

static int roots_search(char *q)
{
  int r;

  for (;;) {
    r = roots_find(q);
    if (r >= 0) return r;
    if (!*q) return -1; /* user misconfiguration */
    q += *q;
    q += 1;
  }
}

int roots(char servers[QUERY_MAXIPLEN],char *q)
{
  int r;
  r = roots_find(q);
  if (r == -1) return 0;
  byte_copy(servers,QUERY_MAXIPLEN,data.s + r);
  return 1;
}

int roots_same(char *q,char *q2)
{
  return roots_search(q) == roots_search(q2);
}

static int init2(DIR *dir)
{
  direntry *d;
  const char *fqdn;
  static char *q;
  static stralloc text;
  char servers[QUERY_MAXIPLEN];
  int serverslen;
  int i;
  int j;
  int k;
  uint32 scope_ids[QUERY_MAXNS];
  
  byte_zero(scope_ids,4*QUERY_MAXNS);

  for (;;) {
    errno = 0;
    d = readdir(dir);
    if (!d) {
      if (errno) return 0;
      return 1;
    }

    if (d->d_name[0] != '.') {
      fqdn = d->d_name;
      if (str_equal(fqdn,"@")) fqdn = ".";
      else if (env_get("FORWARDONLY")) continue; // ignore all files but "@" as documented
      if (dns_domain_fromdot(&q,fqdn,str_len(fqdn)) <= 0) return 0;

      if (openreadclose(d->d_name,&text,QUERY_MAXNS) != 1) return 0;
      if (!stralloc_append(&text,"\n")) return 0;

      serverslen = 0;
      j = 0;
      for (i = k = 0; i < text.len; ++i)
        if (text.s[i] == '\n') {
          if (serverslen <= QUERY_MAXIPLEN - 16)
            if (ip6_ifscan(text.s +  j,servers + serverslen,&ifname)) {
              serverslen += 16; /* all constant IPv6 addresses */
              scope_ids[k] = socket_getifidx(ifname.s); k++;
            }
          j = i + 1;
        }
      byte_zero(servers + serverslen,QUERY_MAXIPLEN - serverslen);

      if (!stralloc_catb(&data,q,dns_domain_length(q))) return 0;
      if (!stralloc_catb(&data,servers,QUERY_MAXIPLEN)) return 0;
    }
  }
}

static int init1(void)
{
  DIR *dir;
  int r;

  if (chdir("servers") == -1) return 0;
  dir = opendir(".");
  if (!dir) return 0;
  r = init2(dir);
  closedir(dir);
  return r;
}

int roots_init(void)
{
  int fddir;
  int r;

  if (!stralloc_copys(&data,"")) return 0;

  fddir = open_read(".");
  if (fddir == -1) return 0;
  r = init1();
  if (fchdir(fddir) == -1) r = 0;
  close(fddir);
  return r;
}
