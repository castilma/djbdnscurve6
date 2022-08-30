#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "stralloc.h"
#include "buffer.h"
#include "exit.h"
#include "open.h"
#include "getln.h"
#include "logmsg.h"
#include "scan.h"
#include "byte.h"
#include "str.h"
#include "fmt.h"
#include "ip.h"
#include "dns.h"

#define WHO "tinydns-edit"

#define TTL_NS 259200
#define TTL_POSITIVE 86400

char *fn;
char *fnnew;

int rename(const char *,const char *);  // keep compiler silent

void die_usage()
{
  logmsg(WHO,100,USAGE,"tinydns-edit data data.new add [ns|childns|host|alias|mx] domain a.b.c.d\n"
                     "tinydns-edit data data.new add [ns|childns|host6|alias6|mx] domain a:b:c:d:e:f:g:h");
}
void nomem()
{
  logmsg(WHO,111,FATAL,"out of memory");
}
void die_read()
{
  logmsg(WHO,100,FATAL,B("fatal: unable to read: ",fn));
}
void die_write()
{
  logmsg(WHO,111,FATAL,B("fatal: unable to write: ",fnnew));
}

char mode;
static char *target;
char targetip4[4];
char targetip6[16];

int fd;
buffer b;
char bspace[1024];

int fdnew;
buffer bnew;
char bnewspace[1024];

static stralloc line;
int match = 1;

#define NUMFIELDS 10
static stralloc f[NUMFIELDS];

static char *d1;
static char *d2;
char ip4[4];
char ip6[16];
char ip4str[IP4_FMT];
char ip6str[IP6_FMT];
char strnum[FMT_ULONG];

static char *names[26];
static int used[26];

void put(const char *buf,unsigned int len)
{
  if (buffer_putalign(&bnew,buf,len) == -1) die_write();
}

int main(int argc,char **argv)
{
  unsigned long ttl;
  struct stat st;
  int i;
  int j;
  int k;
  char ch;

  if (!*argv) die_usage();

  if (!*++argv) die_usage();
  fn = *argv;

  if (!*++argv) die_usage();
  fnnew = *argv;

  if (!*++argv) die_usage();
  if (str_diff(*argv,"add")) die_usage();

  if (!*++argv) die_usage();
  if (str_equal(*argv,"ns")) mode = '.';
  else if (str_equal(*argv,"childns")) mode = '&';
  else if (str_equal(*argv,"host")) mode = '=';
  else if (str_equal(*argv,"host6")) mode = ':';
  else if (str_equal(*argv,"alias")) mode = '+';
  else if (str_equal(*argv,"alias6")) mode = '~';
  else if (str_equal(*argv,"mx")) mode = '@';
  else die_usage();

  if (!*++argv) die_usage();
  if (dns_domain_fromdot(&target,*argv,str_len(*argv)) <= 0) nomem();

  if (!*++argv) die_usage();
  if (mode == ':' || mode == '~') {
    if (!ip6_scan(*argv,targetip6)) die_usage();
  } else {
    if (!ip4_scan(*argv,targetip4)) die_usage();
  }

  umask(077);

  fd = open_read(fn);
  if (fd == -1) die_read();
  if (fstat(fd,&st) == -1) die_read();
  buffer_init(&b,buffer_unixread,fd,bspace,sizeof(bspace));

  fdnew = open_trunc(fnnew);
  if (fdnew == -1) die_write();
  if (fchmod(fdnew,st.st_mode & 0644) == -1) die_write();
  buffer_init(&bnew,buffer_unixwrite,fdnew,bnewspace,sizeof(bnewspace));

  switch (mode) {
    case '.': case '&':
      ttl = TTL_NS;
      for (i = 0; i < 26; ++i) {
        ch = 'a' + i;
        if (!stralloc_copyb(&f[0],&ch,1)) nomem();
        if (!stralloc_cats(&f[0],".ns.")) nomem();
        if (dns_domain_todot_cat(&f[0],target) <= 0) nomem();
        if (dns_domain_fromdot(&names[i],f[0].s,f[0].len) <= 0) nomem();
      }
      break;
    case '+': case '=': case ':': case '~':
      ttl = TTL_POSITIVE;
      break;
    case '@':
      ttl = TTL_POSITIVE;
      for (i = 0; i < 26; ++i) {
        ch = 'a' + i;
        if (!stralloc_copyb(&f[0],&ch,1)) nomem();
        if (!stralloc_cats(&f[0],".mx.")) nomem();
        if (dns_domain_todot_cat(&f[0],target) <= 0) nomem();
        if (dns_domain_fromdot(&names[i],f[0].s,f[0].len) <= 0) nomem();
      }
      break;
  }

  while (match) {
    if (getln(&b,&line,&match,'\n') == -1) die_read();

    put(line.s,line.len);
    if (line.len && !match) put("\n",1);

    while (line.len) {
      ch = line.s[line.len - 1];
      if ((ch != ' ') && (ch != '\t') && (ch != '\n')) break;
      --line.len;
    }
    if (!line.len) continue;
    if (line.s[0] == '#') continue;

    j = 1;
    for (i = 0; i < NUMFIELDS; ++i) {
      if (j >= line.len) {
        if (!stralloc_copys(&f[i],"")) nomem();
      }
      else {
        k = byte_chr(line.s + j,line.len - j,'|');
        if (!stralloc_copyb(&f[i],line.s + j,k)) nomem();
        j += k + 1;
      }
    }

    switch (mode) {
      case '.': case '&':
        if (line.s[0] == mode) {
          if (dns_domain_fromdot(&d1,f[0].s,f[0].len) <= 0) nomem();
          if (dns_domain_equal(d1,target)) {
            if (byte_chr(f[2].s,f[2].len,'.') >= f[2].len) {
              if (!stralloc_cats(&f[2],".ns.")) nomem();
              if (!stralloc_catb(&f[2],f[0].s,f[0].len)) nomem();
            }
          if (dns_domain_fromdot(&d2,f[2].s,f[2].len) <= 0) nomem();
          if (!stralloc_0(&f[3])) nomem();
          if (!scan_ulong(f[3].s,&ttl)) ttl = TTL_NS;
          for (i = 0; i < 26; ++i)
            if (dns_domain_equal(d2,names[i])) {
              used[i] = 1;
              break;
            }
          }
        }
        break;

      case '=':
        if (line.s[0] == '=') {
          if (dns_domain_fromdot(&d1,f[0].s,f[0].len) <= 0) nomem();
          if (dns_domain_equal(d1,target))
            logmsg(WHO,100,FATAL,"host name already used");
          if (!stralloc_0(&f[1])) nomem();
          if (ip4_scan(f[1].s,ip4))
            if (byte_equal(ip4,4,targetip4))
              logmsg(WHO,100,FATAL,"IP address already used");
	     }
       break;

      case ':':
        if (line.s[0] == ':') {
          if (dns_domain_fromdot(&d1,f[0].s,f[0].len) <= 0) nomem();
          if (dns_domain_equal(d1,target))
            logmsg(WHO,100,FATAL,"host name already used");
          if (!stralloc_0(&f[1])) nomem();
          if (ip6_scan(f[1].s,ip6))
            if (byte_equal(ip6,16,targetip6))
              logmsg(WHO,100,FATAL,"IPv6 address already used");
        }
        break;

      case '@':
        if (line.s[0] == '@') {
          if (dns_domain_fromdot(&d1,f[0].s,f[0].len) <= 0) nomem();
          if (dns_domain_equal(d1,target)) {
            if (byte_chr(f[2].s,f[2].len,'.') >= f[2].len) {
              if (!stralloc_cats(&f[2],".mx.")) nomem();
              if (!stralloc_catb(&f[2],f[0].s,f[0].len)) nomem();
            }
            if (dns_domain_fromdot(&d2,f[2].s,f[2].len) <= 0) nomem();
            if (!stralloc_0(&f[4])) nomem();
            if (!scan_ulong(f[4].s,&ttl)) ttl = TTL_POSITIVE;
            for (i = 0; i < 26; ++i)
              if (dns_domain_equal(d2,names[i])) {
                used[i] = 1;
                break;
              }
          }
        }
        break;
    }
  }

  if (!stralloc_copyb(&f[0],&mode,1)) nomem();
  if (dns_domain_todot_cat(&f[0],target) <= 0) nomem();
  if (!stralloc_cats(&f[0],"|")) nomem();
  if (mode == ':' || mode == '~') {
    if (!stralloc_catb(&f[0],ip6str,ip6_fmt(ip6str,targetip6))) nomem();
   } else {
    if (!stralloc_catb(&f[0],ip4str,ip4_fmt(ip4str,targetip4))) nomem();
  }
  switch (mode) {
    case '.': case '&': case '@':
      for (i = 0; i < 26; ++i)
        if (!used[i])
	    break;
      if (i >= 26)
        logmsg(WHO,100,FATAL,"too many records for that domain");
      ch = 'a' + i;
      if (!stralloc_cats(&f[0],"|")) nomem();
      if (!stralloc_catb(&f[0],&ch,1)) nomem();
      if (mode == '@')
        if (!stralloc_cats(&f[0],"|")) nomem();
      break;
  }
  if (!stralloc_cats(&f[0],"|")) nomem();
  if (!stralloc_catb(&f[0],strnum,fmt_ulong(strnum,ttl))) nomem();
  if (!stralloc_cats(&f[0],"\n")) nomem();
  put(f[0].s,f[0].len);

  if (buffer_flush(&bnew) == -1) die_write();
  if (fsync(fdnew) == -1) die_write();
  if (close(fdnew) == -1) die_write(); /* NFS dorks */
  if (rename(fnnew,fn) == -1)
    logmsg(WHO,111,FATAL,B("unable to move ",fnnew," to: ",fn));
  _exit(0);
}
