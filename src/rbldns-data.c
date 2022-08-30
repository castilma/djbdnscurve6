#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "buffer.h"
#include "exit.h"
#include "cdbmake.h"
#include "open.h"
#include "stralloc.h"
#include "getln.h"
#include "logmsg.h"
#include "byte.h"
#include "scan.h"
#include "fmt.h"
#include "ip.h"
#include "str.h"

#define WHO "rbldns-data"

int rename(const char *,const char *);  // keep compiler silent

void nomem(void)
{
  logmsg(WHO,111,FATAL,"out of memory");
}

void parserr(void)
{
   logmsg(WHO,111,FATAL,"parsing error");
}

int fd;
buffer b;
char bspace[1024];

int fdcdb;
struct cdb_make cdb;

static stralloc line;
int match = 1;
unsigned long linenum = 0;

char strnum[FMT_ULONG];

void syntaxerror(const char *why)
{
  strnum[fmt_ulong(strnum,linenum)] = 0;
  logmsg(WHO,-99,WARN,B("unable to parse data line: ",strnum,why));
}
void die_datatmp(void)
{
  logmsg(WHO,111,FATAL,"unable to create data.tmp");
}

int main()
{
  char ipout[4];	/* always return 127.0.0.x IP address */
  unsigned int i;
  unsigned int j;
  unsigned int k;
  unsigned long plen;
  int flagip6;
  char ch;
  char ip4[4];
  char ip6[16];
  stralloc tmp = {0};	/* needs to be here, local and not global */
  stralloc ipstring = {0};
 
  umask(022);

  fd = open_read("data");
  if (fd == -1) logmsg(WHO,111,FATAL,"unable to open data");
  buffer_init(&b,buffer_unixread,fd,bspace,sizeof(bspace));

  fdcdb = open_trunc("data.tmp");
  if (fdcdb == -1) die_datatmp();
  if (cdb_make_start(&cdb,fdcdb) == -1) die_datatmp();

  while (match) {
    ++linenum;
    if (getln(&b,&line,&match,'\n') == -1) 
      logmsg(WHO,111,FATAL,"unable to read line");

    while (line.len) {
      ch = line.s[line.len - 1];
      if ((ch != ' ') && (ch != '\t') && (ch != '\n')) break;
      --line.len;
    }
    if (!line.len) continue;

    switch (line.s[0]) {
      default:
        syntaxerror(": unrecognized leading character");
        case '#':
      break;
      case '=':    /* allow IPv6 mapped IPv4 addresses */
        j = byte_chr(line.s + 1,line.len - 1,':');
        if (j >= line.len - 1) syntaxerror(": missing colon");
        if (ip4_scan(line.s + 1,ipout) != j) syntaxerror(": malformed IPv4 address");
        if (!stralloc_copyb(&tmp,ipout,4)) nomem();
        if (!stralloc_catb(&tmp,line.s + j + 2,line.len - j - 2)) nomem();
        if (cdb_make_add(&cdb,"",0,tmp.s,tmp.len) == -1)
          die_datatmp();
        break;
      case '0': case '1': case '2': case '3': case '4':
      case '5': case '6': case '7': case '8': case '9': case ':':
      case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
 
        if (!stralloc_0(&line)) nomem();

        flagip6 = 0; 
        k = 0;
        i = byte_chr(line.s + 1,line.len - 1,':');
        if (i < line.len - 1) flagip6 = 1;
        if (byte_equal(line.s,7,V4MAPPREFIX)) { k = 7; flagip6 = 0; }

        if (flagip6) { 
          byte_zero(ip6,16);
          ip6_cidr(line.s,ip6,&plen);
          if (!stralloc_copys(&tmp,"^")) nomem();
          if (ip6_bytestring(&ipstring,ip6,&plen)) nomem();
          if (!stralloc_catb(&tmp,ipstring.s,plen)) nomem();
          plen++;
        } else	{ 
          byte_zero(ip4,4);
          ip4_cidr(line.s+k,ip4,&plen);
          if (!stralloc_copys(&tmp,"")) nomem();
          if (ip4_bytestring(&ipstring,ip4,&plen)) nomem();
          if (!stralloc_catb(&tmp,ipstring.s,plen)) nomem();
        }

        if (cdb_make_add(&cdb,tmp.s,plen,"",0) == -1)
          die_datatmp();
      break;
    }
  }

  if (cdb_make_finish(&cdb) == -1) die_datatmp();
  if (fsync(fdcdb) == -1) die_datatmp();
  if (close(fdcdb) == -1) die_datatmp(); /* NFS stupidity */
  if (rename("data.tmp","data.cdb") == -1)
    logmsg(WHO,111,FATAL,"unable to move data.tmp to data.cdb");

  _exit(0);
}
