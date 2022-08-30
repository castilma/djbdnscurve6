#include <unistd.h>
#include "buffer.h"
#include "stralloc.h"
#include "alloc.h"
#include "dns.h"
#include "ip.h"
#include "byte.h"
#include "scan.h"
#include "taia.h"
#include "getoptb.h"
#include "iopause.h"
#include "logmsg.h"
#include "exit.h"
#include "str.h"

#define WHO "dnsfilter"

void nomem(void)
{
  logmsg(WHO,111,FATAL,"out of memory");
}

struct line {
  stralloc left;
  stralloc middle;
  stralloc right;
  struct dns_transmit dt;
  int flagactive;
  iopause_fd *io;
} *x;

struct line tmp;
unsigned int xmax = 1000;
unsigned int xnum = 0;
unsigned int numactive = 0;
unsigned int maxactive = 10;

static stralloc partial;

char inbuf[1024];
int inbuflen = 0;
iopause_fd *inio;
int flag0 = 1;

iopause_fd *io;
int iolen;

char servers[QUERY_MAXIPLEN];
uint32 scopes[QUERY_MAXNS];
char ip4[4];
char ip6[16];
char name[DNS_NAME6_DOMAIN];

void errout(int i)
{
  int j;

  if (!stralloc_copys(&x[i].middle,"?")) nomem();
  if (!stralloc_cats(&x[i].middle,errstr(errno))) nomem();

  for (j = 0; j < x[i].middle.len; ++j)
    if (x[i].middle.s[j] == ' ')
      x[i].middle.s[j] = '-';
}

int main(int argc,char **argv)
{
  struct taia stamp;
  struct taia deadline;
  int opt;
  unsigned long u;
  int i;
  int j;
  int r;

  while ((opt = getopt(argc,argv,"c:l:")) != opteof)
    switch(opt) {
      case 'c':
        scan_ulong(optarg,&u);
        if (u < 1) u = 1;
        if (u > 1000) u = 1000;
        maxactive = u;
        break;
      case 'l':
        scan_ulong(optarg,&u);
        if (u < 1) u = 1;
        if (u > 1000000) u = 1000000;
        xmax = u;
        break;
      default:
        logmsg(WHO,100,USAGE,"dnsfilter [ -c concurrency ] [ -l lines ]");
    }

  x = (struct line *) alloc(xmax * sizeof(struct line));
  if (!x) nomem();
  byte_zero(x,xmax * sizeof(struct line));

  io = (iopause_fd *) alloc((xmax + 1) * sizeof(iopause_fd)); 
  if (!io) nomem();

  if (!stralloc_copys(&partial,"")) nomem();


  while (flag0 || inbuflen || partial.len || xnum) {
    taia_now(&stamp);
    taia_uint(&deadline,120);
    taia_add(&deadline,&deadline,&stamp);

    iolen = 0;

    if (flag0)
      if (inbuflen < sizeof(inbuf)) {
        inio = io + iolen++;
        inio->fd = 0;
        inio->events = IOPAUSE_READ;
      }

    for (i = 0; i < xnum; ++i)
      if (x[i].flagactive) {
        x[i].io = io + iolen++;
        dns_transmit_io(&x[i].dt,x[i].io,&deadline);
      }

    iopause(io,iolen,&deadline,&stamp);

    if (flag0)
      if (inbuflen < sizeof(inbuf))
        if (inio->revents) {
        r = read(0,inbuf + inbuflen,(sizeof(inbuf)) - inbuflen);
        if (r <= 0)
          flag0 = 0;
        else
          inbuflen += r;
        }
    
    for (i = 0; i < xnum; ++i)
      if (x[i].flagactive) {
        r = dns_transmit_get(&x[i].dt,x[i].io,&stamp);
        if (r < 0) {
          errout(i);
          x[i].flagactive = 0;
          --numactive;
        }
        else if (r == 1) {
          if (dns_name_packet(&x[i].middle,x[i].dt.packet,x[i].dt.packetlen) < 0)
            errout(i);
          if (x[i].middle.len)
          if (!stralloc_cats(&x[i].left,"=")) nomem();
          x[i].flagactive = 0;
          --numactive;
         }
      }

    for (;;) {
      if (xnum && !x[0].flagactive) {
        buffer_put(buffer_1,x[0].left.s,x[0].left.len);
        buffer_put(buffer_1,x[0].middle.s,x[0].middle.len);
        buffer_put(buffer_1,x[0].right.s,x[0].right.len);
        buffer_flush(buffer_1);
        --xnum;
        tmp = x[0];
        for (i = 0;i < xnum;++i) x[i] = x[i + 1];
        x[xnum] = tmp;
        continue;
      }

      if ((xnum < xmax) && (numactive < maxactive)) {
        i = byte_chr(inbuf,inbuflen,'\n');
        if (inbuflen && (i == inbuflen)) {
          if (!stralloc_catb(&partial,inbuf,inbuflen)) nomem();
          inbuflen = 0;
          continue;
        }

        if ((i < inbuflen) || (!flag0 && partial.len)) {
          if (i < inbuflen) ++i;
          if (!stralloc_catb(&partial,inbuf,i)) nomem();
          inbuflen -= i;
          for (j = 0; j < inbuflen; ++j) inbuf[j] = inbuf[j + i];
  
          if (partial.len) {
            i = byte_chr(partial.s,partial.len,'\n');
            i = byte_chr(partial.s,i,'\t');
            i = byte_chr(partial.s,i,' ');
    
            if (!stralloc_copyb(&x[xnum].left,partial.s,i)) nomem();
            if (!stralloc_copys(&x[xnum].middle,"")) nomem();
            if (!stralloc_copyb(&x[xnum].right,partial.s + i,partial.len - i)) nomem();
            x[xnum].flagactive = 0;
  
            partial.len = i;
            if (!stralloc_0(&partial)) nomem();
            if (str_chr(partial.s,':') == partial.len - 1) {
              if (ip4_scan(partial.s,ip4)) dns_name4_domain(name,ip4);
            } else { 
              if (ip6_scan(partial.s,ip6)) dns_name6_domain(name,ip6);
            }

            if (dns_resolvconfip(servers,scopes) < 0)
              logmsg(WHO,111,FATAL,"unable to read /etc/resolv.conf");

             if (dns_transmit_start6(&x[xnum].dt,servers,1,name,DNS_T_PTR,V6localnet,scopes) < 0)
                errout(xnum);
              else {
                x[xnum].flagactive = 1;
                ++numactive;
              }
            ++xnum;
          }
  
          partial.len = 0;
          continue;
        }
      }

      break;
    }
  }

  _exit(0);
}
