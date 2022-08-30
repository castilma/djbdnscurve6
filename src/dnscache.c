#include <unistd.h>
#include "case.h"
#include "env.h"
#include "exit.h"
#include "scan.h"
#include "logmsg.h"
#include "str.h"
#include "ip.h"
#include "uint_t.h"
#include "socket_if.h"
#include "dns.h"
#include "taia.h"
#include "byte.h"
#include "roots.h"
#include "fmt.h"
#include "iopause.h"
#include "query.h"
#include "alloc.h"
#include "response.h"
#include "sipcache.h"
#include "ndelay.h"
#include "log.h"
#include "clientok.h"
#include "droproot.h"
#include "readclose.h"
#include "curvedns.h"

#define WHO "dnscache"

uint16 dnsport = 53;
stralloc ifname = {0};
uint32 ifidx = 0; /* aka scope_id */

int flagusetxtformat = 0;
int flagdualstack = 0;
int flagipv6anycast = 0;
char *p = "u";

static int packetquery(char *buf,unsigned int len,char **q,char qtype[2],char qclass[2],char id[2])
{
  unsigned int pos;
  unsigned int ad = 0;
  char header[12];

  errno = EPROTO;
  pos = dns_packet_copy(buf,len,0,header,12); if (!pos) return 0;
  if (header[2] & 128) return 0;  /* must not respond to responses */
  if (!(header[2] & 1)) return 0; /* do not respond to non-recursive queries */
  if (header[2] & 120) return 0;  /* standard query only */
  if (header[2] & 2) return 0;    /* Truncation not allowed */
  if (header[3] & 32) ad = 1; 	  /* Authenticated data */
  if (byte_diff(header + 4,2,"\0\1")) return 0;

  pos = dns_packet_getname(buf,len,pos,q); if (!pos) return 0;
  pos = dns_packet_copy(buf,len,pos,qtype,2); if (!pos) return 0;
  pos = dns_packet_copy(buf,len,pos,qclass,2); if (!pos) return 0;
  if (byte_diff(qclass,2,DNS_C_IN) && byte_diff(qclass,2,DNS_C_ANY)) return 0;
  if (!dns_packet_edns0(header,buf,len,pos)) return 0;

  byte_copy(id,2,header);
  return 1;
}

static char ipsending[16];
static char iplistening[16];
// static char buf[2 * MSGSIZE + 2];
static char buf[MAXSEGMENT];
uint64 numqueries = 0;

static int udp53;

static struct udpclient {
  struct query q;
  struct taia start;
  uint64 active; /* query number, if active; otherwise 0 */
  iopause_fd *io;
  char ip[16];
  uint16 port;
  char id[2];
  uint32 scope_id;
} u[QUERY_MAXUDP];

int uactive = 0;
int eactive = 0;

void u_drop(int j)
{
  if (!u[j].active) return;
  p = "u";
  log_querydrop(&u[j].active,p);
  u[j].active = 0; --uactive; 
}

void u_respond(int j)
{
  if (!u[j].active) return;
  response_id(u[j].id);
  if (response_len > MSGSIZE) response_tc();
    socket_send(udp53,response,response_len,u[j].ip,u[j].port,u[j].scope_id);
  p = "u";
  log_querydone(&u[j].active,response_len,p);
  u[j].active = 0; --uactive; 
}

void u_new(void)
{
  int j;
  int i;
  struct udpclient *x;
  int len;
  static char *q = 0;
  char qtype[2];
  char qclass[2];

  for (j = 0; j < QUERY_MAXUDP; ++j)
    if (!u[j].active)
      break;

  if (j >= QUERY_MAXUDP) {
    j = 0;
    for (i = 1; i < QUERY_MAXUDP; ++i)
      if (taia_less(&u[i].start,&u[j].start))
        j = i;
        errno = ETIMEDOUT;
        u_drop(j);
  }  

  x = u + j;
  taia_now(&x->start);

  len = socket_recv(udp53,buf,sizeof(buf),x->ip,&x->port,&x->scope_id);
  if (len == -1) return;
  if (len >= sizeof(buf)) return;
  if (x->port < 1024) if (x->port != 53) return;
  if (!clientok(x->ip)) { 
    char ipstr[IP6_FMT];
    if (ip6_isv4mapped(x->ip)) len = ip4_fmt(ipstr,x->ip + 12);
    else len = ip6_fmt(ipstr,x->ip);
    ipstr[len] = '\0';
    logmsg(WHO,-99,WARN,B("client blocked: ",ipstr)); 
    return;
  }

  if (!packetquery(buf,len,&q,qtype,qclass,x->id)) return;

  x->active = ++numqueries; ++uactive;
  p = "u";
  if (len > MINMSGSIZE) { ++eactive; p = "e"; }
  log_query(&x->active,x->ip,x->port,x->id,q,qtype,p);

  switch (query_start(&x->q,q,qtype,qclass,ipsending,&x->scope_id)) {
    case -1: case -2: u_drop(j); return;
    case 1: u_respond(j);
  }
}

static int tcp53;

struct tcpclient {
  struct query q;
  struct taia start;
  struct taia timeout;
  uint64 active; /* query number or 1, if active; otherwise 0 */
  iopause_fd *io;
  char ip[16]; /* send response to this address */
  uint16 port; /* send response to this port */
  char id[2];
  int tcp; /* open TCP socket, if active */
  int state;
  char *buf; /* 0, or dynamically allocated of length len */
  unsigned int len;
  unsigned int pos;
  uint32 scope_id;
} t[QUERY_MAXTCP];
int tactive = 0;

/*
state 1: buf 0; normal state at beginning of TCP connection
state 2: buf 0; have read 1 byte of query packet length into len
state 3: buf allocated; have read pos bytes of buf
state 0: buf 0; handling query in q
state -1: buf allocated; have written pos bytes
*/

void t_free(int j)
{
  if (!t[j].buf) return;
  alloc_free(t[j].buf);
  t[j].buf = 0;
}

void t_timeout(int j)
{
  struct taia now;
  if (!t[j].active) return;
  taia_now(&now);
  taia_uint(&t[j].timeout,10);
  taia_add(&t[j].timeout,&t[j].timeout,&now);
}

void t_close(int j)
{
  if (!t[j].active) return;
  t_free(j);
  log_tcpclose(t[j].ip,t[j].port);
  close(t[j].tcp);
  t[j].active = 0; --tactive;
}

void t_drop(int j)
{
  p = "t";
  log_querydrop(&t[j].active,p);
  errno = EPIPE;
  t_close(j);
}

void t_respond(int j)
{
  if (!t[j].active) return;
  p = "t";
  log_querydone(&t[j].active,response_len,p);
  response_id(t[j].id);
  t[j].len = response_len + 2;
  t_free(j);
  t[j].buf = alloc(response_len + 2);
  if (!t[j].buf) { t_close(j); return; }
  uint16_pack_big(t[j].buf,response_len);
  byte_copy(t[j].buf + 2,response_len,response);
  t[j].pos = 0;
  t[j].state = -1;
}

void t_rw(int j)
{
  struct tcpclient *x;
  char *ch;
  static char *q = 0;
  unsigned int readsize;
  char qtype[2];
  char qclass[2];
  int r;

  x = t + j;
  if (x->state == -1) {
    r = write(x->tcp,x->buf + x->pos,x->len - x->pos);
    if (r <= 0) { t_close(j); return; }
    x->pos += r;
    if (x->pos == x->len) {
      t_free(j);
      x->state = 1; /* could drop connection immediately */
    }
    return;
  }

  switch (x->state) {
    case 1: readsize = 2U; break;
    case 2: readsize = 1U; break;
    case 3: readsize = x->len - x->pos; break;
    default: return; /* impossible */
  }

  r = read(x->tcp,buf,readsize);
  if (r == 0) { errno = EPIPE; t_close(j); return; }
  if (r < 0) { t_close(j); return; }

  ch = buf;
  if (x->state == 1) {
    x->len = (unsigned char) *ch++;
    x->len <<= 8;
    x->state = 2;
    if (--r <= 0) return;
  }
  if (x->state == 2) {
    x->len += (unsigned char) *ch;
    if (!x->len) { errno = EPIPE; t_close(j); return; }
    x->buf = alloc(x->len);
    if (!x->buf) { t_close(j); return; }
    x->pos = 0;
    x->state = 3;
    return;
  }

  if (x->state != 3) return; /* impossible */

  byte_copy(&x->buf[x->pos],r,ch);
	x->pos += r;
  if (x->pos < x->len) return;

  if (!packetquery(x->buf,x->len,&q,qtype,qclass,x->id)) { t_close(j); return; }

  x->active = ++numqueries;
  p = "t";
  log_query(&x->active,x->ip,x->port,x->id,q,qtype,p);
  switch (query_start(&x->q,q,qtype,qclass,ipsending,ifidx)) {
    case -1: case -2: t_drop(j); return;
    case 1: t_respond(j); return;
  }
  t_free(j);
  x->state = 0;
}

void t_new(void)
{
  int i;
  int j;
  int len;
  struct tcpclient *x;

  for (j = 0; j < QUERY_MAXTCP; ++j)
    if (!t[j].active)
      break;

  if (j >= QUERY_MAXTCP) {
    j = 0;
    for (i = 1; i < QUERY_MAXTCP; ++i)
      if (taia_less(&t[i].start,&t[j].start))
        j = i;
    errno = ETIMEDOUT;
    if (t[j].state == 0)
      t_drop(j);
    else
      t_close(j);
  }

  x = t + j;
  taia_now(&x->start);

  x->tcp = socket_accept(tcp53,x->ip,&x->port,&x->scope_id);
  if (x->tcp == -1) return;
  if (x->port < 1024) if (x->port != 53) { close(x->tcp); return; }
  if (!clientok(x->ip)) { 
    char ipstr[IP6_FMT];
    if (ip6_isv4mapped(x->ip)) len = ip4_fmt(ipstr,x->ip + 12);
    else len = ip6_fmt(ipstr,x->ip);
    ipstr[len + 1] = '\0';
    logmsg(WHO,-99,WARN,B("client blocked: ",ipstr));
    close(x->tcp); 
    return; 
  }
  if (ndelay_on(x->tcp) == -1) { close(x->tcp); return; } /* Linux bug */

  x->active = 1; ++tactive;
  x->state = 1;
  t_timeout(j);

  log_tcpopen(x->ip,x->port);
}


iopause_fd io[3 + QUERY_MAXUDP + QUERY_MAXTCP];
iopause_fd *udp53io;
iopause_fd *tcp53io;

static void doit(void)
{
  int j;
  struct taia deadline;
  struct taia stamp;
  int iolen;
  int r;

  for (;;) {
    taia_now(&stamp);
    taia_uint(&deadline,120);
    taia_add(&deadline,&deadline,&stamp);

    iolen = 0;

    udp53io = io + iolen++;
    udp53io->fd = udp53;
    udp53io->events = IOPAUSE_READ;

    tcp53io = io + iolen++;
    tcp53io->fd = tcp53;
    tcp53io->events = IOPAUSE_READ;

    for (j = 0; j < QUERY_MAXUDP; ++j)
      if (u[j].active) {
        u[j].io = io + iolen++;
        query_io(&u[j].q,u[j].io,&deadline);
      }

    for (j = 0; j < QUERY_MAXTCP; ++j)
      if (t[j].active) {
        t[j].io = io + iolen++;
        if (t[j].state == 0) 
           query_io(&t[j].q,t[j].io,&deadline);
        else {
           if (taia_less(&t[j].timeout,&deadline)) deadline = t[j].timeout;
           t[j].io->fd = t[j].tcp;
           t[j].io->events = (t[j].state > 0) ? IOPAUSE_READ : IOPAUSE_WRITE;
        }
      }

    if (iopause(io,iolen,&deadline,&stamp) < 0) {
        errno = ECONNRESET;
        logmsg(WHO,errno,FATAL,"IO resources not available");
    }

    for (j = 0; j < QUERY_MAXUDP; ++j)
      if (u[j].active) {
        r = query_get(&u[j].q,u[j].io,&stamp);
        if (r == -1 || r == -2 || r == -3) { errno = ECONNRESET; u_drop(j); }
        if (r == 1) u_respond(j);
      }

    for (j = 0; j < QUERY_MAXTCP; ++j)
      if (t[j].active) {
        if (t[j].io->revents) t_timeout(j);
        if (t[j].state == 0) {
          r = query_get(&t[j].q,t[j].io,&stamp);
          if (r == -1 || r == -2 || r == -3) { errno = ECONNRESET; t_drop(j); }
          if (r == 1) t_respond(j);
        }
        else if (t[j].io->revents || taia_less(&t[j].timeout,&stamp))
          t_rw(j);
      }

    if (udp53io)
      if (udp53io->revents)
        u_new();

    if (tcp53io)
      if (tcp53io->revents)
        t_new();
  }
}
  
char seed[128];

int main()
{
  char *x;
  unsigned long cachesize;
  flagedserver = 0;
  fallback = 0;

  x = env_get("IP");
  if (!x)
    logmsg(WHO,111,ERROR,"$IP not set"); 
  if (case_equals(x,"::")) {
    flagipv6anycast = 1;
  } else if (case_equals(x,":0")) {
    flagdualstack = 1;
    byte_copy(x,2,"::");
    ifidx = 0;
  }
  if (!ip6_ifscan(x,iplistening,&ifname))
    logmsg(WHO,101,SYNTAX,B("unable to parse IP address: ",x));

  if (ifname.len > 1) ifidx = socket_getifidx(ifname.s);

  if (ip6_isv4mapped(iplistening))
    udp53 = socket_udp4();
  else 
    udp53 = socket_udp();
  if (udp53 == -1)
    logmsg(WHO,111,FATAL,"unable to create UDP socket");

  if (flagdualstack) socket_dualstack(udp53);
  if (flagipv6anycast) socket_ip6anycast(udp53);
  if (socket_bind_reuse(udp53,iplistening,dnsport,ifidx) == -1)
    logmsg(WHO,111,FATAL,"unable to bind to UDP socket");

  if (ip6_isv4mapped(iplistening))
    tcp53 = socket_tcp4();
  else 
    tcp53 = socket_tcp6();
  if (tcp53 == -1)
    logmsg(WHO,111,FATAL,"unable to create TCP socket");

  if (flagdualstack) socket_dualstack(tcp53);
  if (flagipv6anycast) socket_ip6anycast(tcp53);
  if (socket_bind_reuse(tcp53,iplistening,dnsport,ifidx) == -1)
    logmsg(WHO,111,FATAL,"unable to bind to TCP socket");

  droproot(WHO);

  socket_tryreservein(udp53,131072);

  byte_zero(seed,sizeof(seed));
  read(0,seed,sizeof(seed));
  dns_random_init(seed);
  close(0);
  query_init();

  x = env_get("IPSEND");
  if (!x)
    logmsg(WHO,111,ERROR,"$IPSEND not set"); 
  if (!ip6_ifscan(x,ipsending,&ifname))
    logmsg(WHO,100,SYNTAX,B("unable to parse IP address: ",x));

  x = env_get("CACHESIZE");
  if (!x)
    logmsg(WHO,111,ERROR,"$CACHESIZE not set"); 
  scan_ulong(x,&cachesize);
  if (!cache_init(cachesize))
    logmsg(WHO,111,FATAL,B("not enough memory for cache of size: ",x));

  if (env_get("HIDETTL"))
    response_hidettl();
  if (env_get("FORWARDONLY"))
    query_forwardonly();
  if (env_get("USETXTFORMAT"))
    flagusetxtformat = 1;
  if (env_get("USETEXTFORMAT"))
    flagusetxtformat = 1;
  x =  env_get("UZ5FALLBACK");
  if (x) scan_uint(x,&fallback);
  if (env_get("FLAGEDSERVER"))
    flagedserver = 1;


  if (!roots_init())
    logmsg(WHO,111,ERROR,"unable to read servers");

  if (socket_listen(tcp53,TCP_BACKLOG) == -1)
    logmsg(WHO,111,FATAL,"unable to listen on TCP socket");

  log_startup(iplistening,ifidx,ipsending,MSGSIZE);
  doit();
}
