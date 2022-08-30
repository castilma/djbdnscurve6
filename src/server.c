/* 'server.c' supports currently only UDP */
#include <sys/stat.h>
#include <unistd.h>
#include "byte.h"
#include "case.h"
#include "env.h"
#include "buffer.h"
#include "ip.h"
#include "uint_t.h"
#include "ndelay.h"
#include "socket_if.h"
#include "droproot.h"
#include "qlog.h"
#include "response.h"
#include "dns.h"
#include "alloc.h"
#include "str.h"
#include "open.h"
#include "logmsg.h"
#include "curve.h"

uint16 dnsport = 53;
extern char *fatal;
extern char *starting;
extern int respond(char *,char *,char *);
extern void init_server(void);
int flagdualstack = 0;
int flagipv6anycast = 0;
extern int flagcurved;

static char ip[16];
static uint16 port;
unsigned char curvekey[32];

static char buf[MAXMSGSIZE];
static int len;

static char *q;

void nomem()
{
  logmsg(fatal,111,FATAL,"out of memory");
}

static int doit(void)
{
  unsigned int pos, zone;
  char header[12];
  char qtype[2];
  char qclass[2];
  char tid[2];
  uint8 secret[32];
  uint8 pubkey[32];
  uint8 nonce[24];
  uint8 sandbox[MAXMSGSIZE];
  uint8 qname[MAXMSGSIZE];
  unsigned int boxlen = 0;
  unsigned int qnamelen = 0;
  int rd;
  int r;

  if (len >= sizeof(buf)) goto NOQ;
  if (!flagcurved) goto NOC;

  /* Parse potential DNSCurve message and read query */

  pos = dns_curve_query(buf,len,0); if (!pos) goto TXT;
  pos = dns_curve_pubkey(pubkey,buf,pos); if (!pos) goto NOC;
  pos = dns_curve_nonce(nonce,buf,pos); if (!pos) goto NOC;
  boxlen = dns_curve_cryptobox(sandbox + 16,buf,len,pos); if (!boxlen) goto NOC;

  byte_zero(sandbox,16);
  byte_zero(nonce + 12,12);

  if (crypto_box_beforenm(secret,pubkey,curvekey)) {
    logmsg(fatal,99,WARN,"can't compute shared secret");
    goto NOC;
  }
  if (crypto_box_open_afternm(sandbox,sandbox,boxlen + 16,nonce,secret)) {
    logmsg(fatal,99,WARN,"can't open cryptobox");
    goto NOC;
  }
  if (!dns_packet_copy(sandbox + 32,boxlen,0,buf,boxlen)) goto NOC;
  flagcurved = 2;
  goto NOC;


  TXT:

  pos = dns_curve_txtquery(buf,len,2); if (!pos) goto NOC;                 // pos of '\x36x1a'
  boxlen = dns_curve_txtqname(sandbox + 4,buf,len); if (!boxlen) goto NOC; // length of base32box incl. nonce
  if (!dns_curve_txtnonce(nonce,sandbox + 4)) goto NOC;                    // length of nonce (= 12)
  zone = dns_curve_txtpubkey(pubkey,buf,pos + 4);
  if (buf[2] & 1) rd = 1;
  else rd = 0;

  byte_zero(sandbox,16);     // BOXZERO bytes
  byte_zero(nonce + 12,12);  // fullnonce

  if (crypto_box_beforenm(secret,pubkey,curvekey)) {
    logmsg(fatal,99,WARN,"can't compute shared secret");
    goto NOC;
  }
  if (crypto_box_open_afternm(sandbox,sandbox,boxlen + 4,nonce,secret)) {
    logmsg(fatal,99,WARN,"can't open cryptobox");
    goto NOC;
  }
  pos = dns_packet_getname(buf,len,pos,&q); if (!pos) goto NOQ;            // orig q
  qnamelen = pos - 12;
  byte_copy(qname,qnamelen,buf + 12); 
  byte_copy(tid,2,buf);
  if (!dns_packet_copy(sandbox + 32,len,0,buf,len)) goto NOC;
  flagcurved = 3;


  NOC:

  pos = dns_packet_copy(buf,len,0,header,12); if (!pos) goto NOQ;
  if (header[2] & 128) goto NOQ;
  if (header[4]) goto NOQ;
  if (header[5] != 1) goto NOQ;

  pos = dns_packet_getname(buf,len,pos,&q); if (!pos) goto NOQ;            // name -> q
  pos = dns_packet_copy(buf,len,pos,qtype,2); if (!pos) goto NOQ;          // -> qtype
  pos = dns_packet_copy(buf,len,pos,qclass,2); if (!pos) goto NOQ;         // -> qclass

  if (!response_query(q,qtype,qclass)) goto NOQ;  // generate response, copy q add answers

  response_id(header);
  if (byte_equal(qclass,2,DNS_C_IN))
    response[2] |= 4;
  else
    if (byte_diff(qclass,2,DNS_C_ANY)) goto WEIRDCLASS;
  response[3] &= ~128;
  if (!(header[2] & 1)) response[2] &= ~1;

  if (header[2] & 126) goto NOTIMP;
  if (byte_equal(qtype,2,DNS_T_AXFR)) goto NOTIMP;

  len = dns_domain_length(q);
  case_lowerb(q,len);
  r = respond(q,qtype,ip);

  if (flagcurved == 2) response_stream(secret,nonce); 
  if (flagcurved == 3) response_alttxt(secret,nonce,tid,qname,qnamelen,rd); 

  // Logging & return
 
  if (flagcurved > 1) {
    flagcurved = 1;  // reset state
    if (r) { qlog(ip,port,header,q,qtype," * "); return 1; }
    else { qlog(ip,port,header,q,qtype," ~ "); return 0; }
  } else {
    if (r) { qlog(ip,port,header,q,qtype," + "); return 1; }
    else { qlog(ip,port,header,q,qtype," - "); return 0; }
  }
    

  NOTIMP:
  response[3] &= ~15;
  response[3] |= 4;
  qlog(ip,port,header,q,qtype," I ");
  return 1;

  WEIRDCLASS:
  response[3] &= ~15;
  response[3] |= 1;
  qlog(ip,port,header,q,qtype," C ");
  return 1;

  NOQ:
  qlog(ip,port,"\0\0","","\0\0"," / ");
  return 0;
}

int main()
{
  char *x;
  int udp53;
  int fd;
  stralloc ifname = {0};
  uint32 ifidx = 0;
  struct stat st;

  x = env_get("IP");
  if (!x)
    logmsg(fatal,111,ERROR,"IP not set");
  if (case_equals(x,"::")) {
    flagipv6anycast = 1;
  } else if (case_equals(x,":0")) {
    flagdualstack = 1;
    byte_copy(x,2,"::");
  }
  if (!ip6_ifscan(x,ip,&ifname))
    logmsg(fatal,111,FATAL,B("unable to parse IPv6 address: ",x));

  if (ifname.len > 1) ifidx = socket_getifidx(ifname.s);
  
  if (ip6_isv4mapped(ip))
    udp53 = socket_udp4();
  else
    udp53 = socket_udp();
  if (udp53 == -1)
    logmsg(fatal,111,FATAL,"unable to create UDP socket");
 
  if (flagdualstack) socket_dualstack(udp53); 
  if (flagipv6anycast) socket_ip6anycast(udp53);
  if (socket_bind_reuse(udp53,ip,dnsport,ifidx) == -1)
    logmsg(fatal,111,FATAL,"unable to bind to UDP socket");

  /* If no CURVEDNS_PRIVATE_KEY is supplied, go for normal mode */

  if (!stat("env/CURVEDNS_PRIVATE_KEY",&st)) {
    fd = open_read("env/CURVEDNS_PRIVATE_KEY");
    if (fd == -1) logmsg(fatal,111,FATAL,"unable read CURVEDNS_PRIVATE_KEY");
    len = read(fd,&curvekey,32);
    close(fd);
    if (len != 32) logmsg(fatal,111,FATAL,"error reading CURVEDNS_PRIVATE_KEY");
    logmsg(fatal,0,INFO,"DNSCurve support enabled");
    flagcurved = 1;
  } else {
    flagcurved = 0;
  }  

  droproot(fatal);

  init_server();

  ndelay_off(udp53);
  socket_tryreservein(udp53,65536);

  log_start(starting,ip,ifidx);

  for (;;) {
    len = socket_recv(udp53,buf,sizeof(buf),ip,&port,&ifidx);
    if (len < 0) continue;
    if (!doit()) continue;
    if (ip6_isv4mapped(ip)) 
      socket_send4(udp53,response,response_len,ip + 12,port);
    else
      socket_send(udp53,response,response_len,ip,port,ifidx);
    /* may block for buffer space; if it fails, too bad */
  }
}
