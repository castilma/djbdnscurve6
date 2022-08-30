#ifndef QUERY_H
#define QUERY_H

#include "dns.h"
#include "uint_t.h"

/* the following constants can be changed on own risk; defaults Y2018 with partial IPv6 support at provider */

#define QUERY_MAXLEVEL 5	  /* search depth */
#define QUERY_MAXALIAS 16	  /* glue depth */	
#define QUERY_MAXLOOP 100	  /* queries per NS */	
#
#define QUERY_MAXUDP 400          /* used by dnscache */
#define QUERY_MAXTCP 40

/* byte patterns for well-known IP addresses and names in DNS messages */

#define IP6_LOOPBACK_ARPA \
"\0011\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\003ip6\004arpa\0"
#define IP6_LOCALNET_ARPA \
"\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\003ip6\004arpa\0"
#define IP6_MULTICAST_ARPA \
"\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\001f\001f\003ip6\004arpa\0"
#define IP6_ALLNODESMULTICAST_ARPA \
"\0011\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0012\0010\001f\001f\003ip6\004arpa\0"
#define IP6_ALLROUTERSMULTICAST_ARPA \
"\0012\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0010\0012\0010\001f\001f\003ip6\004arpa\0"

#define IP6_LOOPBACK_OCTAL \
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\001"
#define IP6_UNSPECIFIED_OCTAL \
"\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
#define IP6_MULTICASTPFX_OCTAL \
"\377\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000"
#define IP6_ALLNODES_OCTAL \
"\377\002\000\000\000\000\000\000\000\000\000\000\000\000\000\001"
#define IP6_ALLROUTERS_OCTAL \
"\377\002\000\000\000\000\000\000\000\000\000\000\000\000\000\002"

#define IP4_LOCALHOST_ARPA \
"\0010\0010\0010\0010\7in-addr\4arpa\0"
#define IP4_LOOPBACK_ARPA \
"\0011\0010\0010\003127\7in-addr\4arpa\0"

#define IP4_LOOPBACK_OCTAL \
"\177\0\0\1"
#define IP4_LOCALHOST_OCTAL \
"\0\0\0\0"

// #define LOCALHOST IP4_LOOPBACK_OCTAL         /* RFC 2606: .localhost (sec 2) */
#define IP4_LOCALNET IP4_LOCALHOST_OCTAL
#define IP6_LOCALNET IP6_UNSPECIFIED_OCTAL
#define IP6_LOCALHOST IP6_LOOPBACK_OCTAL
#define IP6_LOCALHOST_ARPA IP6_LOOPBACK_ARPA

struct query {
  unsigned int loop;
  unsigned int level;
  char *name[QUERY_MAXLEVEL];
  char *control[QUERY_MAXLEVEL]; /* pointing inside name; flagusetxtformat */
  char *ns[QUERY_MAXLEVEL][QUERY_MAXNS];
  char servers[QUERY_MAXLEVEL][QUERY_MAXIPLEN];
  char keys[QUERY_MAXLEVEL][QUERY_MAXNS * 32]; /* each NS has a 32 byte pubkey */
  int flagnskeys[QUERY_MAXLEVEL];
  char *alias[QUERY_MAXALIAS];
  uint32 aliasttl[QUERY_MAXALIAS];
  char ipv6[QUERY_MAXLEVEL];
  char localip[16];
  uint32 scope_id;
  char type[2];
  char class[2];
  uint32 byzg;
  struct dns_transmit dt;
 } ;

extern int query_start(struct query *,char *,char *,char *,char *,uint32);
extern int query_get(struct query *,iopause_fd *,struct taia *);
extern void query_io(struct query *,iopause_fd *,struct taia *);

extern void query_init(void);
extern void query_forwardonly(void);

#endif
