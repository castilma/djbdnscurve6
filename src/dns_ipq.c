#include "case.h"
#include "byte.h"
#include "str.h"
#include "stralloc.h"
#include "dns.h"
#include "socket_if.h"
#include "ip.h"

/**
	@file dns_ipq.c	
	@author djb, feh
	@source ucspi-tcp
	@brief DNS hostname qualification for ipv4 and ipv6
*/

/** 
  @fn int doit -> @return number of added chars to name 
*/
static int doit(stralloc *work,const char *rule)
{
  char ch;
  unsigned int colon;
  unsigned int prefixlen;

  ch = *rule++;
  if ((ch != '?') && (ch != '=') && (ch != '*') && (ch != '-')) return 1;
  colon = str_chr((char *)rule,':');
  if (!rule[colon]) return 1;

  if (work->len < colon) return 1;
  prefixlen = work->len - colon;
  if ((ch == '=') && prefixlen) return 1;
  if (case_diffb((char *)rule,colon,work->s + prefixlen)) return 1;
  if (ch == '?') {
    if (byte_chr(work->s,prefixlen,'.') < prefixlen) return 1;
    if (byte_chr(work->s,prefixlen,'[') < prefixlen) return 1;
    if (byte_chr(work->s,prefixlen,']') < prefixlen) return 1;
  }

  work->len = prefixlen;
  if (ch == '-') work->len = 0;
  return stralloc_cats(work,rule + colon + 1);
}

/** @fn  int dns_ip4_qualify_rules -> @return number of IPv4 addresss with rules */

int dns_ip4_qualify_rules(stralloc *ipout,stralloc *fqdn,const stralloc *in,const stralloc *rules)
{
  unsigned int i;
  unsigned int j;
  unsigned int plus;
  unsigned int fqdnlen;
  int rc = 0;

  if (!stralloc_copy(fqdn,(stralloc *)in)) return DNS_MEM;

  for (j = i = 0; j < rules->len; ++j)
    if (!rules->s[j]) {
      if (!doit(fqdn,rules->s + i)) return DNS_INT;
      i = j + 1;
    }

  fqdnlen = fqdn->len;
  plus = byte_chr(fqdn->s,fqdnlen,'+');
  if (plus >= fqdnlen)
    return dns_ip4(ipout,fqdn);

  i = plus + 1;
  for (;;) {
    j = byte_chr(fqdn->s + i,fqdnlen - i,'+');
    byte_copy(fqdn->s + plus,j,fqdn->s + i);
    fqdn->len = plus + j;
    if (rc += dns_ip4(ipout,fqdn) < 0) return DNS_ERR;
    i += j;
    if (i >= fqdnlen) return rc;
    ++i;
  }
  return 0;
}

/** @fn  int dns_ip_qualify_localhost -> @return number of IP addresss */

int dns_ip_qualify_localhost(stralloc *ipout,stralloc *fqdn,const stralloc *in)
{
  if (!stralloc_copys(ipout,"")) return DNS_MEM;
  if (!stralloc_copys(fqdn,"")) return DNS_MEM;
  ipout->len = 0;

  if (byte_equal(in->s,9,LOCALHOST)) {
    if (!stralloc_copyb(ipout,(const char *) V6loopback,16)) return DNS_MEM;
    if (!stralloc_catb(ipout,(const char *) V46loopback,16)) return DNS_MEM;
    if (!stralloc_copys(fqdn,"localhost.localhost.")) return DNS_MEM;
  }
  if (byte_equal(in->s,13,IP4_LOOPBACK)) {
    if (!stralloc_copyb(ipout,(const char *) V46loopback,16)) return DNS_MEM;
    if (!stralloc_copys(fqdn,"ip4-loopback.localhost.")) return DNS_MEM;
  }
  if (byte_equal(in->s,13,IP6_LOOPBACK)) {
    if (!stralloc_copyb(ipout,(const char *) V6loopback,16)) return DNS_MEM;
    if (!stralloc_copys(fqdn,"ip6-loopback.localhost.")) return DNS_MEM;
  }
//  if (!stralloc_0(fqdn)) return DNS_MEM; // don't do it

  return ipout->len ? ipout->len % 15 : 0;
}

/** @fn  int dns_ip4_qualify -> @return number of IPv4 addresss qualified */

int dns_ip4_qualify(stralloc *ipout,stralloc *fqdn,const stralloc *in)
{
  int r;
  static stralloc rules;

  if ((r = dns_ip_qualify_localhost(ipout,fqdn,in)) > 0 ) return r; 
  if (dns_resolvconfrewrite(&rules) < 0) return DNS_INT;
  return dns_ip4_qualify_rules(ipout,fqdn,in,&rules);
}

/** @fn  int dns_ip4_qualify_rules -> @return number of IPv6 addresss with rules */

int dns_ip6_qualify_rules(stralloc *ipout,stralloc *fqdn,const stralloc *in,const stralloc *rules)
{
  unsigned int i;
  unsigned int j;
  unsigned int plus;
  unsigned int fqdnlen;
  int rc = 0; 

  if (!stralloc_copy(fqdn,(stralloc *)in)) return DNS_MEM;

  for (j = i = 0; j < rules->len; ++j)
    if (!rules->s[j]) {
      if (!doit(fqdn,rules->s + i)) return DNS_INT;
      i = j + 1;
    }

  fqdnlen = fqdn->len;
  plus = byte_chr(fqdn->s,fqdnlen,'+');
  if (plus >= fqdnlen)
    return dns_ip6(ipout,fqdn);

  i = plus + 1;
  for (;;) {
    j = byte_chr(fqdn->s + i,fqdnlen - i,'+');
    byte_copy(fqdn->s + plus,j,fqdn->s + i);
    fqdn->len = plus + j;
    if ((rc += dns_ip6(ipout,fqdn)) < 0) return DNS_ERR;
    i += j;
    if (i >= fqdnlen) return rc;
    ++i;
  }
  return 0;
}

/** @fn  int dns_ip6_qualify -> @return number of IPv6 addresss qualified */

int dns_ip6_qualify(stralloc *ipout,stralloc *fqdn,const stralloc *in)
{
  int r; 
  static stralloc rules;
  
  if ((r = dns_ip_qualify_localhost(ipout,fqdn,in)) > 0) return r;
  if (dns_resolvconfrewrite(&rules) < 0) return DNS_INT;
  return dns_ip6_qualify_rules(ipout,fqdn,in,&rules);
}

/** @fn  int dns_ip_qualify_rules -> @return number of IPv6+IPv4 addresss with rules */

int dns_ip_qualify_rules(stralloc *ipout,stralloc *fqdn,const stralloc *in,const stralloc *rules)
{
  unsigned int i;
  unsigned int j;
  unsigned int k;
  unsigned int plus;
  unsigned int fqdnlen;
  stralloc tmp = {0};
  int rc = 0; 

  if (!stralloc_copy(fqdn,(stralloc *)in)) return DNS_MEM;
  if (!stralloc_copys(ipout,"")) return DNS_MEM;

  for (j = i = 0; j < rules->len; ++j)
    if (!rules->s[j]) {
      if (!doit(fqdn,rules->s + i)) return DNS_INT;
      i = j + 1;
    }

  fqdnlen = fqdn->len;
  plus = byte_chr(fqdn->s,fqdnlen,'+');
  if (plus >= fqdnlen) {
    rc = dns_ip6(ipout,fqdn);
    if (dns_ip4(&tmp,fqdn) > 0) {
      for (k = 0; k < tmp.len; k += 4) {
        if (!stralloc_catb(ipout,(const char *) V4mappedprefix,12)) return DNS_MEM;
        if (!stralloc_catb(ipout,tmp.s + k,4)) return DNS_MEM;
        rc++;
      }
    }
    return rc;
  }

  i = plus + 1;
  for (;;) {
    j = byte_chr(fqdn->s + i,fqdnlen - i,'+');
    byte_copy(fqdn->s + plus,j,fqdn->s + i);
    fqdn->len = plus + j;
    if (!stralloc_copys(ipout,"")) return DNS_MEM;
    rc = dns_ip6(&tmp,fqdn); 
    if (rc) if (!stralloc_cat(ipout,&tmp)) return DNS_MEM;
    if (dns_ip4(&tmp,fqdn) > 0) {
      for (k = 0; k < tmp.len; k += 4) {
        if (!stralloc_catb(ipout,(const char *) V4mappedprefix,12)) return DNS_MEM;
        if (!stralloc_catb(ipout,tmp.s + k,4)) return DNS_MEM;
        rc++;
      }
    }
    
    if (rc < 0) return DNS_ERR;
    i += j;
    if (i >= fqdnlen) return rc;
    ++i;
  }
  return 0;
}

/** @fn  int dns_ip_qualify -> @return number of IP addresss */

int dns_ip_qualify(stralloc *ipout,stralloc *fqdn,const stralloc *in)
{
  int r;
  static stralloc rules;

  if ((r = dns_ip_qualify_localhost(ipout,fqdn,in)) > 0 ) return r; 
  if (dns_resolvconfrewrite(&rules) < 0) return DNS_INT;
  return dns_ip_qualify_rules(ipout,fqdn,in,&rules);
}
