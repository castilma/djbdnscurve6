#include "auto_home.h"

extern void h(const char* home,int uid,int gid,int mode);
extern void d(const char* home,const char* subdir,int uid,int gid,int mode);
extern void c(const char* home,const char* subdir,const char* file,int uid,int gid,int mode);

void hier()
{
  c("/","etc","dnsroots.global",-1,-1,0644);

  h(auto_home,-1,-1,02755);
  d(auto_home,"bin",-1,-1,02755);

  c(auto_home,"bin","dnscache-conf",-1,-1,0755);
  c(auto_home,"bin","tinydns-conf",-1,-1,0755);
  c(auto_home,"bin","walldns-conf",-1,-1,0755);
  c(auto_home,"bin","rbldns-conf",-1,-1,0755);
  c(auto_home,"bin","axfrdns-conf",-1,-1,0755);
  c(auto_home,"bin","curvedns-keygen",-1,-1,0755);

  c(auto_home,"bin","dnscache",-1,-1,0755);
  c(auto_home,"bin","tinydns",-1,-1,0755);
  c(auto_home,"bin","walldns",-1,-1,0755);
  c(auto_home,"bin","rbldns",-1,-1,0755);
  c(auto_home,"bin","axfrdns",-1,-1,0755);

  c(auto_home,"bin","tinydns-get",-1,-1,0755);
  c(auto_home,"bin","tinydns-data",-1,-1,0755);
  c(auto_home,"bin","tinydns-edit",-1,-1,0755);
  c(auto_home,"bin","rbldns-data",-1,-1,0755);
  c(auto_home,"bin","axfr-get",-1,-1,0755);

  c(auto_home,"bin","dnsip",-1,-1,0755);
  c(auto_home,"bin","dnsipq",-1,-1,0755);
  c(auto_home,"bin","dnsname",-1,-1,0755);
  c(auto_home,"bin","dnstxt",-1,-1,0755);
  c(auto_home,"bin","dnsmx",-1,-1,0755);
  c(auto_home,"bin","dnsfilter",-1,-1,0755);
  c(auto_home,"bin","dnsqr",-1,-1,0755);
  c(auto_home,"bin","dnsq",-1,-1,0755);
  c(auto_home,"bin","dnstrace",-1,-1,0755);
  c(auto_home,"bin","dnstracesort",-1,-1,0755);
}
