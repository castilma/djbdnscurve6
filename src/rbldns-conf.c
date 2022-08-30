#include <unistd.h>
#include <pwd.h>
#include "logmsg.h"
#include "exit.h"
#include "auto_home.h"
#include "generic-conf.h"

#define WHO "rbldns-conf"

void usage(void)
{
  logmsg(WHO,100,USAGE,"rbldns-conf acct logacct /rbldns myip base");
}

char *dir;
char *user;
char *loguser;
struct passwd *pw;
char *myip;
char *base;

int main(int argc,char **argv)
{
  user = argv[1];
  if (!user) usage();
  loguser = argv[2];
  if (!loguser) usage();
  dir = argv[3];
  if (!dir) usage();
  if (dir[0] != '/') usage();
  myip = argv[4];
  if (!myip) usage();
  base = argv[5];
  if (!base) usage();

  pw = getpwnam(loguser);
  if (!pw)
    logmsg(WHO,111,FATAL,B("unknown account: ",loguser));

  init(dir,WHO);
  makelog(loguser,pw->pw_uid,pw->pw_gid);

  makedir("env");
  perm(02755);
  start("env/ROOT"); outs(dir); outs("/root\n"); finish();
  perm(0644);
  start("env/IP"); outs(myip); outs("\n"); finish();
  perm(0644);
  start("env/BASE"); outs(base); outs("\n"); finish();
  perm(0644);

  start("run");
  outs("#!/bin/sh\nexec 2>&1\nexec envuidgid "); outs(user);
  outs(" envdir ./env softlimit -d2500000 ");  // 2.500 kbyte memory
  outs(auto_home); outs("/bin/rbldns\n");
  finish();
  perm(0755);

  makedir("root");
  perm(02755);
  start("root/data");
  finish();
  perm(0644);
  start("root/Makefile");
  outs("data.cdb: data\n");
  outs("\t"); outs(auto_home); outs("/bin/rbldns-data\n");
  finish();
  perm(0644);

  _exit(0);
}
