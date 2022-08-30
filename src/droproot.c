#include <unistd.h>
#include "env.h"
#include "scan.h"
#include "prot.h"
#include "logmsg.h"


void droproot(const char *fatal)
{
  char *x;
  unsigned long id;

  x = env_get("ROOT");
 if (!x)
    logmsg(fatal,111,ERROR,"$ROOT not set");
  if (chdir(x) == -1)
    logmsg(fatal,111,FATAL,B("unable to chdir to: ",x));
  if (chroot(".") == -1)
    logmsg(fatal,111,FATAL,B("unable to chroot to: ",x));

  x = env_get("GID");
  if (!x)
    logmsg(fatal,111,FATAL,"$GID not set");
  scan_ulong(x,&id);
  if (prot_gid((int) id) == -1)
    logmsg(fatal,111,FATAL,"unable to setgid");

  x = env_get("UID");
  if (!x)
    logmsg(fatal,111,FATAL,"$UID not set");
  scan_ulong(x,&id);
  if (prot_uid((int) id) == -1)
    logmsg(fatal,111,FATAL,"unable to setuid");
}
