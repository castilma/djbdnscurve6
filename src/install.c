#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "buffer.h"
#include "logmsg.h"
#include "open.h"
#include "exit.h"

extern void hier();

#define WHO "install"

int fdsourcedir = -1;

void h(home,uid,gid,mode)
char *home;
int uid;
int gid;
int mode;
{
  if (mkdir(home,0700) == -1)
    if (errno != EEXIST)
      logmsg(WHO,111,FATAL,B("unable to mkdir: ",home));
  if (chown(home,uid,gid) == -1)
    logmsg(WHO,111,FATAL,B("unable to chown: ",home));
  if (chmod(home,mode) == -1)
    logmsg(WHO,111,FATAL,B("unable to chmod: ",home));
}

void d(home,subdir,uid,gid,mode)
char *home;
char *subdir;
int uid;
int gid;
int mode;
{
  if (chdir(home) == -1)
    logmsg(WHO,111,FATAL,B("unable to switch to: ",home));
  if (mkdir(subdir,0700) == -1)
    if (errno != EEXIST)
      logmsg(WHO,111,FATAL,B("unable to mkdir: ",home,"/",subdir));
  if (chown(subdir,uid,gid) == -1)
    logmsg(WHO,111,FATAL,B("unable to chown: ",home,"/",subdir));
  if (chmod(subdir,mode) == -1)
    logmsg(WHO,111,FATAL,B("unable to chmod: ",home,"/",subdir));
}

char inbuf[BUFFER_INSIZE];
char outbuf[BUFFER_OUTSIZE];
buffer ssin;
buffer ssout;

void c(home,subdir,file,uid,gid,mode)
char *home;
char *subdir;
char *file;
int uid;
int gid;
int mode;
{
  int fdin;
  int fdout;

  if (fchdir(fdsourcedir) == -1)
    logmsg(WHO,111,FATAL,"unable to switch back to source directory");

  fdin = open_read(file);
  if (fdin == -1)
    logmsg(WHO,111,FATAL,B("unable to read: ",file));
  buffer_init(&ssin,buffer_unixread,fdin,inbuf,sizeof(inbuf));

  if (chdir(home) == -1)
    logmsg(WHO,111,FATAL,B("unable to switch to: ",home));
  if (chdir(subdir) == -1)
    logmsg(WHO,111,FATAL,B("unable to switch to: ",home,"/",subdir));

  fdout = open_trunc(file);
  if (fdout == -1)
    logmsg(WHO,111,FATAL,B("unable to write: .../",subdir,"/",file));
  buffer_init(&ssout,buffer_unixwrite,fdout,outbuf,sizeof(outbuf));

  switch(buffer_copy(&ssout,&ssin)) {
    case -2:
      logmsg(WHO,111,FATAL,B("unable to read: ",file));
    case -3:
      logmsg(WHO,111,FATAL,B("unable to write: .../",subdir,"/",file));
  }

  close(fdin);
  if (buffer_flush(&ssout) == -1)
    logmsg(WHO,111,FATAL,B("unable to write: .../",subdir,"/",file));
  if (fsync(fdout) == -1)
    logmsg(WHO,111,FATAL,B("unable to write: .../",subdir,"/",file));
  if (close(fdout) == -1) /* NFS silliness */
    logmsg(WHO,111,FATAL,B("unable to write: .../",subdir,"/",file));

  if (chown(file,uid,gid) == -1)
    logmsg(WHO,111,FATAL,B("unable to chown: .../",subdir,"/",file));
  if (chmod(file,mode) == -1)
    logmsg(WHO,111,FATAL,B("unable to chmod: .../",subdir,"/",file));
}

void z(home,subdir,file,len,uid,gid,mode)
char *home;
char *subdir;
char *file;
int len;
int uid;
int gid;
int mode;
{
  int fdout;

  if (chdir(home) == -1)
    logmsg(WHO,111,FATAL,B("unable to switch to: ",home));
  if (chdir(subdir) == -1)
    logmsg(WHO,111,FATAL,B("unable to switch to: ",home,"/",subdir));

  fdout = open_trunc(file);
  if (fdout == -1)
    logmsg(WHO,111,FATAL,B("unable to write: .../",subdir,"/",file));
  buffer_init(&ssout,buffer_unixwrite,fdout,outbuf,sizeof(outbuf));

  while (len-- > 0)
    if (buffer_put(&ssout,"",1) == -1)
      logmsg(WHO,111,FATAL,B("unable to write: .../",subdir,"/",file));

  if (buffer_flush(&ssout) == -1)
    logmsg(WHO,111,FATAL,B("unable to write: .../",subdir,"/",file));
  if (fsync(fdout) == -1)
    logmsg(WHO,111,FATAL,B("unable to write: .../",subdir,"/",file));
  if (close(fdout) == -1) /* NFS silliness */
    logmsg(WHO,111,FATAL,B("unable to write: .../",subdir,"/",file));

  if (chown(file,uid,gid) == -1)
    logmsg(WHO,111,FATAL,B("unable to chown: .../",subdir,"/",file));
  if (chmod(file,mode) == -1)
    logmsg(WHO,111,FATAL,B("unable to chmod: .../",subdir,"/",file));
}

int main()
{
  fdsourcedir = open_read(".");
  if (fdsourcedir == -1)
    logmsg(WHO,111,FATAL,"unable to open current directory");

  umask(077);
  hier();
  _exit(0);
}
