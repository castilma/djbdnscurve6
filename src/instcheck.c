#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "logmsg.h"
#include "exit.h"

extern void hier();

#define WHO "instcheck"

void perm(prefix1,prefix2,prefix3,file,type,uid,gid,mode)
char *prefix1;
char *prefix2;
char *prefix3;
char *file;
int type;
int uid;
int gid;
int mode;
{
  struct stat st;

  if (stat(file,&st) == -1) {
    if (errno == ENOENT)
      logmsg(WHO,-99,WARN,B(prefix1,prefix2,prefix3,file," does not exist"));
    else
      logmsg(WHO,-99,WARN,B("unable to stat: .../",file)); 
    return;
  }

  if ((uid != -1) && (st.st_uid != uid))
    logmsg(WHO,-99,WARN,B(prefix1,prefix2,prefix3,file," has wrong owner"));
  if ((gid != -1) && (st.st_gid != gid))
    logmsg(WHO,-99,WARN,B(prefix1,prefix2,prefix3,file," has wrong group"));
  if ((st.st_mode & 07777) != mode)
    logmsg(WHO,-99,WARN,B(prefix1,prefix2,prefix3,file," has wrong permissions"));
  if ((st.st_mode & S_IFMT) != type)
    logmsg(WHO,-99,WARN,B(prefix1,prefix2,prefix3,file," has wrong type"));
}

void h(home,uid,gid,mode)
char *home;
int uid;
int gid;
int mode;
{
  perm("","","",home,S_IFDIR,uid,gid,mode);
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
  perm("",home,"/",subdir,S_IFDIR,uid,gid,mode);
}

void p(home,fifo,uid,gid,mode)
char *home;
char *fifo;
int uid;
int gid;
int mode;
{
  if (chdir(home) == -1)
    logmsg(WHO,111,FATAL,B("unable to switch to: ",home));
  perm("",home,"/",fifo,S_IFIFO,uid,gid,mode);
}

void c(home,subdir,file,uid,gid,mode)
char *home;
char *subdir;
char *file;
int uid;
int gid;
int mode;
{
  if (chdir(home) == -1)
    logmsg(WHO,111,FATAL,B("unable to switch to: ",home));
  if (chdir(subdir) == -1)
    logmsg(WHO,111,FATAL,B("unable to switch to: ",home,"/",subdir));
  perm(".../",subdir,"/",file,S_IFREG,uid,gid,mode);
}

void z(home,file,len,uid,gid,mode)
char *home;
char *file;
int len;
int uid;
int gid;
int mode;
{
  if (chdir(home) == -1)
    logmsg(WHO,111,FATAL,B("unable to switch to; ",home));
  perm("",home,"/",file,S_IFREG,uid,gid,mode);
}

int main()
{
  hier();
  _exit(0);
}
