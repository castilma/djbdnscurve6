#include <sys/stat.h>
#include <unistd.h>
#include "logmsg.h"
#include "str.h"
#include "case.h"
#include "open.h"
#include "close.h"
#include "stralloc.h"
#include "base32.h"
#include "auto_home.h"
#include "uint_t.h"
#include "generic-conf.h"
#include "curve.h"
#include <stdio.h>
#include "byte.h"

#define WHO "curvedns-keygen"

int main()
{
  struct stat st;
  char hexpublic[65]; 
  char hexprivate[65];
  char dnsname[55];
  uint8 public[32]; 
  uint8 private[32]; 

  /* check if already exists */

  if (chdir("env") == -1)
    logmsg(WHO,111,FATAL,"unable to switch to: ./env");

  if (stat("CURVEDNS_PRIVATE_KEY",&st) == 0)
    logmsg(WHO,100,ERROR,"A private key file already exists; remove that first.");

  if (!crypto_random_init()) 
    logmsg(WHO,100,FATAL,"unable to ensure randomness");

  // Generate the actual keypair
  if (crypto_box_keypair(public,private))
    logmsg(WHO,100,FATAL,"unable to generate public/private key pair");

  // The DNSCurve (base32)-encoding of the PUBLIC key
  byte_copy(dnsname,3,"uz5");
  if (base32_serverkey(dnsname + 3,public,32) != 52) 
    logmsg(WHO,100,INFO,"base32_encode of public key failed");

  // The hex encoding of the PUBLIC key
  if (!hex_encode(public,32,hexpublic,64)) 
    logmsg(WHO,100,ERROR,"hex_encode of public key failed");
	
  // The hex encoding of the PRIVATE key
  if (!hex_encode(private,32,hexprivate,64))
    logmsg(WHO,100,ERROR,"hex_encode of private key failed");

  hexpublic[64] = '\0';
  hexprivate[64] = '\0';
  dnsname[54] = '\0';

  start("CURVEDNS_PRIVATE_KEY"); 
  out(private,32); 
  finish();
  perm(0400);

  start(dnsname);
  outs(hexpublic); 
  outs("\n"); 
  finish();
  perm(0644);

  /* Report */

  logmsg(WHO,INFO,0,B("DNS public key: ",dnsname));
  logmsg(WHO,INFO,0,B("Hex public key: ",hexpublic));
  logmsg(WHO,INFO,0,B("Hex secret key: ",hexprivate));

  return 0;
}
