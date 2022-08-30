#include "byte.h"
#include "dns.h"
#include "dd.h"
#include "response.h"

#define WHO = "walldns "
const char *fatal = "walldns";
const char *starting = "starting walldns";
int flagcurved;

void init_server(void)
{
  ;
}

int respond(char *q,char qtype[2])
{
  int flaga;
  int flaga4;
  int flagptr;
  char ip4[4];
  char ip6[16];
  int i, j;

  flaga = byte_equal(qtype,2,DNS_T_A);
  flaga4 = byte_equal(qtype,2,DNS_T_AAAA);
  flagptr = byte_equal(qtype,2,DNS_T_PTR);
  if (byte_equal(qtype,2,DNS_T_ANY)) flaga = flagptr = 1;

  if (flaga || flagptr) {
    if (dd4(q,"",ip4) == 4) {
      if (flaga) {
        if (!response_rstart(q,DNS_T_A,655360)) return 0;
        if (!response_addbytes(ip4,4)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      return 1;
    }
    j = dd4(q,"\7in-addr\4arpa",ip4);
    if (j >= 0) {
      if (flaga && (j == 4)) {
        if (!response_rstart(q,DNS_T_A,655360)) return 0;
        for (i = 3; i >=0; --i)
          if (!response_addbytes(ip4 + j,1)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      if (flagptr) {
        if (!response_rstart(q,DNS_T_PTR,655360)) return 0;
        if (!response_addname(q)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      return 1;
    }
  }

  if (flaga4 || flagptr) {
    if (dd6(q,"",ip6) == 16) {
      if (flaga4) {
        if (!response_rstart(q,DNS_T_AAAA,655360)) return 0;
        if (!response_addbytes(ip6,16)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      return 1;
    }
    j = dd6(q,"\3ip6\4arpa",ip6);
    if (j >= 0) {
      if (flaga4 && (j == 16)) {
        if (!response_rstart(q,DNS_T_AAAA,655360)) return 0;
        for (i = 15; i >= 0; --i)
          if (!response_addbytes(ip6 + j,1)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      if (flagptr) {
        if (!response_rstart(q,DNS_T_PTR,655360)) return 0;
        if (!response_addname(q)) return 0;
        response_rfinish(RESPONSE_ANSWER);
      }
      return 1;
    }
  }

  response[2] &= ~4;
  response[3] &= ~15;
  response[3] |= 5;
  return 1;
}
