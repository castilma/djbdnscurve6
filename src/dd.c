#include "dns.h"
#include "dd.h"
#include "ip.h"
#include "scan.h"
#include "dns.h"

int dd4(const char *q,const char *base,char ip[4])
{
  int j;
  unsigned int x;
 
  for (j = 0;; ++j) {
    if (dns_domain_equal(q,base)) return j;
    if (j >= 4) return -1;

    if (*q <= 0) return -1;
    if (*q >= 4) return -1;
    if ((q[1] < '0') || (q[1] > '9')) return -1;
    x = q[1] - '0';
    if (*q == 1) {
      ip[j] = x;
      q += 2;
      continue;
    }
    if (!x) return -1;
    if ((q[2] < '0') || (q[2] > '9')) return -1;
    x = x * 10 + (q[2] - '0');
    if (*q == 2) {
      ip[j] = x;
      q += 3;
      continue;
    }
    if ((q[3] < '0') || (q[3] > '9')) return -1;
    x = x * 10 + (q[3] - '0');
    if (x > 255) return -1;
    ip[j] = x;
    q += 4;
  }
}
int dd6(const char *q,const char *base,char ip[16])
{
  int j;
  int i;
  unsigned int x;

  for (j = 0 ;; ++j) {
    if (dns_domain_equal(q,base)) return j;
    if (j > 15) return -1;

    i = scan_xint(q++,&x);
    if (!i) { --j; continue; }
    if (x > 15) return -1;
    ip[j] = x << 4;
    q += i;
    i = scan_xint(q++,&x);
    if (!i) continue; 
    if (x > 15) return -1;
    ip[j] += x;
    q += i;
    if (j == 15) q--;  /* last character seen */
  }
}
