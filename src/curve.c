#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include "uint_t.h"
#include "curve.h"
#include "logmsg.h"
#include "open.h"
#include "taia.h"
#include "byte.h"
#include "fmt.h"
#include "dns.h"
#include "base32.h"
#include "response.h"

#define TXT_LABLEN 255

void curve_nonce(uint8 nonce[12])
{
  int i; // the choice of static x was bad
   
  for (i = 0; i < 12; i++)
    nonce[i] = dns_random(256);
}

/* DNSCurve stream query messages have a fixed layout: 

   1. Dedicated header: 8 byte
   2. Encoded client pubkey: 32 byte
   3. Client nonce: 12 byte
   4. Cryptobox with query: variable size
*/

int dns_curve_query(const char *buf,const unsigned int len,const unsigned int pos)
{
  if (len < 68) return 0;
  if (byte_diff(buf + pos,8,"Q6fnvWj8")) return 0;

  return (pos + 8);
}

int dns_curve_pubkey(uint8 *pubkey,const char *buf,const unsigned int pos)
{
  byte_copy(pubkey,32,buf + pos);
  return (pos + 32);
}

int dns_curve_nonce(uint8 *nonce,const char *buf,const unsigned int pos)
{
  byte_copy(nonce,12,buf + pos);
  return (pos + 12);
}

int dns_curve_cryptobox(uint8 *cryptobox,const char *buf,const unsigned int len,const unsigned int pos)
{
  if (pos >= len) return 0;
  byte_copy(cryptobox,len - pos,buf + pos); 
  return (len - pos);
}

/* DNSCurve alternate/txt query messages have a different layout: 

   1. Header: 12 byte ('curvetxtq')
   2. Qname expressed in the DNS label format:
      a) Client nonce: 12 byte 
         + 
      b) Cryptobox: variable sized
      -> Base32 encoded 
      -> broken down in 'n' fixed sized 50 byte labels (except smaller final) 
      c) New label: Meta information: 4 byte ('36xla')
      d) appended with Base32 encoded client pubkey: 50 byte => 54 byte
   3. Zone (or 0)

   Note: Case is irrelevant.
*/

char curvetxtq[10] = { '\x00','\x00','\x00','\x01','\x00','\x00','\x00','\x00','\x00','\x00' };

int dns_curve_txtquery(const char *buf,const unsigned int len,const unsigned int pos)
{
  int i;

  if (buf[pos] & 0xfe) return 0;  // auth/trunc set

  if (!byte_equal(buf + pos,10,curvetxtq)) return 0;
  if (!byte_equal(buf + len - 4,2,DNS_T_TXT)) return 0;

  // Look for pubkey 

  for (i = 12; i < len; i++) {
    if (*(buf + i) == 54 && (*(buf + i + 1) & ~0x20) == 'X' &&
        *(buf + i + 2) == '1' && (*(buf + i + 3) & ~0x20) == 'A') return i;
  }

  return 0;
}

/* The decoded client nonce + cryptobox (query) ; returns to following box */

static unsigned char *qname;

int dns_curve_txtqname(uint8 *base32box,const char *buf,const unsigned int len)
{
  uint8 box[MAXMSGSIZE];
  unsigned int boxlen = 0;
  unsigned int lablen;
  int i;

  i = dns_packet_getname(buf,len,12,&qname);  
  if (!i) return 0;

  i = 0;
  for (;;) {
    lablen = *(qname + i);
    if (lablen == 54) break;  // final label with pubkey
    else if (lablen > 50) return 0;
    else if (lablen == 0) return 0;

    byte_copy(box + boxlen,lablen,qname + i + 1);
    boxlen += lablen;
    i += lablen + 1;
  }
  
  return base32_decode(base32box,box,boxlen,0);
}

/* The decoded client pubkey; returns the position of zone in buffer */

int dns_curve_txtpubkey(uint8 *pubkey,const char *buf,const unsigned int pos)
{
  if (base32_decode(pubkey,buf + pos,51,1) != 32) return 0;

  return (pos + 52); // beginning of *zone
}

int dns_curve_txtnonce(uint8 *nonce,const uint8 *base32box)
{
  byte_copy(nonce,12,base32box);
  return 12;
}

/* DNSCurve streamline response:

  1. Crafted header: 8 byte (R6 fn vW J8)
  2. Client nonce: 12 byte 
  3. Server nonce: 12 byte 
  4. Cryptobox with response: variable sized
*/

static uint8 cryptobox[4099];
static uint8 fullnonce[24];

int response_stream(const uint8 *secret,const uint8 *nonce)
{
  unsigned int boxlen = response_len;

  byte_copy(fullnonce,12,nonce);
  curve_nonce(fullnonce + 12);
  byte_zero(cryptobox,32);
  byte_copy(cryptobox + 32,response_len,response);
  if (crypto_box_afternm(cryptobox,cryptobox,response_len + 32,fullnonce,secret)) return 0;

  response_len = 0;
  if (!response_addbytes("R6fnvWJ8",8)) return 0;
  if (!response_addbytes(fullnonce,24)) return 0;
  if (!response_addbytes(cryptobox + 16,boxlen + 16)) return 0;

  return 1;
}

char curvetxtr[14] = { '\x00','\x10',   // question type: TXT
                       '\x00','\x01',   // question class: IN
                       '\xc0','\x0c',   // pointer to qname in question part
                       '\x00','\x10',   // response RR type: TXT
                       '\x00','\x01',   // response RR class: IN
                       '\x00','\x00',
                       '\x00','\x00' }; // response RR TTL: 0

char txtheader[10] = { '\x84','\x00',
                       '\x00','\x01',
                       '\x00','\x01',
                       '\x00','\x00',
                       '\x00','\x00' };

/* Alt TXT response format:

  1. Header: 12 byte
  2. *Name from query (Qname)
  3. Meta information: 14 byte + 2 byte RDLEN
  4. Server nonce: 12 
  5. Cryptobox with response: variable size
*/

/* Original query needs to be included */

int response_alttxt(const uint8 *secret,const uint8 *nonce,const char id[2],const unsigned char *query,const unsigned int len,const int rd)
{
  unsigned int boxlen = response_len;
  unsigned int rrdatalen;
  char rdlen[2];
  unsigned int last;
  uint8 lablen;

  byte_copy(fullnonce,12,nonce);
  curve_nonce(fullnonce + 12);

  byte_zero(cryptobox,32);
  byte_copy(cryptobox + 32,response_len,response);

  if (crypto_box_afternm(cryptobox,cryptobox,response_len + 32,fullnonce,secret)) return 0;
  byte_copy(cryptobox + 4,12,fullnonce + 12);
  if (rd) byte_copy(txtheader,1,"\x85");

  response_len = 0;
  if (!response_addbytes(id,2)) return 0;              // transction id from outer packet
  if (!response_addbytes(txtheader,10)) return 0;      // new header
  if (!response_addbytes(query,len)) return 0;         // org Qname ? EDNS0 !!
  if (!response_addbytes(curvetxtr,14)) return 0;      // Q+A section

  boxlen += (16 + 12);                                 // offset + server nonce
  rrdatalen = boxlen + ((boxlen + 254) / TXT_LABLEN);
  uint16_pack_big(rdlen,rrdatalen);
  if (!response_addbytes(rdlen,2)) return 0;           // length of answer

/* Start the split-up of RDATA in 255 byte parts (the server nonce + the crypto box):
   This fits, due to fact we checked this when RR data length was calculated: (MD) */

  last = 4;
  while (boxlen) {
    lablen = TXT_LABLEN;
    if (boxlen < TXT_LABLEN) lablen = boxlen;
    uint16_pack_big(rdlen,lablen);
    if (!response_addbytes(rdlen + 1,1)) return 0;        
    if (!response_addbytes(cryptobox + last,lablen)) return 0; 
    last += lablen;
    boxlen -= lablen;
  }

  return 1;
}
