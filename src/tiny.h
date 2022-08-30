/* First character used within the tiny data base:

   Character	Meaning
   -----------------------------------------------
   . 		Nameserver NS (authoritive)
   @		Mailserver MX
   &		Nameserver NS (delegation)
   =		IPv4 address for A (CName)
   +		Alias for CName / A  
   :		IPv6 address for AAAA (Cname)
   ~		Alias for CName / AAAA
   %		local extension
   '		TXT record with ASCII rdata
   ^		PTR record
   _		TLSa record
   C		CNAME record
   D		DKIM record
   Z		SOA record 
   O		Generic record type n with octal rdata
   -		Skip record
   #		Comment line

*/

/* Answers in log

   Character	Meaning
   -----------------------------------------------
   + 		ok - rdata responded
   -		no - rdata not available
   I		not implemented
   C		weired Class
   /		no Query

   followed by the query type and the query request.

*/
