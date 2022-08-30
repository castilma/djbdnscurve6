# Don't edit Makefile! Use conf-* for configuration.

SHELL=/bin/sh

default: it-conf it-setup it-server it-clients it-misc

auto-str: \
load auto-str.o 
	./load auto-str 

auto-str.o: \
compile auto-str.c  
	./compile auto-str.c

auto_home.c: \
auto-str ../conf-home
	./auto-str auto_home `head -1 ../conf-home` > auto_home.c

auto_home.o: \
compile auto_home.c
	./compile auto_home.c

axfr-get: \
load axfr-get.o dnscresolv.a
	./load axfr-get dnscresolv.a 

axfr-get.o: \
compile axfr-get.c dns.h 
	./compile axfr-get.c

axfrdns: \
load axfrdns.o droproot.o tdlookup.o response.o qlog.o edns0.o \
clientloc.o dnscresolv.a
	./load axfrdns droproot.o tdlookup.o response.o edns0.o \
	qlog.o clientloc.o dnscresolv.a 

axfrdns-conf: \
load axfrdns-conf.o generic-conf.o auto_home.o 
	./load axfrdns-conf generic-conf.o auto_home.o 

axfrdns-conf.o: \
compile axfrdns-conf.c generic-conf.h auto_home.h 
	./compile axfrdns-conf.c

axfrdns.o: \
compile axfrdns.c droproot.h \
dns.h qlog.h response.h clientloc.h
	./compile axfrdns.c

base32.o: \
compile base32.c base32.h 
	./compile base32.c

cachetest: \
load cachetest.o sipcache.o siphash.o dnscresolv.a
	./load cachetest sipcache.o siphash.o dnscresolv.a

cachetest.o: \
compile cachetest.c sipcache.h
	./compile cachetest.c

check: \
it instcheck
	./instcheck

chkshsgr: \
load chkshsgr.o
	./load chkshsgr 

chkshsgr.o: \
compile chkshsgr.c 
	./compile chkshsgr.c

choose: \
warn-auto.sh choose.sh ../conf-home
	cat warn-auto.sh choose.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> choose
	chmod 755 choose

clientloc.o: \
compile clientloc.c
	./compile clientloc.c

clientok.o: \
compile clientok.c clientok.h
	./compile clientok.c

curve.o: \
compile curve.c dns_random.c curve.h base32.h response.c response.h \
  dns_packet.c
	./compile curve.c dns_random.c dns_packet.c

curvedns.o: \
compile curvedns.c serverok.c base32.c \
	curvedns.h base32.h dns.h serverok.h 
	./compile curvedns.c serverok.c base32.c

curvedns-keygen: \
load curvedns-keygen.o base32.o curve.o auto_home.o \
  dns_random.o generic-conf.o hex.o response.o \
  dns_domain.o dns_packet.o
	./load curvedns-keygen base32.o curve.o auto_home.o \
	generic-conf.o hex.o response.o \
	dns_random.o dns_domain.o dns_packet.o


curvedns-keygen.o: \
compile curvedns-keygen.c base32.c auto_home.h generic-conf.h \
	base32.h hex.h curve.h
	./compile curvedns-keygen.c 

compile: \
warn-auto.sh ../conf-cc
	( cat warn-auto.sh; \
	echo exec "`head -1 ../conf-cc`" '-c $${1+"$$@"}' \
	) > compile
	chmod 755 compile

dd.o: \
compile dd.c dd.h dns.h 
	./compile dd.c

direntry.h: \
choose compile trydrent.c direntry.h1 direntry.h2
	./choose trydrent direntry.h1 direntry.h2 > direntry.h

dnscache: \
load dnscache.o query.o droproot.o clientok.o log.o sipcache.o dd.o \
siphash.o edns0.o response.o roots.o base32.o serverok.o dnscresolv.a \
socket.lib 
	./load dnscache query.o droproot.o sipcache.o siphash.o \
	clientok.o log.o dd.o edns0.o response.o roots.o base32.o \
	serverok.o dnscresolv.a `cat socket.lib`

dnscache-conf: \
load dnscache-conf.o generic-conf.o auto_home.o 
	./load dnscache-conf generic-conf.o auto_home.o 

dnscache-conf.o: \
compile dnscache-conf.c hasdevtcp.h auto_home.h generic-conf.h 
	./compile dnscache-conf.c

dnscache.o: \
compile dnscache.c \
dns.h roots.h query.h response.h sipcache.h siphash.h log.h \
clientok.h droproot.h curvedns.h base32.h serverok.h
	./compile dnscache.c 

dnsfilter: \
load dnsfilter.o socket.lib dnscresolv.a
	./load dnsfilter dnscresolv.a `cat socket.lib`

dnsfilter.o: \
compile dnsfilter.c dns.h 
	./compile dnsfilter.c

dnsip: \
load dnsip.o socket.lib dnscresolv.a
	./load dnsip dnscresolv.a `cat socket.lib`

dnsip.o: \
compile dnsip.c dns.h 
	./compile dnsip.c

dnsipq: \
load dnsipq.o socket.lib dnscresolv.a
	./load dnsipq dnscresolv.a `cat socket.lib`

dnsipq.o: \
compile dnsipq.c dns.h 
	./compile dnsipq.c

dnsmx: \
load dnsmx.o socket.lib dnscresolv.a
	./load dnsmx dnscresolv.a `cat socket.lib`

dnsmx.o: \
compile dnsmx.c dns.h 
	./compile dnsmx.c

dnsname: \
load dnsname.o socket.lib dnscresolv.a
	./load dnsname dnscresolv.a `cat socket.lib`

dnsname.o: \
compile dnsname.c dns.h 
	./compile dnsname.c

dnsq: \
load dnsq.o printrecord.o printpacket.o parsetype.o \
socket.lib dnscresolv.a
	./load dnsq printrecord.o printpacket.o parsetype.o \
	dnscresolv.a `cat socket.lib`

dnsq.o: \
compile dnsq.c dns.h printpacket.h parsetype.h 
	./compile dnsq.c

dnsqr: \
load dnsqr.o printrecord.o printpacket.o parsetype.o \
base32.o socket.lib dnscresolv.a
	./load dnsqr printrecord.o printpacket.o parsetype.o \
	base32.o dnscresolv.a `cat socket.lib`

dnsqr.o: \
compile dnsqr.c dns.h printpacket.h parsetype.h 
	./compile dnsqr.c

dns_domain.o: \
compile dns_domain.c dns.h 
	./compile dns_domain.c

dns_packet.o: \
compile dns_packet.c dns.h 
	./compile dns_packet.c

dnscresolv.a: \
dns_domain.c dns_dtda.c dns_ip.c dns_ipq.c dns_name.c dns_sortip.c \
dns_nd.c dns_packet.c dns_random.c dns_rcip.c dns_rcrw.c dns_resolve.c \
dns_transmit.c dns_txt.c curvedns.c base32.c dns.h curvedns.h \
serverok.c serverok.h 
	./compile dns_domain.c dns_dfd.c dns_dtda.c dns_ip.c dns_ipq.c \
	dns_mx.c dns_name.c dns_nd.c dns_packet.c dns_random.c dns_rcip.c \
	dns_rcrw.c dns_resolve.c dns_transmit.c dns_txt.c dns_sortip.c curvedns.c \
	base32.c hex.c dns.h curvedns.h serverok.c serverok.h 
	./makelib dnscresolv.a dns_domain.o dns_dfd.o dns_dtda.o dns_ip.o dns_ipq.o \
	dns_mx.o dns_name.o dns_nd.o dns_packet.o dns_random.o dns_rcip.o dns_sortip.o \
	dns_rcrw.o dns_resolve.o dns_transmit.o dns_txt.o curvedns.o base32.o hex.o \
	serverok.o 

dnstrace: \
load dnstrace.o dd.o printrecord.o parsetype.o socket.lib dnscresolv.a
	./load dnstrace dd.o printrecord.o parsetype.o \
	dnscresolv.a `cat socket.lib`

dnstrace.o: \
compile dnstrace.c dd.h dns.h printrecord.h parsetype.h 
	./compile dnstrace.c

dnstracesort: \
warn-auto.sh dnstracesort.sh ../conf-home
	cat warn-auto.sh dnstracesort.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> dnstracesort
	chmod 755 dnstracesort

dnstxt: \
load dnstxt.o socket.lib dnscresolv.a
	./load dnstxt dnscresolv.a `cat socket.lib`

dnstxt.o: \
compile dnstxt.c dns.h 
	./compile dnstxt.c

droproot.o: \
compile droproot.c 
	./compile droproot.c

edns0.o: \
compile edns0.c dns.h response.h 
	./compile edns0.c

generic-conf.o: \
compile generic-conf.c generic-conf.h
	./compile generic-conf.c

hasdevtcp.h: \
systype hasdevtcp.h1 hasdevtcp.h2
	( case "`cat systype`" in \
	  sunos-5.*) cat hasdevtcp.h2 ;; \
	  *) cat hasdevtcp.h1 ;; \
	esac ) > hasdevtcp.h

hasshsgr.h: \
choose ./compile load tryshsgr.c hasshsgr.h1 hasshsgr.h2 chkshsgr \
warn-shsgr
	./chkshsgr || ( cat warn-shsgr; exit 1 )
	./choose clr tryshsgr hasshsgr.h1 hasshsgr.h2 > hasshsgr.h

hex.o: \
compile hex.c hex.h
	./compile hex.c

hier.o: \
compile hier.c auto_home.h
	./compile hier.c

install: \
load install.o hier.o auto_home.o 
	./load install hier.o auto_home.o 

install.o: \
compile install.c
	./compile install.c

instcheck: \
load instcheck.o hier.o auto_home.o 
	./load instcheck hier.o auto_home.o
	
instcheck.o: \
compile instcheck.c 
	./compile instcheck.c

it-conf: \
axfrdns-conf dnscache-conf tinydns-conf walldns-conf rbldns-conf curvedns-keygen

it-clients: \
dnsfilter dnsip dnsipq dnsmx dnsname dnsq dnsqr \
dnstrace dnstracesort dnstxt

it-misc: \
cachetest random-ip utime rts

it-server: \
makelib axfrdns axfr-get dnscache walldns rbldns rbldns-data \
tinydns tinydns-data tinydns-get tinydns-edit

it-setup: \
install instcheck makelib

load: \
warn-auto.sh ../conf-ld
	( cat warn-auto.sh; \
	echo 'main="$$1"; shift'; \
	echo exec "`head -1 ../conf-ld`" \
	'-o "$$main" "$$main".o $${1+"$$@"} -lqlibs -lnacl' \
	) > load
	chmod 755 load

log.o: \
compile log.c log.h
	./compile log.c

makelib: \
warn-auto.sh systype
	( cat warn-auto.sh; \
	echo 'main="$$1"; shift'; \
	echo 'rm -f "$$main"'; \
	echo 'ar cr "$$main" $${1+"$$@"}'; \
	case "`cat systype`" in \
	sunos-5.*) ;; \
	unix_sv*) ;; \
	irix64-*) ;; \
	irix-*) ;; \
	dgux-*) ;; \
	hp-ux-*) ;; \
	sco*) ;; \
	*) echo 'ranlib "$$main"' ;; \
	esac \
	) > makelib
	chmod 755 makelib

parsetype.o: \
compile dns.h parsetype.c  
	./compile parsetype.c

printpacket.o: \
compile printpacket.c dns.h printrecord.h printpacket.h 
	./compile printpacket.c

printrecord.o: \
compile printrecord.c dns.h printrecord.h 
	./compile printrecord.c

qlog.o: \
./compile qlog.c qlog.h 
	./compile qlog.c

query.o: \
compile query.c query.h roots.h log.h sipcache.h dns.h dd.h response.h \
curvedns.h base32.h serverok.h
	./compile query.c query.h roots.h log.h sipcache.h dns.h dd.h response.h \
	curvedns.h base32.h serverok.h

random-ip: \
load random-ip.o 
	./load random-ip dnscresolv.a 

random-ip.o: \
compile random-ip.c dns.h 
	./compile random-ip.c

rbldns: \
load rbldns.o server.o response.o dd.o droproot.o qlog.o \
hex.o curve.o edns0.o socket.lib dnscresolv.a
	./load rbldns server.o response.o dd.o droproot.o qlog.o \
	hex.o curve.o edns0.o dnscresolv.a \
	`cat socket.lib`

rbldns-conf: \
load rbldns-conf.o generic-conf.o auto_home.o 
	./load rbldns-conf generic-conf.o auto_home.o

rbldns-conf.o: \
compile rbldns-conf.c auto_home.h generic-conf.h 
	./compile rbldns-conf.c

rbldns-data: \
load rbldns-data.o 
	./load rbldns-data 

rbldns-data.o: \
compile rbldns-data.c 
	./compile rbldns-data.c

rbldns.o: \
compile rbldns.c dns.h dd.h response.h 
	./compile rbldns.c

response.o: \
compile response.c dns.h response.h 
	./compile response.c

roots.o: \
compile roots.c direntry.h dns.h roots.h
	./compile roots.c

rts: \
warn-auto.sh rts.sh ../conf-home
	cat warn-auto.sh rts.sh \
	| sed s}HOME}"`head -1 ../conf-home`"}g \
	> rts
	chmod 755 rts

select.h: \
choose ./compile trysysel.c select.h1 select.h2
	./choose c trysysel select.h1 select.h2 > select.h

server.o: \
compile server.c droproot.h qlog.h response.h dns.h 
	./compile server.c

setup: \
it install
	./install

sipcache.o: \
compile sipcache.c sipcache.h
	./compile sipcache.c

siphash.o: \
compile siphash.c siphash.h
	./compile siphash.c

socket.lib: \
trylsock.c ./compile load
	( ( ./compile trylsock.c && \
	./load trylsock -lsocket -lnsl ) >/dev/null 2>&1 \
	&& echo -lsocket -lnsl || exit 0 ) > socket.lib
	rm -f trylsock.o trylsock

haven2i.h: \
tryn2i.c choose ./compile load socket.lib haven2i.h1 haven2i.h2
	cp /dev/null haven2i.h
	./choose cL tryn2i haven2i.h1 haven2i.h2 socket > haven2i.h

systype: \
find-systype.sh ../conf-cc ../conf-ld trycpp.c x86cpuid.c
	( cat warn-auto.sh; \
	echo CC=\'`head -1 ../conf-cc`\'; \
	echo LD=\'`head -1 ../conf-ld`\'; \
	cat find-systype.sh; \
	) | sh > systype

tdlookup.o: \
compile tdlookup.c dns.h response.h clientloc.h
	./compile tdlookup.c

tinydns: \
load tinydns.o server.o droproot.o tdlookup.o response.o \
hex.o curve.o qlog.o clientloc.o edns0.o socket.lib dnscresolv.a
	./load tinydns server.o droproot.o tdlookup.o curve.o \
	hex.o response.o qlog.o clientloc.o edns0.o dnscresolv.a \
	`cat socket.lib`

tinydns-conf: \
load tinydns-conf.o generic-conf.o auto_home.o 
	./load tinydns-conf generic-conf.o auto_home.o 

tinydns-conf.o: \
compile tinydns-conf.c auto_home.h generic-conf.h
	./compile tinydns-conf.c

tinydns-data: \
load tinydns-data.o 
	./load tinydns-data  dnscresolv.a 

tinydns-data.o: \
compile tinydns-data.c dns.h 
	./compile tinydns-data.c

tinydns-edit: \
load tinydns-edit.o dnscresolv.a
	./load tinydns-edit dnscresolv.a 

tinydns-edit.o: \
compile tinydns-edit.c dns.h 
	./compile tinydns-edit.c

tinydns-get: \
load tinydns-get.o tdlookup.o response.o printpacket.o printrecord.o \
parsetype.o clientloc.o dnscresolv.a
	./load tinydns-get tdlookup.o response.o printpacket.o \
	printrecord.o parsetype.o clientloc.o dnscresolv.a 

tinydns-get.o: \
compile tinydns-get.c response.h printpacket.h parsetype.h dns.h 
	./compile tinydns-get.c

tinydns.o: \
compile tinydns.c dns.h 
	./compile tinydns.c

utime: \
load utime.o 
	./load utime 

utime.o: \
compile utime.c
	./compile utime.c

walldns: \
load walldns.o server.o response.o droproot.o qlog.o dd.o \
hex.o edns0.o socket.lib dnscresolv.a curve.o
	./load walldns server.o response.o curve.o \
	hex.o droproot.o qlog.o edns0.o dd.o dnscresolv.a \
	`cat socket.lib`

walldns-conf: \
load walldns-conf.o generic-conf.o auto_home.o 
	./load walldns-conf generic-conf.o auto_home.o 
	

walldns-conf.o: \
compile walldns-conf.c auto_home.h generic-conf.h
	./compile walldns-conf.c

walldns.o: \
compile walldns.c dns.h dd.h response.h 
	./compile walldns.c

clean:
	rm -f `cat TARGETS`
