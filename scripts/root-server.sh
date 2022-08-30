#!/bin/sh
path=/usr/local/bin

echo "# `date`" > @
for i in a b c d e f g h i j k l m ; 
do 
	echo $i.root-servers.net; 
	$path/dnsip $i.root-servers.net | tr ' ' '\n' | grep -v "ffff" | grep -e [\.:]
	$path/dnsip $i.root-servers.net | tr ' ' '\n' | grep -v "ffff" | grep -e [\.:] >> @

#	dnsip $i.root-servers.net >> /etc/dnscache/root/servers/@.'date'
#	dig -c chaos -t txt version.bind @$i.ROOT-SERVERS.NET.  | grep -v "^;;" | grep -v "^$" | grep -v ";vers";
done

