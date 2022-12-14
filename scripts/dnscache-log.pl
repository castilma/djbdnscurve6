#!/usr/bin/perl -p

# usage: tail -f /service/dnscache/log/main/current | tai64nlocal | dnscache-log
# use tail -F instead of tail -f if your tail supports it (linux, freebsd, etc)

# Author: Faried Nawaz (fn@hungry.com); 
# Source: http://www.hungry.com/~fn/dnscache-log.pl.txt

$| = 1;

# strip off the year and the extra tai64 stuff.
s/^\d{4}-(\d\d-\d\d) (\d\d:\d\d:\d\d).(\d*)/$1 $2/;

# convert addresses in hex to dotted decimal notation.
# ugly fix (fn 2003 01 06) 
if (!m/ stats \d+ \d+ \d+ \d+/) {
  s/\b([a-f0-9]{8})\b/join(".", unpack("C*", pack("H8", $1)))/eg;
}

# strip out length from sent messages.
# sent slot-id length
s/sent (\d+) \d+/sent $1/;


### clean up some messages

# tx gluelessness qtype thing domain where.
s/tx (\d+) (\d+) (\S+) (\S+) (.*)/"tx $1 " . queryType($2) . " $3 $4 $5"/e;

# nodata server ttl qtype thing.
s/nodata (\S+) (\d+) (\d+) (\S+)/"nodata $1 " . queryType($2) . " $3 $4"/e;

# cached qtype info.
s/cached (\d+)/"cached " . queryType($1)/e;

# convert stuff like 127.0.0.2:0422:05be 1 to something more descriptive.
# query slot-id host:port qid qtype thing
s/\b([\d.]+):(\w+):(\w+) (\d+) ([-.\w]+)/printQueryLine($1, $2, $3, $4, $5)/e;

# convert rr messages.
s/rr (\S+) (\d+) (\S+) (\S+) (\S+)/printRRLine($1, $2, $3, $4, $5)/e;

### subs

sub printQueryLine {
  my ($host, $port, $query_id, $query_type, $query) = @_;

  # pad hostname

  my $ret = "$host:";
  $ret .= hex($port);
  $ret .= ":" . hex($query_id);
  $ret .= " " . queryType($query_type) . " $query";
  
  return $ret;
}

sub printRRLine {
  my ($host, $ttl, $query_type, $thing, $data) = @_;

  my $ret = "rr ";
  $ret .= "$host " . padd(6, $ttl) . " ";
  $ret .= queryType($query_type) . " $thing ";
  if ($query_type == 16) {	# it's a txt record
    # the first byte is the length.  we skip it.
    $data = substr($data, 2);
    $ret .= "\"" . unpack("A*", pack("H*", $data)) . "\"";
  } else {
    $ret .= "$data";
  }
    return $ret;
}


sub queryType {
  my ($type) = shift;

  my $ret = "";
 
 # i only list the ones that are in dnscache's dns.h.
 SWITCH: {
    ($type == 1)	&& do { $ret = "a";	last SWITCH; };
    ($type == 2)	&& do { $ret = "ns";	last SWITCH; };
    ($type == 5)	&& do { $ret = "cname";	last SWITCH; };
    ($type == 6)	&& do { $ret = "soa";	last SWITCH; };
    ($type == 12)	&& do { $ret = "ptr";	last SWITCH; };
    ($type == 13)	&& do { $ret = "hinfo";	last SWITCH; };
    ($type == 15)	&& do { $ret = "mx";	last SWITCH; };
    ($type == 16)	&& do { $ret = "txt";	last SWITCH; };
    ($type == 17)	&& do { $ret = "rp";	last SWITCH; };
    ($type == 24)	&& do { $ret = "sig";	last SWITCH; };
    ($type == 25)	&& do { $ret = "key";	last SWITCH; };
    ($type == 28)	&& do { $ret = "aaaa";	last SWITCH; };
    ($type == 252)	&& do { $ret = "axfr";	last SWITCH; };
    ($type == 255)	&& do { $ret = "any";	last SWITCH; };
    do { $ret .= "$type "; last SWITCH; };
  }
  return $ret;
}

# there has to be a better way
sub pads {
  my ($amount, $item) = @_;

  return sprintf "%" . $amount . "s", $item;
}

sub padd {
  my ($amount, $item) = @_;

  return sprintf "%0" . $amount . "d", $item;
}
