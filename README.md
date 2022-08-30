/*! \mainpage

djbdnscurve6
============

is a fork of Dan J. Bernstein's djbdns.

Features
--------

- IPv6 capabilites based on fehQlibs allowing the
  use of compactified IPv6 and LLU addresses.
- Support for TLSA records according to RFC 6698 for tinydns.
- Support for DKIM records according to RFC 6376 for tinydns
  and DNS TXT lookup.
- CurveDNS secured query/response for dnscache.
- CurveDNS enabled servers: tinydns, rbldns, walldns.
  based on NaCl/libsodium applying and improving Matthew Dempsky's patch.
- rbldns supporting IPv6 addresses.
- Multihoming & dualstack capabilities for the servers.
- Miscellaneous improvements in particular for dnscache.
- Siphash cache for dnscache.
- Installation according to the slashpackage convention.


Requirements
------------

djbdnscurve6 requires

- fehQlibs (basics and IP socket connectivity).
- NaCl or libsodium for encryption/decryption services.
- daemontools for startup and environment.
- systemd or others can be used with caution


Packages removed
----------------

- pickdns has been removed.


Unfinished features
-------------------

- tinydns is UDP only and does not provide DNSSec features.
- rts.test has not been fully adjusted yet (it is IPv4 only),
- EDNS0 partially supported by dnscache.


Erwin Hoffmann, July 2022.
