#!/bin/sh
PARMS="wvu:s:p:h:t:"
FLAG=""
host=""
verbose=0
write=0
usage=3
port=25
mtype=1
selector=1
host="mail"
cert="${1}"
domain="${2}"
proto="${3}"

if [ -f "${cert}" ]; then
	shift
else
	echo "Usage: $0 cert domain protocol -h host -p port -u usage -s selector -t types -v -w"
	echo "	-u [2|3] => 2: DANE Trust Anchor, 3: DANE Domain issued cert (default)"
	echo "	-s [0|1] => 0: X.509 fingerprint (default), 1: Subject Public Key Info hash (SPKI)"
	echo "	-t [1|2] => 1: SHA256 (default), 2: SHA512"
	echo "	-p 25 (default)"
  echo "	-v (verbose)"
	echo "	-w (write)"
  return 1
fi

if [ -n "${domain}" ]; then
	shift
else
	echo "Please provide domain name: 'example.com'"
  return 1
fi

if [ -n "${proto}" ]; then
	shift
else
	echo "Please provide protocol: 'tcp' or 'udp'" 
  return 1
fi

if [ $# -gt 0 ]; then
	while getopts ${PARMS} FLAG
	do
		case ${FLAG} in
			(h) host="${OPTARG}";;
			(p) port="${OPTARG}";;
			(u) usage="${OPTARG}";;
			(s) selector="${OPTARG}";;
			(t) mtype="${OPTARG}";;
			(v) verbose=1;;
			(w) write=1;;
		esac
	done
fi

name="_${port}._${proto}.${host}.${domain}"

echo "Generating TLSA record for: '${name}'"

dates=`openssl x509 -dates -in ${cert} -noout | tr '\n' ' '`
subject=`openssl x509 -subject -in ${cert} -noout`
certhash256=`openssl x509 -fingerprint -sha256 -in ${cert} -noout | cut -d= -f2 | tr -d : | tr [A-F] [a-f]`
certhash512=`openssl x509 -fingerprint -sha512 -in ${cert} -noout | cut -d= -f2 | tr -d : | tr [A-F] [a-f]`
spkihash256=`openssl x509 -in ${cert} -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256`
spkihash256=`echo ${spkihash256} | cut -d' ' -f2`
spkihash512=`openssl x509 -in ${cert} -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha512`
spkihash512=`echo ${spkihash512} | cut -d' ' -f2`

if [ ${verbose} -eq 1 ]; then
  echo "Validity of X.509 certificate: ${dates}"
  echo "X.509 SHA256 fingerprint: ${certhash256}"
  echo "X.509 SHA512 fingerprint: ${certhash512}"
  echo "X.509 SHA256 SPKI digest: ${spkihash256}"
  echo "X.509 SHA512 SPKI digest: ${spkihash512}"
fi

fingerprint=""
if [ ${mtype} -eq 1 -a ${selector} -eq 0 ]; then
  fingerprint=${certhash256}
elif [ ${mtype} -eq 2 -a ${selector} -eq 0 ]; then
  fingerprint=${certhash512}
elif [ ${mtype} -eq 1 -a ${selector} -eq 1 ]; then
  fingerprint=${spkihash256}
elif [ ${mtype} -eq 2 -a ${selector} -eq 1 ]; then
  fingerprint=${spkihash512}
fi

if [ ${selector} -eq 0 ]; then
	echo "Using X.509 cert hash: ${fingerprint}"
else
	echo "Using X.509 SPKI hash: ${finterprint}"
fi

record="_${domain}|${usage}|${selector}|${fingerprint}|${host}|${port}|${proto}"

echo "The following record will be included to tinydns' data file:"
echo "   ${record}"

if [ ${write} -eq 1 ]; then
	echo ${record} >> data
	make
fi

return $?
