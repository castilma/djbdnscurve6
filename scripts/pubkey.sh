#!/bin/sh

key=$1
out="pubkey.txt"

if [ "x${key}" = "x" ]
then
  echo "Enter a x509 private key file (readable!) as fist argument.\
  The output is 'pubkey.txt' ready for use."
  exit 1
fi

echo "Extracting pubkey from ${key} ..."

openssl rsa -in ${key} -pubout | grep -v KEY | tr -d '\n' > ${out}

cat ${out}

exit 0
