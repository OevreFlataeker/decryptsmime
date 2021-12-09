#!/bin/bash

if [ $# -lt 3 ]; then
    echo "Usage: ${0} <mailfile to decrypt> <p12file> <p12password"
    exit 1
fi

echo "Decrypting '${1}' with p12 file '${2}'"

./smime_decrypt.py -d decrypted -p ${3} -f ${2} -m ${1}

echo "Finished" 








