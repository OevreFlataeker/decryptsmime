#!/usr/bin/python3

# Based on https://stackoverflow.com/questions/57451015/decrypting-s-mime-with-python3-openssl-library
# and https://github.com/RustyToms/Mrs-SMIME

from M2Crypto import BIO, Rand, SMIME, X509, EVP
from OpenSSL import crypto
from base64 import b64decode
from email.policy import default
from sys import stdin
from argparse import ArgumentParser, FileType
import os
import email
import mimetypes
import re

def get_pfx(fname, password):
    f = open(fname, 'rb')
    pfx_data = f.read()
    f.close()
    pfx = crypto.load_pkcs12(pfx_data, bytes(password, encoding='utf-8'))
    return pfx

def decrypt(p7, pkey,x509):
    s = SMIME.SMIME()
    s.pkey = pkey
    s.x509 = x509
    out = s.decrypt(p7)
    return_message = str(out, encoding='utf-8')
    return return_message

def get_cert(pfx):
    cert = pfx.get_certificate()
    fx509 = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    x509 = X509.load_cert_string(fx509)
    return x509

def get_pkey(fkey):
    pkey = pfx.get_privatekey()
    fkey = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)
    pkey = EVP.load_key_string(fkey)
    return pkey

def split(body,directory):

    try:
        os.mkdir(directory)
    except FileExistsError:
        pass

    counter = 1
    msg = email.message_from_bytes(body, policy=default)


    for part in msg.walk():
        # multipart/* are just containers
        if part.get_content_maintype() == 'multipart':
            continue
        filename = part.get_filename()
        mime_type = part.get_content_type()
        print(f'Part {counter}: ')
        print(f'\tMIME Type: {str(mime_type)}')
        print(f'\tDetected Name: {str(filename)}')
        # Most attachments will have file names, but the text and html versions of the email body will not.
        if not filename:
            # directly specifying txt and html because the guess_extension function
            #  didn't work very well for those types
            if mime_type == 'text/plain':
                ext = '.txt'
            elif mime_type == 'text/html':
                ext = '.html'
            else:
                ext = mimetypes.guess_extension(mime_type, strict=False)
                if not ext:
                    # Use a generic bag-of-bits extension
                    ext = '.bin'

            filename = f'part-{counter:03d}{ext}'
        print(f'\tOutput Name: {str(filename)}')
        counter += 1
        with open(os.path.join(args.directory, filename), 'wb') as fp:
            fp.write(part.get_payload(decode=True))

parser = ArgumentParser(description="""\
Decrypts a SMIME messange and unpacks the attachments into a directory of files.
""")
parser.add_argument('-d', '--directory', required=True,
                        help="""Unpack the MIME attachments into the named
                        directory, which will be created if it doesn't already
                        exist.""")
parser.add_argument('-p', '--password', required=True, help="Password for the p12 file")

parser.add_argument('-f', '--p12file', required=True, help='The P12 file with the key')
parser.add_argument('-m', '--mailfile', required=True, help='The raw encrypted mail')
args = parser.parse_args()

print(f"Reading P12 file {args.p12file} with password")
pfx = get_pfx(args.p12file, args.password)
print("Extracting private key")
pkey = get_pkey(pfx)
print("Extracting certificate")
x509 = get_cert(pfx)

print("Reading mail")
with open(args.mailfile) as f:
    full_message = f.read()

b2 = BIO.MemoryBuffer(bytes(full_message,'ascii'))
p7 = SMIME.smime_load_pkcs7_bio(b2)[0]
print("Decrypting")
out_message = decrypt(p7, pkey, x509)
raw = b64decode("".join(out_message.split('\r\n')[3:]))[54:]
print("Dissecting")
split(raw,args.directory)
