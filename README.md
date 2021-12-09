# DecryptSMIME

Decrypts a SMIME mail

## Usage
usage: smime_decrypt.py [-h] -d DIRECTORY -p PASSWORD -f P12FILE -m MAILFILE
smime_decrypt.py: error: the following arguments are required: -d/--directory, -p/--password, -f/--p12file, -m/--mailfile

```
./smime_decrypt.py -d out -p password -f p12.p12 -m file.smime
Reading P12 file p12.p12 with password
Extracting private key
Extracting certificate
Reading mail
Decrypting
Dissecting
Part 1: 
	MIME Type: text/plain
	Detected Name: None
	Output Name: part-001.txt
Part 2: 
	MIME Type: text/html
	Detected Name: None
	Output Name: part-002.html
Part 3: 
	MIME Type: application/pdf
	Detected Name: secret.pdf
	Output Name: secret.pdf
```
