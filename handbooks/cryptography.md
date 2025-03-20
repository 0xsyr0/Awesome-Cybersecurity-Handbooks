# Cryptography

- [Resources](#resources)

## Table of Contents

- [Base64](#base64)
- [bcrypt](#bcrypt)
- [Creating Password Hashes](#creating-password-hashes)
- [EncFS/6](#encfs6)
- [Featherduster](#featherduster)
- [hash-identifier](#hash-identifier)
- [hashID](#hashid)
- [Magic Function](#magic-function)
- [MD5](#md5)
- [OpenSSL](#openssl)
- [PBKDF2](#pbkdf2)
- [PuTTY Tools](#putty-tools)
- [Python Pickle](#python-pickle)
- [ROT13](#rot13)
- [RSA](#rsa)
- [SHA256](#sha256)
- [XOR](#xor)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Ciphey | Automatically decrypt encryptions without knowing the key or cipher, decode encodings, and crack hashes | https://github.com/Ciphey/Ciphey |
| FeatherDuster | An automated, modular cryptanalysis tool; i.e., a Weapon of Math Destruction. | https://github.com/nccgroup/featherduster |
| RsaCtfTool | RSA attack tool (mainly for ctf) - retreive private key from weak public key and/or uncipher data. | https://github.com/Ganapati/RsaCtfTool |

## Base64

```console
$ echo aGVsbG8gd29ybGQh | base64 -d
$ base64 -d lasjkdfhalsfsaiusfs | base64 -d -    // double decryption
```

## bcrypt

```console
$ python -c 'import bcrypt; print(bcrypt.hashpw(b"<PASSWORD>", bcrypt.gensalt(rounds=10)).decode("ascii"))'
$ python -c "import bcrypt; print(bcrypt.hashpw('<PASSWORD>'.encode(), bcrypt.gensalt(rounds=10)))"
```

### bcrypt-cli

```console
$ npm install -g @carsondarling/bcrypt-cli
$ bcrypt $(echo -n "<PASSWORD>" | sha256sum | cut -d " " -f 1) && echo
```

## Creating Password Hashes

### Linux

```console
$ cat /etc/shadow
root:$6$YIFGN9pFPOS3EmwO$qwICXAw4bqSjjjFaCT1qYscCV72BjFtx/tehbc7sQTJp09UJj9u83eBio1cLcaxyGkx2oDhJsXT6LL0FABlc5.:18277:0:99999:7:::
```

### Windows

### hashdump.exe

```console
$ .\hashdump.exe /samdump
```

### secretsdump.py (Impacket)

```console
$ impacket-secretsdump -just-dc-ntlm <DOMAIN>.local/Administrator:"<PASSWORD>"@<RHOST>
```

### Generating Hash

```console
$ echo Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e06543aa40cbb4ab9dff::: | md5sum
9ec906faff027b1337f9df4955f917b9
```

## EncFS/6

```console
$ sudo apt-get install encfs
```

### Decryption

```console
$ encfsctl export <SOURCE_FOLDER> <DESTINATION_FOLDER>
```

## Featherduster

> https://github.com/nccgroup/featherduster

```console
$ git clone https://github.com/nccgroup/featherduster.git
$ cd featherduster
$ python setup.py install
```

## hash-identifier

```console
$ hash-identifier
```

## hashID

```console
$ hashid -m -j '48bb6e862e54f2a795ffc4e541caed4d'
```

## Magic Function

### It tries to detect various Options of Input

> https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=TlZDaWpGN242cGVNN2E3eUxZUFpyUGdIbVdVSGk5N0xDQXpYeFNFVXJhS21l

## MD5

```console
$ echo 85f3980654g59sif | md5sum
```

## OpenSSL

### Create Certificate and Key

```console
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365
$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XY/ST=<ST>/L=<L>/O=<O>/OU=<OU>/CN=<CN>"
```

### Create password for /etc/passwd

```console
$ openssl passwd '<PASSWORD>'
```

### Create Password for /etc/shadow

```console
$ openssl passwd -6 -salt xyz  <PASSWORD>
```

### Read a Certificate

```console
$ openssl req -in <FILE>.txt -noout -text
$ openssl req -text -noout -verify -in <FILE>.req
```

### Extracting Certificate

```console
$ openssl pkcs12 -in <PFX>.pfx -clcerts -nokeys -out <CERTIFICATE>.crt
```

### Extracting Private Key

```console
$ openssl pkcs12 -in <PFX>.pfx -nocerts -out <KEY>.key
```

### Examples

#### Extracting .pfx Files

```console
$ openssl pkcs12 -in <CERTIFICATE>.pfx -nocerts -out <KEY>.key
$ openssl rsa -in <KEY>.key -out <KEY>.key
$ openssl pkcs12 -in <CERTIFICATE>.pfx -clcerts -nokeys -out <CERTIFICATE>.crt
```

##### Login using Certificate and Key

```console
$ evil-winrm -i <RHOST> -S -k <KEY>.key -c <CERTIFICATE>.crt
```

## PBKDF2

### Structure

```console
sha256:<ITERATION>:<FROM_HEX_TO_BASE64_SALT>:<FROM_HEX_TO_BASE64_HASHED_PASSWORD>
```

### Formatting One-liner

```console
$ echo "sha256:50000:$(echo <SALT> | xxd -r -p | base64):$(echo <HASHED_PASSWORD> | xxd -r -p | base64)"
```

### CyberChef Recipe & Manual Steps

> https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')To_Base64('A-Za-z0-9%2B/%3D')&oeol=FF

#### Salt

```console
227d873cca89103cd83a976bdac52486
```

#### Salt Base64

```console
In2HPMqJEDzYOpdr2sUkhg==
```

#### Hashed Password

```console
97907280dc24fe517c43475bd218bfad56c25d4d11037d8b6da440efd4d691adfead40330b2aa6aaf1f33621d0d73228fc16
```

#### Hashed Password Base64

```console
l5BygNwk/lF8Q0db0hi/rVbCXU0RA32LbaRA79TWka3+rUAzCyqmqvHzNiHQ1zIo/BY=
```

#### Putting all together

```console
sha256:50000:In2HPMqJEDzYOpdr2sUkhg==:l5BygNwk/lF8Q0db0hi/rVbCXU0RA32LbaRA79TWka3+rUAzCyqmqvHzNiHQ1zIo/BY=
```

### Formater

```python
import base64
import binascii

def format_pbkdf2_hash():

    algo = input("Enter the algorithm (e.g., sha256): ")
    iterations = input("Enter the iteration count (e.g., 600000): ")
    
    salt_input = input("Enter the salt (ASCII string or HEX value): ")
    salt_format = input("Is the salt ASCII or HEX? (Enter 'ascii' or 'hex'): ").strip().lower()
    
    hash_hex = input("Enter the hash (hexadecimal string): ")

    try:
        if salt_format == "ascii":
            salt_base64 = base64.b64encode(salt_input.encode()).decode()
        elif salt_format == "hex":
            salt_bytes = binascii.unhexlify(salt_input)
            salt_base64 = base64.b64encode(salt_bytes).decode()
        else:
            print("Invalid salt format. Please enter 'ascii' or 'hex'.")
            return

        hash_bytes = binascii.unhexlify(hash_hex)
        hash_base64 = base64.b64encode(hash_bytes).decode()

        formatted_hash = f"{algo}:{iterations}:{salt_base64}:{hash_base64}"
        print("\nFormatted hash for Hashcat:")
        print(formatted_hash)
    
    except (binascii.Error, ValueError) as e:
        print(f"Error during conversion: {e}")

if __name__ == "__main__":
    format_pbkdf2_hash()

```

### Cracking with Hashcat

```console
$ hashcat -a 0 -m 10900 <FILE> /PATH/TO/WORDLIST/<WORDLIST>
```

## PuTTY Tools

```console
$ sudo apt-get install putty-tools
```

```console
$ puttygen my_private_key.ppk -O private-openssh -o id_rsa
```

## Python Pickle

```python
import cPickle

f = open('<FILE>', 'r')
mydict = cPickle.load(f)
f.close

for i in mydict:
    b=[]
    for x in i:
        b.append(x[0] * x[1])
    print ''.join(b)
```

## ROT13

> https://tech.pookey.co.uk/non-wp/rot-decoder.php


## RSA

> https://github.com/Ganapati/RsaCtfTool

### Manually breaking RSA

```console
$ python
Python 2.7.18 (default, Apr 20 2020, 20:30:41)
[GCC 9.3.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from Crypto.PublicKey import RSA
>>> f = open("decoder.pub","r")
>>> key = RSA.importKey(f.read())
>>> print key.n
85161183100445121230463008656121855194098040675901982832345153586114585729131
>>> print key.e
65537
```

### Notes

```console
e = 85161183100445121230463008656121855194098040675901982832345153586114585729131
n = 65537
```

Use `msieve` to get the prime factors which are `e` if multiplied.

```console
$ ./msieve n = 85161183100445121230463008656121855194098040675901982832345153586114585729131
```

### Prime factors

```console
p = 280651103481631199181053614640888768819
q = 303441468941236417171803802700358403049
```

That means: n = pq

```console
280651103481631199181053614640888768819 * 303441468941236417171803802700358403049
```

### modinv function

> https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python

### crypto.py

```python
from Crypto.PublicKey import RSA

n = 85161183100445121230463008656121855194098040675901982832345153586114585729131
e = 65537
p = 280651103481631199181053614640888768819
q = 303441468941236417171803802700358403049
m = n-(p+q-1)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

d = modinv(e, m)
key = RSA.construct((n, long(e), d, p, q))
print key.exportKey()
```

```console
$ python crypto.py
-----BEGIN RSA PRIVATE KEY-----
MIGsAgEAAiEAvEeFgY9UxibHe/Mls88ARrXQ0RNetXeYj3AmLOYUmGsCAwEAAQIg
LvuiAxyjSPcwXGvmgqIrLQxWT1SAKVZwewy/gpO2bKECEQDTI2+4s2LacjlWAWZA
A2kzAhEA5Eizfe3idizLLBr0vsjD6QIRALlM92clYJOQ/csCjWeO1ssCEQDHxRNG
BVGjRsm5XBGHj1tZAhEAkJAmnUZ7ivTvKY17SIkqPQ==
-----END RSA PRIVATE KEY-----
```

Write it into a file named `decoder.priv`

### Decrypt the File

```console
$ openssl rsautl -decrypt -inkey decoder.priv < pass.crypt
```

## SHA256

### Proof of Concept

```console
$ echo -n fff34363f4d15e958f0fb9a7c2e7cc550a5672321d54b5712cd6e4fa17cd2ac8 | wc -c
64
```

```console
$ echo foobar | sha256sum
aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f  -
```

```console
$ echo -n aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f | wc -c
64
```

### Creating SHA256 hashed Password with Python

```console
$ python3          
Python 3.10.6 (main, Aug 10 2022, 11:19:32) [GCC 12.1.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import hashlib
>>> password = "password123"
>>> encoded = password.encode()
>>> result = hashlib.sha256(encoded)
>>> print(result)
<sha256 _hashlib.HASH object @ 0x7f315f0a96f0>
>>> print(result.hexdigest())
ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

## XOR

### XOR Table

```console
^ = XOE

1 ^ 1 = 0
1 ^ 0 = 1
0 ^ 1 = 1
0 ^ 0 = 0
```

### Byte Flip Attack

```console
110011 flipped with 111111 = 001100
```
