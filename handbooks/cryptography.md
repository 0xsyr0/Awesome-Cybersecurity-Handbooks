# Cryptography

## Table of Contents

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#Resources)
- [Base64](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#Base64)
- [bcrypt](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#bcrypt)
- [Creating Password Hashes](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#Creating-Password-Hashes)
- [EncFS/6](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#EncFS6)
- [Featherduster](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#Featherduster)
- [hash-identifier](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#hash-identifier)
- [hashID](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#hashID)
- [Magic Function](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#Magic-Function)
- [MD5](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#MD5)
- [OpenSSL](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#OpenSSL)
- [PuTTY Tools](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#PuTTY-Tools)
- [Python Pickle](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#Python-Pickle)
- [ROT13](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#ROT13)
- [RSA](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#RSA)
- [SHA256](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#SHA256)
- [XOR](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cryptography.md#XOR)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| FeatherDuster | An automated, modular cryptanalysis tool; i.e., a Weapon of Math Destruction. | https://github.com/nccgroup/featherduster |
| RsaCtfTool | RSA attack tool (mainly for ctf) - retreive private key from weak public key and/or uncipher data. | https://github.com/Ganapati/RsaCtfTool |

## Base64

```c
$ echo aGVsbG8gd29ybGQh | base64 -d
$ base64 -d lasjkdfhalsfsaiusfs | base64 -d -    // double decryption
```

## bcrypt

```c
$ python -c 'import bcrypt; print(bcrypt.hashpw(b"<PASSWORD>", bcrypt.gensalt(rounds=10)).decode("ascii"))'
$ python -c "import bcrypt; print(bcrypt.hashpw('<PASSWORD>'.encode(), bcrypt.gensalt(rounds=10)))"
```

### bcrypt-cli

```c
$ npm install -g @carsondarling/bcrypt-cli
$ bcrypt $(echo -n "<PASSWORD>" | sha256sum | cut -d " " -f 1) && echo
```

## Creating Password Hashes

### Linux

```c
$ cat /etc/shadow
root:$6$YIFGN9pFPOS3EmwO$qwICXAw4bqSjjjFaCT1qYscCV72BjFtx/tehbc7sQTJp09UJj9u83eBio1cLcaxyGkx2oDhJsXT6LL0FABlc5.:18277:0:99999:7:::
```

### Windows

### hashdump.exe

> https://0xprashant.github.io/pages/decryption-instruction/

```c
$ .\hashdump.exe /samdump
```

### secretsdump.py (Impacket)

```c
$ secretsdump.py -just-dc-ntlm <DOMAIN>.local/Administrator:"<PASSWORD>"@<RHOST>
```

### Generating Hash

```c
$ echo Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e06543aa40cbb4ab9dff::: | md5sum
9ec906faff027b1337f9df4955f917b9
```

## EncFS/6

```c
$ sudo apt-get install encfs
```

### Decryption

```c
$ encfsctl export <SOURCE_FOLDER> <DESTINATION_FOLDER>
```

## Featherduster

> https://github.com/nccgroup/featherduster

```c
$ git clone https://github.com/nccgroup/featherduster.git
$ cd featherduster
$ python setup.py install
```

## hash-identifier

```c
$ hash-identifier
```

## hashID

```c
$ hashid -m -j '48bb6e862e54f2a795ffc4e541caed4d'
```

## Magic Function

### It tries to detect various Options of Input

> https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=TlZDaWpGN242cGVNN2E3eUxZUFpyUGdIbVdVSGk5N0xDQXpYeFNFVXJhS21l

## MD5

```c
$ echo 85f3980654g59sif | md5sum
```

## OpenSSL

### Create password for /etc/passwd

```c
$ openssl passwd '<PASSWORD>'
```

### Create Password for /etc/shadow

```c
$ openssl passwd -6 -salt xyz  <PASSWORD>
```

### Read a Certificate

```c
$ openssl req -in req.txt -noout -text
```

### Extracting Certificate

```c
$ openssl pkcs12 -in <PFX>.pfx -clcerts -nokeys -out <CERTIFICATE>.crt
```

### Extracting Private Key

```c
$ openssl pkcs12 -in <PFX>.pfx -nocerts -out <KEY>.key
```

## PuTTY Tools

```c
$ sudo apt-get install putty-tools
```

```c
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

```c
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

```c
e = 85161183100445121230463008656121855194098040675901982832345153586114585729131
n = 65537
```

Use `msieve` to get the prime factors which are `e` if multiplied.

```c
$ ./msieve n = 85161183100445121230463008656121855194098040675901982832345153586114585729131
```

### Prime factors

```c
p = 280651103481631199181053614640888768819
q = 303441468941236417171803802700358403049
```

That means: n = pq

```c
280651103481631199181053614640888768819 * 303441468941236417171803802700358403049
```

### modinv function

> https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python

### crypto.py

```c
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

```c
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

```c
$ openssl rsautl -decrypt -inkey decoder.priv < pass.crypt
```

## SHA256

### Proof of Concept

```c
$ echo -n fff34363f4d15e958f0fb9a7c2e7cc550a5672321d54b5712cd6e4fa17cd2ac8 | wc -c
64
```

```c
$ echo foobar | sha256sum
aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f  -
```

```c
$ echo -n aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f | wc -c
64
```

### Creating SHA256 hashed Password with Python

```c
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

```c
^ = XOE

1 ^ 1 = 0
1 ^ 0 = 1
0 ^ 1 = 1
0 ^ 0 = 0
```

### Byte Flip Attack

```c
110011 flipped with 111111 = 001100
```
