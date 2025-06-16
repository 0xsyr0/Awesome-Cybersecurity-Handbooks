# Sniffing & Spoofing

- [Resources](#resources)

## Table of Contents

- [DNSChef](#dnschef)
- [DNSChef (NG)](#dnschef-ng)
- [FakeDns](#fakedns)
- [fakessh](#fakessh)
- [Hak5 LAN Turtle](#hak5-lan-turtle)
- [mitmproxy](#mitmproxy)
- [Responder](#responder)
- [SSH-MITM](#ssh-mitm)
- [tshark](#tshark)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| DNSChef | DNSChef - DNS proxy for Penetration Testers and Malware Analysts | https://github.com/iphelix/dnschef |
| DNSChef (NG) | DNSChef (NG) - DNS proxy for Penetration Testers and Malware Analysts | https://github.com/byt3bl33d3r/dnschef-ng |
| FakeDns | A regular-expression based python MITM DNS server with support for DNS Rebinding attacks | https://github.com/Crypt0s/FakeDns |
| FakeSSH | A dockerized fake SSH server honeypot written in Go that logs login attempts. | https://github.com/fffaraz/fakessh |
| mDNS | A mDNS sniffer and interpreter. | https://github.com/eldraco/Sapito |
| mitm6 | mitm6 is a pentesting tool that exploits the default configuration of Windows to take over the default DNS server. | https://github.com/dirkjanm/mitm6 |
| mitmproxy | mitmproxy is an interactive, SSL/TLS-capable intercepting proxy with a console interface for HTTP/1, HTTP/2, and WebSockets. | https://github.com/mitmproxy/mitmproxy |
| Responder | IPv6/IPv4 LLMNR/NBT-NS/mDNS Poisoner and NTLMv1/2 Relay. | https://github.com/lgandx/Responder |
| SSH-MITM | ssh mitm server for security audits supporting public key authentication, session hijacking and file manipulation | https://github.com/ssh-mitm/ssh-mitm |

## DNSChef

> https://github.com/iphelix/dnschef

### Configuration File Example

#### dnschef.ini

```console
[A]     # Queries for IPv4 address records
*.thesprawl.org=192.0.2.1

[AAAA]  # Queries for IPv6 address records
*.thesprawl.org=2001:db8::1

[MX]    # Queries for mail server records
*.thesprawl.org=mail.fake.com

[NS]    # Queries for mail server records
*.thesprawl.org=ns.fake.com

[CNAME] # Queries for alias records
*.thesprawl.org=www.fake.com

[TXT]   # Queries for text records
*.thesprawl.org=fake message

[PTR]
*.2.0.192.in-addr.arpa=fake.com

[SOA]
; FORMAT: mname rname t1 t2 t3 t4 t5
*.thesprawl.org=ns.fake.com. hostmaster.fake.com. 1 10800 3600 604800 3600

[NAPTR]
; FORMAT: order preference flags service regexp replacement
*.thesprawl.org=100 10 U E2U+sip !^.*$!sip:customer-service@fake.com! .

[SRV]
; FORMAT: priority weight port target
*.*.thesprawl.org=0 5 5060 sipserver.fake.com

[DNSKEY]
; FORMAT: flags protocol algorithm base64(key)
*.thesprawl.org=256 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==

[RRSIG]
; FORMAT: covered algorithm labels labels orig_ttl sig_exp sig_inc key_tag name base64(sig)
*.thesprawl.org=A 5 3 86400 20030322173103 20030220173103 2642 thesprawl.org. oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6oB9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3tGNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkGJ5D6fwFm8nN+6pBzeDQfsS3Ap3o=
```

#### Start DNSChef using the Configuration File

```console
$ sudo dnschef --file dnschef.ini
```

or

```console
$ dnschef --interface <LHOST> --port 53 --tcp --file dnschef.ini
```

### Using bloodhound-python with DNSChef

```console
$ proxychains bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -dc '<RHOST>' -ns '<LHOST>' -c all --zip --dns-tcp --dns-timeout 30
$ proxychains bloodhound-python -u '<USERNAME>' -p '<PASSWORD>' -d '<DOMAIN>' -dc '<RHOST>' -ns '<LHOST>' -c all --zip --dns-tcp --dns-timeout 300 --disable-pooling -w 1
```

## DNSChef (NG)

> https://github.com/byt3bl33d3r/dnschef-ng

### Installation

```console
$ pipx install dnschef-ng
```

### Common Commands

```console
$ dnschef-ng -6
$ dnschef-ng --fakeip 127.0.0.1 -q
$ dnschef-ng --fakeip 127.0.0.1 --fakeipv6 ::1 -q
$ dnschef-ng --fakeip 127.0.0.1 --fakeipv6 ::1 --fakemail mail.<DOMAIN> --fakealias www.<DOMAIN> --fakens ns.<DOMAIN> -q
```

### Definitions File

#### dnschef.toml

```console
[A]
"<RHOST>"="<IP_ADDRESS>"

[NS]
"*.<DOMAIN>"="<RHOST>"

[PTR]
"*.1.1.192.in-addr.arpa"="<DOMAIN>"
```

#### Start DNSChef (NG) using Definitions File

```console
$ dnschef-ng --file dnschef.toml -q
```

### File Staging

```console
[A]
"*.<DOMAIN>" = { file = "/PATH/TO/FILE/<FILE>", chunk_size = 4 }

[AAAA]
"*.<DOMAIN>" = { file = "/PATH/TO/FILE/<FILE>", chunk_size = 16 }

[TXT]
"ns*.<DOMAIN>" = { file = "/PATH/TO/FILE/<FILE>", chunk_size = 189, response_format = "{prefix}test-{chunk}", response_prefix_pool = ["atlassian-domain-verification=", "onetrust-domain-verification=", "docusign=" ] }
```

## FakeDns

> https://github.com/Crypt0s/FakeDns

### DNS Rebind Attack

```console
$ cat fake.conf
A <DOMAIN> 127.0.0.1 1%<LHOST>
```

#### Start the Server

```console
$ sudo python3 fakedns.py -c fake.conf --rebind
```

#### Test

```console
nslookup > server <LHOST>
Default server: <LHOST>
Address: <LHOST>#53
> <FAKE_DOMAIN>
Server:         <LHOST>
Address:        <LHOST>#53

Name:   <FAKE_DOMAIN>
Address: 127.0.0.1
*## server can't find <FAKE_DOMAIN>: NXDOMAIN
> <FAKE_DOMAIN>
Server:         <LHOST>
Address:        <LHOST>#53

Name:   <FAKE_DOMAIN>
Address: <LHOST>
*## server can't find <FAKE_DOMAIN>: NXDOMAIN
>
```

## fakessh

> https://github.com/fffaraz/fakessh

```console
$ go install github.com/fffaraz/fakessh@latest
$ sudo setcap 'cap_net_bind_service=+ep' ~/go/bin/fakessh
$ ./fakessh 
```

## Hak5 LAN Turtle

> https://github.com/hak5/lanturtle-modules

> http://downloads.openwrt.org/releases/packages-19.07/mips_24kc/packages/gcc_7.4.0-5_mips_24kc.ipk

> https://github.com/lgandx/Responder/archive/refs/heads/master.zip

### FixIt to UseIt

#### Connect

```console
$ ip a / ifconfig / ipconfig    // have a look for 172.16.84.1
$ ssh root@172.16.84.1          // default password: sh3llz
$ Ctrl+c                        // get to root SSH session
```

#### Network Configuration

```console
$ vim /etc/network/config
```

```console
config interface 'wan'
		option ifname 'eth1'
		option proto 'dhcp'
		option metric '20'
		option ipv6 '0'
```

```console
$ /etc/init.d/network restart
```

#### SD Card Information

```console
$ cat /etc/opkg.conf
```

```console
dest root /
dest ram /tmp
dest sd /sd
```

#### Responder Installation

##### Prerequisites

The `exports` should go to the `.bashrc` to make it persistent.

```console
$ opkg install python3 --dest sd
$ export LD_LIBRARY_PATH="/sd/usr/lib:/usr/lib"
$ opkg install python3-pip --dest sd
$ export PATH="/sd/usr/bin:$PATH"
$ mkdir /sd/python3-modules
$ export PYTHONHOME="/sd/usr/"
$ export PYTHONPATH="/sd/python3-modules"
$ python3 -m pip install setuptools --target=/sd/python3-modules
$ python3 -m pip install wheel --target=/sd/python3-modules
$ wget http://downloads.openwrt.org/releases/packages-19.07/mips_24kc/packages/gcc_7.4.0-5_mips_24kc.ipk
$ scp gcc_7.4.0-5_mips_24kc.ipk root@172.16.84.1:/sd/gcc_7.4.0-5_mips_24kc.ipk
$ opkg install gcc_7.4.0-5_mips_24kc.ipk --dest sd
$ opkg install libffi --dest sd
$ opkg install python3-dev --dest sd
$ export CFLAGS="-I/sd/usr/include/bits/ -I/sd/usr/include/ -I/sd/usr/include/linux/ -I/sd/usr/lib/gcc/mips-openwrt-linux-musl/7.4.0/install-tools/include/ -I/sd/usr/lib/gcc/mips-openwrt-linux-musl/7.4.0/include-fixed/"
$ export CFLAGS="-I/sd/usr/include/"
$ python3 -m pip install netifaces --target=/sd/python3-modules
```

###### Exports

```console
$ export LD_LIBRARY_PATH="/sd/usr/lib:/usr/lib"
$ export PATH="/sd/usr/bin:$PATH"
$ export PYTHONHOME="/sd/usr/"
$ export PYTHONPATH="/sd/python3-modules"
$ export CFLAGS="-I/sd/usr/include/bits/ -I/sd/usr/include/ -I/sd/usr/include/linux/ -I/sd/usr/lib/gcc/mips-openwrt-linux-musl/7.4.0/install-tools/include/ -I/sd/usr/lib/gcc/mips-openwrt-linux-musl/7.4.0/include-fixed/"
$ export CFLAGS="-I/sd/usr/include/"
```

##### Download Responder

```console
$ cd /sd
$ wget https://github.com/lgandx/Responder/archive/refs/heads/master.zip
$ opkg install unzip --dest sd
$ unzip responder.zip
$ mv Responder-master Responder
```

##### Certificate Creation

```console
/sd/Responder/certs
```

``` bash
#!/bin/bash
openssl genrsa out responder.key 2048
openssl req -new -x509 -days 3650 -key responder.key -out responder.crt -subj "/"
```

Create the certificates locally and `copy` it to the `LAN Turtle` before you start `Responder`.

## mitmproxy

### SSL Certificate Configuration

#### Prepare SSL Certificate

```console
$ openssl genrsa -out <FILE>.key 2048
```

```console
$ openssl req -new -key <FILE>.key -out <FILE>.csr -subj "/CN=<DOMAIN>"
```

```console
$ openssl x509 -req -in <FILE>.csr -CA RootCA.crt -CAkey RootCA.key -CAcreateserial -out <FILE>.crt -days 365
```

```console
$ cat <FILE>.key <FILE>.crt > <FILE>.pem
```

#### Execution

```console
$ mitmproxy --mode reverse:https://<RHOST> --certs <FILE>.pem --save-stream-file <FILE>.raw -k -p 443
```

## Responder

> https://github.com/lgandx/Responder

```console
$ sudo responder -I <INTERFACE>
```

## SSH-MITM

```console
$ ssh-mitm server
```

```console
$ ssh-mitm server --remote-host <RHOST>
$ socat TCP-LISTEN:<RPORT>,fork TCP:127.0.0.1:10022
```

## tshark

### Capturing SMTP Traffic

```console
$ tshark -i <INTERFACE> -Y 'smtp.data.fragments' -T fields -e 'text'
```

### Analyzing PCAP File

```console
$ tshark --Y http.request -T fields -e http.host -e http.user_agent -r <FILE>.pcap
```
