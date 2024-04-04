# Sniffing & Spoofing

- [Resources](#resources)

## Table of Contents

- [DNSChef](#dnschef)
- [FakeDns](#fakedns)
- [fakessh](#fakessh)
- [Responder](#responder)
- [SSH-MITM](#ssh-mitm)
- [tshark](#tshark)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| FakeDns | A regular-expression based python MITM DNS server with support for DNS Rebinding attacks | https://github.com/Crypt0s/FakeDns |
| FakeSSH | A dockerized fake SSH server honeypot written in Go that logs login attempts. | https://github.com/fffaraz/fakessh |
| mDNS | A mDNS sniffer and interpreter. | https://github.com/eldraco/Sapito |
| mitm6 | mitm6 is a pentesting tool that exploits the default configuration of Windows to take over the default DNS server. | https://github.com/dirkjanm/mitm6 |
| mitmproxy | mitmproxy is an interactive, SSL/TLS-capable intercepting proxy with a console interface for HTTP/1, HTTP/2, and WebSockets. | https://github.com/mitmproxy/mitmproxy |
| Responder | IPv6/IPv4 LLMNR/NBT-NS/mDNS Poisoner and NTLMv1/2 Relay. | https://github.com/lgandx/Responder |
| SSH-MITM | ssh mitm server for security audits supporting public key authentication, session hijacking and file manipulation | https://github.com/ssh-mitm/ssh-mitm |

## DNSChef

> https://github.com/iphelix/dnschef

```c
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

```c
$ dnschef --interface <LHOST> --port 53 --tcp --file dnschef.ini
```

```c
$ proxychains bloodhound-python -c all --disable-pooling -w 1 -u '<USERNAME>@<RHOST>' -p '<PASSWORD>' -d '<DOMAIN>' -dc '<SRV_ENRTY>' -ns '<LHOST>' --dns-tcp --zip --dns-timeout 300
```

## FakeDns

> https://github.com/Crypt0s/FakeDns

### DNS Rebind Attack

```c
$ cat fake.conf
A <DOMAIN> 127.0.0.1 1%<LHOST>
```

#### Start the Server

```c
$ sudo python3 fakedns.py -c fake.conf --rebind
```

#### Test

```c
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

```c
$ go install github.com/fffaraz/fakessh@latest
$ sudo setcap 'cap_net_bind_service=+ep' ~/go/bin/fakessh
$ ./fakessh 
```

## Responder

> https://github.com/lgandx/Responder

```c
$ sudo responder -I <INTERFACE>
```

## SSH-MITM

```c
$ ssh-mitm server
```

```c
$ ssh-mitm server --remote-host <RHOST>
$ socat TCP-LISTEN:<RPORT>,fork TCP:127.0.0.1:10022
```

## tshark

### Capturing SMTP Traffic

```c
$ tshark -i <INTERFACE> -Y 'smtp.data.fragments' -T fields -e 'text'
```
