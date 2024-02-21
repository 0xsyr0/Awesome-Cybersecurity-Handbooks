# Information Gathering

- [Resources](#Resources)

## Table of Contents

- [Amass](#Amass)
- [Banner Grabbing](#Banner-Grabbing)
- [Common Ports](#Common-Ports)
- [dmitry](#dmitry)
- [DMARC](#DMARC)
- [DNS](#DNS)
- [dnsenum](#dnsenum)
- [dnsrecon](#dnsrecon)
- [Enyx](#Enyx)
- [finger](#finger)
- [MASSCAN](#MASSCAN)
- [memcached](#memcached)
- [Naabu](#Naabu)
- [netdiscover](#netdiscover)
- [NetBIOS](#NetBIOS)
- [Nmap](#Nmap)
- [onesixtyone](#onesixtyone)
- [Outlook Web Access (OWA)](#Outlook-Web-Access-OWA)
- [Port Scanning](#Port-Scanning)
- [SMTP](#SMTP)
- [SNMP](#SNMP)
- [snmp-check](#snmp-check)
- [SNMP-MIBS-Downloader](#SNMP-MIBS-Downloader)
- [snmpwalk](#snmpwalk)
- [SPF](#SPF)
- [sslscan](#sslscan)
- [sslyze](#sslyze)
- [subfinder](#subfinder)
- [tcpdump](#tcpdump)
- [Time To Live (TTL) and TCP Window Size Values](#Time-to-Live-TTL-and-TCP-Window-Size-Values)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Amass | The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques. | https://github.com/OWASP/Amass |
| ASNLookup | Quickly look up updated information about specific ASN, Organization or registered IP addresses (IPv4 and IPv6) among other relevant data. | https://asnlookup.com |
| ASNmap | Go CLI and Library for quickly mapping organization network ranges using ASN information. | https://github.com/projectdiscovery/asnmap |
| BashScan | BashScan is a port scanner built to utilize /dev/tcp for network and service discovery on systems that have limitations or are otherwise unable to use alternative scanning solutions such as nmap. | https://github.com/astryzia/BashScan |
| Censys | Attack Surface Management | https://search.censys.io |
| crt.sh | Certificate Search | https://crt.sh |
| crt.sh CLI | Certificate Search | https://github.com/az7rb/crt.sh |
| CTFR | CTFR does not use neither dictionary attack nor brute-force, it just abuses of Certificate Transparency logs. | https://github.com/UnaPibaGeek/ctfr |
| DNSdumpster | DNSdumpster.com is a FREE domain research tool that can discover hosts related to a domain. | https://dnsdumpster.com |
| dnsx | dnsx is a fast and multi-purpose DNS toolkit allow to run multiple probes using retryabledns library, that allows you to perform multiple DNS queries of your choice with a list of user supplied resolvers, additionally supports DNS wildcard filtering like shuffledns. | https://github.com/projectdiscovery/dnsx |
| Driftnet | Exposure Analysis | https://driftnet.io |
| Hardenize | Network Perimeter Monitoring | https://www.hardenize.com |
| IPinfo | Accurate IP address data that keeps pace with secure, specific, and forward-looking use cases. | https://ipinfo.io |
| Jackdaw | Jackdaw is here to collect all information in your domain, store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. | https://github.com/skelsec/jackdaw |
| katana | A next-generation crawling and spidering framework. | https://github.com/projectdiscovery/katana |
| Knock Subdomain Scan | Knockpy is a python3 tool designed to quickly enumerate subdomains on a target domain through dictionary attack. | https://github.com/guelfoweb/knock |
| Minimalistic Offensive Security Tools | Minimalistic TCP and UDP port scanners. | https://github.com/InfosecMatter/Minimalistic-offensive-security-tools |
| naabu | Naabu is a port scanning tool written in Go that allows you to enumerate valid ports for hosts in a fast and reliable manner. | https://github.com/projectdiscovery/naabu |
| Nmap | Network Scanner | https://github.com/nmap/nmap |
| proxify | Swiss Army Knife Proxy for rapid deployments. | https://github.com/projectdiscovery/proxify |
| reconFTW | Reconnaissance Automation | https://github.com/six2dez/reconftw |
| Spoofy | Spoofy is a program that checks if a list of domains can be spoofed based on SPF and DMARC records. | https://github.com/MattKeeley/Spoofy |
| subfinder | Fast passive subdomain enumeration tool. | https://github.com/projectdiscovery/subfinder |
| wtfis | Passive hostname, domain and IP lookup tool for non-robots | https://github.com/pirxthepilot/wtfis |

## Amass

> https://github.com/OWASP/Amass

```c
$ amass enum -d <DOMAIN>
$ amass intel --asn <ASN>
$ amass intel --asn <ASN> -list
$ amass enum -active -d <DOMAIN> -p 80,443,8080
```

## Banner Grabbing

> https://book.hacktricks.xyz/pentesting/pentesting-imap#banner-grabbing

```c
$ nc -v <RHOST> 80
$ telnet <RHOST> 80
$ curl -vX <RHOST>
```

## Common Ports

| Port | Service |
| --- | --- |
| 21/TCP | FTP |
| 22/TCP | SSH |
| 25/TCP | SMTP |
| 53/TCP | DNS |
| 53/UDP | DNS |
| 80/TCP | HTTP |
| 135/TCP | RPC |
| 139/TCP | Netbios |
| 443/TCP | HTTPS |
| 445/TCP | SMB |
| 1723/TCP | VPN |
| 3389/TCP | RDP |
| 5985/TCP | WinRM |

### Domain Controller specific Ports

| Port | Service |
| --- | --- |
| 88/TCP | Kerberos |
| 389/TCP | LDAP |
| 636/TCP | LDAPS |
| 445/TCP | SMB |

## dmitry

```c
$ dmitry -p <RHOST>
```

## DMARC

```c
$ dig txt _dmarc.<DOMAIN> | grep dmarc
```

## DNS

```c
$ whois <DOMAIN>
$ dig @<RHOST> -x <DOMAIN>
$ dig {a|txt|ns|mx} <DOMAIN>
$ dig {a|txt|ns|mx} <DOMAIN> @ns1.<DOMAIN>
$ dig axfr @<RHOST> <DOMAIN>    // zone transfer - needs 53/TCP
$ host -t {a|txt|ns|mx} <DOMAIN>
$ host -a <DOMAIN>
$ host -l <DOMAIN> ns1.<DOMAIN>
$ nslookup -> set type=any -> ls -d <DOMAIN>
$ for sub in $(cat subDOMAINs.txt);do host $sub.<DOMAIN:|grep "has.address";done
```

## dnsenum

```c
$ dnsenum <DOMAIN>
$ dnsenum --threads 64 --dnsserver <RHOST> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt <DOMAIN>
```

## dnsrecon

```c
$ sudo vi /etc/hosts
$ dnsrecon -r 127.0.0.0/24 -n <RHOST>
$ dnsrecon -r 127.0.1.0/24 -n <RHOST>
$ dnsrecon -d <DOMAIN> -t axfr @ns2.<DOMAIN>
```

## Enyx

> https://github.com/trickster0/Enyx

### Grabbing IPv6 Address

```c
$ python enyx.py 2c public <RHOST>
```

## finger

### finger Port 79/TCP

```c
$ finger root@<RHOST>
$ finger "|/bin/id@<RHOST>"

msf6 > use auxiliary/scanner/finger/finger_users
```

> https://github.com/pentestmonkey/finger-user-enum

```c
$ ./finger-user-enum.pl -U users.txt -t <RHOST>
```

## MASSCAN

> https://github.com/robertdavidgraham/masscan

```c
$ sudo masscan -e tun0 -p0-65535 --max-rate 500 --interactive <RHOST>
```

## memcached

>  https://github.com/pd4d10/memcached-cli

```c
memcrashed / 11211/UDP

$ npm install -g memcached-cli
$ memcached-cli <USERNAME>:<PASSWORD>@<RHOST>:11211
$ echo -en "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n" | nc -q1 -u 127.0.0.1 11211

STAT pid 21357
STAT uptime 41557034
STAT time 1519734962

$ sudo nmap <RHOST> -p 11211 -sU -sS --script memcached-info

$ stats items
$ stats cachedump 1 0
$ get link
$ get file
$ get user
$ get passwd
$ get account
$ get username
$ get password
```

## Naabu

```c
$ sudo naabu -p - -l /PATH/TO/FILE/<FILE> -o /PATH/TO/FILE/<FILE>
```

## netdiscover

```c
$ sudo netdiscover -i <INTERFACE> -r <RHOST>
```

## NetBIOS

```c
$ nbtscan <RHOST>
$ nmblookup -A <RHOST>
```

## Nmap

```c
$ nmap -A -T4 -p- -sS -sV -oN initial --script discovery <RHOST>
$ nmap -A -T4 -sC -sV --script vuln <RHOST>
$ nmap -sV --script http-trace <RHOST>
$ nmap -sV --script ssl-cert -p 443 <RHOST>
$ nmap -sV --script ssl-enum-ciphers -p 443 <RHOST>
$ nmap -A -T4 -p- <RHOST>
$ nmap -A -T4 -sS -sU -v <RHOST>
$ nmap -sC -sV -oN initial --script discovery <RHOST>
$ nmap -sC -sV -oA nmap <RHOST>
$ nmap -sS -sV <RHOST>
$ nmap -p- <RHOST>                      // full port scan
$ nmap -sS <RHOST>                      // ping scan
$ nmap -sT <RHOST>                      // TCP scan
$ nmap -sU <RHOST>                      // UDP scan
$ nmap -PR -sN <RHOST>                  // ARP scan
$ nmap -PP -sn <RHOST>                  // ICMP timestamp discovery
$ nmap -PM -sn <RHOST>                  // ICMP address mask discovery
$ nmap -PE -sn <RHOST>                  // ICMP echo discovery
$ nmap -PU -sn <RHOST>                  // UDP ping discovery
$ nmap -PS <RPORT> <RHOST>              // TCP SYN ping discovery
$ nmap -PA <RPORT> <RHOST>              // TCP ACK ping discovery
$ sudo nmap -sS -f -p <RPORT> <RHOST>   // fragment packets for stealth
$ sudo nmap -sS -ff -p <RPORT> <RHOST>  // fragmets packets double times for stealth
$ nmap  --script safe -p 445 <RHOST>    // detailed scan on smb

-p1-65535               // ports
-p-                     // all ports
-sV                     // version detection
-sS                     // TCP SYN scan
-sT                     // TCP connect scan
-sU                     // UDP scan
-sX                     // Xmas scan (sets FIN, PSH, URG flags)
-sC                     // script scan
-T4                     // timing options
-PN                     // no ping
-oA                     // write to file (basename)
-oN                     // write to file (normal)
-sn                     // host discovery only
-6                      // IPv6
-n                      // no dns resolution
-O                      // OS detection
-A                      // aggressive scan
-D                      // Decoy scan
-f                      // fragment packets
-S                      // spoof src ip address
-g                      // spoof src port
-n                      // no DNS lookup
-R                      // Reverse DNS lookup
--mtu                   // set MTU size
--spoof-mac             // spoof mac address
--data-length <size>    // append random data
--scan-delay 5s         // delay
--max-retries 1         // set retry limit to speed the scan up
```

### Getting Script Locations

```c
$ ls -lh /usr/share/nmap/scripts/*ssh*
$ locate -r '\.nse$' | xargs grep categories | grep categories | grep 'default\|version\|safe' | grep smb
```

### Converting Report

```c
$ xsltproc nmap.xml -o nmap.html
```

### Network Sweep Scan

```c
$ sudo nmap -sn <XXX.XXX.XXX>.1-253
$ sudo nmap -sS <XXX.XXX.XXX>.1-253
```

#### Enable Monitoring with iptables

```c
$ sudo iptables -I INPUT 1 -s <RHOST> -j ACCEPT
$ sudo iptables -I OUTPUT 1 -d <RHOST> -j ACCEPT
$ sudo iptables -Z
```

#### Check for Connections

```c
$ sudo iptables -vn -L
```

### Generate grepable Output for IP Addresses and Ports

```c
$ sudo nmap <XXX.XXX.XXX>.1-253 -oG <FILE>
$ sudo nmap -p <RPORT> <XXX.XXX.XXX>.1-253 -oG <FILE>
```

```c
$ grep Up <FILE> | cut -d " " -f 2
$ grep open <FILE> | cut -d " " -f2
```

#### Alternative

```c
$ sudo nmap -iL /PATH/TO/FILE/<FILE> -p- -oG /PATH/TO/FILE/<FILE> | awk -v OFS=':' '/open/ {for (i=4;i<=NF;i++) {split($i,a,"/"); if (a[2]=="open") print $2, a[1]}}' | sort | uniq > /PATH/TO/FILE/<FILE>
```

### ASN

```c
$ nmap --script targets-asn --script-args targets-asn.asn=<ASN>
```

### SMB

```c
$ nmap -sV --script=smb-enum-shares -p 445 <RHOST>
$ nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <RHOST>
```

### Port Knocking

```c
$ for x in 7000 8000 9000; do nmap -Pn –host_timeout 201 –max-retries 0 -p $x <RHOST>; done
```

### RPC

```c
$ nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <RHOST>
```

### Kerberos

```c
$ nmap $TARGET -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test' <RHOST>
```

### File transfer (PUT)

```c
$ nmap -p 80 <RHOST> --script http-put --script-args http-put.url='<RHOST>',http-put.file='<FILE>'
```

## onesixtyone

>  https://github.com/trailofbits/onesixtyone

### Basic Usage

```c
$ echo public > <FILE>
$ echo private >> <FILE>
$ echo manager >> <FILE>
```

```c
$ for ip in $(seq 1 254); do echo <XXX.XXX.XXX>.$ip; done > <FILE>
```

```c
$ onesixtyone -c <FILE> -i <FILE>
```

### Brute-Force Community Strings

```c
$ onesixtyone -i snmp-ips.txt -c community.txt
```

## Outlook Web Access (OWA)

```c
https://<RHOST>/sitemap.xml
```

## Port Scanning

```c
$ for p in {1..65535}; do nc -vn <RHOST> $p -w 1 -z & done 2> <FILE>.txt
```

> https://github.com/AlexRandomed/One-Liner-Bash-Scanner

```c
$ export ip=<RHOST>; for port in $(seq 1 65535); do timeout 0.01 bash -c "</dev/tcp/$ip/$port && echo The port $port is open || echo The Port $port is closed > /dev/null" 2>/dev/null || echo Connection Timeout > /dev/null; done
```

## SMTP

```c
telnet 10.10.10.77 25
Connected to 10.10.10.77.
Escape character is '^]'.
220 Mail Service ready
HELO foobar.com
250 Hello.
MAIL FROM: <foobar@contoso.local>
250 OK
RCPT TO: <barfoo@contoso.local>
250 OK
RCPT TO: <admin@contoso.local>
250 OK
RCPT TO: <foobar@contoso.local>
250 OK
RCPT TO: <foobar@contoso.localb>
250 OK

$ smtp-user-enum -M VRFY -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t <RHOST>
$ smtp-user-enum -M RCPT -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t <RHOST>
$ smtp-user-enum -M EXPN -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t <RHOST>
```

## SNMP

### SNMP Byte Calculation

```c
$ python3
Python 3.9.7 (default, Sep  3 2021, 06:18:44)
[GCC 10.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import binascii
>>> s='50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135'
>>> binascii.unhexlify(s.replace(' ',''))
b'P@ssw0rd@123!!123\x13\x91q\x81\x92"2Rbs\x03\x133CSs\x83\x94$4\x95\x05\x15Eu\x86\x16WGW\x98(8i\t\x19IY\x81\x03\x10a\x11\x11A\x15\x11\x91"\x121&\x13\x011\x13A5'
```

## snmp-check

```c
$ snmp-check <RHOST>
$ snmp-check -t <RHOST> -c public
```

## SNMP-MIBS-Downloader

>  https://github.com/codergs/SNMP-MIBS-Downloader

```c
$ sudo apt-get install snmp-mibs-downloader
```

### Comment out "mibs: line"

```c
$ sudo vi /etc/snmp/snmp.conf
```

## snmpwalk

### Common Commands

```c
$ snmpwalk -c public -v1 <RHOST>
$ snmpwalk -c internal -v2c <RHOST>
```

### Examples

#### Detailed Output

```c
$ snmpwalk -v2c -c public <RHOST> .1
```

#### Windows Hostname

```c
$ snmpwalk -c public -v1 <RHOST> .1.3.6.1.2.1.1.5
```

#### OS / User Details

```c
$ snmpwalk -v2c -c public <RHOST> nsExtendObjects
```

#### Windows User Enumeration

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25
```

#### Windows Process Enumeration

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.4.2.1.2
```

#### Windows Share Information

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.27
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.3.1.1
```

#### Installed Software

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.6.3.1.2
```

#### Network Addresses

```c
$ snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.4.34.1.3
```

#### TCP Ports

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.6.13.1.3
```

## SPF

```c
$ dig txt <DOMAIN> | grep spf
```

## sslscan

```c
$ sslscan <RHOST>
```

## sslyze

```c
$ sslyze <RHOST>
```

## subfinder

```c
$ subfinder -dL /PATH/TO/FILE/<FILE>
$ subfinder -dL /PATH/TO/FILE/<FILE> -nW -ip -p /PATH/TO/FILE/<FILE>
```

### Scan for Top Routinely Exploited Vulnerabilities according to CISA

```c
$ subfinder -d <DOMAIN> -all -silent | httpx -silent | nuclei -rl 50 -c 15 -timeout 10 -tags cisa -vv 
```

## tcpdump

```c
$ tcpdump -envi <INTERFACE> host <RHOST> -s0 -w /PATH/TO/FILE/<FILE>.pcap
```

## Time To Live (TTL) and TCP Window Size Values

| Operating System | Time to Live | TCP Window Size |
| --- | --- | --- |
| Linux Kernel 2.4 and 2.6) | 64 | 5840 |
| Google Linux | 64 | 5720 |
| FreeBSD | 64 | 65535 |
| OpenBSD | 64 | 16384 |
| Windows 95 | 32 | 8192 |
| Windows 2000 | 128 | 16384 |
| Windows XP | 128 | 65535 |
| Windows 98, Vista and 7 (Server 2008) | 128 | 8192 |
| iOS 12.4 (Cisco Routers) | 255 | 8760 |
| AIX 4.3 | 64 | 16384 |
