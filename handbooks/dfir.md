# DFIR

- [Resources](#resources)

## Table of Contents

- [Sniffing SSH Sessions](#sniffing-ssh-sessions)
- [Wireshark](#wireshark)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| CheckPhish | Free Phishing Link Checker & Site URL Scanning | https://checkphish.bolster.ai |
| dnstwist | phishing domain scanner | https://dnstwist.it |
| Fenrir | Simple Bash IOC Scanner | https://github.com/Neo23x0/Fenrir |
| FIR | Fast Incident Response | https://github.com/certsocietegenerale/FIR |
| IRIS | Collaborative Incident Response platform | https://github.com/dfir-iris/iris-web |
| Loki | Loki - Simple IOC and Incident Response Scanner | https://github.com/Neo23x0/Loki |
| packetSifter | PacketSifter is a tool/script that is designed to aid analysts in sifting through a packet capture (pcap) to find noteworthy traffic. Packetsifter accepts a pcap as an argument and outputs several files. | https://github.com/packetsifter/packetsifterTool |
| PhishStats | Fighting phishing and cybercrime since 2014 by gathering, enhancing and sharing phishing information with the infosec community. | https://phishstats.info |
| PhishTank | Join the fight against phishing | https://phishtank.org |
| Simple Email Reputation | EmailRep Alpha Risk API | https://emailrep.io |
| TheHive | TheHive: a Scalable, Open Source and Free Security Incident Response Platform | https://github.com/TheHive-Project/TheHive |
| ThePhish | ThePhish: an automated phishing email analysis tool | https://github.com/emalderson/ThePhish |
| Volexity | Memory Forensics, Memory Analysis and Cybersecurity Services | https://www.volexity.com |

## Sniffing SSH Sessions

```console
$ strace -e trace=read -p <PID> 2>&1 | while read x; do echo "$x" | grep '^read.*= [1-9]$' | cut -f2 -d\"; done
```

## Wireshark

### Filters

```console
ip.addr == <RHOST>                           // shows all packets involving the specific IP address
tcp.port == <RPORT>                          // shows only port XYZ
dns                                          // isolates DNS traffic
http.request.uir contains "login"            // find HTTP requests with "login" in the URL
ntlmssp.auth.username                        // shows used usernames
dcerpc.opnum == 0                            // shows when the eventlog got cleared
frame contains 5c:00:50:00:49:00:50:00:45    // shows frames with a named pipes
smb2.filename contains ".exe"                // smb filtering on .exe files
```

### Logical Operators

- AND (`&&`): `ip.addr == <RHOST> && tcp.port == <RPORT>`
- OR (`||`): `HTTP || FTP`
- NOT (`!`): `!arp`
