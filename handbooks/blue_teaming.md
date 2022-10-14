# Blue Teaming

## Table of Contents

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Resources)
- [Advanced Threat Analytics](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Advanced-Threat-Analytics)
- [Detect ACL Scan](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Detect-ACL-Scan)
- [Detect Dsrm](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Detect-Dsrm)
- [Detect Golden Ticket](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Detect-Golden-Ticket)
- [Detect Kerberoast](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Detect-Kerberoast)
- [Detect Malicious SSP](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Detect-Malicious-SSP)
- [Detect Skeleton Key](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Detect-Skeleton-Key)
- [Device Guard](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Devoice-Guard)
- [General](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Generall)
- [LAPS](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#LAPS)
- [Layered Architecture](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Layered-Architecture)
- [Mitigate Kerberoast](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Mitigate-Kerberoast)
- [Mitigate Skeleton Key](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Mitigate-Skeleton-Key)
- [Mitigate Trust Attack](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Mitigate-Trust-Attack)
- [Privileged Administrative Workstations](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Privileged-Administrative-Workstations)
- [Protected Users Group](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Protected-Users-Group)
- [Red Forest](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Red-Forest)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Azure Hunter | A Cloud Forensics Powershell module to run threat hunting playbooks on data from Azure and O365. | https://github.com/darkquasar/AzureHunter |
| HoneyCreds | HoneyCreds network credential injection to detect responder and other network poisoners. | https://github.com/Ben0xA/HoneyCreds |
| packetSifter | PacketSifter is a tool/script that is designed to aid analysts in sifting through a packet capture (pcap) to find noteworthy traffic. Packetsifter accepts a pcap as an argument and outputs several files. | https://github.com/packetsifter/packetsifterTool |
| STACS | Static Token And Credential Scanner | https://github.com/stacscan/stacs |
| sshgit | Ah shhgit! Find secrets in your code. Secrets detection for your GitHub, GitLab and Bitbucket repositories. | https://github.com/eth0izzle/shhgit |
| GitMonitor | One way to continuously monitor sensitive information that could be exposed on Github. | https://github.com/Talkaboutcybersecurity/GitMonitor |
| Loki | Loki - Simple IOC and Incident Response Scanner | https://github.com/Neo23x0/Loki |
| Fenrir | Simple Bash IOC Scanner | https://github.com/Neo23x0/Fenrir |
| Laurel | Transform Linux Audit logs for SIEM usage | https://github.com/threathunters-io/laurel |
| BlueHound | BlueHound is an open-source tool that helps blue teams pinpoint the security issues that actually matter. | https://github.com/zeronetworks/BlueHound
| PersistenceSniper | Powershell script that can be used by Blue Teams, Incident Responders and System Administrators to hunt persistences implanted in Windows machines. | https://github.com/last-byte/PersistenceSniper |
| YARA | The pattern matching swiss knife | https://github.com/VirusTotal/yara |
| SIGMA | Generic Signature Format for SIEM Systems | https://github.com/SigmaHQ/sigma |
| CrowdSec | Open-source and participative IPS able to analyze visitor behavior & provide an adapted response to all kinds of attacks. | https://github.com/crowdsecurity/crowdsec |
| Windows Hardening Script | Windows 10 Hardening Script | https://gist.github.com/mackwage/08604751462126599d7e52f233490efe |

## Advanced Threat Analytics

* Traffic for DCs is mirrored to ATA Sensors (or installed on dc as service), activity profile is build
* Collects 4776 (credential validation of a user) to detect replay attacks, detects behavioral anomalies
* Detects: account enumeration, netsession enumeration, Brute Force, exposed cleartext credentials, honey tokens, unusual protocols, credential attacks (pth,ptt,ticket replay)
* Will NOT detect non existent users for golden ticket
* Detects DCSync, but not DCShadow


## Detect ACL Scan

Requires enabled audit policy.

```c
4662: Operation was performed on an object
5136: directory service object was modified
4670: permissions on an object were changed
```

## Detect Dsrm

```c
4657: Audit creating/Change of HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehaviour
```

## Detect Golden Ticket

```c
4624: Account Logon
4634: Account Logoff
4672: Admin Logon (should be monitored on the dc)
```

```c
$ Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 |Format-List -Property *
```

## Detect Kerberoast

```c
4769: A Kerberos ticket as requested, Filter: Name != krbtgt, does not end with $, not machine@domain, Failure code is 0x0 (success), ticket encryption is 0x17 (rc4-hmac)
```

## Detect Malicious SSP

```c
4657: Audit/creation of HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages
```

## Detect Skeleton Key

```c
7045: A Service was installed in the system.
4673: Sensitive Privilege user (requires audit privileges)
4611: Trusted logon process has been registered with the Local Security Authority (requires audit privileges)
```

```c
$ Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}
```

## Device Guard

* Hardens against malware
* Run trusted code only, enforced in Kernel and Userspace (CCI, UMCI, KMCI)
* UEFI SEcure Boot protects bios and firmware

## General

* limit login of DAs to DCs only
* never run a service with DA privileges
* check out temporary group memberships (Can have TTL)
* disable account delegation for sensitive accounts (in ad usersettings)


## LAPS

Centralized password storage with periodic randomization, stored in computer objects in fields `mc-mcsAdmPwd` (cleartext), `ms-mcs-AdmPwdExperiationTime`.

## Layered Architecture

* Tier0: Domain Admins/Enterprise Admins
* Tier1: Significant Resource Access
* Tier2: Administrator for Workstations / Support etc.

## Mitigate Kerberoast

Use strong passwords and manage service accounts.

## Mitigate Skeleton Key

### Run lsass.exe as protected Process

```c
$ New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa\ -Name RunAsPPL -Value 1 -Verbose
```

### Check

```c
$ Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}
```

## Mitigate Trust Attack

* Enable SID Filtering
* Enable Selective Authentication (access between forests not automated)

## Privileged Administrative Workstations

Use hardened workstation for performing sensitive task.

## Protected Users Group

* Cannot use CredSSP & Wdigest (no more cleartext creds)
* NTLM Hash not cached
* Kerberos does not use DES or RC4
* Requires at least server 2008, need to test impact, no offline sign-on (no caching), useless for computers and service accounts

## Red Forest

* ESAE Enhanced Security Admin Environment
* Dedicated administrative forest for managing critical assets (forests are security boundaries)
