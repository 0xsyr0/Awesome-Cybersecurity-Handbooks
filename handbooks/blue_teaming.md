# Blue Teaming

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Resources)

## Table of Contents

- [Advanced Threat Analytics](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Advanced-Threat-Analytics)
- [Atomic Red Team](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Atomic-Red-Team)
- [Event Log Analysis](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Event-Log-Analysis)
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
- [Sniffing SSH Sessions](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/blue_teaming.md#Sniffing-SSH-Sessions)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| APT Simulator | A toolset to make a system look as if it was the victim of an APT attack | https://github.com/NextronSystems/APTSimulator |
| Azure Hunter | A Cloud Forensics Powershell module to run threat hunting playbooks on data from Azure and O365. | https://github.com/darkquasar/AzureHunter |
| BlueHound | BlueHound is an open-source tool that helps blue teams pinpoint the security issues that actually matter. | https://github.com/zeronetworks/BlueHound |
| Blue Team Notes | You didn't think I'd go and leave the blue team out, right? | https://github.com/Purp1eW0lf/Blue-Team-Notes |
| C2IntelFeeds | Automatically created C2 Feeds | https://github.com/drb-ra/C2IntelFeeds |
| Canary Tokens | Generate canary tokens | https://canarytokens.org/generate |
| CrowdSec | Open-source and participative IPS able to analyze visitor behavior & provide an adapted response to all kinds of attacks. | https://github.com/crowdsecurity/crowdsec |
| CyberDefender | A blue team training platform. | https://cyberdefenders.org |
| Cyber Threat Intelligence | Real-Time Threat Monitoring. | https://start.me/p/wMrA5z/cyber-threat-intelligence?s=09 |
| Fenrir | Simple Bash IOC Scanner | https://github.com/Neo23x0/Fenrir |
| Forest Druid | Stop chasing AD attack paths. Focus on your Tier 0 perimeter. | https://www.purple-knight.com/forest-druid |
| GitMonitor | One way to continuously monitor sensitive information that could be exposed on Github. | https://github.com/Talkaboutcybersecurity/GitMonitor |
| HoneyCreds | HoneyCreds network credential injection to detect responder and other network poisoners. | https://github.com/Ben0xA/HoneyCreds |
| Laurel | Transform Linux Audit logs for SIEM usage | https://github.com/threathunters-io/laurel |
| Loki | Loki - Simple IOC and Incident Response Scanner | https://github.com/Neo23x0/Loki |
| Monkey365 | Monkey365 provides a tool for security consultants to easily conduct not only Microsoft 365, but also Azure subscriptions and Azure Active Directory security configuration reviews. | https://github.com/silverhack/monkey365 |
| packetSifter | PacketSifter is a tool/script that is designed to aid analysts in sifting through a packet capture (pcap) to find noteworthy traffic. Packetsifter accepts a pcap as an argument and outputs several files. | https://github.com/packetsifter/packetsifterTool |
| PersistenceSniper | Powershell script that can be used by Blue Teams, Incident Responders and System Administrators to hunt persistences implanted in Windows machines. | https://github.com/last-byte/PersistenceSniper |
| Purple Knight | #1 Active Directory security assessment community tool | https://www.purple-knight.com |
| Ransomware Simulator | Ransomware simulator written in Golang | https://github.com/NextronSystems/ransomware-simulator |
| SIGMA | Generic Signature Format for SIEM Systems | https://github.com/SigmaHQ/sigma |
| Simple Email Reputation | EmailRep Alpha Risk API | https://emailrep.io |
| Slack Watchman | Slack enumeration and exposed secrets detection tool | https://github.com/PaperMtn/slack-watchman |
| sshgit | Ah shhgit! Find secrets in your code. Secrets detection for your GitHub, GitLab and Bitbucket repositories. | https://github.com/eth0izzle/shhgit |
| STACS | Static Token And Credential Scanner | https://github.com/stacscan/stacs |
| TheHive | TheHive: a Scalable, Open Source and Free Security Incident Response Platform | https://github.com/TheHive-Project/TheHive |
| ThePhish | ThePhish: an automated phishing email analysis tool | https://github.com/emalderson/ThePhish |
| Thinkst Canary | Canary Tokens | https://canary.tools |
| Wazuh | Wazuh - The Open Source Security Platform. Unified XDR and SIEM protection for endpoints and cloud workloads. | https://github.com/wazuh/wazuh |
| YARA | The pattern matching swiss knife | https://github.com/VirusTotal/yara |

## Advanced Threat Analytics

- Traffic for DCs is mirrored to ATA Sensors (or installed on dc as service), activity profile is build
- Collects 4776 (credential validation of a user) to detect replay attacks, detects behavioral anomalies
- Detects: account enumeration, netsession enumeration, Brute Force, exposed cleartext credentials, honey tokens, unusual protocols, credential attacks (pth,ptt,ticket replay)
- Will NOT detect non existent users for golden ticket
- Detects DCSync, but not DCShadow

## Atomic Red Team

> https://github.com/redcanaryco/atomic-red-team

> https://github.com/redcanaryco/invoke-atomicredteam

### Invoke-AtomicRedTeam

```c
PC C:\> PowerShell -ExecutionPolicy bypass
PC C:\> Import-Module "C:\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
PC C:\> $PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="C:\AtomicRedTeam\atomics"}
PC C:\> help Invoke-AtomicTest
PC C:\> Invoke-AtomicTest T1127 -ShowDetailsBrief
PC C:\> Invoke-AtomicTest T1127 -ShowDetails
PC C:\> Invoke-AtomicTest T1127 -CheckPrereqs
PC C:\> Invoke-AtomicTest T1127 -GetPrereqs
PC C:\> Invoke-AtomicTest T1053.005 -ShowDetailsBrief
PC C:\> Invoke-AtomicTest T1053.005 -TestNumbers 1,2
PC C:\> schtasks /tn T1053_005_OnLogon
```

### Emulation

```c
PC C:\> ls C:\AtomicRedTeam\atomics | Where-Object Name -Match "T1566.001|T1203|T1059.003|T1083|T1082|T1016|T1049|T1007|T1087.001"
PC C:\> 'T1566.001','T1059.003','T1083','T1082','T1016','T1049','T1007','T1087.001' | ForEach-Object {echo "Enumerating $_"; Invoke-AtomicTest $_ -ShowDetailsBrief }
PC C:\> 'T1566.001','T1059.003','T1083','T1082','T1016','T1049','T1007','T1087.001' | ForEach-Object {echo "Enumerating $_"; Invoke-AtomicTest $_ -CheckPrereqs }
PC C:\> Invoke-AtomicTest T1059.003-3
```

### Emulation to Detection

```c
PC C:\> Invoke-AtomicTest T1547.001 -CheckPrereqs
PC C:\> Invoke-AtomicTest T1547.001 -TestNumbers 2
```

### Customising

```c
PC C:\> cat T1136.001/T1136.001.yaml
PC C:\> Invoke-AtomicTest T1136.001 -TestNumbers 3
PC C:\> net user
PC C:\> Invoke-AtomicTest T1136.001 -TestNumbers 3 -PromptForInputArgs
PC C:\> net user
PC C:\> Invoke-AtomicTest T1136.001 -TestNumbers 3 -PromptForInputArgs -Cleanup
```

### Creating new Atomic Tests by using the GUI

```c
PC C:\> Start-AtomicGui
```

> http://localhost:8487/home

## Event Log Analysis

### Detect ACL Scan

Requires enabled audit policy.

```c
4662: Operation was performed on an object
5136: directory service object was modified
4670: permissions on an object were changed
```

### Detect Dsrm

```c
4657: Audit creating/Change of HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehaviour
```

### Detect Golden Ticket

```c
4624: Account Logon
4634: Account Logoff
4672: Admin Logon (should be monitored on the dc)
```

```c
$ Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 |Format-List -Property *
```

### Detect Kerberoast

```c
4769: A Kerberos ticket as requested, Filter: Name != krbtgt, does not end with $, not machine@domain, Failure code is 0x0 (success), ticket encryption is 0x17 (rc4-hmac)
```

### Detect Malicious SSP

```c
4657: Audit/creation of HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages
```

### Detect Skeleton Key

```c
7045: A Service was installed in the system.
4673: Sensitive Privilege user (requires audit privileges)
4611: Trusted logon process has been registered with the Local Security Authority (requires audit privileges)
```

```c
$ Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}
```

### Detect hidden Windows Services via Access Control Lists (ACLs)

> https://twitter.com/0gtweet/status/1610545641284927492?s=09

> https://github.com/gtworek/PSBits/blob/master/Services/Get-ServiceDenyACEs.ps1

```c
$keys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\"

foreach ($key in $keys)
{
    if (Test-Path ($key.pspath+"\Security"))
    {
        $sd = (Get-ItemProperty -Path ($key.pspath+"\Security") -Name "Security" -ErrorAction SilentlyContinue).Security 
        if ($sd -eq $null)
        {
            continue
        }
        $o = New-Object -typename System.Security.AccessControl.FileSecurity
        $o.SetSecurityDescriptorBinaryForm($sd)
        $sddl = $o.Sddl
        $sddl1 = $sddl.Replace('(D;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BG)','') #common deny ACE, not suspicious at all
        if ($sddl1.Contains('(D;'))
        {
            Write-Host $key.PSChildName ' ' $sddl
        }
    }
}
```

## Device Guard

- Hardens against malware
- Run trusted code only, enforced in Kernel and Userspace (CCI, UMCI, KMCI)
- UEFI SEcure Boot protects bios and firmware

## General

- Limit login of DAs to DCs only
- Never run a service with DA privileges
- Check out temporary group memberships (Can have TTL)
- Disable account delegation for sensitive accounts (in ad usersettings)


## LAPS

Centralized password storage with periodic randomization, stored in computer objects in fields `mc-mcsAdmPwd` (cleartext), `ms-mcs-AdmPwdExperiationTime`.

## Layered Architecture

- Tier0: Domain Admins/Enterprise Admins
- Tier1: Significant Resource Access
- Tier2: Administrator for Workstations / Support etc.

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

- Enable SID Filtering
- Enable Selective Authentication (access between forests not automated)

## Privileged Administrative Workstations

Use hardened workstation for performing sensitive task.

## Protected Users Group

- Cannot use CredSSP & Wdigest (no more cleartext creds)
- NTLM Hash not cached
- Kerberos does not use DES or RC4
- Requires at least server 2008, need to test impact, no offline sign-on (no caching), useless for computers and service accounts

## Red Forest

- ESAE Enhanced Security Admin Environment
- Dedicated administrative forest for managing critical assets (forests are security boundaries)

## Sniffing SSH Sessions

```c
$ strace -e trace=read -p <PID> 2>&1 | while read x; do echo "$x" | grep '^read.*= [1-9]$' | cut -f2 -d\"; done
```
