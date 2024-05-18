# Blue Teaming

- [Resources](#resources)

## Table of Contents

- [Advanced Threat Analytics](#advanced-threat-analytics)
- [API Security Tasks](#api-security-tasks)
- [Atomic Red Team](#atomic-red-team)
- [Detection of Computer Domain Joins](#detection-of-computer-domain-joins)
- [Detection of User Creation / Modification](#detection-of-user-creation--modification)
- [Event Log Analysis](#event-log-analysis)
- [Device Guard](#devoice-guard)
- [General Configuration](#general-configuration)
- [LAPS](#laps)
- [Layered Architecture](#layered-architecture)
- [Mitigate Kerberoast](#mitigate-kerberoast)
- [Mitigate Skeleton Key](#mitigate-skeleton-key)
- [Mitigate Trust Attack](#mitigate-trust-attack)
- [Privileged Administrative Workstations](#privileged-administrative-workstations)
- [Protected Users Group](#protected-users-group)
- [Red Forest](#red-forest)
- [Sniffing SSH Sessions](#sniffing-ssh-sessions)

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
| PlumHound | Bloodhound for Blue and Purple Teams | https://github.com/PlumHound/PlumHound |
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

## API Security Tasks

Shoutout to `Tara Janca` from `We Hack Purple`!

1. List all APIs (create an inventory)
2. Put them behind a gateway
3. Throttling and resource quotas
4. Logging, monitoring and alerting
5. Block all unused HTTP methods
6. Use a service mesh for communication management
7. Implement standards for your organisation / API definition documents
8. Strict Linting
9. Authenticate THEN authorize
10. Avoid verbose error messages
11. Decommission old or unused versions of APIs
12. Do all the same secure coding practices you normally do; input validation using approved lists, parameterized queries, bounds checking, etc.

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

## Detection of Computer Domain Joins

```c
PS C:\> Get-ADComputer -filter * -properties whencreated | Select Name,@{n="Owner";e={(Get-acl "ad:\$($_.distinguishedname)").owner}},whencreated 
```

## Detection of User Creation / Modification

```c
PS C:\> Get-ADUser -Filter {((Enabled -eq $True) -and (Created -gt "Monday, April 10, 2023 00:00:00 AM"))} -Property Created, LastLogonDate | select SamAccountName, Name, Created | Sort-Object Created
```

## Event Log Analysis

### Windows Event IDs

| Event ID | Description | Importance for Defenders | Example MITRA ATT&CK Technique |
| --- | --- | --- | --- |
| 1102 | Security Log cleared | May indicate an attacker is attempting to cover their tracks by clearing the security log (e.g., security log cleared after an unauthorized admin logon) | T1070 - Indicator Removal on Host |
| 4624 | Successful account Logon | Helps identify unauthorized or suspicious logon attempts, and track user activity on the network (e.g., logons during off-hours from unusual hosts) | T1078 - Valid Accounts |
| 4625 | Failed account Logon | Indicates potential brute-force attacks or unauthorized attempts to access a system (e.g., multiple failed logons from a single source in a short time) | T1110 - Brute Force |
| 4648 | Logon attempt with explicit credentials | May suggest credential theft or improper use of accounts (e.g., an attacker creates a new token for an account after compromising cleartext credentials) | T1134 - Access Token Manipulation |
| 4662 | An operation was performed on an object | Helps track access to critical objects in Active Directory, which could indicate unauthorized activity (e.g., an attacker performs a DCSync attack by performing replication from an unusual host) | T1003 - OS Credential Dumping |
| 4663 | Access to an object was requested | Monitors attempts to perform specific actions on sensitive objects like files, processes, and registry keys, which could indicate unauthorized access (e.g., an attacker attempts to read a file or folder which has been specifically configured for auditing) | T1530 - Data from Local System |
| 4670 | Permissions on an object were changed | Helps detect potential tampering with sensitive files or unauthorized privilege escalation (e.g., a low-privileged user modifying permissions on a sensitive file to gain access) | T1222 - File Permissions Modification |
| 4672 | Administrator privileges assigned to a new Logon | Helps detect privilege escalation and unauthorized admin account usage (e.g., a standard user suddenly granted admin rights without a change request) | T1078 - Valid Accounts |
| 4698 | A scheduled task was created | Helps detect malicious scheduled task creation and could indicate persistence, privilege escalation, or lateral movement (e.g., an attacker creates a scheduled task that runs a beacon periodically) | T1053 - Scheduled Task/Job |
| 4719 | Attempt to perform a group policy modification | | |
| 4720 | New user account created | Monitors for unauthorized account creation or potential insider threats (e.g., a new account created outside of normal business hours without HR approval) | T1136 - Create Account |
| 4724 | An attempt was made to reset an account's password | Monitors for unauthorized password resets, which could indicate account takeover (e.g., an attacker resetting the password of a high-privileged account) | T1098 - Account Manipulation |
| 4728 | Member added to a security-enabled global group | Tracks changes to important security groups, which could indicate unauthorized privilege escalation (e.g., an attacker adds a user to the "Domain Admins" group) | T1098 - Account Manipulation |
| 4729 | Member was removed from a global security group. | | |
| 4732 | Member added to a security-enabled Local group | Monitors changes to local security groups, which could suggest unauthorized access or privilege escalation (e.g., an attacker adds a user to the "Administrators" local group) | T1098 - Account Manipulation |
| 4739 | Domain policy change | | |
| 4756 | Member added to a universal security group. | | |
| 4757 | Member removed from a universal security group. | | |
| 4768 | A Kerberos authentication ticket was requested (TGT Request) | Monitors initial authentication requests to track user logons, and helps identify potential abuse of the Kerberos protocol (e.g., an attacker compromises the NTLM hash of a privileged account and performs an overpass-the-hash attack which requests a TGT from an unusual host) | T1558 - Steal or Forge Kerberos Tickets |
| 4769 | A Kerberos service ticket was requested | Monitors for potential Kerberoasting attacks or other suspicious activities targeting the Kerberos protocol (e.g., a sudden increase in requests for unique services from a single user) | T1558 - Steal or Forge Kerberos Tickets |
| 4776 | The domain controller attempted to validate the credentials | Helps identify failed or successful attempts to validate credentials against the domain controller, which could indicate unauthorized access or suspicious authentication activity (e.g., an unusual number of failed validations from a single IP address) | T1110 - Brute Force |
| 7045 | New service installed | Monitors for potential malicious services being installed, indicating lateral movement or persistence (e.g., a remote access tool installed as a service on multiple machines) | T1543 - Create or Modify System Process |

### Detect ACL Scan

Requires enabled audit policy.

```c
4662: Operation was performed on an object
5136: directory service object was modified
4670: permissions on an object were changed
```

### Detect DACL Abuse

| Event ID | Attack | Description |
| ---| --- | --- |
| 4662, 4738, 5136, 4769 | Set an SPN for the user and perform a kerberoast attack. | Setting a user's SPN results in a 4738, 4662 and 5136 for the target account. A subsequent 4769 captures the kerberoasting event. |
| 4662, 4738, 5136, 4768 | Disable pre-authentication and capture a user's TGT with an AS-REP roast attack. | Disabling pre-authentication results in a 4738 and 5136 for the target account. A subsequent 4768 captures the AS-REP roasting attack. |
| 4662, 5136, 4768 | Perform a shadow credential attack which sets the user object msDS-KeyCredentialLink property. | Setting mDS-KeyCredentialLink results in a 4662 and 5136 for the target account. A subsequent 4768 with pre-authentication type 16 and credential information is generated. |
| 4724, 4738 | Change the user's password | Changing a user's password results in a 4724 and 4738 for the target account. |

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
PC C:\> Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 |Format-List -Property *
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
PC C:\> Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}
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

## General Configuration

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
PC C:\> New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa\ -Name RunAsPPL -Value 1 -Verbose
```

### Check

```c
PC C:\> Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}
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
