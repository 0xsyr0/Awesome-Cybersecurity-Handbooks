# Threat Hunting

- [Resources](#resources)

## Table of Contents

- [Advanced Threat Analytics](#advanced-yhreat-analytics)
- [Kusto Query Language (KQL)](#kusto-query-language-kql)
- [Named Pipes](#named-pipes)
- [Sysmon Event Codes](#sysmon-event-codes)
- [Threat Hunting with Shodan](#threat-hunting-with-shodan)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Azure Hunter | A Cloud Forensics Powershell module to run threat hunting playbooks on data from Azure and O365. | https://github.com/darkquasar/AzureHunter |
| DeepBlueCLI | DeepBlueCLI - a PowerShell Module for Threat Hunting via Windows Event Logs | https://github.com/sans-blue-team/DeepBlueCLI |
| Decider | A web application that assists network defenders, analysts, and researchers in the process of mapping adversary behaviors to the MITRE ATT&CK® framework. | https://github.com/cisagov/decider |
| GreyNoise | GreyNoise Visualizer | https://viz.greynoise.io |
| HELK | The Hunting ELK | https://github.com/Cyb3rWard0g/HELK |
| Hunt-Sleeping-Beacons | Aims to identify sleeping beacons | https://github.com/thefLink/Hunt-Sleeping-Beacons |
| NoWhere2Hide | C2 Active Scanner | https://github.com/c2links/NoWhere2Hide |
| MalWeb | Scan for malicious URLs, Domains and IP Addresses present on a web page. | https://github.com/umair9747/malweb |
| ModTracer | ModTracer Finds Hidden Linux Kernel Rootkits and then make visible again. | https://github.com/MatheuZSecurity/ModTracer |
| msuserstats | msuserstats is a comprehensive powershell tool to manage accounts from Microsoft EntraID and Active Directory. It supports: a unified view on users across EntraID and AD; allows to find the latest sign-in from both worlds; reports on MFA methods and can support enforcement of MFA. | https://github.com/Phil0x4a/msuserstats |
| PersistenceSniper | Powershell script that can be used by Blue Teams, Incident Responders and System Administrators to hunt persistences implanted in Windows machines. | https://github.com/last-byte/PersistenceSniper |
| RogueSliver | A suite of tools to disrupt campaigns using the Sliver C2 framework. | https://github.com/ACE-Responder/RogueSliver |
| Watchman | Watches files and records, or triggers actions, when they change. | https://github.com/facebook/watchman |

## Advanced Threat Analytics

- Traffic for DCs is mirrored to ATA Sensors (or installed on dc as service), activity profile is build
- Collects 4776 (credential validation of a user) to detect replay attacks, detects behavioral anomalies
- Detects: account enumeration, netsession enumeration, Brute Force, exposed cleartext credentials, honey tokens, unusual protocols, credential attacks (pth,ptt,ticket replay)
- Will NOT detect non existent users for golden ticket
- Detects DCSync, but not DCShadow

## Kusto Query Language (KQL)

### Detect Credential Dumping via Suspicious Modules

```console
DeviceImageLoadEvents
| where InitiatingProcessFileName in~ ("mimikatz.exe", "procdump.exe")
| where FileName in~ ("dbgcore.dll", "comsvcs.dll")
```

### Detect LSASS Memory Access

```console
DeviceProcessEvents
| where FileName in~ ("procdump.exe", "mimikatz.exe", "taskmgr.exe")
| where ProcessCommandLine contains "lsass"
```

### Unusual Access to SAM/SECURITY/NTDS Files

```console
DeviceFileEvents
| where FileName in~ ("SAM", "SECURITY", "SYSTEM", "ntds.dit")
| where FolderPath has_any ("\\Windows\\System32\\config", "C:\\Windows\\NTDS")
| where ActionType == "FileRead"
```

### PowerShell Commands Related to Credential Dumping

```console
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Get-Credential", "Invoke-Mimikatz", "DumpCreds", "lsass")
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
```

## Named Pipes

### Common Named Pipes

| Named Pipe | Name | Description |
| --- | --- | --- |
| \PIPE\svcctl | Service Control Manager (SCM) | Manages system services remotely, allowing control over starting, stopping, and configuring services. Attackers may use this to manipulate services for persistence or remote command execution. |
| \PIPE\samr | Security Account Manager (SAM) | Provides access to the SAM database, which stores user credentials. Often used by attackers to enumerate accounts or retrieve password hashes. |
| \PIPE\netlogon | Netlogon Service | Used for authentication and domain trust operations. Attackers can exploit it to perform pass-the-hash attacks or gain unauthorized domain access. |
| \PIPE\lsarpc | Local Security Authority Remote Procedure Call (LSARPC) | Grants access to security policies and account privileges. Attackers might use this pipe to gather information on security configurations and user privileges. |
| \PIPE\atsvc | AT Service / Task Scheduler | Facilitates remote task scheduling, often abused by attackers to execute commands on a remote system at specified times. Commonly used for persistence, lateral movement, and privilege escalation. |
| \PIPE\eventlog | Event Log Service | Manages event logging. Attackers may interact with this to clear or manipulate event logs to hide their tracks after malicious actions. |
| \PIPE\spoolss | Print Spooler Service | Manages print jobs. Historically vulnerable (e.g., PrintNightmare), making it a target for remote code execution and lateral movement. |
| \PIPE\wmi | Windows Management Instrumentation (WMI) | Provides an interface for querying and managing system configurations. Attackers use WMI for remote system management, often for enumeration or remote command execution. |
| \PIPE\browser | Browser Service | Supports network browsing and domain controller location services. Attackers may use it to identify network hosts and domains. |
| \PIPE\msrpc | Microsoft RPC Endpoint Mapper | Acts as a gateway for RPC-based services. The pipe provides access to various RPC services, making it a high-value target for attackers to gain access to multiple functions. |

### Hexadecimal Notation

```console
5c:00:50:00:49:00:50:00:45
```

```console
5c:00: The Unicode encoding for the character \ (backslash).
50:00: The Unicode encoding for the character P.
49:00: The Unicode encoding for the character I.
50:00: The Unicode encoding for the character P.
45:00: The Unicode encoding for the character E.
```

## Sysmon Event Codes

| Code | Info |
| --- | --- |
| 1 | Process Create |
| 3 | Network Connection |
| 11 | File Create Activity |
| 13 | Registry Key Modification |
| 22 | DNS Query |

## Threat Hunting with Shodan

### Abused Visual Studio Code Tunnels

> https://www.sentinelone.com/labs/operation-digital-eye-chinese-apt-compromises-critical-digital-infrastructure-via-visual-studio-code-tunnels/

```console
HTTP/1.1 404 Not Found Date: GMT Content-Type: text/html Content-Length: 548 Connection: keep-alive X-Served-By:  Strict-Transport-Security: max-age=31536000; includeSubDomains ssl.jarm:"2ad2ad0002ad2ad00042d42d00000023f2ae7180b8a0816654f2296c007d93" ssl:"Kubernetes Ingress Controller Fake Certificate"
```
