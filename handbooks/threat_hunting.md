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

> https://tryhackme.com/room/kqlkustointroduction

> https://learn.microsoft.com/en-us/kusto/query/kql-quick-reference?view=azure-data-explorer&preserve-view=true

### Functions and Operators

```console
count(), sum(), avg(), where(), parse()
==           \\ equal to
!=           \\ not equal to
<            \\ less than
render
summarize
|            \\ Pipeline
```

| Operator / Function Name | Description | Example |
| --- | --- | --- |
| search | Searches the specified table for matching value or pattern | `search "failed" \| where \| Filters the specified table based on specified conditions \| SigninLogs \| where EventID == "4624"` |
| take | Used to limit the number of returned rows in the result set | `SigninLogs \| take 5` |
| sort | Sort records in ascending or descending order based on the specified column \| `SigninLogs \| sort by TimeGenerated, Identity desc \| take 5` |
| ago | Returns the time offset relative to the time the query executes | `ago(1h)` |
| print | Outputs a single row with one or more scalar expressions | `print bin(4.5, 1)` |
| project | Selects specific columns from a table | `Perf \| project ObjectName, CounterValue, CounterName` |
| extend | Used to create a new calculated column and add it to the result set | `Perf \| extend AlertThreshold = 80` |
| count | Calculates the number of records in a table | `SecurityAlert \| count()` |
| join | Combines data from multiple tables based on common columns | `LeftTable \| join [JoinParameters] ( RightTable ) on Attributes` |
| union | Combines two or more tables and returns all their rows | `OfficeActivity \| union SecurityEvent` |
| range | Specifies a time range for your query | `range LastWeek from ago(7d) to now() step 1d` |
| summarize | Aggregates data based on specified columns and aggregation functions | `Perf \| summarize count() by CounterName` |
| top | Returns the top N records based on a specified column (optional) | `SigninLogs \| top 5 by TimeGenerated desc` |
| parse | Evaluates a string expression and parses its value into one or more calculated columns using regular expressions. And used for structuring unstructured data | `parse kind=regex Col with * var1:string var2:long` |
| render | Renders results as a graphical output | `SecurityEvent | render timechart` |
| distinct | Removes duplicate records from the table and returns a table with a distinct combination of the provided columns | `SecurityEvent \| distinct Account , Activity` |
| bin | Rounds all values in a timeframe and groups them | `bin(StartTime, 1d)` |
| let | Allows you to create and set a variable or assign a name to an expression | `let aWeekAgo = ago(7d);SigninLogs \| where TimeGenerated >= aWeekAgo` |

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
