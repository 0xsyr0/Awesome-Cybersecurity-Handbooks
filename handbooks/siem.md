# SIEM

- [Resources](#resources)

## Table of Contents

- [Event Log Analysis](#event-log-analysis)
	- [Windows Event IDs](#windows-event-ids)
	- [Detect ACL Scan](#detect-acl-scan)
	- [Detect DACL Abuse](#detect-dacl-abuse)
	- [Detect Active Directory Certificate Service (ADCS) Abuse](#detect-active-directory-certificate-service-adcs-abuse)
	- [Detect Dsrm](#detect-dsrm)
	- [Detect Golden Ticket](#detect-golden-ticket)
 	- [Detect Kerberoast](#detect-kerberoast)
	- [Detect Malicious SSP](#detect-malicious-ssp)
	- [Detect Skeleton Key](#detect-skeleton-key)
 	- [Detect hidden Windows Services via Access Control Lists (ACLs)](#detect-hidden-windows-services-via-access-control-lists-acls)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Elastop | HTOP for Elasticsearch | https://github.com/acidvegas/elastop |
| DetectionLabELK | DetectionLabELK is a fork from DetectionLab with ELK stack instead of Splunk. | https://github.com/cyberdefenders/DetectionLabELK |

## Event Log Analysis

### Windows Event IDs

| Event ID | Description | Importance for Defenders | Example MITRA ATT&CK Technique |
| --- | --- | --- | --- |
| 1102 | Security Log cleared | May indicate an attacker is attempting to cover their tracks by clearing the security log (e.g., security log cleared after an unauthorized admin logon). | T1070 - Indicator Removal on Host |
| 4624 | Successful account Logon | Helps identify unauthorized or suspicious logon attempts, and track user activity on the network (e.g., logons during off-hours from unusual hosts). | T1078 - Valid Accounts |
| 4625 | Failed account Logon | Indicates potential brute-force attacks or unauthorized attempts to access a system (e.g., multiple failed logons from a single source in a short time). | T1110 - Brute Force |
| 4648 | Logon attempt with explicit credentials | May suggest credential theft or improper use of accounts (e.g., an attacker creates a new token for an account after compromising cleartext credentials). | T1134 - Access Token Manipulation |
| 4662 | An operation was performed on an object | Helps track access to critical objects in Active Directory, which could indicate unauthorized activity (e.g., an attacker performs a DCSync attack by performing replication from an unusual host). | T1003 - OS Credential Dumping |
| 4663 | Access to an object was requested | Monitors attempts to perform specific actions on sensitive objects like files, processes, and registry keys, which could indicate unauthorized access (e.g., an attacker attempts to read a file or folder which has been specifically configured for auditing). | T1530 - Data from Local System |
| 4670 | Permissions on an object were changed | Helps detect potential tampering with sensitive files or unauthorized privilege escalation (e.g., a low-privileged user modifying permissions on a sensitive file to gain access). | T1222 - File Permissions Modification |
| 4672 | Administrator privileges assigned to a new Logon | Helps detect privilege escalation and unauthorized admin account usage (e.g., a standard user suddenly granted admin rights without a change request). | T1078 - Valid Accounts |
| 4698 | A scheduled task was created | Helps detect malicious scheduled task creation and could indicate persistence, privilege escalation, or lateral movement (e.g., an attacker creates a scheduled task that runs a beacon periodically). | T1053 - Scheduled Task/Job |
| 4719 | Attempt to perform a group policy modification | An authorized or unauthorized user tried to perform a group policy modification. | TA0005-Defense Evasion |
| 4720 | New user account created | Monitors for unauthorized account creation or potential insider threats (e.g., a new account created outside of normal business hours without HR approval). | T1136 - Create Account |
| 4724 | An attempt was made to reset an account's password | Monitors for unauthorized password resets, which could indicate account takeover (e.g., an attacker resetting the password of a high-privileged account). | T1098 - Account Manipulation |
| 4728 | Member added to a security-enabled global group | Tracks changes to important security groups, which could indicate unauthorized privilege escalation (e.g., an attacker adds a user to the "Domain Admins" group). | T1098 - Account Manipulation |
| 4729 | Member was removed from a global security group | A member got removed from a global security group which an attacker could do to clear indicators of compromise. | TA0005-Defense Evasion |
| 4732 | Member added to a security-enabled Local group | Monitors changes to local security groups, which could suggest unauthorized access or privilege escalation (e.g., an attacker adds a user to the "Administrators" local group). | T1098 - Account Manipulation |
| 4739 | Domain policy change | An attacker could use changes in domain policies for persistence. | TA0005-Defense Evasion |
| 4756 | Member added to a universal security group | High risk domain group membership change. | TA0003-Persistence |
| 4757 | A member was removed from a security-enabled universal group. | An attacker could try to remove his indicators of compromise or lock specific users out and distrupt access. | TA0005-Defense Evasion |
| 4768 | A Kerberos authentication ticket was requested (TGT Request) | Monitors initial authentication requests to track user logons, and helps identify potential abuse of the Kerberos protocol (e.g., an attacker compromises the NTLM hash of a privileged account and performs an overpass-the-hash attack which requests a TGT from an unusual host). | T1558 - Steal or Forge Kerberos Tickets |
| 4769 | A Kerberos service ticket was requested | Monitors for potential Kerberoasting attacks or other suspicious activities targeting the Kerberos protocol (e.g., a sudden increase in requests for unique services from a single user). | T1558 - Steal or Forge Kerberos Tickets |
| 4776 | The domain controller attempted to validate the credentials | Helps identify failed or successful attempts to validate credentials against the domain controller, which could indicate unauthorized access or suspicious authentication activity (e.g., an unusual number of failed validations from a single IP address). | T1110 - Brute Force |
| 7045 | New service installed | Monitors for potential malicious services being installed, indicating lateral movement or persistence (e.g., a remote access tool installed as a service on multiple machines). | T1543 - Create or Modify System Process |

### Detect ACL Scan

Requires enabled audit policy.

| Event ID | Description |
| ---| --- |
| 4662 | Operation was performed on an object. |
| 5136 | Directory service object was modified. |
| 4670 | Permissions on an object were changed. |

### Detect DACL Abuse

| Event ID | Attack | Description |
| ---| --- | --- |
| 4662, 4738, 5136, 4769 | Set an SPN for the user and perform a kerberoast attack. | Setting a user's SPN results in a 4738, 4662 and 5136 for the target account. A subsequent 4769 captures the kerberoasting event. |
| 4662, 4738, 5136, 4768 | Disable pre-authentication and capture a user's TGT with an AS-REP roast attack. | Disabling pre-authentication results in a 4738 and 5136 for the target account. A subsequent 4768 captures the AS-REP roasting attack. |
| 4662, 5136, 4768 | Perform a shadow credential attack which sets the user object msDS-KeyCredentialLink property. | Setting mDS-KeyCredentialLink results in a 4662 and 5136 for the target account. A subsequent 4768 with pre-authentication type 16 and credential information is generated. |
| 4724, 4738 | Change the user's password | Changing a user's password results in a 4724 and 4738 for the target account. |

### Detect Active Directory Certificate Service (ADCS) Abuse

| Event ID | Description | Importance for Defenders | Example MITRA ATT&CK Technique |
| ---| --- | --- | --- |
| 4898 | A certificate template was loaded or modified. | Monitor for unauthorized modifications to certificate templates, which could enable rogue certificate issuance. | T1552.004 – Unsecured Credentials: Windows Certificates |
| 4887 | A certificate request was submitted. | Track certificate requests, especially from unexpected accounts or high-privileged users. | T1552.004 – Unsecured Credentials: Windows Certificates |
| 4888 | A certificate request was approved. | Identify unauthorized or bulk approvals that could indicate an attacker issuing rogue certificates. |T1552.004 – Unsecured Credentials: Windows Certificates  |
| 4889 | A certificate request was denied. | Can help establish baseline behavior, especially when paired with high numbers of approvals. | General detection (not abuse-specific). |
| 4890 | A certificate services template was updated. | Detect changes to templates that grant enrollment to unauthorized users. | T1552.004, T1078 – Valid Accounts |
| 4891 | A certificate was issued. | Unexpected certificate issuance could indicate an attacker leveraging ADCS for persistence or impersonation. | T1552.004 – Unsecured Credentials: Windows Certificates |
| 4892 | A certificate was revoked. | Normally part of certificate lifecycle management but could indicate incident response action. | General detection (not abuse-specific). |
| 4768 | A Kerberos TGT was requested. | Monitor for high-frequency TGT requests from the same system, which may indicate Kerberoasting. | T1558.001 – Kerberoasting |
| 4769 | A Kerberos service ticket was requested. | Look for anomalous service ticket requests that indicate Pass-the-Ticket or Kerberoasting. | T1550.003 – Pass-the-Ticket |
| 4770 | A Kerberos service ticket was renewed. | Suspicious renewals (especially in ESC6 scenarios) can indicate long-term credential abuse. | Can be linked to T1550.003 |
| 5145 | A network share object was accessed (\\<CA>\CertEnroll). | Monitor for unauthorized access to Certificate Enrollment Services, which could indicate certificate retrieval by attackers. | T1078 – Valid Accounts |
| 6416 | A new trust was created to another domain. | Monitor trust modifications that may indicate SID History abuse for persistence. | T1484.002 – Domain Trust Modification |

| Event ID | ESC | Importance for Defenders |
| --- | --- | --- |
| 4887, 4888, 4891 | ESC1 - Enrollment Agent Template Abuse | Detect certificate enrollments where a user obtains a certificate for another identity. |
| 4890, 4887, 4888, 4891 | ESC2 - Weakly Secured User Certificate Templates | Identify templates allowing low-privileged users to obtain authentication certificates. |
| 4890, 4887, 4888, 4891 | ESC3 - SYSTEM Context Certificate Enrollment | Detect SYSTEM account certificate requests, as these could lead to domain takeover. |
| 4890, 4898 | ESC4 - Writable Certificate Templates | Monitor for template modifications granting unauthorized enrollment permissions. |
| 5145, 4769, 4770 | ESC5 - CA Web Enrollment (NTLM Relay - PetitPotam) | Look for NTLM relay traffic and certificate issuance from unusual endpoints. |
| 4768, 4769, 4770 | ESC6 - AD Object Control over ADCS Servers | Monitor abnormal AD control changes that may indicate attackers granting themselves certificate enrollment rights. |
| 6416, 4890 | ESC7 - SID History Abuse via ADCS | Detect SID History modifications that attackers use to gain unauthorized access. |
| 4887, 4888, 4891, 4890 | ESC8 - Certificate Request Agent Abuse | Identify certificate issuance where an account requests on behalf of another account, enabling persistence. |

### Detect Dsrm

| Event ID | Description |
| ---| --- |
| 4657 | Audit creating/Change of HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehaviour |

### Detect Golden Ticket

| Event ID | Description |
| ---| --- |
| 4624 | Account Logon |
| 4634 | Account Logoff |
| 4672 | Admin Logon (should be monitored on the DC). |

```cmd
PS C:\> Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 |Format-List -Property *
```

### Detect Kerberoast

| Event ID | Description |
| ---| --- |
| 4769 | A Kerberos ticket as requested, Filter: Name != krbtgt, does not end with $, not machine@domain, Failure code is 0x0 (success), ticket encryption is 0x17 (rc4-hmac). |

### Detect Malicious SSP

| Event ID | Description |
| ---| --- |
| 4657 | Audit/creation of HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages |

### Detect Skeleton Key

| Event ID | Description |
| ---| --- |
| 7045 | A Service was installed in the system. |
| 4673 | Sensitive Privilege user (requires audit privileges). |
| 4611 | Trusted logon process has been registered with the Local Security Authority (requires audit privileges). |

```cmd
PS C:\> Get-WinEvent -FilterHashtable @{Logname='System';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}
```

### Detect hidden Windows Services via Access Control Lists (ACLs)

> https://twitter.com/0gtweet/status/1610545641284927492?s=09

> https://github.com/gtworek/PSBits/blob/master/Services/Get-ServiceDenyACEs.ps1

```console
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
