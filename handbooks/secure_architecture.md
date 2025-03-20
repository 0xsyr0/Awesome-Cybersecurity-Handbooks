# Security Architecture

- [Resources](#resources)

## Table of Contents

- [API Security Tasks](#api-security-tasks)
- [Device Guard](#device-guard)
- [General Configuration](#general-configuration)
- [LAPS](#laps)
- [Layered Architecture](#layered-architecture)
- [Mitigate Kerberoast](#mitigate-kerberoast)
- [Mitigate Skeleton Key](#mitigate-skeleton-key)
- [Mitigate Trust Attack](#mitigate-trust-attack)
- [Privileged Administrative Workstations](#privileged-administrative-workstations)
- [Protected Users Group](#protected-users-group)
- [Red Forest](#red-forest)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| badssl.com | 🔒 Memorable site for testing clients against bad SSL configs. | https://github.com/chromium/badssl.com |
| Dangerzone | Take potentially dangerous PDFs, office documents, or images and convert them to safe PDFs | https://github.com/freedomofpress/dangerzone |
| Hawk-eye | A powerful scanner to scan your Filesystem, S3, MySQL, Redis, Google Cloud Storage and Firebase storage for PII and sensitive data. | https://github.com/rohitcoder/hawk-eye |
| Slack Watchman | Slack enumeration and exposed secrets detection tool | https://github.com/PaperMtn/slack-watchman |
| STACS | Static Token And Credential Scanner | https://github.com/stacscan/stacs |

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

## Device Guard

- Hardens against malware
- Run trusted code only, enforced in Kernel and Userspace (CCI, UMCI, KMCI)
- UEFI Secure Boot protects bios and firmware

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

```cmd
PS C:\> New-ItemProperty HKLM:\System\CurrentControlSet\Control\Lsa\ -Name RunAsPPL -Value 1 -Verbose
```

### Check

```cmd
PS C:\> Get-WinEvent -FilterHashtable @{Logname='System';ID=12} | ?{$_.message -like "*protected process*"}
```

## Mitigate Trust Attack

- Enable SID Filtering
- Enable Selective Authentication (access between forests not automated)

## Privileged Administrative Workstations

- Use hardened workstation for performing sensitive task.

## Protected Users Group

- Cannot use CredSSP & Wdigest (no more cleartext creds)
- NTLM Hash not cached
- Kerberos does not use DES or RC4
- Requires at least server 2008, need to test impact, no offline sign-on (no caching), useless for computers and service accounts

## Red Forest

- ESAE Enhanced Security Admin Environment
- Dedicated administrative forest for managing critical assets (forests are security boundaries)
