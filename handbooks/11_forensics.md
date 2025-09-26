# Forensics

- [Resources](#resources)

## Table of Contents

- [Android](#android)
- [bc](#bc)
- [binwalk](#binwalk)
- [capa](#capa)
- [dd](#dd)
- [emlAnalyzer](#emlanalyzer)
- [exiftool](#exiftool)
- [file](#file)
- [FOREMOST](#foremost)
- [git-dumper](#git-dumper)
- [Git](#git)
- [HEX](#hex)
- [inetsim](#inetsim)
- [iOS](#ios)
- [Jamovi](#jamovi)
- [lnkparse](#lnkparse)
- [ltrace](#ltrace)
- [memdump](#memdump)
- [MemProcFS](#memprocfs)
- [Microsoft Windows](#microsoft-windows)
- [Monitor Filesystem Changes](#monitor-filesystem-changes)
- [oletools](#oletools)
- [pngcheck](#pngcheck)
- [steg_brute](#steg_brute)
- [Steghide](#steghide)
- [strings](#strings)
- [Sysinternals](#sysinternals)
- [usbrip](#usbrip)
- [Volatility](#volatility)
- [xxd](#xxd)
- [zsteg](#zsteg)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| BinDiff | Quickly find differences and similarities in disassembled code | https://github.com/google/bindiff |
| CAPA | The FLARE team's open-source tool to identify capabilities in executable files. | https://github.com/mandiant/capa |
| Cheatsheet: Linux Forensics Analysis | Cheat sheet to use during Linux forensics. | https://fareedfauzi.github.io/2024/03/29/Linux-Forensics-cheatsheet.html |
| Cheatsheet: Windows Forensics Analysis | Cheat sheet to use during Windows forensics. | https://fareedfauzi.github.io/2023/12/22/Windows-Forensics-checklist-cheatsheet.html |
| Depix | Recovers passwords from pixelized screenshots | https://github.com/spipm/Depix |
| FLOSS | FLARE Obfuscated String Solver - Automatically extract obfuscated strings from malware. | https://github.com/mandiant/flare-floss |
| FOREMOST | Foremost is a console program to recover files based on their headers, footers, and internal data structures. | https://github.com/korczis/foremost |
| kbd-audio | Acoustic keyboard eavesdropping | https://github.com/ggerganov/kbd-audio |
| oletools | python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office documents, for malware analysis, forensics and debugging. | https://github.com/decalage2/oletools |
| MemProcFS | MemProcFS is an easy and convenient way of viewing physical memory as files in a virtual file system. | https://github.com/ufrisk/MemProcFS |
| Process Hacker | A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware. | https://process-hacker.com |
| Process Monitor | Process Monitor is an advanced monitoring tool for Windows that shows real-time file system, Registry and process/thread activity. | https://learn.microsoft.com/en-us/sysinternals/downloads/procmon |
| Regshot | Regshot is a small, free and open-source registry compare utility that allows you to quickly take a snapshot of your registry and then compare it with a second one - done after doing system changes or installing a new software product | https://github.com/Seabreg/Regshot |
| scdbg | Visual Studio 2008 port of the libemu library that includes scdbg.exe, a modification of the sctest project, that includes more hooks, interactive debugging, reporting features, and ability to work with file format exploit shellcode. Will run under WINE | https://github.com/dzzie/VS_LIBEMU |
| Steghide | Execute a brute force attack with Steghide to file with hide information and password established. | https://github.com/Va5c0/Steghide-Brute-Force-Tool |
| Sysinternals Live | live.sysinternals.com - / | https://live.sysinternals.com |
| Sysinternals Suite | The Sysinternals Troubleshooting Utilities have been rolled up into a single Suite of tools. | https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite |
| Sysinternals Utilities | Sysinternals Utilities Index | https://docs.microsoft.com/en-us/sysinternals/downloads |
| Volatility | An advanced memory forensics framework | https://github.com/volatilityfoundation/volatility |

# Forensics Handbook

## Resources

| Name | Description | URL |
| --- | --- | --- |
| BinDiff | Quickly find differences and similarities in disassembled code | https://github.com/google/bindiff |
| CAPA | The FLARE team's open-source tool to identify capabilities in executable files. | https://github.com/mandiant/capa |
| Cheatsheet: Linux Forensics Analysis | Cheat sheet to use during Linux forensics. | https://fareedfauzi.github.io/2024/03/29/Linux-Forensics-cheatsheet.html |
| Cheatsheet: Windows Forensics Analysis | Cheat sheet to use during Windows forensics. | https://fareedfauzi.github.io/2023/12/22/Windows-Forensics-checklist-cheatsheet.html |
| Depix | Recovers passwords from pixelized screenshots | https://github.com/spipm/Depix |
| FLOSS | FLARE Obfuscated String Solver - Automatically extract obfuscated strings from malware. | https://github.com/mandiant/flare-floss |
| FOREMOST | Foremost is a console program to recover files based on their headers, footers, and internal data structures. | https://github.com/korczis/foremost |
| kbd-audio | Acoustic keyboard eavesdropping | https://github.com/ggerganov/kbd-audio |
| MemProcFS | MemProcFS is an easy and convenient way of viewing physical memory as files in a virtual file system. | https://github.com/ufrisk/MemProcFS |
| oletools | python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office documents, for malware analysis, forensics and debugging. | https://github.com/decalage2/oletools |
| Process Hacker | A free, powerful, multi-purpose tool that helps you monitor system resources, debug software and detect malware. | https://process-hacker.com |
| Process Monitor | Process Monitor is an advanced monitoring tool for Windows that shows real-time file system, Registry and process/thread activity. | https://learn.microsoft.com/en-us/sysinternals/downloads/procmon |
| Regshot | Regshot is a small, free and open-source registry compare utility that allows you to quickly take a snapshot of your registry and then compare it with a second one - done after doing system changes or installing a new software product | https://github.com/Seabreg/Regshot |
| scdbg | Visual Studio 2008 port of the libemu library that includes scdbg.exe, a modification of the sctest project, that includes more hooks, interactive debugging, reporting features, and ability to work with file format exploit shellcode. Will run under WINE | https://github.com/dzzie/VS_LIBEMU |
| Steghide | Execute a brute force attack with Steghide to file with hide information and password established. | https://github.com/Va5c0/Steghide-Brute-Force-Tool |
| Sysinternals Live | live.sysinternals.com - / | https://live.sysinternals.com |
| Sysinternals Suite | The Sysinternals Troubleshooting Utilities have been rolled up into a single Suite of tools. | https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite |
| Sysinternals Utilities | Sysinternals Utilities Index | https://docs.microsoft.com/en-us/sysinternals/downloads |
| Volatility | An advanced memory forensics framework | https://github.com/volatilityfoundation/volatility |

## Android

### Extracting Backups

```console
$ ( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 <FILE>.ab ) |  tar xfvz -
```

## bc

```console
$ echo "obase=16; ibase=2; 00000000010...00000000000000" | bc | xxd -p -r
```

## binwalk

> https://github.com/ReFirmLabs/binwalk

```console
$ binwalk <FILE>
$ binwalk -e <FILE>
```

## capa

```cmd
C:\> capa <FILE> -vv
```

## dd

### Remote Disk Dump

```console
$ ssh root@<RHOST> "dd if=/dev/sda1 status=progress" | dd of=sda1.dmp
```

## emlAnalyzer

```console
$ emlAnalyzer -i <FILE>\:.eml --header --html -u --text --extract-all
```

## exiftool

### Changes Time and Date

```console
$ exiftool -AllDates='JJJJ:MM:TT HH:MM:SS' <FILE>.ext
```

### Extracting Thumbnail

```console
$ exiftool -b -ThumbnailImage picture.ext > <FILE>.jpg
```

### File Information

```console
$ exiftool -p '$Filename $ImageSize' <FILE>.jpg
```

### Removes all Metadata

```console
$ exiftool -all= <FILE>.JPG
```

### Camera Serial Number

```console
$ exiftool -SerialNumber <FILE>.ext
```

### Renames all Files along the Time and Date when they were created

```console
$ exiftool -P -'Filename<DateTimeOriginal' -d %Y%m%d_%Hh%Mm%Ss_Handy.%%e folder/*
```

### Extracts all Metadata and write it into a File

```console
$ exiftool -q -r -t -f -S -n -csv -fileName -GPSPosition -Model -FocalLength -ExposureTime -FNumber -ISO -BrightnessValue -LensID "." > <FILE>.csv
```

### Extract Creators from .pdf-Files

```console
$ exiftool *.pdf | grep Creator | awk '{print $3}' | sort -u > users.txt
```

## file

```console
$ file <FILE>
```

## FOREMOST

> https://github.com/korczis/foremost

```console
$ foremost -i <FILE>
```

## git-dumper

> https://github.com/arthaud/git-dumper

```console
$ ./git-dumper.py http://<DOMAIN>/<repo>
```

## Git

```console
$ git log --pretty=oneline
$ git log -p
```

## HEX

```console
$ hexdump -C <FILE> | less
```

### Binary to HEX

#### convert.py

```console
#!/usr/bin/env python3
file=open('blueshadow.txt','r')
val=int(file.read(), 2)
hexfile=open('bluehadowhex','w')
hexfile.write(hex(val))
hexfile.close()
file.close()
```

## inetsim

```console
$ cat /etc/inetsim/inetsim.conf | grep dns_default_ip
# dns_default_ip
# Syntax: dns_default_ip 
dns_default_ip   <LHOST>
```

```console
$ sudo inetsim
```

## iOS

### Reading standard File Format "Mach-O" from iOS Applications

```console
$ sudo apt-get install libplist-utils
$ plistutil -i challenge.plist -o challenge.plist.xml
```

## Jamovi

### Extracting .omv Files

```console
$ unzip <FILE>.omv
```

## lnkparse3

```console
$ lnkparse (FILE)
```

## ltrace

```console
$ ltrace <BINARY>
```

## memdump

### Bash Script

```console
#!/bin/bash
cat /proc/$1/maps | grep "rw-p" | awk '{print $1}' | ( IFS="-"
    while reade a b; do
        dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
            skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
    done )
```

## MemProcFS

```console
$ sudo ./memprocfs -device /PATH/TO/FILE/<FILE>.DMP -mount /mnt/ -forensic 1
```

## Microsoft Windows

### Shell Bags

```console
<USER_PROFILE>\NTUSER.DAT
<USER_PROFILE>\AppData\Local\Microsoft\Windows\UsrClass.dat
```

## Monitor Filesystem Changes

### Tooling

#### Linux

- Sleuth Kit
- FTK Imager

#### Microsoft Windows

- FTK Imager
- EnCase Forensic
- X1 Social Discovery

### Hashing Filesystem

#### Linux

```console
$ mount /dev/sda1 /mnt
```

```console
$ find /mnt -type f -exec sha256sum {} \; > full_filesystem_hashes.txt
```

or

```console
$ sha256deep -r /mnt > filesystem_hashes.txt
```

##### Monitor Changes

```console
#!/bin/bash
find /mnt -type f -exec sha256sum {} \; > current_hashes.txt
diff full_filesystem_hashes.txt current_hashes.txt > changes_detected.txt
```

#### Microsoft Windows

```cmd
PS C:\> Get-ChildItem C:\ -Recurse -File | Get-FileHash -Algorithm SHA256 | Export-Csv -Path C:\filesystem_hashes.csv
```

```cmd
PS C:\> certutil -hashfile C:\path\to\file SHA256
```

## oletools

> https://github.com/decalage2/oletools

### Installation

```console
$ sudo -H pip install -U oletools[full]
```

### Common Commands

```console
$ oledump <FILE>                         // first analysis
$ oledump <FILE> -s 4                    // analysing datastream 4
$ oledump <FILE> -s 4 --vbadecompress    // decrompress macros
```

### Forensic Chain

```console
$ olevba <FILE>
$ mraptor <FILE>
$ msodde -l debug <FILE>
$ pyxswf <FILE>
$ oleobj -l debug <FILE>
$ rtfobj -l debug <FILE>
$ olebrowse <FILE>
$ olemeta <FILE>
$ oletimes <FILE>
$ oledir <FILE>
$ olemap <FILE>
```

## pngcheck

```console
$ pngcheck -vtp7f <FILE>
```

## scdbg

> http://sandsprite.com/blogs/index.php?uid=7&pid=152

```cmd
PS C:\> .\scdbg.exe -findsc /f \PATH\TO\FILE\<FILE>.sc
```

## steg_brute

```console
$ python steg_brute.py -b -d /usr/share/wordlists/rockyou.txt -f <FILE>.wav
```

## Steghide

> https://github.com/Va5c0/Steghide-Brute-Force-Tool

```console
$ steghide info <FILE>
$ steghide info <FILE> -p <PASSWORD>
$ steghide extract -sf <FILE>
$ steghide extract -sf <FILE> -p <PASSWORD>
```

## strings

```console
$ strings <FILE>.mem > <FILE>.strings.ascii.txt
$ strings -e l <FILE>.mem > <FILE>.strings.unicode_little_endian.txt
$ strings -e b <FILE>.mem > <FILE>.strings.unicode_big_endian.txt
```

## Sysinternals

> https://docs.microsoft.com/en-us/sysinternals/downloads/

> https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite

> https://live.sysinternals.com/

```cmd
PS C:\> Download-SysInternalsTools C:\SysinternalsSuite
```

## usbrip

> https://github.com/snovvcrash/usbrip

```console
$ sudo usbrip events violations <FILE>.json -f syslog
```

## Volatility

> https://www.volatilityfoundation.org/releases

> https://github.com/volatilityfoundation/volatility

> https://volatility3.readthedocs.io/en/stable/volatility3.plugins.html

### Common Commands

```console
$ volatility -f <FILE> imageinfo
$ volatility -f <FILE> filescan
$ volatility -f <FILE> psscan
$ volatility -f <FILE> dumpfiles
$ volatility -f <FILE> <FILE>.info
$ volatility -f <FILE> <FILE>.pslist
$ volatility -f <FILE> <FILE>.psscan
$ volatility -f <FILE> <FILE>.dumpfiles
$ volatility -f <FILE> <FILE>.dumpfiles --pid <ID>
$ volatility -f <FILE> windows.pstree.PsTree
$ volatility -f <FILE> windows.pslist.PsList
$ volatility -f <FILE> windows.cmdline.CmdLine
$ volatility -f <FILE> windows.filescan.FileScan
$ volatility -f <FILE> windows.dlllist.DllList
$ volatility -f <FILE> windows.malfind.Malfind
$ volatility -f <FILE> windows.psscan.PsScan
```

### Examples

```console
$ volatility -f <FILE> --profile=Win7SP1x86 filescan
$ volatility -f <FILE> --profile=Win7SP1x64 filescan | grep <NAME>
$ volatility -f <FILE> --profile=Win7SP1x86 truecryptsummary
$ volatility -f <FILE> --profile=Win7SP1x64 psscan --output=dot --output-file=memdump.dot_
$ volatility -f <FILE> --profile=Win7SP1x64 dumpfiles -Q 0x000000001e8feb70 -D .
$ volatility -f <FILE> --profile=Win7SP1x86 dumpfiles -Q 0x000000000bbc7166 --name file -D . -vvv
```

### Bulk Investigation

```console
$ for plugin in windows.malfind.Malfind windows.psscan.PsScan windows.pstree.PsTree windows.pslist.PsList windows.cmdline.CmdLine windows.filescan.FileScan windows.dlllist.DllList; do volatility -q -f <FILE> $plugin > <FILE>.$plugin.txt; done
```

## xxd

```console
$ xxd <FILE>
```

### Output in HEX

```console
$ cat <FILE> | xxd -p
$ printf <VALUE> | xxd -p
```

### HEX to ASCII

```console
$ cat <FILE> | xxd -p -r
$ curl http://<RHOST/file | xxd -r -p
```

### Convert Output into one Line

```console
$ xxd -p -c 10000 <FILE>
```

### kConvert File

```console
$ xxd -r -p <FILE>.txt <FILE>.gpg    // gpg is just an example
```

### Format String into Decimal

```console
$ echo -n '!AD*G-KaPdSgVkY' | xxd -pu
```

### Cut with xxd

```console
$ xxd -p <FILE> | sed 's/../\\x&/g'
\x23\x21\x2f\x62\x69\x6e\x2f\x70\x79\x74\x68\x6f\x6e\x33\x0a\x69\x6d\x70\x6f\x72\x74\x20\x72\x65\x71\x75\x65\x73\x74\x73
```

### Create ELF File

```console
$ xxd -r -ps <HEX_FILE> <FILE>.bin
```

## zsteg

> https://github.com/zed-0xff/zsteg

```console
$ zsteg -a <FILE>    // runs all the methods on the given file
$ zsteg -E <FILE>    // extracts data from the given payload (example : zsteg -E b4,bgr,msb,xy name.png)
```
