# Forensics

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#Resources)

## Table of Contents

- [Android](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#Android)
- [bc](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#bc)
- [binwalk](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#binwalk)
- [capa](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#capa)
- [dd](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#dd)
- [emlAnalyzer](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#emlAnalyzer)
- [exiftool](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#exiftool)
- [file](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#file)
- [FOREMOST](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#FOREMOST)
- [git-dumper](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#git-dumper)
- [Git](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#Git)
- [HEX](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#HEX)
- [iOS](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#iOS)
- [Jamovi](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#Jamovi)
- [ltrace](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#ltrace)
- [memdump](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#memdump)
- [Microsoft Windows](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#Microsoft-Windows)
- [oletools](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#oletools)
- [pngcheck](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#pngcheck)
- [steg_brute](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#steg_brute)
- [Steghide](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#Steghide)
- [usbrip](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#usbrip)
- [Volatility](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#Volatility)
- [xxd](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#xxd)
- [zsteg](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/11_forensics.md#zsteg)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| FOREMOST | Foremost is a console program to recover files based on their headers, footers, and internal data structures. | https://github.com/korczis/foremost |
| kbd-audio | Acoustic keyboard eavesdropping | https://github.com/ggerganov/kbd-audio |
| oletools | python tools to analyze MS OLE2 files (Structured Storage, Compound File Binary Format) and MS Office documents, for malware analysis, forensics and debugging. | https://github.com/decalage2/oletools |
| scdbg | Visual Studio 2008 port of the libemu library that includes scdbg.exe, a modification of the sctest project, that includes more hooks, interactive debugging, reporting features, and ability to work with file format exploit shellcode. Will run under WINE | https://github.com/dzzie/VS_LIBEMU |
| Steghide | Execute a brute force attack with Steghide to file with hide information and password established. | https://github.com/Va5c0/Steghide-Brute-Force-Tool |
| Volatility | An advanced memory forensics framework | https://github.com/volatilityfoundation/volatility |

## Android

### Extracting Backups

```c
$ ( printf "\x1f\x8b\x08\x00\x00\x00\x00\x00" ; tail -c +25 <FILE>.ab ) |  tar xfvz -
```

## bc

```c
$ echo "obase=16; ibase=2; 00000000010...00000000000000" | bc | xxd -p -r
```

## binwalk

> https://github.com/ReFirmLabs/binwalk

```c
$ binwalk <FILE>
$ binwalk -e <FILE>
```

## capa

```c
C:\> capa <FILE> -vv
```

## dd

### Remote Disk Dump

```c
$ ssh root@<RHOST> "dd if=/dev/sda1 status=progress" | dd of=sda1.dmp
```

## emlAnalyzer

```c
$ emlAnalyzer -i <FILE>\:.eml --header --html -u --text --extract-all
```

## exiftool

### Changes Time and Date

```c
$ exiftool -AllDates='JJJJ:MM:TT HH:MM:SS' <FILE>.ext
```

### Extracting Thumbnail

```c
$ exiftool -b -ThumbnailImage picture.ext > <FILE>.jpg
```

### File Information

```c
$ exiftool -p '$Filename $ImageSize' <FILE>.jpg
```

### Removes all Metadata

```c
$ exiftool -all= <FILE>.JPG
```

### Camera Serial Number

```c
$ exiftool -SerialNumber <FILE>.ext
```

### Renames all Files along the Time and Date when they were created

```c
$ exiftool -P -'Filename<DateTimeOriginal' -d %Y%m%d_%Hh%Mm%Ss_Handy.%%e folder/*
```

### Extracts all Metadata and write it into a File

```c
$ exiftool -q -r -t -f -S -n -csv -fileName -GPSPosition -Model -FocalLength -ExposureTime -FNumber -ISO -BrightnessValue -LensID "." > <FILE>.csv
```

### Extract Creators from .pdf-Files

```c
$ exiftool *.pdf | grep Creator | awk '{print $3}' | sort -u > users.txt
```

## file

```c
$ file <FILE>
```

## FOREMOST

> https://github.com/korczis/foremost

```c
$ foremost -i <FILE>
```

## git-dumper

> https://github.com/arthaud/git-dumper

```c
$ ./git-dumper.py http://<DOMAIN>/<repo>
```

## Git

```c
$ git log --pretty=oneline
$ git log -p
```

## HEX

```c
$ hexdump -C <FILE> | less
```

### Binary to HEX

#### convert.py

```c
#!/usr/bin/env python3
file=open('blueshadow.txt','r')
val=int(file.read(), 2)
hexfile=open('bluehadowhex','w')
hexfile.write(hex(val))
hexfile.close()
file.close()
```

## iOS

### Reading standard File Format "Mach-O" from iOS Applications

```c
$ sudo apt-get install libplist-utils
$ plistutil -i challenge.plist -o challenge.plist.xml
```

## Jamovi

### Extracting .omv Files

```c
$ unzip <FILE>.omv
```

## ltrace

```c
$ ltrace <BINARY>
```

## memdump

### Bash Script

```c
#!/bin/bash
cat /proc/$1/maps | grep "rw-p" | awk '{print $1}' | ( IFS="-"
    while reade a b; do
        dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
            skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
    done )
```

## Microsoft Windows

### Shell Bags

```c
<user_profile>\NTUSER.DAT
<user_profile>\AppData\Local\Microsoft\Windows\UsrClass.dat
```

## oletools

> https://github.com/decalage2/oletools

### Installation

```c
$ sudo -H pip install -U oletools[full]
```

### Forensic Chain

```c
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

```c
$ pngcheck -vtp7f <FILE>
```

## scdbg

> http://sandsprite.com/blogs/index.php?uid=7&pid=152

```c
PS C:\> .\scdbg.exe -findsc /f \PATH\TO\FILE\<FILE>.sc
```

## steg_brute

```c
$ python steg_brute.py -b -d /usr/share/wordlists/rockyou.txt -f <FILE>.wav
```

## Steghide

> https://github.com/Va5c0/Steghide-Brute-Force-Tool

```c
$ steghide info <FILE>
$ steghide info <FILE> -p <PASSWORD>
$ steghide extract -sf <FILE>
$ steghide extract -sf <FILE> -p <PASSWORD>
```

## usbrip

> https://github.com/snovvcrash/usbrip

```c
$ sudo usbrip events violations <FILE>.json -f syslog
```

## Volatility

> https://www.volatilityfoundation.org/releases

> https://github.com/volatilityfoundation/volatility

### Common Commands

```c
$ volatility -f <FILE> imageinfo
$ volatility -f <FILE> filescan
$ volatility -f <FILE> psscan
$ volatility -f <FILE> dumpfiles
$ volatility -f <FILE>.vmem <FILE>.info
$ volatility -f <FILE>.vmem <FILE>.pslist
$ volatility -f <FILE>.vmem <FILE>.psscan
$ volatility -f <FILE>.vmem <FILE>.dumpfiles
$ volatility -f <FILE>.vmem <FILE>.dumpfiles --pid <ID>
```

### Examples

```c
$ volatility -f <FILE> --profile=Win7SP1x86 filescan
$ volatility -f <FILE> --profile=Win7SP1x64 filescan | grep <NAME>
$ volatility -f <FILE> --profile=Win7SP1x86 truecryptsummary
$ volatility -f <FILE> --profile=Win7SP1x64 psscan --output=dot --output-file=memdump.dot_
$ volatility -f <FILE> --profile=Win7SP1x64 dumpfiles -Q 0x000000001e8feb70 -D .
$ volatility -f <FILE> --profile=Win7SP1x86 dumpfiles -Q 0x000000000bbc7166 --name file -D . -vvv
```

## xxd

```c
$ xxd <FILE>
```

### Output in HEX

```c
$ cat <FILE> | xxd -p
$ printf <VALUE> | xxd -p
```

### HEX to ASCII

```c
$ cat <FILE> | xxd -p -r
$ curl http://<RHOST/file | xxd -r -p
```

### Convert Output into one Line

```c
$ xxd -p -c 10000 <FILE>
```

### kConvert File

```c
$ xxd -r -p <FILE>.txt <FILE>.gpg    // gpg is just an example
```

### Format String into Decimal

```c
$ echo -n '!AD*G-KaPdSgVkY' | xxd -pu
```

### Cut with xxd

```c
$ xxd -p <FILE> | sed 's/../\\x&/g'
\x23\x21\x2f\x62\x69\x6e\x2f\x70\x79\x74\x68\x6f\x6e\x33\x0a\x69\x6d\x70\x6f\x72\x74\x20\x72\x65\x71\x75\x65\x73\x74\x73
```

### Create ELF File

```c
$ xxd -r -ps <HEX_FILE> <FILE>.bin
```

## zsteg

> https://github.com/zed-0xff/zsteg

```c
$ zsteg -a <FILE>    // runs all the methods on the given file
$ zsteg -E <FILE>    // extracts data from the given payload (example : zsteg -E b4,bgr,msb,xy name.png)
```
