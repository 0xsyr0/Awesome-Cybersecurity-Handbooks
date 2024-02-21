# Reverse Engineering

- [Resources](#resources)

## Table of Contents

- [Assembly Instructions](#assembly-instructions)
- [AvalonialLSpy](#avaloniallspy)
- [Basic Block in angr](#basic-block-in-angr)
- [Binwalk](#binwalk)
- [CFR](#cfr)
- [dumpbin](#dumpbin)
- [file](#file)
- [GDB](#gdb)
- [GEF](#gef)
- [Ghidra](#ghidra)
- [peda](#peda)
- [Radare2](#radare2)
- [strings](#strings)
- [upx](#upx)

## Resources

| Name | Description |URL |
| --- | --- | --- |
| AvalonialLSpy | This is cross-platform version of ILSpy built with Avalonia. | https://github.com/icsharpcode/AvaloniaILSpy |
| binwalk | Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images. | https://github.com/ReFirmLabs/binwalk |
| CFF Explorer | Created by Erik Pistelli, a freeware suite of tools including a PE editor called CFF Explorer and a process viewer. | https://ntcore.com/?page_id=388 |
| cutter | Cutter is a free and open-source reverse engineering platform powered by rizin. | https://github.com/rizinorg/cutter |
| CyberChef | The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis | https://github.com/gchq/CyberChef |
| Decompiler Explorer | Interactive online decompiler which shows equivalent C-like output of decompiled programs from many popular decompilers. | https://dogbolt.org |
| Detect-It-Easy | Program for determining types of files for Windows, Linux and MacOS. | https://github.com/horsicq/Detect-It-Easy |
| dnSpy | dnSpy is a debugger and .NET assembly editor. You can use it to edit and debug assemblies even if you don't have any source code available. | https://github.com/dnSpy/dnSpy |
| Exeinfo PE | exeinfo PE for Windows by A.S.L | https://github.com/ExeinfoASL/Exeinfo |
| GEF | GEF is a set of commands for x86/64, ARM, MIPS, PowerPC and SPARC to assist exploit developers and reverse-engineers when using old school GDB. | https://github.com/hugsy/gef |
| Ghidra | Ghidra is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate. | https://github.com/NationalSecurityAgency/ghidra |
| HxD | HxD is a carefully designed and fast hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size. | https://mh-nexus.de/en/hxd |
| ImHex | A Hex Editor for Reverse Engineers, Programmers and people who value their retinas when working at 3 AM. | https://github.com/WerWolv/ImHex |
| JD-GUI | JD-GUI, a standalone graphical utility that displays Java sources from CLASS files. | https://github.com/java-decompiler/jd-gui |
| Malcat | Malcat is a feature-rich hexadecimal editor / disassembler for Windows and Linux targeted to IT-security professionals. | https://malcat.fr |
| PE Tools | Portable executable (PE) manipulation toolkit | https://github.com/petoolse/petools |
| PE-bear | Portable Executable reversing tool with a friendly GUI | https://github.com/hasherezade/pe-bear |
| peda | PEDA - Python Exploit Development Assistance for GDB | https://github.com/longld/peda |
| pwndbg | pwndbg is a GDB plug-in that makes debugging with GDB suck less, with a focus on features needed by low-level software developers, hardware hackers, reverse-engineers and exploit developers. | https://github.com/pwndbg/pwndbg |
| Radare2 | Radare2: The Libre Unix-Like Reverse Engineering Framework | https://github.com/radareorg/radare2 |
| Rizin | UNIX-like reverse engineering framework and command-line toolset. | https://github.com/rizinorg/rizin |
| rz-ghidra | Deep ghidra decompiler and sleigh disassembler integration for rizin | https://github.com/rizinorg/rz-ghidra |
| WinDbgX | An attempt to create a friendly version of WinDbg | https://github.com/zodiacon/WinDbgX |
| x64dbg | An open-source user mode debugger for Windows. Optimized for reverse engineering and malware analysis. | https://github.com/x64dbg/x64dbg |

## Assembly Instructions

```c
jne     # jump equal to
cmp     # compare
call    # call function for example
```

## AvaloniaILSpy

> https://github.com/icsharpcode/AvaloniaILSpy

```c
$ chmod a+x ILSpy
$ ./ILSpy
```

## Basic Block in angr

```c
import angr
import sys

def main(argv):
  path_to_binary = "<BINARY>"
  project = angr.Project(path_to_binary)
  initial_state = project.factory.entry_state()
  sm = project.factory.simgr(initial_state)
  # list of basic blocks to find or to avoid
  sm.explore(find=[], avoid=[])
  for state in sm.deadended:
    print(state.posix.dumps(sys.stdin.fileno()))
  else:
    raise Exception('Could not find the solution')

if __name__ == '__main__':
  main(sys.argv)
```

## Binwalk

> https://github.com/ReFirmLabs/binwalk

```c
$ binwalk <FILE>
$ binwalk -e <FILE>
```

## CFR

> https://www.benf.org/other/cfr/

```c
$ java -jar cfr-0.151.jar --outputpath /PATH/TO/DIRECTORY/ /PATH/TO/FILE/<FILE>.jar
```

## dumpbin

```c
C:\>dumpbin /headers /PATH/TO/FILE/<FILE>.exe
C:\>dumpbin /exports /PATH/TO/FILE/<FILE>.dll
```

## file

```c
$ file <FILE>
```

## GDB

### Common Commands

```c
(gdb) b main                           // sets breakpoint to main function
(gdb) b *0x5655792b                    // sets breakpoint on specific address
(gdb) run                              // starts debugging
(gdb) r                                // starts debugging
(gdb) r `python -c 'print "A"*200'`    // rerun the program with a specific parameter
(gdb) c                                // continue
(gdb) r Aa0Aa---snip---g5Ag            // run custom strings on a binary
(gdb) si                               // switch to instructions
(gdb) si enter                         // step-wise debugging
(gdb) x/s 0x555555556004               // x/s conversion
(gdb) p system                         // print memory address of system
(gdb) searchmem /bin/sh                // search within the binary
(gdb) disas main                       // disassemble main function
(gdb) b*0x080484ca                     // add a specific breakpoint
(gdb) x/100x $esp                      // getting EIP register
(gdb) x/100x $esp-400                  // locate in EIP register
(gdb) pattern create 48                // creates 48 character long pattern
(gdb) x/wx $rsp                        // finding rsp offset
(gdb) pattern search                   // finding pattern
(gdb) info functions <FUNCTION>        // getting function information
```

### Load a File

```c
$ gdb -q <FILE>
```

### Load a File with Arguments

```c
$ gdb --args ./<FILE> <LPORT>
```

## GEF

> https://github.com/hugsy/gef

```c
$ bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

## Ghidra

> https://github.com/NationalSecurityAgency/ghidra

> https://hackaday.io/course/172292-introduction-to-reverse-engineering-with-ghidra

```c
L    // rename variables
;    // add a comment
```

## peda

> https://github.com/longld/peda

### Config File

```c
$ vi ~/.gdbinit
source ~/peda/peda.py
```

### Check File Properties

```c
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

## Radare2

> https://github.com/radareorg/radare2

> https://r2wiki.readthedocs.io/en/latest/

### Shortcuts

```c
v + view mode
V = visual mode
  p = cycle different panes
  v = function graph
    V = enter function in graph view
```

### Search Function

```c
:> s sym.main
Enter
Enter
```

### Common Commands

```c
?                 // help function
r2 <FILE>         // load a file
r2 -A ./<FILE>    // load a file
aaa               // analyze it
afl               // list all functions
s main            // set breakpoint on main
pdf               // start viewer
pdf@main          // start viewer on main
pdf@<function>    // start viewer on specific function
00+               // enable read function
s 0x00400968      // set replace function
wx 9090           // replace s with nops
wa nop            // write replaced nops
```

```c
$ r2 supershell
```

### Analyze Everything

```c
[0x004006e0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Check for objc references
[x] Check for vtables
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information
[x] Use -AA or aaaa to perform additional experimental analysis.
```

### Show Functions

```c
[0x004006e0]> afl
0x004006e0    1 41           entry0
0x004006a0    1 6            sym.imp.__libc_start_main
0x00400710    4 50   -> 41   sym.deregister_tm_clones
0x00400750    4 58   -> 55   sym.register_tm_clones
0x00400790    3 28           entry.fini0
0x004007b0    4 38   -> 35   entry.init0
0x004009b0    1 2            sym.__libc_csu_fini
0x004009b4    1 9            sym._fini
0x004007d6    6 89           sym.tonto_chi_legge
0x00400940    4 101          sym.__libc_csu_init
0x0040082f    9 260          main
0x00400640    1 6            sym.imp.puts
0x004006b0    1 6            sym.imp.exit
0x00400620    1 6            sym.imp.strncpy
0x00400630    1 6            sym.imp.strncmp
0x00400680    1 6            sym.imp.printf
0x004006c0    1 6            sym.imp.setuid
0x00400670    1 6            sym.imp.system
0x00400660    1 6            sym.imp.__stack_chk_fail
0x004005f0    3 26           sym._init
0x00400650    1 6            sym.imp.strlen
0x00400690    1 6            sym.imp.strcspn
```

### Example

```c
$ r2 -d -A <FILE>                // -d run, -A analysis
[0x080491ab]> s main; pdf          // disassemble main, pdf = Print Disassembly Function
[0x080491ab]> db 0x080491bb        // db = debug breakpoint
[0x080491ab]> dc                   // dc = debug continue
[0x08049172]> pxw @ esp            // analyze top of the stack
[0x08049172]> ds                   // ds = debug step
[0x080491aa]> pxw @ 0xff984aec     // read a specific value
[0x41414141]> dr eip               // dr = debug register
```

## strings

```c
$ strings <FILE>
$ strings -o <FILE>
$ strings -n 1 <FILE>
```

### Printing Memory Location

```c
$ strings -a -t x /lib/i386-linux-gnu/libc.so.6
```

## upx

```c
$ upx -d <FILE>
```
