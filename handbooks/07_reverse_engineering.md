# Reverse Engineering

## Table of Contents

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#Resources)
- [Assembly Instructions](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#Assembly-Instructions)
- [AvalonialLSpy](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#AvalonialLSpy)
- [Basic Block in angr](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#Basic-Block-in-angr)
- [Binwalk](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#Binwalk)
- [CFR](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#CFR)
- [file](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#file)
- [GDB/GEF/peda](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#GDB--GEF--peda)
- [Ghidra](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#Ghidra)
- [Radare2](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#Radare2)
- [strings](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#strings)
- [upx](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/07_reverse_engineering.md#upx)

## Resources

| Name | Description |URL |
| --- | --- | --- |
| binwalk | Binwalk is a fast, easy to use tool for analyzing, reverse engineering, and extracting firmware images. | https://github.com/ReFirmLabs/binwalk |
| ImHex | A Hex Editor for Reverse Engineers, Programmers and people who value their retinas when working at 3 AM. | https://github.com/WerWolv/ImHex |
| JD-GUI | JD-GUI, a standalone graphical utility that displays Java sources from CLASS files. | https://github.com/java-decompiler/jd-gui |
| dnSpy | dnSpy is a debugger and .NET assembly editor. You can use it to edit and debug assemblies even if you don't have any source code available. | https://github.com/dnSpy/dnSpy |
| AvalonialLSpy | This is cross-platform version of ILSpy built with Avalonia. | https://github.com/icsharpcode/AvaloniaILSpy |
| ghidra | Ghidra is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate. | https://github.com/NationalSecurityAgency/ghidra |
| pwndbg | pwndbg is a GDB plug-in that makes debugging with GDB suck less, with a focus on features needed by low-level software developers, hardware hackers, reverse-engineers and exploit developers. | https://github.com/pwndbg/pwndbg |
| cutter | Cutter is a free and open-source reverse engineering platform powered by rizin. | https://github.com/rizinorg/cutter |
| Radare2 | Radare2: The Libre Unix-Like Reverse Engineering Framework | https://github.com/radareorg/radare2 |
| peda | PEDA - Python Exploit Development Assistance for GDB | https://github.com/longld/peda |
| GEF | GEF is a set of commands for x86/64, ARM, MIPS, PowerPC and SPARC to assist exploit developers and reverse-engineers when using old school GDB. | https://github.com/hugsy/gef |
| Decompiler Explorer | Interactive online decompiler which shows equivalent C-like output of decompiled programs from many popular decompilers. | https://dogbolt.org/ |

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

## file

```c
$ file <FILE>
```

## GDB/GEF/peda

> https://github.com/longld/peda

> https://github.com/hugsy/gef

### Addons

> https://github.com/longld/peda

> https://github.com/hugsy/gef

### Config File

```c
$ vi ~/.gdbinit
source ~/peda/peda.py
```

### Common Commands

```c
gdb-peda$ b main                           // sets breakpoint to main function
gdb-peda$ b *0x5655792b                    // sets breakpoint on specific address
gdb-peda$ run                              // starts debugging
gdb-peda$ r                                // starts debugging
gdb-peda$ r `python -c 'print "A"*200'`    // rerun the program with a specific parameter
gdb-peda$ c                                // continue
gdb-peda$ r Aa0Aa---snip---g5Ag            // run custom strings on a binary
gdb-peda$ si                               // switch to instructions
gdb-peda$ si enter                         // step-wise debugging
gdb-peda$ x/s 0x555555556004               // x/s conversion
gdb-peda$ p system                         // print memory address of system
gdb-peda$ searchmem /bin/sh                // search within the binary
gdb-peda$ disas main                       // disassemble main function
gdb-peda$ b*0x080484ca                     // add a specific breakpoint
gdb-peda$ x/100x $esp                      // getting EIP register
gdb-peda$ x/100x $esp-400                  // locate in EIP register
gdb-peda$ pattern create 48                // creates 48 character long pattern
gdb-peda$ x/wx $rsp                        // finding rsp offset
gdb-peda$ pattern search                   // finding pattern
gdb-peda$ info functions <FUNCTION>        // getting function information
```

### Load a File

```c
$ gdb -q <FILE>
```

### Load a File with Arguments

```c
$ gdb --args ./<FILE> <LPORT>
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

## Ghidra

> https://github.com/NationalSecurityAgency/ghidra

> https://hackaday.io/course/172292-introduction-to-reverse-engineering-with-ghidra

```c
L    // rename variables
;    // add a comment
```

## Radare2

> https://github.com/radareorg/radare2


### Commands

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
