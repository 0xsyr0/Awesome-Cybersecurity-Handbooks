# Reverse Engineering

- [Resources](#resources)

## Table of Contents

- [Assembly](#assembly)
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
| CodemerxDecompile | The first standalone .NET decompiler for Mac, Linux and Windows | https://github.com/codemerx/CodemerxDecompile |
| cutter | Cutter is a free and open-source reverse engineering platform powered by rizin. | https://github.com/rizinorg/cutter |
| CyberChef | The Cyber Swiss Army Knife - a web app for encryption, encoding, compression and data analysis | https://github.com/gchq/CyberChef |
| Decompiler Explorer | Interactive online decompiler which shows equivalent C-like output of decompiled programs from many popular decompilers. | https://dogbolt.org |
| Detect-It-Easy | Program for determining types of files for Windows, Linux and MacOS. | https://github.com/horsicq/Detect-It-Easy |
| dnSpy | dnSpy is a debugger and .NET assembly editor. You can use it to edit and debug assemblies even if you don't have any source code available. | https://github.com/dnSpy/dnSpy |
| Exeinfo PE | exeinfo PE for Windows by A.S.L | https://github.com/ExeinfoASL/Exeinfo |
| GEF | GEF is a set of commands for x86/64, ARM, MIPS, PowerPC and SPARC to assist exploit developers and reverse-engineers when using old school GDB. | https://github.com/hugsy/gef |
| Ghidra | Ghidra is a software reverse engineering (SRE) framework created and maintained by the National Security Agency Research Directorate. | https://github.com/NationalSecurityAgency/ghidra |
| ghidraMCP | MCP Server for Ghidra | https://github.com/LaurieWired/GhidraMCP |
| GoReSym | Go symbol recovery tool | https://github.com/mandiant/GoReSym |
| GoStringUngarbler | Python tool to resolve all strings in Go binaries obfuscated by garble | https://github.com/mandiant/gostringungarbler |
| HxD | HxD is a carefully designed and fast hex editor which, additionally to raw disk editing and modifying of main memory (RAM), handles files of any size. | https://mh-nexus.de/en/hxd |
| IDA MCP Server | A Model Context Protocol server for IDA | https://github.com/MxIris-Reverse-Engineering/ida-mcp-server |
| ImHex | A Hex Editor for Reverse Engineers, Programmers and people who value their retinas when working at 3 AM. | https://github.com/WerWolv/ImHex |
| JD-GUI | JD-GUI, a standalone graphical utility that displays Java sources from CLASS files. | https://github.com/java-decompiler/jd-gui |
| Malcat | Malcat is a feature-rich hexadecimal editor / disassembler for Windows and Linux targeted to IT-security professionals. | https://malcat.fr |
| PE-bear | Portable Executable reversing tool with a friendly GUI | https://github.com/hasherezade/pe-bear |
| PECheck | A tool to verify and create PE Checksums for Portable Executable (PE) files. | https://github.com/Wh1t3Rh1n0/PECheck |
| PE Tools | Portable executable (PE) manipulation toolkit | https://github.com/petoolse/petools |
| PE Tree | Python module for viewing Portable Executable (PE) files in a tree-view using pefile and PyQt5. Can also be used with IDA Pro and Rekall to dump in-memory PE files and reconstruct imports. | https://github.com/blackberry/pe_tree |
| peda | PEDA - Python Exploit Development Assistance for GDB | https://github.com/longld/peda |
| pwndbg | pwndbg is a GDB plug-in that makes debugging with GDB suck less, with a focus on features needed by low-level software developers, hardware hackers, reverse-engineers and exploit developers. | https://github.com/pwndbg/pwndbg |
| Radare2 | Radare2: The Libre Unix-Like Reverse Engineering Framework | https://github.com/radareorg/radare2 |
| Redress | Redress - A tool for analyzing stripped Go binaries | https://github.com/goretk/redress |
| resym | Cross-platform tool that allows browsing and extracting C and C++ type declarations from PDB files. | https://github.com/ergrelet/resym |
| Rizin | UNIX-like reverse engineering framework and command-line toolset. | https://github.com/rizinorg/rizin |
| rz-ghidra | Deep ghidra decompiler and sleigh disassembler integration for rizin | https://github.com/rizinorg/rz-ghidra |
| WinDbgX | An attempt to create a friendly version of WinDbg | https://github.com/zodiacon/WinDbgX |
| x64dbg | An open-source user mode debugger for Windows. Optimized for reverse engineering and malware analysis. | https://github.com/x64dbg/x64dbg |

## Assembly

### x86

#### General Purpose Registers

- EAX – Accumulator (used for arithmetic, return values)  
- EBX – Base register (data, addressing)  
- ECX – Counter (loops, shifts)  
- EDX – Data register (I/O, multiply/divide)  
- ESI – Source index (string ops, memory copy)  
- EDI – Destination index (string ops, memory copy)  
- EBP – Base pointer (stack frames)  
- ESP – Stack pointer (current stack top)  

#### Data Movement

```asm
; NASM (Intel)                  ; GAS (AT&T)
mov eax, ebx                    movl %ebx, %eax        ; eax = ebx
mov eax, [ebx]                  movl (%ebx), %eax      ; eax = value at memory[ebx]
mov [ebx], eax                  movl %eax, (%ebx)      ; memory[ebx] = eax
lea eax, [ebx+4]                leal 4(%ebx), %eax     ; load effective address (eax = ebx+4)
xchg eax, ebx                   xchgl %eax, %ebx       ; swap values
```

#### Arithmetic

```asm
; NASM (Intel)                  ; GAS (AT&T)
add eax, 5                      addl $5, %eax          ; eax = eax + 5
sub eax, ebx                    subl %ebx, %eax        ; eax = eax - ebx
inc eax                         incl %eax              ; eax = eax + 1
dec ebx                         decl %ebx              ; ebx = ebx - 1
imul eax, ebx                   imull %ebx, %eax       ; signed multiply
idiv ecx                        idivl %ecx             ; signed divide (EAX/ECX, remainder in EDX)
neg eax                         negl %eax              ; two's complement negate
adc eax, ebx                    adcl %ebx, %eax        ; add with carry
sbb eax, ebx                    sbbl %ebx, %eax        ; sub with borrow
```

#### Logic / Bitwise

```asm
; NASM (Intel)                  ; GAS (AT&T)
and eax, ebx                    andl %ebx, %eax        ; bitwise AND
or eax, 1                       orl $1, %eax           ; bitwise OR
xor eax, eax                    xorl %eax, %eax        ; clear register (eax = 0)
not eax                         notl %eax              ; bitwise NOT
shl eax, 1                      shll $1, %eax          ; shift left
shr eax, 1                      shrl $1, %eax          ; shift right (logical)
sar eax, 1                      sarl $1, %eax          ; shift right (arithmetic)
rol eax, 1                      roll $1, %eax          ; rotate left
ror eax, 1                      rorl $1, %eax          ; rotate right
bt eax, 5                       btl $5, %eax           ; bit test -> CF
```

#### Comparison & Jumps

```asm
; NASM (Intel)                  ; GAS (AT&T)
cmp eax, ebx                    cmpl %ebx, %eax        ; compare (sets flags)
test eax, eax                   testl %eax, %eax       ; logical AND for flags (check zero)
je label                        je label               ; jump if equal
jne label                       jne label              ; jump if not equal
jg label                        jg label               ; jump if greater (signed)
jl label                        jl label               ; jump if less (signed)
jge label                       jge label              ; jump if greater/equal (signed)
jle label                       jle label              ; jump if less/equal (signed)
ja label                        ja label               ; jump if above (unsigned)
jb label                        jb label               ; jump if below (unsigned)
jmp label                       jmp label              ; unconditional jump
```

#### Stack Operations

```asm
; NASM (Intel)                  ; GAS (AT&T)
push eax                        pushl %eax             ; push eax onto stack
pop ebx                         popl %ebx              ; pop stack into ebx
pushad                          pushal                 ; push all general registers
popad                           popal                  ; pop all general registers
enter 8,0                       enter $8, $0           ; setup stack frame (like function prologue)
leave                           leave                  ; restore stack frame (function epilogue)
```

#### Loops

```asm
; NASM (Intel)                  ; GAS (AT&T)
loop label                      loop label             ; decrement ecx, jump if ecx != 0
jecxz label                     jecxz label            ; jump if ecx == 0
```

#### Procedure Calls

```asm
; NASM (Intel)                  ; GAS (AT&T)
call func                       call func              ; push return addr, jump to func
ret                             ret                    ; return from procedure
```

#### Flags (EFLAGS register)

- ZF – Zero flag  
- SF – Sign flag  
- CF – Carry flag  
- OF – Overflow flag  
- PF – Parity flag  

#### Example Function

```asm
; NASM (Intel)                          ; GAS (AT&T)
function:                               function:
    push ebp                            pushl %ebp
    mov ebp, esp                        movl %esp, %ebp
    sub esp, 16                         subl $16, %esp       ; allocate local space
    mov eax, [ebp+8]                    movl 8(%ebp), %eax   ; load first argument
    add eax, [ebp+12]                   addl 12(%ebp), %eax  ; add second argument
    leave                               leave
    ret                                 ret
```

### x86-64

#### General-purpose Registers (64/32/16/8-bit)

- RAX/EAX/AX/AL – accumulator, return values  
- RBX/EBX/BX/BL – base  
- RCX/ECX/CX/CL – counter, arg #1 (Win64)  
- RDX/EDX/DX/DL – data, arg #2 (Win64)  
- RSI/ESI/SI/SIL – src index, arg #2 (SysV), arg #3 (Win64)  
- RDI/EDI/DI/DIL – dst index, arg #1 (SysV), arg #4 (Win64)  
- RBP/EBP/BP/BPL – base/frame ptr  
- RSP/ESP/SP/SPL – stack ptr  
- R8–R15 (and lower sizes R8D/R8W/R8B …) – extra args/temps  

#### Flags (RFLAGS)

- CF, PF, AF, ZF, SF, OF, DF, IF (used by Jcc/SETcc/CMOVcc)  

##### Data Movement

```asm
; NASM (Intel)                         ; GAS (AT&T)
mov rax, rbx                           movq %rbx, %rax             ; copy
mov rax, [rbx]                         movq (%rbx), %rax           ; load qword
mov [rbx], rax                         movq %rax, (%rbx)           ; store qword
movzx eax, byte [rcx]                  movzbl (%rcx), %eax         ; zero-extend 8->32
movsx rax, word [rcx]                  movswq (%rcx), %rax         ; sign-extend 16->64
mov rax, 0x1122334455667788            movabsq $0x1122334455667788, %rax
lea rdx, [rcx+rax*4+8]                 leaq 8(%rcx,%rax,4), %rdx   ; address calc (no mem touch)
xchg rax, rbx                          xchgq %rax, %rbx            ; swap
```

##### Zero-extension Rule

- Any write to a 32-bit register (e.g., `EAX`) zeroes the upper 32 bits of its 64-bit parent (`RAX`).

#### Arithmetic

```asm
; NASM (Intel)                         ; GAS (AT&T)
add rax, rbx                           addq %rbx, %rax
sub rax, 8                             subq $8, %rax
inc rax                                incq %rax                   ; (does not affect CF)
dec rbx                                decq %rbx
imul rax, rbx                          imulq %rbx, %rax            ; signed multiply low in rax
imul rax, rbx, 10                      imulq $10, %rbx, %rax       ; rax = rbx*10
mul rbx                                mulq %rbx                   ; unsigned: RDX:RAX = RAX*RBX
idiv rcx                               idivq %rcx                  ; signed: (RDX:RAX)/RCX -> RAX,RDX
neg rax                                negq %rax
adc rax, rbx                           adcq %rbx, %rax
sbb rax, rbx                           sbbq %rbx, %rax
```

#### Logic / Bitwise / Shifts

```asm
; NASM (Intel)                         ; GAS (AT&T)
and rax, rbx                           andq %rbx, %rax
or rax, 1                              orq $1, %rax
xor rax, rax                           xorq %rax, %rax             ; clear register
not rax                                notq %rax
shl rax, 1                             shlq $1, %rax
shr rax, 1                             shrq $1, %rax
sar rax, 1                             sarq $1, %rax
rol rax, 1                             rolq $1, %rax
ror rax, 1                             rorq $1, %rax
bt rax, 5                              btq $5, %rax                ; bit test -> CF
```

#### Compare / Test / Conditional Moves & Sets

```asm
; NASM (Intel)                         ; GAS (AT&T)
cmp rax, rbx                           cmpq %rbx, %rax
test rax, rax                          testq %rax, %rax
cmovz rax, rbx                         cmovzq %rbx, %rax           ; aka cmove
cmovnz rax, rcx                        cmovnzq %rcx, %rax
setl al                                setl %al                    ; less (signed)
seta al                                seta %al                    ; above (unsigned)
```

#### Jumps (Jcc)

```asm
; NASM (Intel)                         ; GAS (AT&T)
je label                               je label
jne label                              jne label
jg label                               jg label
jge label                              jge label
jl label                               jl label
jle label                              jle label
ja label                               ja label
jb label                               jb label
jmp label                              jmp label
```

#### Calls / Returns

```asm
; NASM (Intel)                         ; GAS (AT&T)
call func                              call func
ret                                    ret
```

#### Stack Operations (64-bit)

- **pushad**/**popad** are removed in x86-64.

```asm
; NASM (Intel)                         ; GAS (AT&T)
push rax                               pushq %rax
pop rbx                                popq %rbx
pushfq                                 pushfq
popfq                                  popfq
; (Note: pushad/popad removed in x86-64)
```

#### Function Prologue / Epilogue

```asm
; NASM (Intel)                         ; GAS (AT&T)
push rbp                               pushq %rbp
mov rbp, rsp                           movq %rsp, %rbp
sub rsp, 32                            subq $32, %rsp              ; keep 16B alignment
; ... body ...
leave                                  leave
ret                                    ret
```

##### Stack Alignment Rule

- Before a `call`, **RSP must be 16-byte aligned** (SysV). Align by reserving an extra `8` bytes if needed.

#### RIP-relative Addressing (x86-64 only)

```asm
; NASM (Intel)                         ; GAS (AT&T)
lea rax, [rel msg]                     leaq msg(%rip), %rax
mov edx, dword [rel var]               movl var(%rip), %edx
```

#### Sign-Extension / Zero-extension Helpers

```asm
; NASM (Intel)                         ; GAS (AT&T)
cdqe                                   cltq                         ; EAX -> RAX sign-extend
cqo                                    cqto                         ; RDX:RAX sign-extend from RAX
movsxd rax, ecx                        movslq %ecx, %rax
```

#### String / Memory Ops

- **REP** prefixes use **RCX** count, **RSI**/**DI** pointers.

```asm
; NASM (Intel)                         ; GAS (AT&T)
movsb                                   movsb
movsw                                   movsw
movsd                                   movsd
movsq                                   movsq
stosb                                   stosb
stosq                                   stosq
lodsb                                   lodsb
lodsq                                   lodsq
cmpsb                                   cmpsb
cmpsq                                   cmpsq
scasb                                   scasb
scasq                                   scasq
rep movsq                               rep movsq                  ; memcpy 8-byte chunks
rep stosb                               rep stosb                  ; memset
```

##### System V ADM64 (Linux / macOS / \*nix) Calling Convention

- Integer/pointer args: **RDI, RSI, RDX, RCX, R8, R9**, then stack.  
- Return: **RAX** (and **RDX** for 128-bit).  
- Callee-saved: **RBX, RBP, R12–R15** (must preserve).  
- Red zone: 128 bytes below RSP usable (Linux/macOS; not on Windows/interrupts).  

#### Minimal SysV Function

```asm
; NASM (Intel)                         ; GAS (AT&T)
global add2                            .globl add2
add2:                                  add2:
    lea rax, [rdi + rsi]               leaq (%rdi,%rsi), %rax
    ret                                ret
```

#### Windows x64 Calling Convention (summary)

- Integer/pointer args: **RCX, RDX, R8, R9**, then stack.  
- Return: **RAX**.  
- Callee-saved: **RBX, RBP, RDI, RSI, R12–R15**.  
- Caller reserves **32 bytes of shadow space** on stack for callees.  
- No red zone.  

#### Minimal Win64 Function (with shadow space)

```asm
; NASM (Intel)                         ; GAS (AT&T)
global add2                            .globl add2
add2:                                  add2:
    push rbp                           pushq %rbp
    mov rbp, rsp                       movq %rsp, %rbp
    sub rsp, 32                        subq $32, %rsp              ; shadow space
    lea rax, [rcx + rdx]               leaq (%rcx,%rdx), %rax
    add rsp, 32                        addq $32, %rsp
    pop rbp                            popq %rbp
    ret                                ret
```

#### Linux syscall (x86-64)

- **RAX** = syscall number  
- Args: **RDI, RSI, RDX, R10, R8, R9**  
- Ret: **RAX** (negated errno on error)  

```asm
; NASM (Intel)                         ; GAS (AT&T)
; write(1, msg, len)
mov rax, 1                             movq $1, %rax        ; SYS_write
mov rdi, 1                             movq $1, %rdi        ; fd = stdout
lea rsi, [rel msg]                     leaq msg(%rip), %rsi
mov rdx, msg_len                       movq $msg_len, %rdx
syscall                                syscall
```

#### Control-flow Miscellany

```asm
; NASM (Intel)                         ; GAS (AT&T)
call rax                               call *%rax           ; indirect call
jmp  rax                               jmp *%rax            ; tailcall/jump table
cmp  rax, 0                            cmpq $0, %rax
setz al                                setz %al
test rax, rax                          testq %rax, %rax
jz   zero_path                         jz zero_path
```

#### SIMD

- Registers: **XMM0–XMM15** (SSE/AVX), **YMM0–YMM15** (AVX), **ZMM** (AVX-512 where available).  
- Moves: `movdqa/movdqu` (int aligned/unaligned), `movaps/movups` (fp aligned/unaligned).  
- Scalars: `addss/addsd` (float/double). Vectors: `addps/addpd`, etc.

```asm
; NASM (Intel)                         ; GAS (AT&T)
movdqa xmm0, [rdi]                     movdqa (%rdi), %xmm0
movdqu xmm1, [rsi]                     movdqu (%rsi), %xmm1
paddd xmm0, xmm1                       paddd %xmm1, %xmm0
movdqu [rdx], xmm0                     movdqu %xmm0, (%rdx)

movaps xmm2, [rdi]                     movaps (%rdi), %xmm2
addps xmm2, [rsi]                      addps (%rsi), %xmm2
movaps [rdx], xmm2                     movaps %xmm2, (%rdx)
```

#### Common Patterns

```asm
; NASM (Intel)                         ; GAS (AT&T)
; Compare & branch
cmp rdi, rsi                           cmpq %rsi, %rdi
jl  less                               jl less

; Max without branch (unsigned) via cmov
mov  rax, rdi                          movq %rdi, %rax
cmp  rax, rsi                          cmpq %rsi, %rax
cmova rax, rsi                         cmovaq %rsi, %rax

; Clear and set
xor eax, eax                           xorl %eax, %eax
or  rax, 1                             orq $1, %rax

; Save / restore callee-saved (SysV)
push rbx                               pushq %rbx
push r12                               pushq %r12
; ... body ...
pop  r12                               popq %r12
pop  rbx                               popq %rbx
ret                                     ret
```

#### Notes / Gotchas

- No `pushad`/`popad` in x86-64.  
- `enter`/`leave` exist; `leave` is common, `enter` is rare.  
- RIP-relative addressing is default for position-independent code.  
- Keep stack 16-byte aligned at call sites (SysV); reserve 32-byte shadow space (Win64).  
- Writing to 8/16-bit registers does **not** zero-extend; use `movzx/movsx` if needed.  
- Any write to a 32-bit register zero-extends to its 64-bit parent.  

## AvaloniaILSpy

> https://github.com/icsharpcode/AvaloniaILSpy

```console
$ chmod a+x ILSpy
$ ./ILSpy
```

## Basic Block in angr

```python
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

```console
$ binwalk <FILE>
$ binwalk -e <FILE>
```

## CFR

> https://www.benf.org/other/cfr/

```console
$ java -jar cfr-0.151.jar --outputpath /PATH/TO/DIRECTORY/ /PATH/TO/FILE/<FILE>.jar
```

## dumpbin

```cmd
C:\> dumpbin /headers /PATH/TO/FILE/<FILE>.exe
C:\> dumpbin /exports /PATH/TO/FILE/<FILE>.dll
```

## file

```console
$ file <FILE>
```

## GDB

### Common Commands

```console
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

```console
$ gdb -q <FILE>
```

### Load a File with Arguments

```console
$ gdb --args ./<FILE> <LPORT>
```

## GEF

> https://github.com/hugsy/gef

```console
$ bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

## Ghidra

> https://github.com/NationalSecurityAgency/ghidra

> https://hackaday.io/course/172292-introduction-to-reverse-engineering-with-ghidra

```console
L    // rename variables
;    // add a comment
```

## peda

> https://github.com/longld/peda

### Config File

```console
$ vi ~/.gdbinit
source ~/peda/peda.py
```

### Check File Properties

```console
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

> https://monosource.gitbooks.io/radare2-explorations/content/

> https://gist.github.com/werew/cad8f30bc930bfca385554b443eec2a7

### Customization

#### Themes

```console
[0x004006e0]> eco
[0x004006e0]> eco consonance
```

#### Example Configuration File

##### .radare2rc 

```console
# ---- UI / readability
e scr.color = true            # enable colored output
e scr.utf8 = true             # use UTF-8 box-drawing for graphs/UI
e asm.syntax = intel          # disassembly in Intel syntax
e asm.lines = true            # draw ASCII flow lines in disasm
e asm.bytes = false           # hide raw instruction bytes (cleaner view)
e asm.cmt.right = true        # show comments at right if they fit
# e asm.pseudo = true          # optional: pseudocode in disasm
e cmd.stack = true            # show stack + regs in visual mode
eco consonance                # apply the "consonance" color theme
# ec prompt red               # example: change prompt color (optional)

# ---- symbols / demangling / strings
e asm.demangle = true         # demangle C++/Swift symbols
e bin.str.purge = true        # filter out junk strings (false positives)

# ---- analysis behavior
e anal.esil = true            # enable ESIL VM emulation in analysis
e anal.hasnext = true         # continue analysis past last known func
e anal.strings = true         # consider only referenced strings
e anal.vars = true            # auto-analyze function local variables

# ---- IO / performance (safe caching)
e io.cache = true             # enable R/W caching layer
e io.cache.read = true        # cache reads for speed
e io.cache.write = true       # cache writes (not applied until wq/wf)
e io.pcache = true            # enable page-level IO caching
e io.pcache.read = true       # cache reads at page granularity

# ---- debugging defaults
e dbg.bep = entry             # break on entrypoint when debugging
e dbg.follow = false          # don't auto-follow fork/exec children
```

### Configuration related Commands

```console
[0x004006e0]> e                // print current configuration
[0x004006e0]> e scr.nkey =?    // shows command specific help
```

### Shortcuts

```console
v = view mode
V = visual mode
```

### Project Management

```console
[0x004006e0]> Po <PROJECT>    // open/create a project
[0x004006e0]> Ps <PROJECT>    // save current session to a project
[0x004006e0]> PS              // list all projects
[0x004006e0]> P- <PROJECT>    // delete a project
[0x004006e0]> Pj              // list projects in JSON
[0x004006e0]> PS*             // list projects in radare2 commands format
[0x004006e0]> Ps              // save current session (overwrites if exists)
[0x004006e0]> Pn <PROJECT>    // rename current project
[0x004006e0]> Pq              // close project
```

### Preliminary Analysis

```console
$ rabin2 -I <FILE>
$ rabin2 -MRsSz <FILE>    // -M -> classes, methods and symbols; -R -> relocations; -s -> symbols; -S -> sections; -z -> strings
```

### Visual Mode

#### Common Commands

```console
V = visual mode
  p = cycle different views
  v = function graph
    V = enter function in graph view
  ? = help menu
  p = debug view
  V = enter block graph
  S = step over
  : = execute normal radare2 commands
  :> px 4@bp+0x8 = find out ebp + 8 > print out 4 bytes of memory address
```

### View Mode

#### Common Commands

```console
$ r2 <FILE>           // load a binary
$ r2 -A <FILE>        // analysis
$ r2 -d <FILE>        // run a binary
$ r2 -w <FILE>        // write to a binary (patching)
$ r2 -B 0x0 <FILE>    // set base address to 0x0
```

```console
[0x004006e0]> ?           // help
[0x004006e0]> i?          // list info commands
[0x004006e0]> ? 0x16+6    // quick calculation
[0x004006e0]> ob 0x0      // set base address
[0x004006e0]> q           // quit
```

#### Basic Controls

```console
;     // command chaining
|     // pipe with shell commands
~     // grep
..    // repeats last commands
$$    // current position
@     // absolute offsets
@@    // used for iterations
```

```console
[0x004006e0]> wx ff @@10 20 30        // write ff at offsets 10, 20 and 30
[0x004006e0]> wx ff @@`?s  1 10 2`    // write ff at offsets 1, 2 and 3
[0x004006e0]> wx 90 @@ sym.*          // write a nop on every symbol
```

#### Analysis & Navigation

```console
[0x004006e0]> aaa                   // analyze the binary
[0x004006e0]> afl                   // list all functions
[0x004006e0]> afl | grep -i net     // search for functions by keyword
[0x004006e0]> afl | grep -i sock
[0x004006e0]> afl | grep -i recv
[0x004006e0]> afl | grep -i main
[0x004006e0]> axt                   // list cross references
```

#### Positioning

```console
[0x004006e0]> s <address|symbol>    // move cursor
  s-5                               // 5 bytes backwards
  s-                                // undo seek
  s+                                // redo seek
[0x004006e0]> s main                // seek to main
[0x004006e0]> s 0x00400968          // seek to specific address
[0x004006e0]> s hit0_0              // seek to cross-reference
```

#### Disassembly & Views

```console
[0x004006e0]> pdf               // print disassembly of function
[0x004006e0]> pdf@main          // disassemble main
[0x004006e0]> pdf@<FUNCTION>    // disassemble specific function
[0x004006e0]> pd 2@$$           // print 2 instructions at current position
[0x004006e0]> px 5@[ebp+0x8]    // dump 5 bytes from memory at ebp+0x8
```

#### Strings & Data

```console
[0x004006e0]> iz              // list strings in data sections
[0x004006e0]> izz             // list all strings in binary
[0x004006e0]> iz~<STRING>     // search for specific string
[0x004006e0]> / <STRING>      // search for specific string
[0x004006e0]> / 0x000904c4    // search for references to a string address
```

#### Seraching & ROP

```console
[0x004006e0]> /x c4049000     // search for raw bytes (little endian)
[0x004006e0]> /x 58c3         // search for "pop eax; ret"
[0x004006e0]> /x c3           // search for all rets
[0x004006e0]> /R              // search for ROP gadgets
[0x004006e0]> "/R pop eax"    // search for specific gadget
[0x004006e0]> "/R ret"        // search for rets
[0x004006e0]> "/R add esp"    // search for stack pivot gadgets
```

#### Patching

```console
[0x004006e0]> wx 9090                 // write NOPs (hex)
[0x004006e0]> wa nop                  // assemble to NOP
[0x004006e0]> wao nop                 // overwrite with NOP
[0x004006e0]> CC <COMMENT> @0xADDR    // add/remove comment
```

### Disassembling Workflow

```console
$ r2 <FILE>
```

```console
[0x004006e0]> aaa                     // analyse the binary
[0x004006e0]> i                       // show information about the binary
[0x004006e0]> iA                      // take a look at the architecture
[0x004006e0]> ii                      // show imported libraries
[0x004006e0]> i~canary                // use grep-similar function to search within the output of the i command
[0x004006e0]> i~stripped              // check if the binary is stripped
[0x004006e0]> iz                      // shows strings in data section (when the application is running)
[0x004006e0]> afl                     // analyze function list
[0x004006e0]> s sym.main              // jump to main (alternatively: s main)
[0x004006e0]> s sym.authenticate      // jump to authenticate function
[0x004006e0]> pdf                     // show opcode disassemble function (alternatively: pdf @sym.authenticate)
[0x004006e0]> s sym.check_username    // jump to username check
[0x004006e0]> ? 0x6262616a            // calculate the value 0x6262616a
```

### Examples

#### Cross References

```console
$ r2 <FILE>
```

```console
[0x004006e0]> aaa
[0x004006e0]> iz
[0x004006e0]> iz~sername        // ignores lower or capital letters
[0x004006e0]> axt 0x0804955d    // search for cross reference in memory address
```

or

```console
[0x004006e0]> s 0x0804955d    // jump to memory address
[0x004006e0]> pd 10$$         // disassemble and print 10 lines from here (alternatively: pd 10@0x0804955d)
```

#### Runtime Debugging

```console
$ r2 -d <FILE>
```

```console
[0x004006e0]> aaa
[0x004006e0]> afl
[0x004006e0]> axt sym.secret
[0x004006e0]> db sym.check_username    // set breakpoint
[0x004006e0]> dc                       // start program
[0x004006e0]> V                        // enter visual mode as alternative
S                                      // step over
:                                      // execute normal radare2 commands
:> px 4@bp+0x8                         // find out ebp + 8 > print out 4 bytes of memory address
```

##### Runtime Example

```console
$ r2 -d -A <FILE>                 // -d run, -A analysis
[0x080491ab]> s main; pdf         // disassemble main, pdf = Print Disassembly Function
[0x080491ab]> db 0x080491bb       // db = debug breakpoint
[0x080491ab]> dc                  // dc = debug continue
[0x08049172]> pxw @ esp           // analyze top of the stack
[0x08049172]> ds                  // ds = debug step
[0x080491aa]> pxw @ 0xff984aec    // read a specific value
[0x41414141]> dr eip              // dr = debug register
```

#### Patching

##### Binary Analysis

```console
$ r2 -d <FILE>
```

```console
[0x004006e0]> aaa
[0x004006e0]> pdf @sym.check_username
[0x004006e0]> db 0x08048c2a
[0x004006e0]> dc
[0x004006e0]> V
p                                        // enter debug view
pd 2@$$                                  // print current code position
wao nop                                  // overwrite with nops
pd 4@$$                                  // verify how many nops are required
S                                        // step over
V                                        // enter block graph
:> px 5@[ebp+0x8]                        // print 5 bytes out of memory of ebp+0x8
q
```

##### Patching Process

```console
$ r2 -w <FILE>
```

```console
[0x004006e0]> aaa
[0x004006e0]> pdf @sym.check_username
[0x004006e0]> s 0x08048c2a
[0x004006e0]> pd 4@$$
[0x004006e0]> wao nop
[0x004006e0]> pd 4@$$
[0x004006e0]> q
```

## strings

```console
$ strings <FILE>
$ strings -o <FILE>
$ strings -n 1 <FILE>
```

### Printing Memory Location

```console
$ strings -a -t x /lib/i386-linux-gnu/libc.so.6
```

## upx

```console
$ upx -d <FILE>
```
