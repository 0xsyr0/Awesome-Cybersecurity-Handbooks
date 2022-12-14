# OSINT

## Table of Contents

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/osint.md#Resources)
- [Fast Google Dorks Scan](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/osint.md#Fast-Google-Dorks-Scan)
- [Google](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/osint.md#Google)
- [h8mail](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/osint.md#h8mail)
- [Photon](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/osint.md#Photon)
- [Social Analyzer](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/osint.md#Social-Analyzer)
- [theHarvester](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/osint.md#theHarvester)

## Resources

| Name | Description | URL |
| --- | --- | --- | 
| DeHashed | Breach Monitoring  | https://dehashed.com |
| DorkSearch | Faster Google Dorking | https://dorksearch.com |
| Exploit-DB - Google Hacking Database | Exploit Database Google Dorks | https://www.exploit-db.com/google-hacking-database |
| GHunt |  GHunt is a modulable OSINT tool designed to evolve over the years, and incorporates many techniques to investigate Google accounts, or objects. | https://github.com/mxrch/GHunt |
| GitFive | Track down GitHub users. | https://github.com/mxrch/GitFive |
| hunter | Hunter lets you find professional email addresses in seconds and connect with the people that matter for your business. | https://hunter.io |
| Intelligence X | OSINT Search Engine | https://intelx.io |
| linkedin2username | Generate username lists from companies on LinkedIn. | https://github.com/initstring/linkedin2username |
| NerdyData | Get a list of websites that use certain technologies, plus their company and spend data. | https://www.nerdydata.com |
| Osintgram | Osintgram is a OSINT tool on Instagram. It offers an interactive shell to perform analysis on Instagram account of any users by its nickname. | https://github.com/Datalux/Osintgram |
| OSINT Recon Tool | OSINT Mindmap Tool | https://recontool.org/#mindmap |
| osintui | Open Source Intelligence Terminal User Interface | https://github.com/wssheldon/osintui |
| Sherlock | Hunt down social media accounts by username across social networks. | https://github.com/sherlock-project/sherlock |
| tweets_analyzer | Tweets metadata scraper & activity analyzer | https://github.com/x0rz/tweets_analyzer |

## Fast Google Dorks Scan

> https://github.com/IvanGlinkin/Fast-Google-Dorks-Scan

```c
$ ./FGDS.sh <TARGET_DOMAIN>
$ proxychains bash ./FGDS.sh <TARGET_DOMAIN>
```

## Google

### Google Dorks

> https://cheatsheet.haax.fr/open-source-intelligence-osint/dorks/google_dorks/

> https://www.searchenginejournal.com/google-search-operators-commands/215331/

```c
intitle:index.of <TEXT>    // open directory listings
```

```c
ext:php
inurl:%3F
site:*.*.*.<domain>
filetype:txt
```

#### Example

```c
site:tesla.com ext:php
```

### Leaks

```c
site:http://jsfiddle.net "<DOMAIN>"
site:http://codebeautify.org "<DOMAIN>"
site:http://codepen.io "<DOMAIN>"
site:http://pastebin.com "<DOMAIN>"
```

#### Example

```c
site:http://jsfiddle.net | site:http://codebeautify.org | site:http://codepen.io | site:http://pastebin.com "<DOMAIN>"
site:http://jsfiddle.net | site:http://codebeautify.org | site:http://codepen.io | site:http://pastebin.com "<DOMAIN>" "demo" "test" "api"
```

### Abusing Google ID

> https://medium.com/week-in-osint/getting-a-grasp-on-googleids-77a8ab707e43

#### Setup

1. Add a new contact to you google account (email address required)
2. Open developer tools and select the network tab
3. Reload the page
4. Set the right pane to request
5. Check all batchexecute packets

##### Example

> https://contacts.google.com/_/ContactsUi/data/batchexecute?rpcids=OSOtuf&f.sid=-916332265175998083&bl=boq_contactsuiserver_20200707.13_p0&hl=en&soc-app=527&soc-platform=1&soc-device=1&_reqid=765234&rt=c

6. Watch out for a string like the following one

##### Example

```c
[[["OSOtuf","[\"55fa738b0a752dc5\",\"117395327982835488254\"]",null,"generic"]]]
```

The Google ID's are always `21` characters long and starting with `10` or `11`.

> https://get.google.com/albumarchive/<userID>

> https://www.google.com/maps/contrib/<userID>

## h8mail

> https://github.com/khast3x/h8mail

```c
$ h8mail -t <EMAIL>
```

## Photon

> https://github.com/s0md3v/Photon

```c
$ python3 photon.py -u https://<TARGET_URL> -l 3 -t 100 --wayback
```

## Social Analyzer

> https://github.com/qeeqbox/social-analyzer

```c
$ python3 app.py --cli --mode "fast" --username "<GIVENNAME> <SURNAME>" --websites "youtube facebook instagram" --output "pretty" --options "found,title,link,rate"
```

## theHarvester

> https://github.com/laramies/theHarvester

```c
$ theHarvester -d <TARGET_DOMAIN> -l 500 -b google -f myresults.html
```
