# Wordlists

- [Resources](#resources)

## Table of Contents

- [Bash](#bash)
- [CeWL](#cewl)
- [CUPP](#cupp)
- [crunch](#crunch)
- [JavaScript Quick Wordlist](#javascript-quick-wordlist)
- [Mutate Wordlists](#mutate-wordlists)
- [Username Anarchy](#username-anarchy)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| bopscrk | Tool to generate smart and powerful wordlists | https://github.com/r3nt0n/bopscrk |
| CeWL | CeWL is a Custom Word List Generator. | https://github.com/digininja/cewl |
| clem9669/wordlists | Various wordlists FR & EN - Cracking French passwords | https://github.com/clem9669/wordlists |
| COOK | An overpower wordlist generator, splitter, merger, finder, saver, create words permutation and combinations, apply different encoding/decoding and everything you need. | https://github.com/glitchedgitz/cook |
| CUPP | Common User Passwords Profiler (CUPP) | https://github.com/Mebus/cupp |
| Kerberos Username Enumeration | Collection of username lists for enumerating kerberos domain users | https://github.com/attackdebris/kerberos_enum_userlists |
| maskprocessor | High-Performance word generator with a per-position configureable charset | https://github.com/hashcat/maskprocessor |
| pseudohash | Password list generator that focuses on keywords mutated by commonly used password creation patterns | https://github.com/t3l3machus/psudohash |
| SecLists | A collection of multiple types of lists used during security assessments, collected in one place. | https://github.com/danielmiessler/SecLists |
| Username Anarchy | Username tools for penetration testing | https://github.com/urbanadventurer/username-anarchy |

## Bash

### Add Numbers to Password Segment

```c
$ for i in {1..100}; do printf "Password@%d\n" $i >> <FILE>; done
```

## CeWL

> https://github.com/digininja/cewl

```c
$ cewl -d 0 -m 5 -w <FILE> http://<RHOST>/index.php --lowercase
$ cewl -d 5 -m 3 -w <FILE> http://<RHOST>/index.php --with-numbers
```

## CUPP

> https://github.com/Mebus/cupp

```c
$ ./cupp -i
```

## crunch

```c
$ crunch 6 6 -t foobar%%% > wordlist
$ crunch 5 5 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ -o <FILE>.txt
```

## JavaScript Quick Wordlist

> https://twitter.com/renniepak/status/1780916964925345916

```js
javascript:(function(){const e=document.documentElement.innerText.match(/[a-zA-Z_\-]+/g),n=[...new Set(e)].sort();document.open(),document.write(n.join("<br>")),document.close();})();
```

## Mutate Wordlists

### Remove all Number Sequences

```c
$ head /usr/share/wordlists/rockyou.txt > <FILE>.txt
$ sed -i '/^1/d' <FILE>.txt
```

## Username Anarchy

> https://github.com/urbanadventurer/username-anarchy

```c
$ ruby username-anarchy -f first,first.last,last,flast -i <FILE> > <FILE>
```
