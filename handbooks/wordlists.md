# Wordlists

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/wordlists.md#Resources)

## Table of Contents

- [CeWL](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/wordlists.md#CeWL)
- [CUPP](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/wordlists.md#CUPP)
- [crunch](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/wordlists.md#crunch)

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
$ crunch 5 5 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ -o <FILE>.txt
```
