# Social Engineering Tools

| Name | Description | URL |
| --- | --- | --- |
| The Social-Engineer Toolkit (SET) | The Social-Engineer Toolkit is an open-source penetration testing framework designed for social engineering. | https://github.com/trustedsec/social-engineer-toolkit |
| Gophish | Open-Source Phishing Toolkit | https://github.com/gophish/gophish |
| BlackPhish | Super lightweight with many features and blazing fast speeds. | https://github.com/iinc0gnit0/BlackPhish |
| SocialFish | Phishing Tool & Information Collector  | https://github.com/UndeadSec/SocialFish |
| Nexphisher | Advanced Phishing tool for Linux & Termux | https://github.com/htr-tech/nexphisher |
| evilginx2 | Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication | https://github.com/kgretzky/evilginx2 |
| evilgophish | evilginx2 + gophish | https://github.com/fin3ss3g0d/evilgophish |

## Gophish

> https://github.com/sdcampbell/Internal-Pentest-Playbook

> https://www.ired.team/offensive-security/initial-access/phishing-with-gophish-and-digitalocean

### Port Forwarding

```c
$ ssh -i ~/.ssh/<SSH_KEY> root@<RHOST> -p <RPORT> -L3333:localhost:3333 -N -f
```

## Metasploit

### NTLMv1 Hashes

```c
msf6 > use auxiliary/server/capture/smb
msf6 auxiliary(server/capture/smb) > run
```
