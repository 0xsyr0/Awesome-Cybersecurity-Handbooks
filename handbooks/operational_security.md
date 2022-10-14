# Operational Security

## Table of Contents

- [Clear History](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#Clear-History)
- [ProxyChains](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/operational_security.md#ProxyChains)

## Clear History

```c
* echo "" > /var/log/auth.log
* echo "" > ~/.bash_history
* rm ~/.bash_history
* history -c
* export HISTFILESIZE=0
* export HISTSIZE=0
* kill -9 $$
* ln /dev/null ~/.bash_history -sf
* ln -sf /dev/null ~/.bash_history && history -c && exit
```

## ProxyChains

> https://github.com/haad/proxychains

```c
$ proxychains <APPLICATION>
```

### Configuration

```c
socks4 metasploit
socks5 ssh
```
