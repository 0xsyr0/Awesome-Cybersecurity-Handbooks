# Reporting Tools

- [Resources](#resources)

## Table of Contents

- [Folder Structure on Operations Server](#folder-structure-on-operations-server)
- [Logging](#logging)
- [Markdown](#markdown)
- [Meetings](#meetings)
- [Obsidian](#obsidian)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Awesome Markdown | A collection of awesome markdown goodies (libraries, services, editors, tools, cheatsheets, etc.) | https://github.com/mundimark/awesome-markdown |
| Cervantes | Cervantes is an opensource collaborative platform for pentesters or red teams who want to save time to manage their projects, clients, vulnerabilities and reports in one place. | https://github.com/CervantesSec/cervantes |
| Ghostwriter | Ghostwriter is a Django-based web application designed to be used by an individual or a team of red team operators. | https://github.com/GhostManager/Ghostwriter |
| Obsidian | Obsidian is a powerful knowledge base on top of a local folder of plain text Markdown files. | https://obsidian.md |
| PwnDoc-ng | Pentest Report Generator  | https://github.com/pwndoc-ng/pwndoc-ng |
| SysReptor | Pentest Reporting Easy As Pie | https://github.com/Syslifters/sysreptor |
| WriteHat | A pentest reporting tool written in Python. Free yourself from Microsoft Word. | https://github.com/blacklanternsecurity/writehat |
| XMind | Full-featured mind mapping and brainstorming app. | https://www.xmind.net |

## Folder Structure on Operations Server

```c
assessment_name
├── 0-operations
├── 1-osint
├── 2-recon
├── 3-targets
│   ├── domain_name
│   │   └── exfil
│   └── ip_hostname
│       └── exfil
├── 4-screenshots
│   └── YYYYMMDD_HHMM_IP_description.png
├── 5-payloads
├── 6-loot
├── 7-logs
└── README.md
```

### Examples of Screenshots

- 20220801_1508_10.10.1.106_nmap_tcp445.png
- 20220801_1508_10.10.1.106_smb_enumeration.png
- 20220801_1508_10.10.1.106_smb_password_file.png

## Logging

### Basic Logging and Documentation Handling

* Screenshot everything!
* Note every attempt even it's a failure
* Create and update a report storyboard during the process

For adding `time and date` and the current `IP address`, add the required commands to either the `.bashrc` 
or to the `.zshrc`.

### Bash local IP address

```c
PS1="[`date  +"%Y-%m-%d %H:%M"`]\[\033[01;31m\] `ip a | grep -A 1 eth0 | grep inet | awk '{ print $2 }' | c
ut -d '/' -f 1`\[\033[00m\] \[\033[01;34m\]\w\[\033[00m\] \$ "
```

### Bash external IP address

```c
PS1='[`date  +"%Y-%m-%d %H:%M"`]\[\033[01;31m\] `curl -s ifconfig.co`\[\033[00m\] \[\033[01;34m\]\w\[\033[00m\] \$ '
```

### ZSH local IP address

```c
PS1="[20%D %T] %B%F{red}$(ip a | grep -A 1 eth0 | grep inet | awk '{ print $2 }' | cut -d '/' -f 1)%f%b %B%F{blue}%1~%f%b $ "
```

### ZSH external IP address

```c
PS1="[20%D %T] %B%F{red}$(curl -s ifconfig.co)%f%b %B%F{blue}%1~%f%b $ "
```

### PowerShell

For `PowerShell` paste it into the open terminal.

```c
$IPv4 = Test-Connection -ComputerName (hostname) -Count 1  | Select -ExpandProperty IPV4Address; function prompt{ "PS" + " [$(Get-Date)] $IPv4> $(get-location) " }
```

### Linux Logging Examples

#### Logging using tee

```c
command args | tee <FILE>.log
```

#### Append to an existing log file

```c
command args | tee -a <FILE>.log
```

#### All commands logging using script utility

```c
script <FILE>.log
```

#### Single command logging using script utility

```c
script -c 'command args' <FILE>.log
```

### Windows Logging Examples

```c
Get-ChildItem -Path D: -File -System -Recurse | Tee-Object -FilePath "C:\temp\<FILE>.txt" -Append | Out-File C:\temp\<FILE>.txt
```

### Metasploit spool command

```c
msf> spool <file>.log
```

## Markdown

### Basic Formatting

```c
* ```c
* ```bash
* ```python
* `<TEXT>`
```

### Table of Contents

```c
1. [Example](#Example)
2. [Example 2](#Example-2)
3. [ExampleLink](https://github.com/<USERNAME>/<REPOSITORY>/blob/master/<FOLDER>/<FILE>.md)

1. # Example
2. # Example 2 <a name="Example-2"></a>
2. # ExampleLink
```

### Tables

```c
| Example |
| --- |
| Value |
```

```c
| Example | Example 2
| --- | --- |
| Value | Value 2 |
```

### Pictures

```c
<p align="center">
  <img width="300" height="300" src="https://github.com/<USERNAME>/<REPOSITORY>/blob/main/<FOLDER>/<FILE>.png">
</p>
```

## Meetings

### Schedule

| | Monday | Tuesday | Wednesday | Thursday | Friday | Saturday | Sunday |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Start | Assessment Kickoff | | Sync | | Weekly Review | | |
| Weekly | Planning | | Sync | | Weekly Review | | |
| Closing | Planning | | Sync | | Closing / Assessment Review | | |

## Obsidian

### Useful plugins

* Admonition
* Advanced Tables
* Better Word Count
* Calendar
* File Explorer Note count
* Full Calendar
* Git
* Iconize
* Icons
* Kanban
* Paste URL into selection
* Table of Contents
* TagFolder
* Tag Wrangler
