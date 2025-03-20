# Simulation & Emulation

- [Resources](#resources)

## Table of Contents

- [Atomic Red Team](#atomic-red-team)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| APT Simulator | A toolset to make a system look as if it was the victim of an APT attack | https://github.com/NextronSystems/APTSimulator |
| Atomic Red Team | Small and highly portable detection tests based on MITRE's ATT&CK. | https://github.com/redcanaryco/atomic-red-team |
| atomicgen.io | A simple tool designed to create Atomic Red Team tests with ease. | https://github.com/krdmnbrk/atomicgen.io |
| Automated Emulation | An automated Breach and Attack Simulation lab with terraform. Built for IaC stability, consistency, and speed. | https://github.com/iknowjason/AutomatedEmulation |
| beacon-fronting | A simple command line program to help defender test their detections for network beacon patterns and domain fronting | https://github.com/BinaryDefense/beacon-fronting |
| GHOSTS | GHOSTS is a realistic user simulation framework for cyber experimentation, simulation, training, and exercise | https://github.com/cmu-sei/GHOSTS |
| Invoke-AtomicRedTeam | Invoke-AtomicRedTeam is a PowerShell module to execute tests as defined in the Red Canary's Atomic Red Team project. | https://github.com/redcanaryco/invoke-atomicredteam |
| OpenBAS | Open Breach and Attack Simulation Platform | https://github.com/OpenBAS-Platform/openbas |
| PSRansom | PowerShell Ransomware Simulator with C2 Server | https://github.com/JoelGMSec/PSRansom |
| PurpleSharp | PurpleSharp is a C# adversary simulation tool that executes adversary techniques with the purpose of generating attack telemetry in monitored Windows environments | https://github.com/mvelazc0/PurpleSharp |
| QuickBuck - Ransomware Simulator | Ransomware simulator written in Golang | https://github.com/NextronSystems/ransomware-simulator |
| Ransomware Simulator | Ransomware simulator written in Golang | https://github.com/NextronSystems/ransomware-simulator |
| Splunk Attack Range | A tool that allows you to create vulnerable instrumented local or cloud environments to simulate attacks against and collect the data into Splunk | https://github.com/splunk/attack_range |
| Stratus Red Team | ☁️ ⚡ Granular, Actionable Adversary Emulation for the Cloud | https://github.com/DataDog/stratus-red-team |
| SysmonSimulator | Sysmon event simulation utility which can be used to simulate the attacks to generate the Sysmon Event logs for testing the EDR detections and correlation rules by Blue teams. | https://github.com/ScarredMonk/SysmonSimulator |
| MITRE Caldera™ | Automated Adversary Emulation Platform | https://github.com/mitre/caldera |
| VECTR | VECTR is a tool that facilitates tracking of your red and blue team testing activities to measure detection and prevention capabilities across different attack scenarios | https://github.com/SecurityRiskAdvisors/VECTR |

## Atomic Red Team

> https://github.com/redcanaryco/atomic-red-team

> https://github.com/redcanaryco/invoke-atomicredteam

### Invoke-AtomicRedTeam

```cmd
PC C:\> PowerShell -ExecutionPolicy bypass
PC C:\> Import-Module "C:\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
PC C:\> $PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="C:\AtomicRedTeam\atomics"}
PC C:\> help Invoke-AtomicTest
PC C:\> Invoke-AtomicTest T1127 -ShowDetailsBrief
PC C:\> Invoke-AtomicTest T1127 -ShowDetails
PC C:\> Invoke-AtomicTest T1127 -CheckPrereqs
PC C:\> Invoke-AtomicTest T1127 -GetPrereqs
PC C:\> Invoke-AtomicTest T1053.005 -ShowDetailsBrief
PC C:\> Invoke-AtomicTest T1053.005 -TestNumbers 1,2
PC C:\> schtasks /tn T1053_005_OnLogon
```

### Emulation

```cmd
PC C:\> ls C:\AtomicRedTeam\atomics | Where-Object Name -Match "T1566.001|T1203|T1059.003|T1083|T1082|T1016|T1049|T1007|T1087.001"
PC C:\> 'T1566.001','T1059.003','T1083','T1082','T1016','T1049','T1007','T1087.001' | ForEach-Object {echo "Enumerating $_"; Invoke-AtomicTest $_ -ShowDetailsBrief }
PC C:\> 'T1566.001','T1059.003','T1083','T1082','T1016','T1049','T1007','T1087.001' | ForEach-Object {echo "Enumerating $_"; Invoke-AtomicTest $_ -CheckPrereqs }
PC C:\> Invoke-AtomicTest T1059.003-3
```

### Emulation to Detection

```cmd
PC C:\> Invoke-AtomicTest T1547.001 -CheckPrereqs
PC C:\> Invoke-AtomicTest T1547.001 -TestNumbers 2
```

### Customising

```cmd
PC C:\> cat T1136.001/T1136.001.yaml
PC C:\> Invoke-AtomicTest T1136.001 -TestNumbers 3
PC C:\> net user
PC C:\> Invoke-AtomicTest T1136.001 -TestNumbers 3 -PromptForInputArgs
PC C:\> net user
PC C:\> Invoke-AtomicTest T1136.001 -TestNumbers 3 -PromptForInputArgs -Cleanup
```

### Creating new Atomic Tests by using the GUI

```cmd
PC C:\> Start-AtomicGui
```

> http://localhost:8487/home
