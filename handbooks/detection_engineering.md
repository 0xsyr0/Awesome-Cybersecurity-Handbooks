# Detection Engineering

- [Resources](#resources)

## Table of Contents

- [YARA](#yara)
- [yarGen](#yargen)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Detection Studio | Convert Sigma rules to SIEM queries, directly in your browser. | https://github.com/northsh/detection.studio |
| Laurel | Transform Linux Audit logs for SIEM usage | https://github.com/threathunters-io/laurel |
| SIGMA | Generic Signature Format for SIEM Systems | https://github.com/SigmaHQ/sigma |
| sysmon-config | Sysmon configuration file template with default high-quality event tracing | https://github.com/SwiftOnSecurity/sysmon-config |
| Unvoder IO | Detection Engineering IDE | https://uncoder.io |
| YARA | The pattern matching swiss knife | https://github.com/VirusTotal/yara |
| yarGen | yarGen is a generator for YARA rules | https://github.com/Neo23x0/yarGen |

## YARA

### Installation

> https://yara.readthedocs.io/en/stable/gettingstarted.html

> https://github.com/VirusTotal/yara/releases

```c
$ sudo apt-get install automake libtool make gcc pkg-config
```

```c
$ sudo apt-get install flex bison
```

```c
$ ./bootstrap.sh
```

```c
$ ./configure
```

```c
$ make
```

```c
$ sudo make install
```

```c
$ make check
```

```c
$ ./configure --enable-magic
```

```c
$ yara /PATH/TO/yarGen/yarGen-0.23.4/yargen_rules.yar /PATH/TO/BINARY/<BINARY> -s <BINARY> /PATH/TO/BINARY/<BINARY>
```

## yarGen

> https://github.com/Neo23x0/yarGen

```c
$ mkdir yarGen
```

```c
$ cd yarGen/
```

```c
$ wget https://github.com/Neo23x0/yarGen/archive/refs/tags/0.23.4.zip
```

```c
$ unzip 0.23.4.zip
```

```c
$ cd yarGen-0.23.4/
```

```c
$ python3 -m venv venv
```

```c
$ source venv/bin/activate
```

```c
$ pip3 install -r requirements.txt
```

```c
$ python3 yarGen.py --update
```

```c
$ mkdir sample
```

```c
$ cp rusty-recon-bot sample/
```

```c
$ python3 yarGen.py -a "<AUTHOR>" -r "<NAME>" -m sample/
```
