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

```console
$ sudo apt-get install automake libtool make gcc pkg-config
```

```console
$ sudo apt-get install flex bison
```

```console
$ ./bootstrap.sh
```

```console
$ ./configure
```

```console
$ make
```

```console
$ sudo make install
```

```console
$ make check
```

```console
$ ./configure --enable-magic
```

```console
$ yara /PATH/TO/yarGen/yarGen-0.23.4/yargen_rules.yar /PATH/TO/BINARY/<BINARY> -s <BINARY> /PATH/TO/BINARY/<BINARY>
```

## yarGen

> https://github.com/Neo23x0/yarGen

```console
$ mkdir yarGen
```

```console
$ cd yarGen/
```

```console
$ wget https://github.com/Neo23x0/yarGen/archive/refs/tags/0.23.4.zip
```

```console
$ unzip 0.23.4.zip
```

```console
$ cd yarGen-0.23.4/
```

```console
$ python3 -m venv venv
```

```console
$ source venv/bin/activate
```

```console
$ pip install -r requirements.txt
```

```console
$ python3 yarGen.py --update
```

```console
$ mkdir sample
```

```console
$ cp rusty-recon-bot sample/
```

```console
$ python3 yarGen.py -a "<AUTHOR>" -r "<NAME>" -m sample/
```
