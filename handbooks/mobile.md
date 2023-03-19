# Mobile

## Table of Contents

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/mobile.md#Resource)
- [Apktool](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/mobile.md#Apktool)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| APKLeak | Scanning APK file for URIs, endpoints & secrets. | https://github.com/dwisiswant0/apkleaks |
| PhoneSploit Pro | An All-In-One hacking tool to remotely exploit Android devices using ADB and Metasploit-Framework to get a Meterpreter session. | https://github.com/AzeemIdrisi/PhoneSploit-Pro |

## Apktool

> https://github.com/iBotPeaches/Apktool

> https://medium.com/@sandeepcirusanagunla/decompile-and-recompile-an-android-apk-using-apktool-3d84c2055a82

### Decompiling

```c
$ apktool d <FILE>.apk
$ apktool d -f -r <FILE>.apk
```

### Compiling

```c
$ apktool b <SOURCE_FOLDER>
```

### Compiling and Signing

```c
$ java -jar apktool_2.6.1.jar b -f -d /PATH/TO/FOLDER/ -o <FILE>.apk
$ keytool -genkey -v -keystore my-release-key.keystore -alias <ALIAS> -keyalg RSA -keysize 2048 -validity 10000
$ jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore <FILE>.apk <ALIAS>
$ jarsigner -verify -verbose -certs <FILE>.apk
```
