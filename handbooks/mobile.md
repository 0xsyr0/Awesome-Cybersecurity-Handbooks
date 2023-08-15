# Mobile

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/mobile.md#Resource)

## Table of Contents

- [Apktool](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/mobile.md#Apktool)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| android-penetration-testing-cheat-sheet | Checklist for Android Penetration Testing | https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet |
| APKLeaks | Scanning APK file for URIs, endpoints & secrets. | https://github.com/dwisiswant0/apkleaks |
| Apktool | A tool for reverse engineering Android apk files | https://github.com/iBotPeaches/Apktool |
| apk.sh | apk.sh makes reverse engineering Android apps easier, automating some repetitive tasks like pulling, decoding, rebuilding and patching an APK. | https://github.com/ax/apk.sh |
| Awesome iOS Security | A curated list of awesome iOS application security resources. | https://github.com/Cy-clon3/awesome-ios-security |
| dex2jar | Tools to work with android .dex and java .class files | https://github.com/pxb1988/dex2jar |
| medusa | Binary instrumentation framework based on FRIDA | https://github.com/Ch0pin/medusa |
| Mobile Application Penetration Testing Cheat Sheet | The Mobile App Pentest cheat sheet was created to provide concise collection of high value information on specific mobile application penetration testing topics. | https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet |
| Mobile Security Framework (MobSF) | Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis. | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| Mobile Verification Toolkit | MVT (Mobile Verification Toolkit) helps with conducting forensics of mobile devices in order to find signs of a potential compromise. | https://github.com/mvt-project/mvt |
| OWASP Mobile Application Security Testing Guide (MASTG) | The Mobile Application Security Testing Guide (MASTG) is a comprehensive manual for mobile app security testing and reverse engineering. It describes the technical processes for verifying the controls listed in the OWASP Mobile Application Security Verification Standard (MASVS). | https://github.com/OWASP/owasp-mastg |
| PhoneSploit Pro | An all-in-one hacking tool to remotely exploit Android devices using ADB and Metasploit-Framework to get a Meterpreter session. | https://github.com/AzeemIdrisi/PhoneSploit-Pro |
| QuadraInspect | QuadraInspect is an Android framework that integrates AndroPass, APKUtil, and MobFS, providing a powerful tool for analyzing the security of Android applications. | https://github.com/morpheuslord/QuadraInspect |

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
