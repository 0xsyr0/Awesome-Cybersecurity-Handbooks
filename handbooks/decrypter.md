# Decrypter

- [Resources](#resources)

## Table of Contents

- [openfire_decrypt](#openfire_decrypt)
- [splunksecrets](#splunksecrets)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Decrypt mRemoteNG passwords | Decrypt mRemoteNG passwords | https://github.com/gquere/mRemoteNG_password_decrypt |
| dpyAesDecrypt | dAescrypt.py is a multithreaded brute-force tool to crack .aes files encrypted using the pyAesCrypt library. It supports password length filtering, progress display with ETA, and optional decryption after cracking. | https://github.com/Nabeelcn25/dpyAesCrypt.py |
| firefox_decrypt | Firefox Decrypt is a tool to extract passwords from Mozilla (Firefox™, Waterfox™, Thunderbird®, SeaMonkey®) profiles | https://github.com/unode/firefox_decrypt |
| gpp-decrypt | Tool to parse the Group Policy Preferences XML file which extracts the username and decrypts the cpassword attribute. | https://github.com/t0thkr1s/gpp-decrypt |
| Jenkins Credentials Decryptor | Command line tool for dumping Jenkins credentials. | https://github.com/hoto/jenkins-credentials-decryptor |
| jenkins-decryptor | Recover encrypted Jenkins secrets | https://github.com/dadevel/jenkins-decryptor |
| mRemoteNG-Decrypt | Python script to decrypt passwords stored by mRemoteNG | https://github.com/haseebT/mRemoteNG-Decrypt |
| nodered_decrypt.py | Decrypt Node-RED Credentials | https://gist.github.com/Yeeb1/fe9adcd39306e3ced6bdfc7758a43519 |
| openfire_decrypt | Little java tool to decrypt passwords from Openfire embedded-db | https://github.com/c0rdis/openfire_decrypt |
| PMP-Decrypter | This is a tool to decrypt the encrypted password strings in Patch My PC settings.xml files. | https://github.com/LuemmelSec/PMP-Decrypter |
| pswm-decoder | a simple decoder for https://github.com/Julynx/pswm | https://github.com/repo4Chu/pswm-decoder |
| Roundcube | PHP script to decrypt Roundcube IMAP passwords that were encrypted with the des_key defined in the configuration. | https://github.com/TaddlM/roundcube |
| SharpLansweeperDecrypt | Automatically extract and decrypt all configured scanning credentials of a Lansweeper instance. | https://github.com/Yeeb1/SharpLansweeperDecrypt |
| SolarPuttyDecrypt | A post-exploitation tool to decrypt SolarPutty's sessions files | https://github.com/VoidSec/SolarPuttyDecrypt |
| splunksecrets | splunksecrets is a tool for working with Splunk secrets offline | https://github.com/HurricaneLabs/splunksecrets |

## openfire_decrypt

> https://github.com/c0rdis/openfire_decrypt

```console
$ javac OpenFireDecryptPass.java
```

```console
$ java OpenFireDecryptPass 08f62fb6091259a2be869ae0ace90f600ec3729a9d5d4683 UaNTQtUV6S7kwm9
```

## splunksecrets

### splunk.secret

```console
pMfObv4r7t09OLdUkYoNqal0IUST4SRsvehOpf0BDaAUXZT7AhNnz3T6pSpo9uYzbqDuXahUllXO7PEeFNg6s9QumAlUZxnbFDhZGN63qjuZbTw1sthPCLAfXb1GIDKNM2pyiL8scN0XJkLVC32w2GEervDNGjlm9XB2bAdp7D2HmYYFAzVHJTzeZ0uiYbzUU93LA24BdAZh6tk7RfVmpkA508Gip026vm2iCCVZoeqz0Uwmd3c4WGPpodQELU
```

### Execution

```console
$ splunksecrets splunk-decrypt -S splunk.secret
Ciphertext: $7$lPCemQk01ejJvI8nwCjXjx7PJclrQJ+SfC3/ST+K0s+1LsdlNuXwlA==
```
