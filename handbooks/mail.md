# Mail

- [Resources](#resources)

## Table of Contents

- [IMAP](#imap)
- [msg](#msg)
- [Outlook](#outlook)
- [POP3](#pop3)
- [sendemail](#sendemail)
- [swaks](#swaks)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| MailHog | Web and API based SMTP testing | https://github.com/mailhog/MailHog |
| Swaks | Swiss Army Knife for SMTP | https://github.com/jetmore/swaks |

## msg

### Converting .msg-Files to .eml-Files

```console
$ sudo apt-get install libemail-outlook-message-perl libemail-sender-perl
$ msgconvert *.msg
```

## Outlook

### Staring Outlook without a profile

```console
Ctrl + r
outlook.exe /PIM NoEmail
Enter
```

## POP3

```console
USER <USERNAME>
PASS <PASSWORD>
STAT
LIST
RETR <NUMBER>
```

## sendemail

```console
$ sendemail -f '<USERNAME>@<DOMAIN>' -t '<USERNAME>@<DOMAIN>' -u 'Invoice Attached' -m 'You are overdue payment' -a 'invoice.rtf' -s <RHOST> -v
```

## swaks

> https://jetmore.org/john/code/swaks/

> https://github.com/jetmore/swaks

### Basic Commands

```console
$ swaks --server <RHOST> -t <EMAIL> -t <EMAIL> --from <EMAIL> --header "Subject: <SUBJECT>" --body <FILE>.txt --attach @<FILE> --suppress-data -ap
$ swaks --server <RHOST> --port 587 --auth-user "<EMAIL>" --auth-password "<PASSWORD>" --to "<EMAIL>" --from "<EMAIL>" --header "Subject: <SUBJECT>" --body "\\\<LHOST>\"
```

### Automation

```console
$ while read mail; do swaks --to $mail --from <EMAIL> --header "Subject: Test / Test" --body "goto http://<LHOST>/" --server <RHOST>; done < mail.txt
```