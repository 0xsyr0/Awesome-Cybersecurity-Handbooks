# CONTRIBUTE.md

Thank you for your interest in making this repository better and to keeping it up to date!
This notes should give you a guideline on how to contribute to the project.

## Table of Contents

- [Resources](#resources)
- [Styleguides](#styleguides)
    - [Hot to make a bug report](#how-to-make-a-bug-report)
    - [How to fix a bug](#how-to-fix-a-bug)
    - [Coding conventions and style guide](#coding-conventions-and-style-guide)

## Resources

Please only contribute techniques and applications related to the already existing handbooks.

- [Awesome Cybersecurity Handbooks](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks)

Furthermore, self-promotion is not allowed or accepted and please only add external resources if they are written in English.

## Styleguides

### How to make a bug report

If you want to submit a bug like for example a typo please use the following structure.

- Description: Add a short description.
- Environment: Which handbook and tool is affected.
- Command: The command which was used.
- Error message: Output or screenshot which shows the issue. Ideally in Markdown.
- Labels: Typo/Bug/Outdated/Improvement

### How to fix a bug

For fixing a bug I highly recommend forking the repository and creating a pull request (PR) with the detailed description mentioned in the section above.
Please notice that your commits need to be signed in ordert to merch your PR.

### Coding conventions and style guide

When it comes to contribution in terms of techniques or applications please use the following example as baseline in your PR.

```c
## MAIN SECTION LIKE POST EXPLOITATION

### SUB-SECTION

> URL (ONLY IF ABSOLUTELY NECESSARY)

COMMAND A
COMMAND B

#### PAYLOAD

COMMAND C
```

- For new tools stick to the Kali Linux menu structure.
- Keep spaces between sections and commands.
- Please use prompts like `$`, `C:\>` or `PS C:\>` to make it easy to follow along in which environment the command needs to be executed.
- Try to avoid unnecessary explanations.
- Keep values which needed to be replaced in capital letters.
- Enclose the values in `<>`
- Stick to the already available values like `LHOST`, `RHOST`, `LPORT`, `RPORT`, `DOMAIN`, `FILE`, `SHARE`, `URL` etc.
- If you use  for example payloads from other people, please mention them in your PR.
- Keep it as slim as possible

