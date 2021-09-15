## 版本

v1.2.0

## 要求

OS：`centos 7.9 x64`

CPU：`2C及以上`

MEM：`4G及以上`

认证：集群节点需**统一认证**；使用密码认证时，集群节点需使用同一用户名和密码。

运行：在预设的master节点执行

## 功能

- 支持升级集群内核，升级后内核版本为：5.13.2
- 支持离线部署普通的k8s集群，k8s版本为：v1.21.3
- 支持离线部署高可用k8s集群，k8s版本为：v1.21.3
- K8S HA集群使用云原生的kube-vip，其自带VIP和负载均衡
- K8S集群默认安装图形化管理工具kuboard，kuboard版本为：v2
- K8S集群默认安装nfs和localpath存储类
- K8S证书100年，且开启了自动轮询

## 快速开始

```shell
wget https://github.com/kongyu666/kubeeasy/releases/download/v1.2.0/kubeeasy-centos7.9-v1.2.0
chmod +x kubeeasy-centos7.9-v1.2.0 && mv kubeeasy-centos7.9-v1.2.0 /usr/bin/kubeeasy
kubeeasy install kubernetes \
  --master 10.24.2.10 \
  --worker 10.24.2.11 \
  --user root \
  --password 000000 \
  --version 1.21.3
```

## 集群模式选择

 以下提供了两种K8S集群方案，根据实际情况选择一种方案即可。

 高可用集群模式主机列表

| **IP** **地址** | **主机名**        | **角色**                              |
| :-------------- | ----------------- | ------------------------------------- |
| 10.24.3.21      | k8s-maste-noder01 | master \| etcd \|  worker \| kube-vip |
| 10.24.3.22      | k8s-master-node02 | master \| etcd \|  worker \| kube-vip |
| 10.24.3.23      | k8s-master-node03 | master \| etcd \|  worker \| kube-vip |
| 10.24.3.24      | k8s-worker-node1  | worker                                |
| 10.24.3.25      | k8s-worker-node3  | worker                                |
| 10.24.3.20      | /                 | 虚拟 IP 地址                          |

 普通集群模式主机列表

| **IP** **地址** | **主机名**        | **角色**                  |
| --------------- | ----------------- | ------------------------- |
| 10.24.3.11      | k8s-maste-noder01 | master \| etcd \|  worker |
| 10.24.3.12      | k8s-worker-node1  | worker                    |
| 10.24.3.13      | k8s-worker-node2  | worker                    |

 安装方式分为[在线版](#_在线安装方式)和[离线版](#_离线安装方式)（在线版安装速度快，离线版安装稳定），任选一种部署。

还有其他小功能，在[其他功能](#_其他功能)里面可以查看。

## 在线安装方式

**注意**确保有正常可用的yum源

### 1.1 安装kubeeasy

将kubeeasy文件上传至预设的master节点/root目录，赋予执行权限并移动到/usr/bin目录下。

```shell
wget https://github.com/kongyu666/kubeeasy/releases/download/v1.2.0/kubeeasy-centos7.9-v1.2.0
chmod +x kubeeasy-centos7.9-v1.2.0 && mv kubeeasy-centos7.9-v1.2.0 /usr/bin/kubeeasy 
```

### 1.2 基础ssh配置

使用kubeeasy在集群中创建ssh免秘钥，其中优化的ssh的连接以及配置了集群的免秘钥登录等。

1. 集群连通性检测-ssh

```shell
kubeeasy check ssh \
 --host 10.24.3.11-10.24.3.13 \
 --user root \
 --password 000000
```

2. 集群免秘钥设置


```shell
kubeeasy create ssh-keygen \
 --master 10.24.3.11 \
 --worker 10.24.3.12,10.24.3.13 \
 --user root \
 --password 000000
```


### 1.3 磁盘挂载

使用kubeeasy在集群中挂载数据盘，将其挂载到/data目录，后续的数据存储路径默认都是在/data目录下。（如果没有磁盘可以忽略此操作）

1. 磁盘挂载（集群磁盘名相同时）

```shell
kubeeasy create mount-disk \
 --host 10.24.3.11-10.24.3.13 \
 --disk sdb \
 --mount-dir /data/ \
 --user root \
 --password 000000
```

2. 磁盘挂载（集群磁盘名不同时只能一台一台操作）

```shell
kubeeasy mount \
 --host 10.24.3.11 \
 --disk sdb \
 --user root \
 --password 000000
```


### 1.4 集群升级系统内核

使用kubeeasy升级集群的内核，将其3.x的内核升级为5.x。（建议升级内核）脚本执行完后，会自动重启主机，以生效系统内核。

1. 升级集群内核为5.x

```shell
kubeeasy install upgrade-kernel \
 --master 10.24.3.11 \
 --worker 10.24.3.12,10.24.3.13 \
 --user root \
 --password 000000
```


### 1.5 部署K8S集群

使用kubeeasy部署K8S集群，以下分为【普通集群】和【高可用集群】的安装方式，根据实际情况选择一种方案部署。安装后的K8S的版本为v1.21.3，使用docker作为容器运行时，网络组件使用calico网络，默认还安装kuboard图形化管理器和K8S存储类（nfs和local-path），K8S的证书有效期为100年，且开启了证书轮换。

如需更改K8S的Pod网段，修改--pod-cidr参数相应的值。

1. 安装k8s集群

```shell
kubeeasy install kubernetes \
 --master 10.24.3.11 \
 --worker 10.24.3.12,10.24.3.13 \
 --user root \
 --password 000000 \
 --version 1.21.3 \
 --pod-cidr 10.244.0.0/16
```

2. 安装高可用k8s集群（master节点个数必须大于等于3）

```shell
kubeeasy install kubernetes \
 --master 10.24.3.21,10.24.3.22,10.24.3.23 \
 --worker 10.24.3.24,10.24.3.25 \
 --user root \
 --password 000000 \
 --version 1.21.3 \
 --virtual-ip 10.24.3.20 \
 --pod-cidr 10.244.0.0/16
```


### 1.6 部署K8S存储类（可选）

kubeeasy目前提供了两种高可用性的存储类：longhorn、openebs，可以选择性安装。

1. 安装longhorn存储类

```shell
kubeeasy add --storage longhorn
```

2. 安装openebs存储类

```shell
kubeeasy add --storage openebs
```


### 1.7 部署K8S图形化管理器

使用kubeeasy部署KubeSphere，KubeSphere 是在 Kubernetes 之上构建的以应用为中心的多租户容器平台，提供全栈的 IT 自动化运维的能力，简化企业的 DevOps 工作流。KubeSphere 提供了运维友好的向导式操作界面，帮助企业快速构建一个强大和功能丰富的容器云平台。（建议安装）

1. 安装kubesphere管理界面

```shell
kubeeasy add --ui kubesphere
```


### 1.8 部署K8S虚拟机管理器

使用kubeeasy部署kubevirt，kubevirt以CRD形式将VM管理接口接入到kubernetes，通过pod去使用libvirtd管理VM方式，实现pod与VM的一对一对应，做到如同容器一般去管理虚拟机，并且做到与容器一样的资源管理、调度规划。

1. 安装kubevirt虚拟机管理器

```shell
kubeeasy add --virt kubevirt
```



## 离线安装方式

 **注意**：离线部署方式的主机必须配置网关

### 1.1 安装kubeeasy

将kubeeasy文件上传至预设的master节点/root目录，赋予执行权限并移动到/usr/bin目录下。

```shell
chmod +x kubeeasy-centos7.9-v1.2.0 && mv kubeeasy-centos7.9-v1.2.0 /usr/bin/kubeeasy 
```

### 1.2 集群安装依赖包

```shell
kubeeasy install depend \
  --host 10.24.3.11-10.24.3.13 \
  --user root \
  --password 000000 \
  --offline-file dependencies/centos-7-rpms.tar.gz
```

### 1.3 基础ssh配置

使用kubeeasy在集群中创建ssh免秘钥，其中优化的ssh的连接以及配置了集群的免秘钥登录等。

1. 集群连通性检测-ssh

```shell
kubeeasy check ssh \
 --host 10.24.3.11-10.24.3.13 \
 --user root \
 --password 000000
```

2. 集群免秘钥设置


```shell
kubeeasy create ssh-keygen \
 --master 10.24.3.11 \
 --worker 10.24.3.12,10.24.3.13 \
 --user root \
 --password 000000
```


### 1.4 磁盘挂载

使用kubeeasy在集群中挂载数据盘，将其挂载到/data目录，后续的数据存储路径默认都是在/data目录下。（如果没有磁盘可以忽略此操作）

1. 磁盘挂载（集群磁盘名相同时）

```shell
kubeeasy create mount-disk \
 --host 10.24.3.11-10.24.3.13 \
 --disk sdb \
 --mount-dir /data/ \
 --user root \
 --password 000000
```

2. 磁盘挂载（集群磁盘名不同时只能一台一台操作）

```shell
kubeeasy mount \
 --host 10.24.3.11 \
 --disk sdb \
 --user root \
 --password 000000
```


### 1.5 集群升级系统内核

使用kubeeasy升级集群的内核，将其3.x的内核升级为5.x。（建议升级内核）脚本执行完后，会自动重启主机，以生效系统内核。

1. 升级集群内核为5.x

```shell
kubeeasy install upgrade-kernel \
  --master 10.24.3.11 \
  --worker 10.24.3.12,10.24.3.13 \
  --user root \
  --password 000000 \
  --offline-file kubeeasy.tar.gz
```


### 1.6 部署K8S集群

使用kubeeasy部署K8S集群，以下分为【普通集群】和【高可用集群】的安装方式，根据实际情况选择一种方案部署。安装后的K8S的版本为v1.21.3，使用docker作为容器运行时，网络组件使用calico网络，默认还安装kuboard图形化管理器和K8S存储类（nfs和local-path），K8S的证书有效期为100年，且开启了证书轮换。

如需更改K8S的Pod网段，修改--pod-cidr参数相应的值。

1. 安装k8s集群

```shell
kubeeasy install kubernetes \
  --master 10.24.3.11 \
  --worker 10.24.3.12,10.24.3.13 \
  --user root \
  --password 000000 \
  --version 1.21.3 \
  --pod-cidr 10.244.0.0/16 \
  --offline-file kubeeasy.tar.gz
```

2. 安装高可用k8s集群（master节点个数必须大于等于3）

```shell
kubeeasy install kubernetes \
  --master 10.24.3.21,10.24.3.22,10.24.3.23 \
  --worker 10.24.3.24,10.24.3.25 \
  --user root \
  --password 000000 \
  --version 1.21.3 \
  --virtual-ip 10.24.3.20 \
  --pod-cidr 10.244.0.0/16 \
  --offline-file kubeeasy.tar.gz
```


### 1.7 部署K8S存储类（可选）

kubeeasy目前提供了两种高可用性的存储类：longhorn、openebs，可以选择性安装。

1. 分发镜像

```shell
kubeeasy push storage-file \
  --offline-file k8s-storage.tar.gz \
  --master 10.24.3.11 \
  --worker 10.24.3.12,10.24.3.13 \
  --user root \
  --password 000000
```

2. 安装longhorn存储类

```shell
kubeeasy add --storage longhorn
```

3. 安装openebs存储类

```shell
kubeeasy add --storage openebs
```


### 1.8 部署K8S图形化管理器

使用kubeeasy部署KubeSphere，KubeSphere 是在 Kubernetes 之上构建的以应用为中心的多租户容器平台，提供全栈的 IT 自动化运维的能力，简化企业的 DevOps 工作流。KubeSphere 提供了运维友好的向导式操作界面，帮助企业快速构建一个强大和功能丰富的容器云平台。（建议安装）

1. 分发镜像

```shell
kubeeasy push kubesphere-file \
 --offline-file kubesphere.tar.gz \
 --master 10.24.3.11 \
 --worker 10.24.3.12,10.24.3.13 \
 --user root \
 --password 000000
```

2. 安装kubesphere管理界面

```shell
kubeeasy add --ui kubesphere
```


### 1.9 部署K8S虚拟机管理器

使用kubeeasy部署kubevirt，kubevirt以CRD形式将VM管理接口接入到kubernetes，通过pod去使用libvirtd管理VM方式，实现pod与VM的一对一对应，做到如同容器一般去管理虚拟机，并且做到与容器一样的资源管理、调度规划。

1. 分发镜像

```shell
kubeeasy push kubevirt-file \
  --offline-file kubevirt.tar.gz \
  --master 10.24.3.11 \
  --worker 10.24.3.12,10.24.3.13 \
  --user root \
  --password 000000
```

2. 安装kubevirt虚拟机管理器

```shell
kubeeasy add --virt kubevirt
```

## 其他功能

### 重置K8S节点

使用kubeeasy将集群重置（意思就是删除所有相关软件，恢复一个纯净的系统）

1. 重置正常的K8S集群（会重置整个集群）

```shell
kubeeasy reset \
 --user root \
 --password 000000
```

2. 强制重置指定的节点（如果节点不正常可以选择强制重置节点）

```shell
kubeeasy reset --force \
 --master 10.24.3.21,10.24.3.22,10.24.3.23 \
 --worker 10.24.3.24,10.24.3.25 \
 --user root \
 --password 000000
```

### 增加K8S节点

使用kubeeasy将新的节点加入K8S集群中

1. 增加K8S节点

>  增加master节点只适用于高可用集群的模式

```shell
kubeeasy add \
 --worker 10.24.3.14,10.24.3.15
 --user root \
 --password 000000
```

### 删除K8S节点

使用kubeeasy将节点从K8S集群中删除

1. 删除K8S节点

>  删除操作会重置节点，包括删除K8S服务、docker数据等清空操作。

```shell
kubeeasy add \
 --worker 10.24.3.14,10.24.3.15
 --user root \
 --password 000000
```

### 移除K8S节点

使用kubeeasy将节点从K8S集群中移除

1. 移除K8S节点

>  移除操作会不会重置节点，只是从K8S集群中移除，并不会删除docker的数据。

```shell
kubeeasy remove \
 --worker 10.24.3.14,10.24.3.15
 --user root \
 --password 000000
```

### 集群分发并读取容器镜像

使用kubeeasy将容器镜像离线包分发到指定节点并读取，如test-images.tar.gz。

1. 分发现有的容器镜像并读取

```shell
kubeeasy push image-file \
 --offline-file test-images.tar.gz \
 --master 10.24.3.11 \
 --worker 10.24.3.12,10.24.3.13 \
 --user root \
 --password 000000
```

### 容器镜像

使用kubeeasy将容器列表文件的镜像保存到指定目录、也可以将其上传到镜像仓库中，但前提是您需要先登录镜像仓库。

images-list.txt文件命名规范：

test ：表示一个镜像包集，下方区域是镜像列表，保存后以test命名

https://raw.githubusercontent.com/kongyu666/files/main/other/images-list.txt

1. 保存镜像离线包

```shell
kubeeasy images savei \\
 --images-file images-list.txt \\
 --images-dir ./images
```

2. 推送镜像到仓库

```shell
docker login hub.docker.com -u admin -p admin
kubeeasy images pushi \
 --images-file images-list.txt \
 --images-registry hub.docker.com/kongyu
```

### 其他

集群免秘钥设置

```shell
kubeeasy create ssh-keygen \
 --master 192.168.200.11 \
 --worker 192.168.200.12,192.168.200.13 \
 --user root \
 --password 000000
```



集群时间同步设置

```shell
kubeeasy create time \
 --master 192.168.200.11 \
 --worker 192.168.200.12,192.168.200.13 \
 --user root \
 --password 000000
```



集群连通性检测-ssh
```shell
kubeeasy check ssh \
 --host 192.168.200.11-192.168.200.13 \
 --user root \
 --password 000000
```



集群连通性检测-ping
```shell
kubeeasy check ping \
 --host 192.168.200.11-192.168.200.13
```


修改集群root密码
```shell
kubeeasy create password \
 --host 192.168.200.11-192.168.200.13 \
 --user root \
 --password 000000 \
 --new-password 123456
```


清除历史命令
```shell
kubeeasy set history \
 --host 192.168.200.11-192.168.200.13 \
 --user root \
 --password 000000
```











