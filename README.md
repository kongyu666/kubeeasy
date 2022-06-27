## 版本

版本：kubeeasy-v1.3.2

更新说明：

1.  新增安装软件包并发执行任务
2. 新增私有容器registry仓库，用于集群拉取镜像
3. 修改容器镜像的操作
4. 新增系统指标检测(CPU Memory Disk)
5. 新增集群优化系统配置
6. 新增集群使用命令输出
7. 优化部分内容

## 要求

OS：`centos 7.9 x64`

CPU：`2C及以上`

MEM：`4G及以上`

认证：集群节点需**统一认证**，需使用同一用户名和密码

运行：在预设的master节点执行

## 功能

- 支持升级集群内核，升级后内核版本为：5.17.9
- 支持离线部署普通的k8s集群，k8s版本为：v1.21.3
- 支持离线部署高可用k8s集群，k8s版本为：v1.21.3
- K8S HA集群使用云原生的kube-vip，其自带VIP和负载均衡
- K8S集群默认安装图形化管理工具kuboard-v2
- K8S集群默认安装local-hostpath存储类
- K8S证书100年，且开启了自动轮询
- 内置容器镜像的功能：pull、push、save、load

## 集群模式选择

 以下提供了两种K8S集群方案，根据实际情况选择一种方案即可

 高可用集群模式主机列表

| **IP** **地址** | **主机名**        | **角色**                              |
| :-------------- | ----------------- | ------------------------------------- |
| 192.168.1.201   | k8s-maste-noder01 | master \| etcd \|  worker \| kube-vip |
| 192.168.1.202   | k8s-master-node02 | master \| etcd \|  worker \| kube-vip |
| 192.168.1.203   | k8s-master-node03 | master \| etcd \|  worker \| kube-vip |
| 192.168.1.204   | k8s-worker-node1  | worker                                |
| 192.168.1.205   | k8s-worker-node3  | worker                                |
| 192.168.1.250   | /                 | 虚拟 IP 地址                          |

 普通集群模式主机列表

| **IP** **地址** | **主机名**        | **角色**                  |
| --------------- | ----------------- | ------------------------- |
| 192.168.1.201   | k8s-maste-noder01 | master \| etcd \|  worker |
| 192.168.1.202   | k8s-worker-node1  | worker                    |
| 192.168.1.203   | k8s-worker-node2  | worker                    |

 安装方式只有[离线版](#离线安装方式)，还有其他功能，在[其他功能](#其他功能)里面可以查看

## 离线安装方式

> **注意**：离线部署方式的主机必须配置网关

### 1.1 安装kubeeasy

将kubeeasy文件上传至预设的master节点/root目录，然后赋予执行权限并移动到/usr/bin目录下

```shell
mv kubeeasy-v1.3.2.sh /usr/bin/kubeeasy && chmod +x /usr/bin/kubeeasy
```

### 1.2 集群安装依赖包

使用kubeeasy在集群中安装软件包，包含远程连接sshpass等软件包

```shell
kubeeasy install depend \
  --host 192.168.1.201-192.168.1.203 \
  --user root \
  --password 000000 \
  --offline-file ./centos-7-rpms.tar.gz
```

### 1.3 基础ssh配置

使用kubeeasy在集群中创建ssh免秘钥，其中优化的ssh的连接以及配置了集群的免秘钥登录等

1. 集群连通性检测-ssh

```shell
kubeeasy check ssh \
  --host 192.168.1.201-192.168.1.203 \
  --user root \
  --password 000000
```

2. 集群免秘钥设置


```shell
kubeeasy create ssh-keygen \
  --master 192.168.1.201 \
  --worker 192.168.1.202,192.168.1.203 \
  --user root \
  --password 000000
```


### 1.4 磁盘挂载

使用kubeeasy在集群中挂载数据盘，将其挂载到/data目录，后续的数据存储路径默认都是在/data目录下。（如果没有磁盘可以忽略此操作）

1. 磁盘挂载（集群磁盘名相同时）

```shell
kubeeasy create mount-disk \
  --host 192.168.1.201-192.168.1.203 \
  --disk /dev/sdb \
  --mount-dir /data \
  --user root \
  --password 000000
```

2. 磁盘挂载（集群磁盘名不同时只能按顺序操作）

```shell
kubeeasy create mount-disk \
  --host 192.168.1.201 \
  --disk /dev/sdb \
  --mount-dir /data \
  --user root \
  --password 000000
```


### 1.5 集群升级系统内核

使用kubeeasy升级集群的内核，将其3.10的内核升级为5.14（建议升级内核）。脚本执行完后，会自动重启主机，以生效系统内核。

1. 升级集群内核为5.x

```shell
kubeeasy install upgrade-kernel \
  --host 192.168.1.201-192.168.1.203 \
  --user root \
  --password 000000 \
  --offline-file ./kernel-rpms-v5.17.9.tar.gz
```


### 1.6 部署K8S集群

使用kubeeasy部署K8S集群，以下分为**普通集群**和**高可用集群**的安装方式，根据实际情况选择一种方案部署。安装后的K8S的版本为v1.21.3，使用docker作为容器运行时，网络组件使用calico网络，默认还安装kuboard图形化管理器和K8S存储类（openebs-hostpath），K8S的证书有效期为100年，且开启了证书轮换

> 如需更改K8S的Pod网段，修改--pod-cidr参数相应的值

1. 安装k8s集群

```shell
kubeeasy install kubernetes \
  --master 192.168.1.201 \
  --worker 192.168.1.202,192.168.1.203 \
  --user root \
  --password 000000 \
  --version 1.21.3 \
  --pod-cidr 10.244.0.0/16 \
  --offline-file ./kubeeasy-v1.3.2.tar.gz
```

2. 安装高可用k8s集群（master节点个数必须大于等于3）

```shell
kubeeasy install kubernetes \
  --master 192.168.1.201,192.168.1.202,192.168.1.203 \
  --worker 192.168.1.204 \
  --user root \
  --password 000000 \
  --version 1.21.3 \
  --virtual-ip 192.168.1.250 \
  --pod-cidr 10.244.0.0/16 \
  --offline-file ./kubeeasy-v1.3.2.tar.gz
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
  --master 192.168.1.201 \
  --worker 192.168.1.202 \
  --user root \
  --password 000000
```

### 增加K8S节点

使用kubeeasy将新的节点加入K8S集群中

1. 离线增加K8S节点

>  增加master节点只适用于高可用集群的模式
>
>  从普通的K8S集群转换为高可用的K8S集群点击 [这里](./ConvertToHA.md)

```shell
# 需要先安装依赖包
kubeeasy install depend \
  --host 192.168.1.204,192.168.1.205 \
  --user root \
  --password 000000 \
  --offline-file ./centos-7-rpms.tar.gz
# 加入K8S集群
kubeeasy add \
  --worker 192.168.1.204,192.168.1.205
  --user root \
  --password 000000 \
  --offline-file ./kubeeasy-v1.3.2.tar.gz
```

### 删除K8S节点

使用kubeeasy将节点从K8S集群中删除

1. 删除K8S节点

>  删除操作会重置节点，包括删除K8S服务、docker数据等清空操作。

```shell
kubeeasy delete \
  --worker 192.168.1.202,192.168.1.203
  --user root \
  --password 000000
```

### 移除K8S节点

使用kubeeasy将节点从K8S集群中移除

1. 移除K8S节点

>  移除操作会不会重置节点，只是从K8S集群中移除，并不会删除docker的数据。

```shell
kubeeasy remove \
  --worker 192.168.1.202,192.168.1.203
  --user root \
  --password 000000
```

### 集群分发并读取容器镜像

使用kubeeasy将容器镜像离线包分发到指定节点并读取，如test-images.tar.gz。

1. 分发现有的容器镜像并读取

```shell
kubeeasy images load \
  --host 192.168.1.201,192.168.1.201,192.168.1.203 \
  --user root \
  --password 000000 \
  --offline-file test-images.tar.gz
```

### 容器镜像

使用kubeeasy将容器列表文件的镜像保存到指定目录、也可以将其上传到镜像仓库中，但前提是您需要先登录镜像仓库。

[images-list.txt](https://gitee.com/iskongyu/files/raw/main/other/images-list.txt)文件命名规范：

test ：表示一个镜像包集，下方区域是镜像列表，保存后以test命名


1. 保存镜像离线包

```shell
kubeeasy images save \
  --images-file images-list.txt \
  --images-dir ./images
```

2. 推送镜像到仓库

```shell
docker login dockerhub.kubeeasy.local:5000 -u admin -p admin
kubeeasy images push \
  --images-file images-list.txt \
  --images-registry dockerhub.kubeeasy.local:5000/kongyu
```

### 其他

集群优化系统配置

```shell
## 依赖于sshpass命令，需要先安装此命令
rpm -ivh https://mirrors.aliyun.com/centos/7/extras/x86_64/Packages/sshpass-1.06-2.el7.x86_64.rpm
kubeeasy install precondition \
  --host 192.168.1.201-192.168.1.203 \
  --user root \
  --password 000000
```

集群使用命令

```shell
kubeeasy get command \
  --host 192.168.1.201-192.168.1.203 \
  --user root \
  --password 000000 \
  --cmd "hostname"
```

集群免秘钥设置

```shell
kubeeasy create ssh-keygen \
  --master 192.168.1.201 \
  --worker 192.168.1.202,192.168.1.203 \
  --user root \
  --password 000000
```

集群时间同步设置

```shell
kubeeasy create time \
  --master 192.168.1.201 \
  --worker 192.168.1.202,192.168.1.203 \
  --user root \
  --password 000000
```

集群系统指标检测(CPU Memory Disk)

```shell
kubeeasy check system \
  --host 192.168.1.201-192.168.1.203 \
  --user root \
  --password 000000
```

集群连通性检测-ssh

```shell
kubeeasy check ssh \
  --host 192.168.1.201-192.168.1.203 \
  --user root \
  --password 000000
```

集群连通性检测-ping
```shell
kubeeasy check ping \
  --host 192.168.1.201-192.168.1.203
```


修改集群root密码
```shell
kubeeasy create password \
  --host 192.168.1.201-192.168.1.203 \
  --user root \
  --password 000000 \
  --new-password 123456
```


清除历史命令
```shell
kubeeasy set history \
  --host 192.168.1.201-192.168.1.203 \
  --user root \
  --password 000000
```

