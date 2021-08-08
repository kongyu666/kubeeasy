## 要求

OS：`centos 7.9 x64`

CPU：`2C及以上`

MEM：`4G及以上`

认证：集群节点需**统一认证**; 使用密码认证时，集群节点需使用同一用户名和密码。

运行：在预设的master节点执行

## 架构

![architecture-ha-k8s-cluster](https://kubesphere.com.cn/images/docs/installing-on-linux/high-availability-configurations/set-up-ha-cluster-using-keepalived-haproxy/architecture-ha-k8s-cluster.png)

## 功能

- 支持升级集群内核，升级后内核版本为：5.13.2
- 支持离线部署普通的k8s集群，k8s版本为：v1.21.3
- 支持离线部署高可用k8s集群，k8s版本为：v1.21.3
- k8s集群默认安装图形化管理工具kuboard，kuboard版本为：v2
- k8s集群默认安装nfs和localpath存储类
- k8s证书100年

## 快速开始

```shell
bash kubeeasy.sh init \
  --master 10.24.2.32 \
  --worker 10.24.2.45 \
  --user root \
  --password 000000 \
  --offline-file kubeeasy.tar.gz
```

