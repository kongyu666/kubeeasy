
## 修改集群配置文件
修改/root/.kubeeasy/cluster文件，将ha=0改为ha=1，vip=改为vip=10.24.3.10 (自身环境的虚拟IP)
```shell
ha=1
vip=10.24.3.10
```

## 部署kube-vip
下载kube-vip.yaml，并修改vip和interface
```shell
cp /tmp/kubeeasy/manifests/kube-vip.yaml ./
vi +15 kube-vip.yaml  ## 管理网卡接口
vi +37 kube-vip.yaml  ## 管理网卡接口的虚拟IP地址
mv kube-vip.yaml /etc/kubernetes/manifests/
```

查看kube-vip
```shell
kubectl get pod -n kube-system
ip addr show eth0
```

## 加入master节点
将10.24.2.25主机加入K8S集群中的master节点
```shell
kubeeasy add \
 --master 10.24.2.25
 --user root \
 --password 000000
```
