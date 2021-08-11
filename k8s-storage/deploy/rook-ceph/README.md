kubectl create -f crds.yaml -f common.yaml -f operator.yaml
kubectl -n rook-ceph get pod
kubectl create -f cluster.yaml
kubectl -n rook-ceph get pod

