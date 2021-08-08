#!/bin/bash
token=$(kubectl -n kube-system get secret $(kubectl -n kube-system get secret | grep kuboard-user | awk '{print $1}') -o go-template='{{.data.token}}' | base64 -d)
echo $token > /root/token.txt
cat  /root/token.txt
