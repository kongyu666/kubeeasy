#!/bin/bash
for i in `seq 1 100000`; do curl http://k8s-test:32500; done &> /dev/null &
