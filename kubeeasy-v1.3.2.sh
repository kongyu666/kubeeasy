#!/usr/bin/env bash
###################################################################
# Script Name    : kubeeasy
# Version:       : v1.3.2
# Description    : Install kubernetes (HA) cluster using kubeadm.
# Create Date    : 2022-06-01
# Author         : KongYu
# Email          : 2385569970@qq.com
# Notable Changes: 1. 新增安装软件包并发执行任务
#                  2. 新增私有容器registry仓库，用于集群拉取镜像
#                  3. 修改容器镜像的操作
#                  4. 新增系统指标检测(CPU Memory Disk)
#                  5. 新增集群优化系统配置
#                  6. 新增集群使用命令输出
#                  7. 优化部分内容
###################################################################

[[ -n $DEBUG ]] && set -x
set -o errtrace # Make sure any error trap is inherited
set -o nounset  # Disallow expansion of unset variables
set -o pipefail # Use last non-zero exit code in a pipeline

######################################################################################################
# environment configuration
######################################################################################################

# 版本
KUBE_VERSION="${KUBE_VERSION:-1.21.3}"
FLANNEL_VERSION="${FLANNEL_VERSION:-0.14.0}"
METRICS_SERVER_VERSION="${METRICS_SERVER_VERSION:-0.5.0}"
CALICO_VERSION="${CALICO_VERSION:-3.19.1}"
LONGHORN_VERSION="${LONGHORN_VERSION:-1.1.1}"
KUBERNETES_DASHBOARD_VERSION="${KUBERNETES_DASHBOARD_VERSION:-2.3.1}"
KUBESPHERE_VERSION="${KUBESPHERE_VERSION:-3.1.0}"

# 集群配置
KUBE_DNSDOMAIN="${KUBE_DNSDOMAIN:-cluster.local}"
KUBE_APISERVER="${KUBE_APISERVER:-apiserver.$KUBE_DNSDOMAIN}"
KUBE_POD_SUBNET="${KUBE_POD_SUBNET:-10.244.0.0/16}"
KUBE_SERVICE_SUBNET="${KUBE_SERVICE_SUBNET:-10.96.0.0/16}"
KUBE_IMAGE_REPO="${KUBE_IMAGE_REPO:-dockerhub.kubeeasy.local:5000/kubernetes}"
KUBE_NETWORK="${KUBE_NETWORK:-calico}"
KUBE_STORAGE="${KUBE_STORAGE:-local}"
KUBE_UI="${KUBE_UI:-kuboard}"
KUBE_VIRT=${KUBE_VIRT:-kubevirt}
KUBE_ADDON="${KUBE_ADDON:-metrics-server}"
KUBE_FLANNEL_TYPE="${KUBE_FLANNEL_TYPE:-vxlan}"
KUBE_CRI="${KUBE_CRI:-docker}"
KUBE_CRI_VERSION="${KUBE_CRI_VERSION:-latest}"
KUBE_CRI_ENDPOINT="${KUBE_CRI_ENDPOINT:-/var/run/dockershim.sock}"
DOCKER_DATA_ROOT="${DOCKER_DATA_ROOT:-/data/docker}"

# 定义的master和worker节点地址，以逗号分隔
MASTER_NODES="${MASTER_NODES:-}"
WORKER_NODES="${WORKER_NODES:-}"
HOST="${HOST:-}"

# 高可用配置
VIRTUAL_IP=${VIRTUAL_IP:-}
KUBE_APISERVER_PORT=${KUBE_APISERVER_PORT:-6443}

# 定义在哪个节点上进行设置
MGMT_NODE="${MGMT_NODE:-127.0.0.1}"

# 节点的连接信息
SSH_USER="${SSH_USER:-root}"
SSH_PASSWORD="${SSH_PASSWORD:-000000}"
SSH_PRIVATE_KEY="${SSH_PRIVATE_KEY:-}"
SSH_PORT="${SSH_PORT:-22}"
SUDO_USER="${SUDO_USER:-root}"

# 节点命名设置
HOSTNAME_PREFIX="${HOSTNAME_PREFIX:-k8s}"

# 脚本设置
TMP_DIR="/tmp"
LOG_FILE="/var/log/kubeeasy/install.log"
SSH_OPTIONS="-o ConnectTimeout=600 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q"
ERROR_INFO="\n\033[31mERROR Summary: \033[0m\n  "
ACCESS_INFO="\n\033[32mACCESS Summary: \033[0m\n  "
COMMAND_OUTPUT=""
SCRIPT_PARAMETER="$*"
OFFLINE_DIR="${TMP_DIR}/kubeeasy"
OFFLINE_TAG="${OFFLINE_TAG:-0}"
OFFLINE_FILE=""
OS_SUPPORT="centos7 centos8"
GITHUB_PROXY="${GITHUB_PROXY:-https://gh.lework.workers.dev/}"
SKIP_UPGRADE_PLAN=${SKIP_UPGRADE_PLAN:-false}
UPGRADE_KERNEL_TAG="${UPGRADE_KERNEL_TAG:-0}"
HELP_TAG="${HELP_TAG:-0}"
IMAGES_FILE=${IMAGES_FILE:-./images-list.txt}
IMAGES_DIR=${IMAGES_FILE:-./images}

trap trap::info 1 2 3 15 EXIT

######################################################################################################
# function
######################################################################################################

function trap::info() {
  # 信号处理

  [[ ${#ERROR_INFO} -gt 37 ]] && echo -e "$ERROR_INFO"
  [[ ${#ACCESS_INFO} -gt 38 ]] && echo -e "$ACCESS_INFO"
  #[ -f "$LOG_FILE" ] && echo -e "\n  See detailed log >> $LOG_FILE \n"
  trap '' EXIT
  exit
}

function log::error() {
  # 错误日志

  local item
  item="[$(date +'%Y-%m-%d %H:%M:%S')] \033[31mERROR:   \033[0m$*"
  ERROR_INFO="${ERROR_INFO}${item}\n  "
  echo -e "${item}" | tee -a "$LOG_FILE"
}

function log::info() {
  # 基础日志

  printf "[%s] \033[32mINFO:    \033[0m%s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG_FILE"
}

function log::warning() {
  # 警告日志

  printf "[%s] \033[33mWARNING: \033[0m%s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG_FILE"
}

function log::access() {
  # 访问信息

  ACCESS_INFO="${ACCESS_INFO}$*\n  "
  printf "[%s] \033[32mINFO:    \033[0m%s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG_FILE"
}

function log::exec() {
  # 执行日志

  printf "[%s] \033[34mEXEC:    \033[0m%s\n" "$(date +'%Y-%m-%d %H:%M:%S')" "$*" >>"$LOG_FILE"
}

function utils::version_to_number() {
  # 版本号转数字

  echo "$@" | awk -F. '{ printf("%d%03d%03d%03d\n", $1,$2,$3,$4); }'
}

function utils::retry() {
  # 重试

  local retries=$1
  shift

  local count=0
  until eval "$*"; do
    exit=$?
    wait=$((2 ** count))
    count=$((count + 1))
    if [ "$count" -lt "$retries" ]; then
      echo "Retry $count/$retries exited $exit, retrying in $wait seconds..."
      sleep $wait
    else
      echo "Retry $count/$retries exited $exit, no more retries left."
      return $exit
    fi
  done
  return 0
}

function utils::quote() {
  # 转义引号

  # shellcheck disable=SC2046
  if [ $(echo "$*" | tr -d "\n" | wc -c) -eq 0 ]; then
    echo "''"
  elif [ $(echo "$*" | tr -d "[a-z][A-Z][0-9]:,.=~_/\n-" | wc -c) -gt 0 ]; then
    printf "%s" "$*" | sed -e "1h;2,\$H;\$!d;g" -e "s/'/\'\"\'\"\'/g" | sed -e "1h;2,\$H;\$!d;g" -e "s/^/'/g" -e "s/$/'/g"
  else
    echo "$*"
  fi
}

function utils::download_file() {
  # 下载文件

  local url="$1"
  local dest="$2"
  local unzip_tag="${3:-1}"

  local dest_dirname
  dest_dirname=$(dirname "$dest")
  local filename
  filename=$(basename "$dest")

  log::info "[download]" "download ${filename} file"
  command::exec "${MGMT_NODE}" "
    set -e
    if [ ! -f \"${dest}\" ]; then
      [ ! -d \"${dest_dirname}\" ] && mkdir -pv \"${dest_dirname}\" 
      wget --timeout=10 --waitretry=3 --tries=5 --retry-connrefused \"${url}\" -O \"${dest}\"
      if [[ \"${unzip_tag}\" == \"unzip\" ]]; then
        command -v unzip 2>/dev/null || yum install -y unzip
        unzip -o \"${dest}\" -d \"${dest_dirname}\"
      fi
    else
      echo \"${dest} is exists!\"
    fi
  "
  local status="$?"
  check::exit_code "$status" "download" "download ${filename} file"
  return "$status"
}

function utils::is_element_in_array() {
  # 判断是否在数组中存在元素

  local -r element="${1}"
  local -r array=("${@:2}")

  local walker=''

  for walker in "${array[@]}"; do
    [[ "${walker}" == "${element}" ]] && return 0
  done

  return 1
}

function command::exec() {
  # 执行命令

  local host=${1:-}
  shift
  local command="$*"

  if [[ "${SUDO_TAG:-}" == "1" ]]; then
    sudo_options="sudo -H -n -u ${SUDO_USER}"

    if [[ "${SUDO_PASSWORD:-}" != "" ]]; then
      sudo_options="${sudo_options// -n/} -p \"\" -S <<< \"${SUDO_PASSWORD}\""
    fi
    command="$sudo_options bash -c $(utils::quote "$command")"
  fi

  command="$(utils::quote "$command")"

  if [[ "${host}" == "127.0.0.1" ]]; then
    # 本地执行
    log::exec "[command]" "bash -c $(printf "%s" "${command//${SUDO_PASSWORD:-}/******}")"
    # shellcheck disable=SC2094
    COMMAND_OUTPUT=$(eval bash -c "${command}" 2>>"$LOG_FILE" | tee -a "$LOG_FILE")
    local status=$?
  else
    # 远程执行
    local ssh_cmd="ssh"
    if [[ "${SSH_PASSWORD}" != "" ]]; then
      ssh_cmd="sshpass -p \"${SSH_PASSWORD}\" ${ssh_cmd}"
    elif [[ "$SSH_PRIVATE_KEY" != "" ]]; then
      [ -f "${SSH_PRIVATE_KEY}" ] || {
        log::error "[exec]" "ssh private_key:${SSH_PRIVATE_KEY} not found."
        exit 1
      }
      ssh_cmd="${ssh_cmd} -i $SSH_PRIVATE_KEY"
    fi
    log::exec "[command]" "${ssh_cmd//${SSH_PASSWORD:-}/******} ${SSH_OPTIONS} ${SSH_USER}@${host} -p ${SSH_PORT} bash -c $(printf "%s" "${command//${SUDO_PASSWORD:-}/******}")"
    # shellcheck disable=SC2094
    COMMAND_OUTPUT=$(eval "${ssh_cmd} ${SSH_OPTIONS} ${SSH_USER}@${host} -p ${SSH_PORT}" bash -c '"${command}"' 2>>"$LOG_FILE" | tee -a "$LOG_FILE")
    local status=$?
  fi
  return $status
}

function command::scp() {
  # 拷贝文件

  local host=${1:-}
  local src=${2:-}
  local dest=${3:-/tmp/}

  if [[ "${host}" == "127.0.0.1" ]]; then
    local command="rsync -az ${src} ${dest}"
    log::exec "[command]" "bash -c \"${command}\""
    # shellcheck disable=SC2094
    COMMAND_OUTPUT=$(bash -c "${command}" 2>>"$LOG_FILE" | tee -a "$LOG_FILE")
    local status=$?
  else
    local scp_cmd="scp"
    if [[ "${SSH_PASSWORD}" != "" ]]; then
      scp_cmd="sshpass -p \"${SSH_PASSWORD}\" ${scp_cmd}"
    elif [[ "$SSH_PRIVATE_KEY" != "" ]]; then
      [ -f "${SSH_PRIVATE_KEY}" ] || {
        log::error "[exec]" "ssh private_key:${SSH_PRIVATE_KEY} not found."
        exit 1
      }
      scp_cmd="${scp_cmd} -i $SSH_PRIVATE_KEY"
    fi
    log::exec "[command]" "${scp_cmd//${SSH_PASSWORD:-}/******} ${SSH_OPTIONS} -P ${SSH_PORT} -r ${src} ${SSH_USER}@${host}:${dest}" >>"$LOG_FILE"
    # shellcheck disable=SC2094
    COMMAND_OUTPUT=$(eval "${scp_cmd} ${SSH_OPTIONS} -P ${SSH_PORT} -r ${src} ${SSH_USER}@${host}:${dest}" 2>>"$LOG_FILE" | tee -a "$LOG_FILE")
    local status=$?
  fi
  return $status
}

function command::rsync() {
  # 增量拷贝文件

  local host=${1:-}
  local src=${2:-}
  local dest=${3:-/tmp/}

  if [[ "${host}" == "127.0.0.1" ]]; then
    local command="rsync -az ${src} ${dest}"
    log::exec "[command]" "bash -c \"${command}\""
    # shellcheck disable=SC2094
    COMMAND_OUTPUT=$(bash -c "${command}" 2>>"$LOG_FILE" | tee -a "$LOG_FILE")
    local status=$?
  else
    local rsync_cmd="rsync -avz"
    if [[ "${SSH_PASSWORD}" != "" ]]; then
      rsync_cmd="sshpass -p \"${SSH_PASSWORD}\" ${rsync_cmd}"
    elif [[ "$SSH_PRIVATE_KEY" != "" ]]; then
      [ -f "${SSH_PRIVATE_KEY}" ] || {
        log::error "[exec]" "ssh private_key:${SSH_PRIVATE_KEY} not found."
        exit 1
      }
      rsync_cmd="${rsync_cmd} -i $SSH_PRIVATE_KEY"
    fi
    log::exec "[command]" "
    ${rsync_cmd//${SSH_PASSWORD:-}/******} --port ${SSH_PORT} ${src} ${SSH_USER}@${host}:${dest}
    " >>"$LOG_FILE"
    # shellcheck disable=SC2094
    COMMAND_OUTPUT=$(eval "${rsync_cmd} --port ${SSH_PORT} ${src} ${SSH_USER}@${host}:${dest}" 2>>"$LOG_FILE" | tee -a "$LOG_FILE")
    local status=$?
  fi
  return $status
}

function utils::mount_disk() {
  ## 挂载系统磁盘并格式化
  local hosts=${HOST}
  local disk="${MOUNT_DISK}"
  local mount_dir="${DOCKER_DATA_ROOT:-}"
  # mount disk
  for host in ${hosts}; do
    log::info "[disk]" "${host}: ${disk} disk pre"
    command::exec "${host}" "
      ## 创建挂载点
      mkdir -p ${mount_dir}
      umount ${disk} &> /dev/null || true
      sed -i '/\/dev\/kubeeasy\/data/d' /etc/fstab
      ## 清除磁盘
      #sgdisk --zap-all ${disk}
      #wipefs -a ${disk}
      #dd if=/dev/zero of="${disk}" bs=1M count=100 oflag=direct,dsync
      blkdiscard ${disk}
      #partprobe ${disk}
    "

    log::info "[disk]" "${host}: ${disk} create physical volume"
    command::exec "${host}" "
      pvcreate -f ${disk}
    "
    check::exit_code "$?" "disk" "${host}: ${disk} create physical volume"

    log::info "[disk]" "${host}: ${disk} create volume group"
    command::exec "${host}" "
      vgcreate -f kubeeasy ${disk}
    "
    check::exit_code "$?" "disk" "${host}: ${disk} create volume group"

    log::info "[disk]" "${host}: ${disk} create logical volume"
    command::exec "${host}" "
      lvcreate -n data -l 100%vg kubeeasy
    "
    check::exit_code "$?" "disk" "${host}: ${disk} create logical volume"

    log::info "[disk]" "${host}: ${disk} mount to ${mount_dir}"
    command::exec "${host}" "
      mkfs.xfs -f /dev/kubeeasy/data && \
      echo '/dev/kubeeasy/data ${mount_dir} xfs defaults 0 0' >> /etc/fstab && \
      mount /dev/kubeeasy/data ${mount_dir}
    "
    check::exit_code "$?" "disk" "${host}: ${disk} mount to ${mount_dir}"

  done
  log::info "[get]" "command: df -h /dev/mapper/kubeeasy-data"

}

function create::password() {

  local hosts=${HOST}
  local new_password="${NEW_SSH_PASSWORD:-}"
  # mount disk
  for host in ${hosts}; do
    log::info "[password]" "${host}: change root password"
    command::exec "${host}" "
      echo ${new_password} | passwd --stdin root
   "
    check::exit_code "$?" "password" "${host}: change root password"
  done
}

function script::stop_security() {
  # Disable firewalld
  for target in firewalld python-firewall firewalld-filesystem iptables; do
    systemctl stop $target &>/dev/null || true
    systemctl disable $target &>/dev/null || true
  done

  # selinux
  setenforce 0
  sed -i "s/SELINUX=.*/SELINUX=disabled/g" /etc/selinux/config
}

function script::exec_command() {
  ## 执行命令
  command=${COMMAND_GET}
  for host in $MASTER_NODES $WORKER_NODES $HOST; do
    ## 配置前置条件
    log::info "[exec]" "$host cmd: ${command}"
    command::exec "${host}" "
      ${command}
    "  && printf "%s \n" "${COMMAND_OUTPUT}" || printf "%s \n" "command execution failure."
  done
}

function script::init_node() {
  # 节点初始化脚本

  # clean
  sed -i -e "/$KUBE_APISERVER/d" -e '/worker/d' -e '/master/d' /etc/hosts

  sed -i '/## kubeeasy managed start/,/## kubeeasy managed end/d' /etc/security/limits.conf /etc/systemd/system.conf /etc/bashrc /etc/rc.local /etc/audit/rules.d/audit.rules

  # Disable selinux
  sed -i 's/SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
  setenforce 0

  # Disable swap
  swapoff -a && sysctl -w vm.swappiness=0
  sed -ri '/^[^#]*swap/s@^@#@' /etc/fstab

  # Disable firewalld
  for target in firewalld python-firewall firewalld-filesystem iptables; do
    systemctl stop $target &>/dev/null || true
    systemctl disable $target &>/dev/null || true
  done

  # ssh
  # 关闭反向解析，加快连接速度
  sed -i \
    -e 's/#UseDNS yes/UseDNS no/g' \
    -e 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/g' \
    /etc/ssh/sshd_config
  # 取消确认键
  sed -i 's/#   StrictHostKeyChecking ask/   StrictHostKeyChecking no/g' /etc/ssh/ssh_config
  systemctl restart sshd
  
  # Change limits
  [ ! -f /etc/security/limits.conf_bak ] && cp /etc/security/limits.conf{,_bak}
  cat << EOF >> /etc/security/limits.conf
## kubeeasy managed start
root soft nofile 655360
root hard nofile 655360
root soft nproc 655360
root hard nproc 655360
root soft core unlimited
root hard core unlimited
* soft nofile 655360
* hard nofile 655360
* soft nproc 655360
* hard nproc 655360
* soft core unlimited
* hard core unlimited
## kubeeasy managed end
EOF

  [ -f /etc/security/limits.d/20-nproc.conf ] && sed -i 's#4096#655360#g' /etc/security/limits.d/20-nproc.conf
  cat << EOF >> /etc/systemd/system.conf
## kubeeasy managed start
DefaultLimitCORE=infinity
DefaultLimitNOFILE=655360
DefaultLimitNPROC=655360
DefaultTasksMax=75%
## kubeeasy managed end
EOF

   # Change sysctl
   cat << EOF >  /etc/sysctl.d/99-kubeeasy.conf
# https://www.kernel.org/doc/Documentation/sysctl/
# 开启IP转发.
net.ipv4.ip_forward = 1
# 要求iptables不对bridge的数据进行处理
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-arptables = 1
# vm.max_map_count 计算当前的内存映射文件数。
# mmap 限制（vm.max_map_count）的最小值是打开文件的ulimit数量（cat /proc/sys/fs/file-max）。
# 每128KB系统内存 map_count应该大约为1。 因此，在32GB系统上，max_map_count为262144。
# Default: 65530
vm.max_map_count = 262144
# Default: 30
# 0 - 任何情况下都不使用swap。
# 1 - 除非内存不足（OOM），否则不使用swap。
vm.swappiness = 0
# 文件监控
fs.inotify.max_user_instances=524288
fs.inotify.max_user_watches=524288
fs.inotify.max_queued_events=16384
# 调高 PID 数量
kernel.pid_max = 65536
kernel.threads-max=30938
EOF

  # history
  cat <<EOF >>/etc/bashrc
## kubeeasy managed start
# history actions record，include action time, user, login ip
HISTFILESIZE=100000
HISTSIZE=100000
USER_IP=\$(who -u am i 2>/dev/null | awk '{print \$NF}' | sed -e 's/[()]//g')
if [ -z \$USER_IP ]
then
  USER_IP=\$(hostname -i)
fi
HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S \$USER_IP:\$(whoami) "
HISTFILE=~/.bash_history
shopt -s histappend
PROMPT_COMMAND="history -a"
export HISTFILESIZE HISTSIZE HISTTIMEFORMAT HISTFILE PROMPT_COMMAND

# PS1
PS1='\[\033[0m\]\[\033[1;36m\][\u\[\033[0m\]@\[\033[1;32m\]\h\[\033[0m\] \[\033[1;31m\]\W\[\033[0m\]\[\033[1;36m\]]\[\033[33;1m\]\\$ \[\033[0m\]'
## kubeeasy managed end
EOF


   # journal
   mkdir -p /var/log/journal /etc/systemd/journald.conf.d
   cat << EOF > /etc/systemd/journald.conf.d/99-prophet.conf
[Journal]
# 持久化保存到磁盘
Storage=persistent
# 压缩历史日志
Compress=yes
SyncIntervalSec=5m
RateLimitInterval=30s
RateLimitBurst=1000
# 最大占用空间 10G
SystemMaxUse=10G
# 单日志文件最大 200M
SystemMaxFileSize=200M
# 日志保存时间 3 周
MaxRetentionSec=3week
# 不将日志转发到 syslog
ForwardToSyslog=no
EOF

  # motd
  cat <<EOF >/etc/profile.d/ssh-login-info.sh
#!/bin/sh
#
# @Time    : 2022-04-13
# @Author  : KongYu
# @Desc    : ssh login banner

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
shopt -q login_shell && : || return 0
echo -e "\033[1;3\$((RANDOM%10%8))m

  ██╗  ██╗ █████╗ ███████╗
  ██║ ██╔╝██╔══██╗██╔════╝
  █████╔╝ ╚█████╔╝███████╗
  ██╔═██╗ ██╔══██╗╚════██║
  ██║  ██╗╚█████╔╝███████║
  ╚═╝  ╚═╝ ╚════╝ ╚══════╝ \033[0m"


# os
upSeconds="\$(cut -d. -f1 /proc/uptime)"
secs=\$((\${upSeconds}%60))
mins=\$((\${upSeconds}/60%60))
hours=\$((\${upSeconds}/3600%24))
days=\$((\${upSeconds}/86400))
UPTIME_INFO=\$(printf "%d days, %02dh %02dm %02ds" "\$days" "\$hours" "\$mins" "\$secs")

if [ -f /etc/redhat-release ] ; then
    PRETTY_NAME=\$(< /etc/redhat-release)

elif [ -f /etc/debian_version ]; then
   DIST_VER=\$(</etc/debian_version)
   PRETTY_NAME="\$(grep PRETTY_NAME /etc/os-release | sed -e 's/PRETTY_NAME=//g' -e  's/"//g') (\$DIST_VER)"

else
    PRETTY_NAME=\$(cat /etc/*-release | grep "PRETTY_NAME" | sed -e 's/PRETTY_NAME=//g' -e 's/"//g')
fi

if [[ -d "/system/app/" && -d "/system/priv-app" ]]; then
    model="\$(getprop ro.product.brand) \$(getprop ro.product.model)"

elif [[ -f /sys/devices/virtual/dmi/id/product_name ||
        -f /sys/devices/virtual/dmi/id/product_version ]]; then
    model="\$(< /sys/devices/virtual/dmi/id/product_name)"
    model+="\$(< /sys/devices/virtual/dmi/id/product_version)"

elif [[ -f /sys/firmware/devicetree/base/model ]]; then
    model="\$(< /sys/firmware/devicetree/base/model)"

elif [[ -f /tmp/sysinfo/model ]]; then
    model="\$(< /tmp/sysinfo/model)"
fi

MODEL_INFO=\${model}
KERNEL=\$(uname -srmo)
USER_NUM=\$(who -u | wc -l)
RUNNING=\$(ps ax | wc -l | tr -d " ")

# disk total
totaldisk=\$(df -h -x devtmpfs -x tmpfs -x debugfs -x aufs -x overlay --total 2>/dev/null | tail -1)
disktotal=\$(awk '{print \$2}' <<< "\${totaldisk}")
diskused=\$(awk '{print \$3}' <<< "\${totaldisk}")
diskusedper=\$(awk '{print \$5}' <<< "\${totaldisk}")
DISK_INFO="\033[0;33m\${diskused}\033[0m/\033[1;34m\${disktotal}\033[0m (\033[0;33m\${diskusedper}\033[0m)"

# disk root
totaldisk_root=\$(df -h -x devtmpfs -x tmpfs -x debugfs -x aufs -x overlay --total 2>/dev/null | egrep -v Filesystem | head -n1)
disktotal_root=\$(awk '{print \$2}' <<< "\${totaldisk_root}")
diskused_root=\$(awk '{print \$3}' <<< "\${totaldisk_root}")
diskusedper_root=\$(awk '{print \$5}' <<< "\${totaldisk_root}")
DISK_INFO_ROOT="\033[0;33m\${diskused_root}\033[0m/\033[1;34m\${disktotal_root}\033[0m (\033[0;33m\${diskusedper_root}\033[0m)"

# cpu
cpu=\$(awk -F':' '/^model name/ {print \$2}' /proc/cpuinfo | uniq | sed -e 's/^[ \t]*//')
cpun=\$(grep -c '^processor' /proc/cpuinfo)
cpuc=\$(grep '^cpu cores' /proc/cpuinfo | tail -1 | awk '{print \$4}')
cpup=\$(grep '^physical id' /proc/cpuinfo | wc -l)
MODEL_NAME=\$cpu
CPU_INFO="\$(( cpun*cpuc ))(cores) \$(grep '^cpu MHz' /proc/cpuinfo | tail -1 | awk '{print \$4}')(MHz) \${cpup}P(physical) \${cpuc}C(cores) \${cpun}L(processor)"

# cpu usage
CPU_USAGE=\$(echo 100 - \$(top -b -n 1 | grep Cpu | awk '{print \$8}') | bc)

# get the load averages
read one five fifteen rest < /proc/loadavg
LOADAVG_INFO="\033[0;33m\${one}\033[0m(1min) \033[0;33m\${five}\033[0m(5min) \033[0;33m\${fifteen}\033[0m(15min)"

# mem
MEM_INFO="\$(cat /proc/meminfo | awk '/MemTotal:/{total=\$2/1024/1024;next} /MemAvailable:/{use=total-\$2/1024/1024; printf("\033[0;33m%.2fGiB\033[0m/\033[1;34m%.2fGiB\033[0m (\033[0;33m%.2f%%\033[0m)",use,total,(use/total)*100);}')"

# network
# extranet_ip=" and \$(curl -s ip.cip.cc)"
IP_INFO="\$(ip a | grep glo | awk '{print \$2}' | head -1 | cut -f1 -d/)\${extranet_ip:-}"

# Container info
CONTAINER_INFO=\$(sudo /usr/bin/crictl ps -a -o yaml 2> /dev/null | awk '/^  state: /{gsub("CONTAINER_", "", \$NF) ++S[\$NF]}END{for(m in S) printf "%s%s:%s ",substr(m,1,1),tolower(substr(m,2)),S[m]}')Images:\$(sudo /usr/bin/crictl images -q 2> /dev/null | wc -l)

# info
echo -e "
 Information as of: \033[1;34m\$(date +"%Y-%m-%d %T")\033[0m

 \033[0;1;31mProduct\033[0m............: \${MODEL_INFO}
 \033[0;1;31mOS\033[0m.................: \${PRETTY_NAME}
 \033[0;1;31mKernel\033[0m.............: \${KERNEL}
 \033[0;1;31mCPU Model Name\033[0m.....: \${MODEL_NAME}
 \033[0;1;31mCPU Cores\033[0m..........: \${CPU_INFO}

 \033[0;1;31mHostname\033[0m...........: \033[1;34m\$(hostname)\033[0m
 \033[0;1;31mIP Addresses\033[0m.......: \033[1;34m\${IP_INFO}\033[0m

 \033[0;1;31mUptime\033[0m.............: \033[0;33m\${UPTIME_INFO}\033[0m
 \033[0;1;31mMemory Usage\033[0m.......: \${MEM_INFO}
 \033[0;1;31mCPU Usage\033[0m..........: \033[0;33m\${CPU_USAGE}%\033[0m
 \033[0;1;31mLoad Averages\033[0m......: \${LOADAVG_INFO}
 \033[0;1;31mDisk Total Usage\033[0m...: \${DISK_INFO}
 \033[0;1;31mDisk Root Usage\033[0m....: \${DISK_INFO_ROOT}

 \033[0;1;31mUsers online\033[0m.......: \033[1;34m\${USER_NUM}\033[0m
 \033[0;1;31mRunning Processes\033[0m..: \033[1;34m\${RUNNING}\033[0m
 \033[0;1;31mContainer Info\033[0m.....: \${CONTAINER_INFO}
"
EOF

  chmod +x /etc/profile.d/ssh-login-info.sh
  echo 'ALL ALL=(ALL) NOPASSWD:/usr/bin/crictl' >/etc/sudoers.d/crictl

  # sync time
  local segment=$(ip route | grep kernel | awk '{print $1}' | head -1)
  timedatectl set-timezone Asia/Shanghai
  timedatectl set-local-rtc 1
  hwclock --systohc
  date
  hwclock -r

  [[ "${OFFLINE_TAG:-}" != "1" ]] && yum install -y chrony
  if [ "${host}" == "${MGMT_NODE}" ]; then
    cat <<EOF >/etc/chrony.conf
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
server ntp.aliyun.com iburst
server ${MGMT_NODE} iburst
allow ${segment}
local stratum 10
EOF
  else
    cat <<EOF >/etc/chrony.conf
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
server ${MGMT_NODE} iburst
#allow ${segment}
local stratum 10
EOF
  fi

  systemctl restart chronyd
  systemctl enable chronyd

  module=(
    ip_vs
    ip_vs_rr
    ip_vs_wrr
    ip_vs_sh
    overlay
    nf_conntrack
    br_netfilter
  )
  [ -f /etc/modules-load.d/ipvs.conf ] && cp -f /etc/modules-load.d/ipvs.conf{,_bak}
  for kernel_module in "${module[@]}"; do
    /sbin/modinfo -F filename "$kernel_module" |& grep -qv ERROR && echo "$kernel_module" >>/etc/modules-load.d/ipvs.conf
  done
  systemctl restart systemd-modules-load
  systemctl enable systemd-modules-load
  sysctl --system

  grep single-request-reopen /etc/resolv.conf || sed -i '1ioptions timeout:2 attempts:3 rotate single-request-reopen' /etc/resolv.conf

  ipvsadm --clear
  iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X
}

function script::upgrade_kernel() {
  # 升级内核
  grub2-set-default 0 && grub2-mkconfig -o /etc/grub2.cfg
  grubby --default-kernel
  grubby --args="user_namespace.enable=1" --update-kernel="$(grubby --default-kernel)"
}

function script::install_docker() {
  # 安装 docker

  local OFFLINE_TAG=${OFFLINE_TAG}
  [[ ! -f "/usr/bin/docker" ]] && {
    tar -zxvf ${OFFLINE_DIR}/packages/docker-v20.10.9.tar.gz -C /tmp
    cp -rvf /tmp/docker/* /usr/bin/
    mv /usr/bin/{docker.service,containerd.service} /etc/systemd/system/ || true
    rm -rf /tmp/docker
  }

  [ ! -d ${DOCKER_DATA_ROOT} ] && mkdir -p ${DOCKER_DATA_ROOT}
  [ ! -d /etc/docker ] && mkdir /etc/docker
  cat <<EOF >/etc/docker/daemon.json
{
  "bip": "10.0.0.1/16",
  "data-root": "${DOCKER_DATA_ROOT}",
  "features": { "buildkit": true },
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "200m",
    "max-file": "5"
  },
  "exec-opts": ["native.cgroupdriver=systemd"],
  "insecure-registries": ["0.0.0.0/0"],
  "registry-mirrors": [
    "https://xf9m4ezh.mirror.aliyuncs.com"
  ]
}
EOF
  cat <<EOF >/etc/crictl.yaml
runtime-endpoint: unix:///var/run/dockershim.sock
image-endpoint: unix:///var/run/dockershim.sock
timeout: 2
debug: false
pull-image-on-create: true
disable-pull-on-run: false
EOF
  systemctl daemon-reload

  systemctl enable containerd
  systemctl restart containerd

  systemctl enable docker
  systemctl restart docker

}

function script::install_kube() {
  # 安装kube组件

  local version="-${1:-latest}"
  version="${version#-latest}"

  [[ ! -f "/usr/local/bin/kubeadm" ]] && {
    ## 安装 kubeadm  kubectl  kubelet helm
    tar -zxvf ${OFFLINE_DIR}/packages/kubernetes-v1.21.3.tar.gz -C /tmp
    cp -rvf /tmp/kubernetes/* /usr/local/bin/
    mv /usr/local/bin/kubelet.service /etc/systemd/system/
    mkdir -p /etc/systemd/system/kubelet.service.d
    mv /usr/local/bin/10-kubeadm.conf /etc/systemd/system/kubelet.service.d
    rm -rf /tmp/kubernetes
  }
  [[ ! -f "/opt/cni/bin/" ]] && {
    ## 安装 cni-plugins
    mkdir -p /opt/cni/bin/
    tar -zxvf ${OFFLINE_DIR}/packages/cni-plugins-linux-amd64-v1.0.1.tgz -C /opt/cni/bin/
  }

  ## 添加命令自动补全
  [ -d /etc/bash_completion.d ] && {
    kubectl completion bash >/etc/bash_completion.d/kubectl
    kubeadm completion bash >/etc/bash_completion.d/kubadm
    helm completion bash >/etc/bash_completion.d/helm
  }
  ## 启动kubelet服务
  systemctl daemon-reload
  systemctl enable kubelet
  systemctl enable --now iscsid
}

function check::command_exists() {
  # 检查命令是否存在

  local cmd=${1}
  local package=${2}

  if command -V "$cmd" >/dev/null 2>&1; then
    log::info "[check]" "$cmd command exists."
  else
    log::warning "[check]" "I require $cmd but it's not installed."
    log::warning "[check]" "install $package package."
    command::exec "127.0.0.1" "yum install -y ${package}"
    check::exit_code "$?" "check" "$package install" "exit"
  fi
}

function check::command() {
  # 检查用到的命令

  #  check::command_exists ssh openssh-clients
  check::command_exists sshpass sshpass
  [[ "${INSTALL_TAG:-}" == "1" && "${KUBE_INSTALL_TAG:-}" == "1" && "${OFFLINE_TAG:-}" != "1" || "${ADD_TAG:-}" == "1" ]] && check::command_exists wget wget
  [[ "${OFFLINE_TAG:-}" == "1" ]] && check::command_exists rsync rsync
  #  [[ "${OFFLINE_TAG:-}" == "1" ]] && check::command_exists tar tar
}

function check::ssh_conn() {
  # 检查ssh连通性

  local OFFLINE_TAG=${OFFLINE_TAG:-}
  for host in $MASTER_NODES $WORKER_NODES; do
    [ "$host" == "127.0.0.1" ] && continue
    command::exec "${host}" "
      [[ "${OFFLINE_TAG}" == "1" ]] && rm -rf /etc/yum.repos.d/*
      echo 0
    "
    check::exit_code "$?" "check" "ssh $host connection" "exit"
  done
}

function check::ssh_conn_new() {
  # 检查ssh连通性

  for host in $MASTER_NODES $WORKER_NODES $HOST; do
    [ "$host" == "127.0.0.1" ] && continue
    command::exec "${host}" "
    sed -i -e 's/#UseDNS yes/UseDNS no/g' \
    -e 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/g' \
    /etc/ssh/sshd_config
    sed -i 's/#   StrictHostKeyChecking ask/   StrictHostKeyChecking no/g' /etc/ssh/ssh_config
    systemctl restart sshd || true
    "
    check::exit_code "$?" "check" "ssh $host connection"
  done
}

function check::ping_conn() {
  # ping 连通性

  for host in $MASTER_NODES $WORKER_NODES $HOST; do
    [ "$host" == "127.0.0.1" ] && continue
    ping $host -c 4 &>/dev/null
    check::exit_code "$?" "check" "ping $host connection"
  done

}

function check::system_metrics() {
  ## 输出系统各项指标

  for host in $HOST; do
    log::info "[check]" "check system metrics on $host"
    command::exec "${host}" "
      # os
      upSeconds=\"\$(cut -d. -f1 /proc/uptime)\"
      secs=\$((\${upSeconds}%60))
      mins=\$((\${upSeconds}/60%60))
      hours=\$((\${upSeconds}/3600%24))
      days=\$((\${upSeconds}/86400))
      UPTIME_INFO=\$(printf \"%d days, %02dh %02dm %02ds\" \"\$days\" \"\$hours\" \"\$mins\" \"\$secs\")

      if [ -f /etc/redhat-release ] ; then
          PRETTY_NAME=\$(< /etc/redhat-release)

      elif [ -f /etc/debian_version ]; then
         DIST_VER=\$(</etc/debian_version)
         PRETTY_NAME=\"\$(grep PRETTY_NAME /etc/os-release | sed -e 's/PRETTY_NAME=//g' -e  's/\"//g') (\$DIST_VER)\"

      else
          PRETTY_NAME=\$(cat /etc/*-release | grep \"PRETTY_NAME\" | sed -e 's/PRETTY_NAME=//g' -e 's/\"//g')
      fi

      if [[ -d \"/system/app/\" && -d \"/system/priv-app\" ]]; then
          model=\"\$(getprop ro.product.brand) \$(getprop ro.product.model)\"

      elif [[ -f /sys/devices/virtual/dmi/id/product_name ||
              -f /sys/devices/virtual/dmi/id/product_version ]]; then
          model=\"\$(< /sys/devices/virtual/dmi/id/product_name)\"
          model+=\" \$(< /sys/devices/virtual/dmi/id/product_version)\"

      elif [[ -f /sys/firmware/devicetree/base/model ]]; then
          model=\"\$(< /sys/firmware/devicetree/base/model)\"

      elif [[ -f /tmp/sysinfo/model ]]; then
          model=\"\$(< /tmp/sysinfo/model)\"
      fi

      MODEL_INFO=\${model}
      KERNEL=\$(uname -srmo)
      USER_NUM=\$(who -u | wc -l)
      RUNNING=\$(ps ax | wc -l | tr -d \" \")

      # disk total
      totaldisk=\$(df -h -x devtmpfs -x tmpfs -x debugfs -x aufs -x overlay --total 2>/dev/null | tail -1)
      disktotal=\$(awk '{print \$2}' <<< \"\${totaldisk}\")
      diskused=\$(awk '{print \$3}' <<< \"\${totaldisk}\")
      diskusedper=\$(awk '{print \$5}' <<< \"\${totaldisk}\")
      DISK_INFO=\"\033[0;33m\${diskused}\033[0m/\033[1;34m\${disktotal}\033[0m (\033[0;33m\${diskusedper}\033[0m)\"

      # disk root
      totaldisk_root=\$(df -h -x devtmpfs -x tmpfs -x debugfs -x aufs -x overlay --total 2>/dev/null | egrep -v Filesystem | head -n1)
      disktotal_root=\$(awk '{print \$2}' <<< \"\${totaldisk_root}\")
      diskused_root=\$(awk '{print \$3}' <<< \"\${totaldisk_root}\")
      diskusedper_root=\$(awk '{print \$5}' <<< \"\${totaldisk_root}\")
      DISK_INFO_ROOT=\"\033[0;33m\${diskused_root}\033[0m/\033[1;34m\${disktotal_root}\033[0m (\033[0;33m\${diskusedper_root}\033[0m)\"

      # cpu
      cpu=\$(awk -F':' '/^model name/ {print \$2}' /proc/cpuinfo | uniq | sed -e 's/^[ \t]*//')
      cpun=\$(grep -c '^processor' /proc/cpuinfo)
      cpuc=\$(grep '^cpu cores' /proc/cpuinfo | tail -1 | awk '{print \$4}')
      cpup=\$(grep '^physical id' /proc/cpuinfo | wc -l)
      MODEL_NAME=\$cpu
      CPU_INFO=\"\$(( cpun*cpuc ))(cores) \$(grep '^cpu MHz' /proc/cpuinfo | tail -1 | awk '{print \$4}')(MHz) \${cpup}P(physical) \${cpuc}C(cores) \${cpun}L(processor)\"

      # cpu usage
      CPU_USAGE=\$(echo 100 - \$(top -b -n 1 | grep Cpu | awk '{print \$8}') | bc)

      # get the load averages
      read one five fifteen rest < /proc/loadavg
      LOADAVG_INFO=\"\033[0;33m\${one}\033[0m(1min) \033[0;33m\${five}\033[0m(5min) \033[0;33m\${fifteen}\033[0m(15min)\"

      # mem
      MEM_INFO=\"\$(cat /proc/meminfo | awk '/MemTotal:/{total=\$2/1024/1024;next} /MemAvailable:/{use=total-\$2/1024/1024; printf(\"\033[0;33m%.2fGiB\033[0m/\033[1;34m%.2fGiB\033[0m (\033[0;33m%.2f%%\033[0m)\",use,total,(use/total)*100);}')\"

      # network
      # extranet_ip=\" and \$(curl -s ip.cip.cc)\"
      IP_INFO=\"\$(ip a | grep glo | awk '{print \$2}' | head -1 | cut -f1 -d/)\${extranet_ip:-}\"

      # info
      echo -e \"
       Information as of: \033[1;34m\$(date +\"%Y-%m-%d %T\")\033[0m

       \033[0;1;31mProduct\033[0m............: \${MODEL_INFO}
       \033[0;1;31mOS\033[0m.................: \${PRETTY_NAME}
       \033[0;1;31mKernel\033[0m.............: \${KERNEL}
       \033[0;1;31mCPU Model Name\033[0m.....: \${MODEL_NAME}
       \033[0;1;31mCPU Cores\033[0m..........: \${CPU_INFO}

       \033[0;1;31mHostname\033[0m...........: \033[1;34m\$(hostname)\033[0m
       \033[0;1;31mIP Addresses\033[0m.......: \033[1;34m\${IP_INFO}\033[0m

       \033[0;1;31mUptime\033[0m.............: \033[0;33m\${UPTIME_INFO}\033[0m
       \033[0;1;31mMemory Usage\033[0m.......: \${MEM_INFO}
       \033[0;1;31mCPU Usage\033[0m..........: \033[0;33m\${CPU_USAGE}%\033[0m
       \033[0;1;31mLoad Averages\033[0m......: \${LOADAVG_INFO}
       \033[0;1;31mDisk Total Usage\033[0m...: \${DISK_INFO}
       \033[0;1;31mDisk Root Usage\033[0m....: \${DISK_INFO_ROOT}

       \033[0;1;31mUsers online\033[0m.......: \033[1;34m\${USER_NUM}\033[0m
       \033[0;1;31mRunning Processes\033[0m..: \033[1;34m\${RUNNING}\033[0m
      \"
    "  && printf "%s \n" "${COMMAND_OUTPUT}" | tee -a ~/system_metrics.txt
    check::exit_code "$?" "check" "check system metrics on $host"
  done
  log::info "[generate]" "generate system metrics to ~/system_metrics.txt"
}

function check::time() {

  local segment=$(ip route | egrep -v docker0 | grep kernel | awk '{print $1}')
  timedatectl set-timezone Asia/Shanghai
  timedatectl set-local-rtc 1
  hwclock --systohc
  date
  hwclock -r
#  [[ "${OFFLINE_TAG}" != "1" ]] && yum -y install chrony

  if [ "${host}" == "${MGMT_NODE}" ]; then
    cat <<EOF >/etc/chrony.conf
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
server ntp.aliyun.com iburst
server ${MGMT_NODE} iburst
allow ${segment}
local stratum 10
EOF
  else
    cat <<EOF >/etc/chrony.conf
driftfile /var/lib/chrony/drift
makestep 1.0 3
rtcsync
logdir /var/log/chrony
server ${MGMT_NODE} iburst
#allow ${segment}
local stratum 10
EOF
  fi

  systemctl restart chronyd
  systemctl enable chronyd
}

function install::time() {
  MGMT_NODE=$(echo "${MASTER_NODES}" | awk '{print $1}')

  local servers="$MASTER_NODES $WORKER_NODES"

  for host in $servers; do
    # check chrony
    log::info "[create]" "create chrony on $host"
    command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0}
      export MGMT_NODE=${MGMT_NODE}
      export host=${host}
      $(declare -f script::stop_security)
      script::stop_security
      $(declare -f check::time)
      check::time
  "
    check::exit_code "$?" "create" "create chrony on $host"
  done
  log::info "[get]" "command: chronyc sources"
}

function install::ssh_keygen() {

  MGMT_NODE=$(echo "${MASTER_NODES}" | awk '{print $1}')
  # 生成秘钥
  command::exec "${MGMT_NODE}" "
    rm -rf ~/.ssh
    ssh-keygen -t rsa -P \"\" -f ~/.ssh/id_rsa -C \"2385569970@qq.com\"
    cat ~/.ssh/id_rsa.pub > ~/.ssh/authorized_keys
  "

  local servers="$MASTER_NODES $WORKER_NODES"
  for host in $servers; do
    # create ssh keygen
    command::exec "${host}" "
      sed -i \
      -e 's/#UseDNS yes/UseDNS no/g' \
      -e 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/g' \
      /etc/ssh/sshd_config
      sed -i 's/#   StrictHostKeyChecking ask/   StrictHostKeyChecking no/g' /etc/ssh/ssh_config
      systemctl restart sshd
    "
    log::info "[create]" "create ssh keygen $host"
    command::scp "${host}" "~/.ssh" "~/"
    check::exit_code "$?" "create" "create ssh keygen $host"
  done

  echo
}

function install::precondition() {

  MGMT_NODE=$(echo "${HOST}" | awk '{print $1}')
  for host in $MASTER_NODES $WORKER_NODES $HOST; do
    ## 配置前置条件
    log::info "[install]" "install precondition on $host."
    command::exec "${host}" "
      export MGMT_NODE=${MGMT_NODE}
      $(declare -f script::init_node)
      script::init_node
    "
    check::exit_code "$?" "install" "install precondition on $host"
  done

}

function check::apiserver_conn() {
  # 检查apiserver连通性

  command::exec "${MGMT_NODE}" "kubectl get node"
  check::exit_code "$?" "check" "conn apiserver" "exit"
}

function check::exit_code() {
  # 检查返回码

  local code=${1:-}
  local app=${2:-}
  local desc=${3:-}
  local exit_script=${4:-}

  if [[ "${code}" == "0" ]]; then
    log::info "[${app}]" "${desc} succeeded."
  else
    log::error "[${app}]" "${desc} failed."
    [[ "$exit_script" == "exit" ]] && exit "$code"
  fi
}

function check::preflight() {
  # 预检

  # check command
  DEPEND_INSTALL_TAG=${DEPEND_INSTALL_TAG:-0}
  [[ "${DEPEND_INSTALL_TAG}" != "1" ]] && check::command

  # check ssh conn
  check::ssh_conn

  # check os
  #  check::os

  # check apiserver conn
  if [[ $((${ADD_TAG:-0} + ${DEL_TAG:-0} + ${UPGRADE_TAG:-0} + ${RENEW_CERT_TAG:-0})) -gt 0 ]]; then
    check::apiserver_conn
  fi
}

function install::package() {
  # 安装包

  for host in $MASTER_NODES $WORKER_NODES; do
    # install docker
    log::info "[install]" "install ${KUBE_CRI} on $host."
    command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0}
      export DOCKER_DATA_ROOT=${DOCKER_DATA_ROOT}
      export OFFLINE_DIR=${OFFLINE_DIR}
      $(declare -f script::install_docker)
      script::install_docker
    "
    check::exit_code "$?" "install" "install ${KUBE_CRI} on $host"
  done

  # load and push images to registry
  [[ ${INSTALL_TAG:-} == "1" ]] && {
    log::info "[images]" "load and push images to registry on $MGMT_NODE_IP."
    command::exec "${MGMT_NODE_IP}" "
    [[ \$(docker images -qa | wc -l) == \"0\" ]] && docker load -i ${OFFLINE_DIR}/images/k8s-images.tar.gz
    [[ \$(docker ps -a | grep registry | wc -l) == \"0\" ]] && docker run -d -v /data/registry:/var/lib/registry -e REGISTRY_STORAGE_DELETE_ENABLED=true -p 5000:5000 --restart=always --privileged=true --name registry dockerhub.kubeeasy.local:5000/registry:2.7
    images=\$(cat ${OFFLINE_DIR}/images/images-list.txt)
    for image in \$images
    do
      nohup docker push \$image &> /dev/null &
    done
  "
    check::exit_code "$?" "images" "load and push images to registry on $host"
  }

  for host in $MASTER_NODES $WORKER_NODES; do
    # install kube
    log::info "[install]" "install kube on $host"
    command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0}
      export host=${host}
      export KUBE_APISERVER_PORT=${KUBE_APISERVER_PORT}
      export OFFLINE_DIR=${OFFLINE_DIR}
      $(declare -f script::install_kube)
      script::install_kube $KUBE_VERSION
    "
    check::exit_code "$?" "install" "install kube on $host"
  done

  local apiservers=$MASTER_NODES

  if [[ "$apiservers" == "127.0.0.1" ]]; then
    command::exec "${MGMT_NODE}" "ip -o route get to 8.8.8.8 | sed -n 's/.*src \([0-9.]\+\).*/\1/p'"
    get::command_output "apiservers" "$?"
  fi

  if [[ "${ADD_TAG:-}" == "1" ]]; then
    command::exec "${MGMT_NODE}" "
      kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{$.items[*].status.addresses[?(@.type==\"InternalIP\")].address}'
    "
    get::command_output "apiservers" "$?"
  fi
}

function init::upgrade_kernel() {
  # 升级节点内核

  [[ "${UPGRADE_KERNEL_TAG:-}" != "1" ]] && return

  for host in ${HOST}; do
    log::info "[init]" "upgrade kernel: $host"
    command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0}
      $(declare -f script::upgrade_kernel)
      script::upgrade_kernel
    "
    check::exit_code "$?" "init" "upgrade kernel $host" "exit"
  done
  for host in ${HOST}; do
    command::exec "${host}" "bash -c 'sleep 15 && reboot' &>/dev/null &"
    check::exit_code "$?" "reboot" "$host: wait for 15s to restart"
  done
  exit 0
}

function init::node_config() {
  # 初始化节点配置

  local master_index=${master_index:-1}
  local worker_index=${worker_index:-1}

  local VIRTUAL_IP=${VIRTUAL_IP:-}

  log::info "[get]" "Get $MGMT_NODE InternalIP."
  command::exec "${MGMT_NODE}" "
    ip -4 route get 8.8.8.8 2>/dev/null | head -1 | awk '{print \$7}'
  "
  get::command_output "MGMT_NODE_IP" "$?" "exit"
  log::info "[result]" "MGMT_NODE_IP is ${MGMT_NODE_IP}"

  local KUBE_APISERVER_IP="${MGMT_NODE}"
  # 判断是否有VIP
  [ "${VIRTUAL_IP}" != "" ] && KUBE_APISERVER_IP=${VIRTUAL_IP}

  # master
  for host in $MASTER_NODES; do
    log::info "[init]" "master: $host"
    command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0} KUBE_APISERVER=${KUBE_APISERVER}
      export host=${host} MGMT_NODE=${MGMT_NODE}
      $(declare -f script::init_node)
      script::init_node
   "
    check::exit_code "$?" "init" "init master $host"

    # 设置主机名和解析
    log::info "[init]" "master: $host set hostname and hosts"
    command::exec "${host}" "
      sed -i '/## kubeeasy managed/d' /etc/hosts
      cat << EOF >> /etc/hosts
## kubeeasy managed start
${KUBE_APISERVER_IP} $KUBE_APISERVER
${MGMT_NODE} dockerhub.kubeeasy.local
$(
      echo -e $node_hosts
    )
## kubeeasy managed end
EOF
      sed -i '/## kubeeasy managed start/,/## kubeeasy managed start/{/^$/d}' /etc/hosts
      sed -i '/127.0.0.1 temp/d' /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-master-node${master_index}
    "
    check::exit_code "$?" "init" "$host set hostname and hosts"

    master_index=$((master_index + 1))
  done

  # worker
  for host in $WORKER_NODES; do
    log::info "[init]" "worker: $host"
    command::exec "${host}" "
      export OFFLINE_TAG=${OFFLINE_TAG:-0} KUBE_APISERVER=${KUBE_APISERVER}
      export host=${host} MGMT_NODE=${MGMT_NODE}
      $(declare -f script::init_node)
      script::init_node
    "
    check::exit_code "$?" "init" "init worker $host"

    # 设置主机名和解析
    log::info "[init]" "master: $host set hostname and hosts"
    command::exec "${host}" "
      sed -i '/## kubeeasy managed/d' /etc/hosts
      cat << EOF >> /etc/hosts
## kubeeasy managed start
${KUBE_APISERVER_IP} $KUBE_APISERVER
${MGMT_NODE} dockerhub.kubeeasy.local
$(
      echo -e $node_hosts
    )
## kubeeasy managed end
EOF
      sed -i '/## kubeeasy managed start/,/## kubeeasy managed start/{/^$/d}' /etc/hosts
      sed -i '/127.0.0.1 temp/d' /etc/hosts
      hostnamectl set-hostname ${HOSTNAME_PREFIX}-worker-node${worker_index}
    "
    check::exit_code "$?" "init" "$host set hostname and hosts"
    worker_index=$((worker_index + 1))
  done
}

function init::node() {
  # 初始化节点

  init::upgrade_kernel

  local node_hosts=""
  local i=1
  for h in $MASTER_NODES; do
    node_hosts="${node_hosts}\n$h ${HOSTNAME_PREFIX}-master-node${i}"
    i=$((i + 1))
  done

  local i=1
  for h in $WORKER_NODES; do
    node_hosts="${node_hosts}\n$h ${HOSTNAME_PREFIX}-worker-node${i}"
    i=$((i + 1))
  done
  node_hosts="${node_hosts}"
  init::node_config
}

function init::add_node() {
  # 初始化添加的节点

  init::upgrade_kernel

  local master_index=0
  local worker_index=0
  local node_hosts=""
  local add_node_hosts="127.0.0.1 temp"

  command::exec "${MGMT_NODE}" "
    kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address } {end}' | awk '{print \$1}'
  "
  get::command_output "MGMT_NODE" "$?" "exit"

  # 获取现有集群节点主机名
  command::exec "${MGMT_NODE}" "
    kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {.metadata.name }\\n{end}'
  "
  get::command_output "node_hosts" "$?" "exit"

  for host in $MASTER_NODES $WORKER_NODES; do
    if [[ $node_hosts == *"$host"* ]]; then
      log::error "[init]" "The host $host is already in the cluster!"
      exit 1
    fi
  done

  if [[ "$MASTER_NODES" != "" ]]; then
    command::exec "${MGMT_NODE}" "
      kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{\$.items[*].metadata.name}' | grep -Eo '[0-9]+\$'
    "
    get::command_output "master_index" "$?" "exit"
    master_index=$((master_index + 1))
    local i=$master_index
    for host in $MASTER_NODES; do
      add_node_hosts="${add_node_hosts}\n${host:-} ${HOSTNAME_PREFIX}-master-node${i}"
      i=$((i + 1))
    done
  fi

  if [[ "$WORKER_NODES" != "" ]]; then
    command::exec "${MGMT_NODE}" "
      kubectl get node --selector='!node-role.kubernetes.io/master' -o jsonpath='{\$.items[*].metadata.name}' | grep -Eo '[0-9]+\$' || echo 0
    "
    get::command_output "worker_index" "$?" "exit"
    worker_index=$((worker_index + 1))
    local i=$worker_index
    for host in $WORKER_NODES; do
      add_node_hosts="${add_node_hosts}\n${host:-} ${HOSTNAME_PREFIX}-worker-node${i}"
      i=$((i + 1))
    done
  fi
  #向集群节点添加新增的节点主机名解析
  for host in $(echo -ne "$node_hosts" | awk '{print $1}'); do
    command::exec "${host}" "
       sed -E -i \"/## kubeeasy managed end/i $add_node_hosts\" /etc/hosts
       sed -i '/127.0.0.1 temp/d' /etc/hosts
     "
    check::exit_code "$?" "init" "$host add new node hosts"
  done

  node_hosts="${node_hosts}${add_node_hosts}"
  init::node_config
}

function kubeadm::init() {
  # 集群初始化
  local KUBE_PORT="6443"
  local VIRTUAL_IP=${VIRTUAL_IP:-}

  [ -n "${VIRTUAL_IP}" ] && KUBE_PORT=${KUBE_APISERVER_PORT}
  command::exec "${MGMT_NODE}" "
    # 标记是普通集群
    mkdir -p /root/.kubeeasy/
    echo \"ha=0\" > /root/.kubeeasy/cluster
    echo \"vip=0\" >> /root/.kubeeasy/cluster
    echo \"root_pass=${SSH_PASSWORD}\" >> /root/.kubeeasy/cluster
  "
  # 配置kube-vip yaml
  if [[ -n "${VIRTUAL_IP}" ]]; then
    command::exec "${MGMT_NODE}" "
    # 标记是HA集群
    mkdir -p /root/.kubeeasy/
    echo \"ha=1\" > /root/.kubeeasy/cluster
    echo \"vip=${VIRTUAL_IP}\" >> /root/.kubeeasy/cluster
    echo \"root_pass=${SSH_PASSWORD}\" >> /root/.kubeeasy/cluster
    "
    if [[ "${OFFLINE_TAG:-}" == "1" ]]; then
      log::info "[kube-vip]" "kube-vip init on ${MGMT_NODE}"
      command::exec "${MGMT_NODE}" "
        mkdir -p /etc/kubernetes/manifests
        \cp \"${TMP_DIR}/kubeeasy/manifests/kube-vip.yaml\" \"/etc/kubernetes/manifests/kube-vip.yaml\"
      "
      check::exit_code "$?" "kube-vip" "${MGMT_NODE}: kube-vip init" "exit"
    fi
    # 获取网卡名
    log::info "[init]" "Get ${MGMT_NODE} NIC Name."
    command::exec "${MGMT_NODE}" "
      ip -4 route get 8.8.8.8 2>/dev/null | head -1 | awk '{print \$5}'
    "
    get::command_output "nic_name" "$?" "exit"

    log::info "[set]" "set kube-vip.yaml nic&vip to ${MGMT_NODE}"
    command::exec "${MGMT_NODE}" "
      sed -i \"s#ens33#${nic_name}#g\" /etc/kubernetes/manifests/kube-vip.yaml
      sed -i \"s#192.168.200.10#${VIRTUAL_IP}#g\" /etc/kubernetes/manifests/kube-vip.yaml
    "
    check::exit_code "$?" "set" "${MGMT_NODE}: set kube-vip.yaml nic&vip" "exit"
  fi

  # 初始化k8s
  log::info "[kubeadm init]" "kubeadm init on ${MGMT_NODE}"
  log::info "[kubeadm init]" "${MGMT_NODE}: set kubeadm-config.yaml"
  command::exec "${MGMT_NODE}" "
    mkdir -p /etc/kubernetes/
    cat << EOF > /etc/kubernetes/kubeadm-config.yaml
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: InitConfiguration
${kubelet_nodeRegistration}
nodeRegistration:
  criSocket: /var/run/dockershim.sock
  kubeletExtraArgs:
    cgroup-driver: systemd
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
mode: ipvs
ipvs:
  minSyncPeriod: 5s
  syncPeriod: 5s
  scheduler: 'wrr'
---
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
cgroupDriver: systemd
maxPods: 200
featureGates:
  CSIStorageCapacity: true
  ExpandCSIVolumes: true
  RotateKubeletServerCertificate: true
  TTLAfterFinished: true
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: ClusterConfiguration
kubernetesVersion: $KUBE_VERSION
controlPlaneEndpoint: $KUBE_APISERVER:${KUBE_PORT}
networking:
  dnsDomain: $KUBE_DNSDOMAIN
  podSubnet: $KUBE_POD_SUBNET
  serviceSubnet: $KUBE_SERVICE_SUBNET
imageRepository: $KUBE_IMAGE_REPO
apiServer:
  certSANs:
  - 127.0.0.1
  - $KUBE_APISERVER
$(for h in $MASTER_NODES; do echo "  - $h"; done)
  extraArgs:
    event-ttl: '720h'
    service-node-port-range: '1024-65535'
  extraVolumes:
  - name: localtime
    hostPath: /etc/localtime
    mountPath: /etc/localtime
    readOnly: true
    pathType: File
controllerManager:
  extraArgs:
    bind-address: 0.0.0.0
    node-cidr-mask-size: '24'
    deployment-controller-sync-period: '10s'
    node-monitor-grace-period: '20s'
    pod-eviction-timeout: '2m'
    terminated-pod-gc-threshold: '30'
    experimental-cluster-signing-duration: 87600h
    feature-gates: RotateKubeletServerCertificate=true
  extraVolumes:
  - hostPath: /etc/localtime
    mountPath: /etc/localtime
    name: localtime
    readOnly: true
    pathType: File
scheduler:
  extraArgs:
    bind-address: 0.0.0.0
  extraVolumes:
  - hostPath: /etc/localtime
    mountPath: /etc/localtime
    name: localtime
    readOnly: true
    pathType: File
dns:
  type: CoreDNS
  imageRepository: dockerhub.kubeeasy.local:5000/kubernetes
  imageTag: 1.8.0
EOF
"
  check::exit_code "$?" "kubeadm init" "${MGMT_NODE}: set kubeadm-config.yaml" "exit"

  log::info "[kubeadm init]" "${MGMT_NODE}: kubeadm init start."
  command::exec "${MGMT_NODE}" "
    ## 判断是否已经初始
    kubectl cluster-info &> /dev/null || kubeadm init --config=/etc/kubernetes/kubeadm-config.yaml --upload-certs
  "
  check::exit_code "$?" "kubeadm init" "${MGMT_NODE}: kubeadm init" "exit"

  sleep 3

  log::info "[kubeadm init]" "${MGMT_NODE}: set kube config."
  command::exec "${MGMT_NODE}" "
     mkdir -p \$HOME/.kube
     sudo cp -f /etc/kubernetes/admin.conf \$HOME/.kube/config
  "
  check::exit_code "$?" "kubeadm init" "${MGMT_NODE}: set kube config"

  # 去除所有节点（包括master节点）的污点
  local KUBE_APISERVER_IP="${MGMT_NODE}"
  [ "${VIRTUAL_IP}" != "" ] && KUBE_APISERVER_IP=${VIRTUAL_IP}
  log::info "[kubeadm init]" "${MGMT_NODE}: delete master taint"
  command::exec "${MGMT_NODE}" "
    # 给master去除污点并打上worker标签
    sed -i 's#.*$KUBE_APISERVER#$KUBE_APISERVER_IP $KUBE_APISERVER#g' /etc/hosts
    kubectl taint nodes \$(hostname) node-role.kubernetes.io/master-
    kubectl label node \$(hostname) node-role.kubernetes.io/worker= --overwrite
  "
  check::exit_code "$?" "kubeadm init" "${MGMT_NODE}: delete master taint"

  command::exec "${MGMT_NODE}" "
    kubectl create clusterrolebinding node-client-auto-approve-csr --clusterrole=system:certificates.k8s.io:certificatesigningrequests:nodeclient --user=kubelet-bootstrap
    kubectl create clusterrolebinding node-client-auto-renew-crt --clusterrole=system:certificates.k8s.io:certificatesigningrequests:selfnodeclient --group=system:nodes
    kubectl create clusterrolebinding node-server-auto-renew-crt --clusterrole=system:certificates.k8s.io:certificatesigningrequests:selfnodeserver --group=system:nodes
  "
  check::exit_code "$?" "kubeadm init" "Auto-Approve kubelet cert csr"
}

function kubeadm::join() {
  # 加入集群
  local KUBE_PORT="6443"
  [ -n "${VIRTUAL_IP}" ] && KUBE_PORT=${KUBE_APISERVER_PORT}
  log::info "[kubeadm join]" "master: get join token and cert info"
  command::exec "${MGMT_NODE}" "
    openssl x509 -pubkey -in /etc/kubernetes/pki/ca.crt | openssl rsa -pubin -outform der 2>/dev/null | openssl dgst -sha256 -hex | sed 's/^.* //'
  "
  get::command_output "CACRT_HASH" "$?" "exit"

  command::exec "${MGMT_NODE}" "
    kubeadm init phase upload-certs --upload-certs --config /etc/kubernetes/kubeadm-config.yaml 2>> /dev/null | tail -1
  "
  get::command_output "INTI_CERTKEY" "$?" "exit"

  command::exec "${MGMT_NODE}" "
    kubeadm token create
  "
  get::command_output "INIT_TOKEN" "$?" "exit"

  # 配置kube-vip yaml
  command::exec "${MGMT_NODE}" "
    cat ~/.kubeeasy/cluster | grep \"ha\" | cut -d = -f 2
  "
  get::command_output "ha_tag" "$?" "exit"
  command::exec "${MGMT_NODE}" "
    cat ~/.kubeeasy/cluster | grep \"vip\" | cut -d = -f 2
  "
  get::command_output "vip" "$?" "exit"
  if [[ "${vip}" != "0" ]]; then
    # 拷贝kube-vip yaml
    for host in $MASTER_NODES; do
      [[ "${MGMT_NODE}" == "$host" ]] && continue
      log::info "[scp]" "scp kube-vip.yaml to ${host}"
      command::exec "${host}" "
        mkdir -p /etc/kubernetes/manifests
      "
      command::scp "${host}" "/etc/kubernetes/manifests/kube-vip.yaml" "/etc/kubernetes/manifests"
      command::scp "${host}" "/root/.kubeeasy/" "/root"
      check::exit_code "$?" "scp" "${host}: scp kube-vip.yaml" "exit"
    done
  fi

  # 修改kube-vip 网卡名和vip
  if [[ "${vip}" != "0" ]]; then
    for host in ${MASTER_NODES}; do
      [[ "${MGMT_NODE}" == "$host" ]] && continue
      # 获取网卡名
      log::info "[init]" "Get ${host} NIC Name."
      command::exec "${host}" "
        ip -4 route get 8.8.8.8 2>/dev/null | head -1 | awk '{print \$5}'
      "
      get::command_output "nic_name" "$?" "exit"

      log::info "[set]" "set kube-vip.yaml nic&vip to ${host}"
      command::exec "${host}" "
        sed -i \"s#ens33#${nic_name}#g\" /etc/kubernetes/manifests/kube-vip.yaml
        sed -i \"s#192.168.200.10#${vip}#g\" /etc/kubernetes/manifests/kube-vip.yaml
      "
      check::exit_code "$?" "set" "${host}: set kube-vip.yaml nic&vip" "exit"
    done
  fi

  for host in $MASTER_NODES; do
    [[ "${MGMT_NODE}" == "$host" ]] && continue
    # 加入k8s集群
    log::info "[kubeadm join]" "master $host join cluster."
    command::exec "${host}" "
      mkdir -p /etc/kubernetes/
      cat << EOF > /etc/kubernetes/kubeadm-config.yaml
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: JoinConfiguration
discovery:
  bootstrapToken:
    apiServerEndpoint: $KUBE_APISERVER:${KUBE_PORT}
    caCertHashes:
    - sha256:${CACRT_HASH:-}
    token: ${INIT_TOKEN}
  timeout: 5m0s
controlPlane:
  certificateKey: ${INTI_CERTKEY:-}
${kubelet_nodeRegistration}
EOF
      # 加入集群前，manifests目录必须为空
      mv /etc/kubernetes/manifests/kube-vip.yaml /tmp/kube-vip.yaml
      kubeadm join --config /etc/kubernetes/kubeadm-config.yaml
      mv /tmp/kube-vip.yaml /etc/kubernetes/manifests/kube-vip.yaml
    "
    check::exit_code "$?" "kubeadm join" "master $host join cluster"

    log::info "[kubeadm join]" "$host: set kube config."
    command::exec "${host}" "
      mkdir -p \$HOME/.kube
      sudo cp -f /etc/kubernetes/admin.conf \$HOME/.kube/config
    "
    check::exit_code "$?" "kubeadm join" "$host: set kube config"

    # 判断是否有VIP
    local KUBE_APISERVER_IP="${MGMT_NODE}"
    [ "${vip}" != "0" ] && KUBE_APISERVER_IP=${vip}
    command::exec "${host}" "
      sed -i 's#.*$KUBE_APISERVER#$KUBE_APISERVER_IP $KUBE_APISERVER#g' /etc/hosts
      # 给master去除污点并打上worker标签
      kubectl taint nodes \$(hostname) node-role.kubernetes.io/master-
      kubectl label node \$(hostname) node-role.kubernetes.io/worker= --overwrite
    "
  done

  for host in $WORKER_NODES; do
    local KUBE_APISERVER_IP="${MGMT_NODE}"
    [ "${vip}" != "0" ] && KUBE_APISERVER_IP=${vip}
    log::info "[kubeadm join]" "worker $host join cluster."
    command::exec "${host}" "
      sed -i 's#.*$KUBE_APISERVER#$KUBE_APISERVER_IP $KUBE_APISERVER#g' /etc/hosts
      mkdir -p /etc/kubernetes/manifests
      cat << EOF > /etc/kubernetes/kubeadm-config.yaml
---
apiVersion: kubeadm.k8s.io/v1beta2
kind: JoinConfiguration
discovery:
  bootstrapToken:
    apiServerEndpoint: $KUBE_APISERVER:${KUBE_PORT}
    caCertHashes:
    - sha256:${CACRT_HASH:-}
    token: ${INIT_TOKEN}
  timeout: 5m0s
${kubelet_nodeRegistration}
EOF
      kubeadm join --config /etc/kubernetes/kubeadm-config.yaml
    "
    check::exit_code "$?" "kubeadm join" "worker $host join cluster"

    log::info "[kubeadm join]" "set $host worker node role."
    command::exec "${MGMT_NODE}" "
      # node节点打标签
      kubectl get node --selector='!node-role.kubernetes.io/master' | grep '<none>' | awk '{print \"kubectl label node \" \$1 \" node-role.kubernetes.io/worker= --overwrite\" }' | bash
    "
    check::exit_code "$?" "kubeadm join" "set $host worker node role"
  done
}

function kube::wait() {
  # 等待资源完成

  local app=$1
  local namespace=$2
  local resource=$3
  local selector=${4:-}

  sleep 3
  log::info "[waiting]" "waiting $app"
  command::exec "${MGMT_NODE}" "
    $(declare -f utils::retry)
    utils::retry 6 kubectl wait --namespace ${namespace} \
    --for=condition=ready ${resource} \
    --selector=$selector \
    --timeout=60s
  "
  local status="$?"
  check::exit_code "$status" "waiting" "$app ${resource} ready"
  return "$status"
}

function kube::apply() {
  # 应用yaml

  local file=$1
  local info=$(echo $1 | awk -F "/" '{print $NF}')
  log::info "[apply]" "apply $info file"
  command::exec "${MGMT_NODE}" "
    $(declare -f utils::retry)
    if [ -f \"$file\" ]; then
      utils::retry 6 kubectl apply --wait=true --timeout=10s -f \"$file\"
    else
      utils::retry 6 \"cat <<EOF | kubectl apply --wait=true --timeout=10s -f -
\$(printf \"%s\" \"${2:-}\")
EOF
      \"
    fi
  "
  local status="$?"
  check::exit_code "$status" "apply" "apply $info file"
  return "$status"
}

function kube::status() {
  # 集群状态

  sleep 5
  log::info "[cluster]" "kubernetes cluster status"
  command::exec "${MGMT_NODE}" "
     echo '+ kubectl get node -o wide'
     kubectl get node -o wide
     echo '+ kubectl get pods -A -o wide'
     kubectl get pods -A -o wide
     echo ''
  " && printf "%s \n" "${COMMAND_OUTPUT}"

  curl 'https://oapi.dingtalk.com/robot/send?access_token=140115392d858fd1c456e943373adbf9f4f77c1c751ee171f711cd4ca8b681e2' \
    -H 'Content-Type: application/json' \
    -d '
  {"msgtype": "text",
    "text": {
        "content": "'"kubeeasy install info: ${COMMAND_OUTPUT}"'"
     },
    "at": {
	    "isAtAll": true
	  }
  }' &>/dev/null || true

}

function config::etcd_snapshot() {
  # 更新 etcd 备份副本

  command::exec "${MGMT_NODE}" "
    count=\$(kubectl get node --selector='node-role.kubernetes.io/master' --no-headers | wc -l)
    kubectl -n kube-system patch cronjobs etcd-snapshot --patch \"
spec:
  jobTemplate:
    spec:
      completions: \${count:-1}
      parallelism: \${count:-1}
\"
  "
  check::exit_code "$?" "config" "etcd-snapshot completions options"
}

function get::command_output() {
  # 获取命令的返回值

  local app="$1"
  local status="$2"
  local is_exit="${3:-}"

  if [[ "$status" == "0" && "${COMMAND_OUTPUT}" != "" ]]; then
    log::info "[result]" "get $app value succeeded."
    eval "$app=\"${COMMAND_OUTPUT}\""
  else
    log::error "[result]" "get $app value failed."
    [[ "$is_exit" == "exit" ]] && exit "$status"
  fi
  return "$status"
}

function add::network() {
  # 添加network组件

  local OFFLINE_TAG=${OFFLINE_TAG}
  local TMP_DIR=${TMP_DIR}

  if [[ "$KUBE_NETWORK" == "flannel" ]]; then
    log::info "[network]" "add flannel"

    local flannel_file="${OFFLINE_DIR}/manifests/kube-flannel.yml"
    utils::download_file "https://cdn.jsdelivr.net/gh/coreos/flannel@v${FLANNEL_VERSION}/Documentation/kube-flannel.yml" "${flannel_file}"

    command::exec "${MGMT_NODE}" "
      sed -i 's#10.244.0.0/16#$KUBE_POD_SUBNET#g' \"${flannel_file}\"
      sed -i 's#\"Type\": \"vxlan\"#\"Type\": \"${KUBE_FLANNEL_TYPE}\"#g' \"${flannel_file}\"
      if [[ \"${KUBE_FLANNEL_TYPE}\" == \"vxlan\" ]]; then
        sed -i 's#\"Type\": \"vxlan\"#\"Type\": \"vxlan\", \"DirectRouting\": true#g' \"${flannel_file}\"
      fi
    "
    check::exit_code "$?" "flannel" "change flannel pod subnet"
    kube::apply "${flannel_file}"
    kube::wait "flannel" "kube-system" "pods" "app=flannel"

  elif [[ "$KUBE_NETWORK" == "calico" ]]; then
    if [ "${OFFLINE_TAG}" == "1" ]; then
      log::info "[network]" "add calico network"
      local calico_file="${OFFLINE_DIR}/manifests/calico.yaml"
      command::exec "${MGMT_NODE}" "
        sed -i 's#10.244.0.0/16#$KUBE_POD_SUBNET#g' \"${calico_file}\"
      "
      check::exit_code "$?" "calico" "change calico pod subnet"
      kube::apply "${OFFLINE_DIR}/manifests/calico.yaml"
      kube::wait "calico-kube-controllers" "kube-system" "pods" "k8s-app=calico-kube-controllers"
      kube::wait "calico-node" "kube-system" "pods" "k8s-app=calico-node"
    else
      # 没有指定离线包就在线安装
      local calico_file="${TMP_DIR}/kubeeasy/manifests/calico.yaml"
      utils::download_file "${GITHUB_PROXY}https://raw.githubusercontent.com/kongyu666/kubeeasy/main/manifests/calico.yaml" "${calico_file}"
      log::info "[network]" "add calico network"
      command::exec "${MGMT_NODE}" "
        sed -i 's#10.244.0.0/16#$KUBE_POD_SUBNET#g' \"${calico_file}\"
      "
      check::exit_code "$?" "calico" "change calico pod subnet"
      kube::apply "${calico_file}"
      kube::wait "calico-kube-controllers" "kube-system" "pods" "k8s-app=calico-kube-controllers"
      kube::wait "calico-node" "kube-system" "pods" "k8s-app=calico-node"
    fi
  else
    log::warning "[network]" "No $KUBE_NETWORK config."
  fi
}

function add::storage() {
  # 添加存储
  local STORAGE_YAML_DIR="${TMP_DIR}/k8s-storage/deploy/"
  local NFS_YAML="${OFFLINE_DIR}/manifests/nfs-provisioner.yaml"
  local LOCAL_YAML="${OFFLINE_DIR}/manifests/localpv-provisioner.yaml"
  local LONGHORN_YAML="${TMP_DIR}/k8s-storage/deploy/longhorn/longhorn.yaml"
  local OPENEBS_YAML="${TMP_DIR}/k8s-storage/deploy/openebs/openebs-operator.yaml"

  if [[ "$KUBE_STORAGE" == "local" ]]; then
    # 添加nfs和openebs local存储类
    log::info "[storage]" "add local storage class"
    kube::apply "${LOCAL_YAML}"
    kube::wait "localpv-provisioner" "kube-system" "pods" "app=localpv-provisioner"

  elif [[ "$KUBE_STORAGE" == "openebs" ]]; then
    # 添加openebs存储类
    log::info "[storage]" "add openebs storage class"
    [[ -f "${OPENEBS_YAML}" ]] || utils::download_file "${GITHUB_PROXY}https://raw.githubusercontent.com/kongyu666/kubeeasy/main/k8s-storage/deploy/openebs/openebs-operator.yaml" "${OPENEBS_YAML}"
    kube::apply "${OPENEBS_YAML}"
    kube::wait "openebs-provisioner" "openebs" "pods" "name=openebs-provisioner"
    sleep 5
    log::info "[cluster]" "kubernetes storage status"
    command::exec "${MGMT_NODE}" "
       echo '+ kubectl get pod -n openebs -o wide'
       kubectl get pod -n openebs -o wide
       echo '+ kubectl get storageclasses.storage.k8s.io'
       kubectl get storageclasses.storage.k8s.io
       echo ''
    " && printf "%s \n" "${COMMAND_OUTPUT}"

  elif [[ "$KUBE_STORAGE" == "longhorn" ]]; then
    # 添加longhorn存储类
    log::info "[storage]" "add longhorn storage class"
    [[ -f "${LONGHORN_YAML}" ]] || utils::download_file "${GITHUB_PROXY}https://raw.githubusercontent.com/kongyu666/kubeeasy/main/k8s-storage/deploy/longhorn/longhorn.yaml" "${LONGHORN_YAML}"
    kube::apply "${LONGHORN_YAML}"
    kube::wait "csi-provisioner" "longhorn-system" "pods" "app=csi-provisioner"
    sleep 5
    log::info "[cluster]" "kubernetes storage status"
    command::exec "${MGMT_NODE}" "
       echo '+ kubectl get pod -n longhorn-system -o wide'
       kubectl get pod -n longhorn-system -o wide
       echo '+ kubectl get storageclasses.storage.k8s.io'
       kubectl get storageclasses.storage.k8s.io
       echo ''
    " && printf "%s \n" "${COMMAND_OUTPUT}"

  else
    log::warning "[storage]" "No $KUBE_STORAGE config."
  fi
}

function add::ui() {
  # 添加用户界面
  local OFFLINE_TAG=${OFFLINE_TAG}
  local TMP_DIR=${TMP_DIR}

  if [[ "$KUBE_UI" == "kuboard" ]]; then
    log::info "[ui]" "add kuboard"
    local kuboard_file="${TMP_DIR}/kubeeasy/manifests/kuboard-v2.yaml"
    local metrics_file="${TMP_DIR}/kubeeasy/manifests/metrics-server.yaml"
    [[ -f "${kuboard_file}" ]] || utils::download_file "${GITHUB_PROXY}https://raw.githubusercontent.com/kongyu666/kubeeasy/main/manifests/kuboard-v2.yaml" "${kuboard_file}"
    [[ -f "${metrics_file}" ]] || utils::download_file "${GITHUB_PROXY}https://raw.githubusercontent.com/kongyu666/kubeeasy/main/manifests/metrics-server.yaml" "${metrics_file}"
    kube::apply "${OFFLINE_DIR}/manifests/kuboard-v2.yaml"
    kube::apply "${OFFLINE_DIR}/manifests/metrics-server.yaml"
    kube::wait "kuboard" "kube-system" "pods" "k8s.kuboard.cn/name=kuboard"
    kube::wait "metrics-server" "kube-system" "pods" "k8s-app=metrics-server"
    local dashboard_token=""
    command::exec "${MGMT_NODE}" "
      kubectl -n kube-system get secret \$(kubectl -n kube-system get secret | grep kuboard-user | awk '{print \$1}') -o go-template='{{.data.token}}' | base64 -d | tee -a ~/k8s-token.txt
    "
    get::command_output "dashboard_token" "$?"
    local node_ip=${MGMT_NODE}
    [ -n "${VIRTUAL_IP}" ] && node_ip=${VIRTUAL_IP}
    log::access "[kuboard]" "http://${node_ip}:32567"
    log::access "[Token]" "${dashboard_token}"
  elif [[ "$KUBE_UI" == "kubesphere" ]]; then
    log::info "[ui]" "add kubesphere"
    local cluster_configuration="${TMP_DIR}/kubesphere/deploy/cluster-configuration.yaml"
    local kubesphere_installer="${TMP_DIR}/kubesphere/deploy/kubesphere-installer.yaml"
    [[ -f "${cluster_configuration}" ]] || utils::download_file "${GITHUB_PROXY}https://raw.githubusercontent.com/kongyu666/kubeeasy/main/kubesphere/deploy/cluster-configuration.yaml" "${cluster_configuration}"
    [[ -f "${kubesphere_installer}" ]] || utils::download_file "${GITHUB_PROXY}https://raw.githubusercontent.com/kongyu666/kubeeasy/main/kubesphere/deploy/kubesphere-installer.yaml" "${kubesphere_installer}"
    kube::apply "${TMP_DIR}/kubesphere/deploy/kubesphere-installer.yaml"
    kube::apply "${TMP_DIR}/kubesphere/deploy/cluster-configuration.yaml"
    sleep 60
    kube::wait "ks-installer" "kubesphere-system" "pods" "app=ks-install"
    kube::wait "kubesphere-system" "kubesphere-system" "pods --all"
    kube::wait "kubesphere-controls-system" "kubesphere-controls-system" "pods --all"
    kube::wait "kubesphere-monitoring-system" "kubesphere-monitoring-system" "pods --all"
    if [[ "$?" == "0" ]]; then
      command::exec "${MGMT_NODE}" "
        kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address } {end}' | awk '{print \$1}'
      "
      get::command_output "node_ip" "$?"
      log::access "[kubesphere]" "Console: http://${node_ip:-NodeIP}:30880;  Account: admin; Password: P@88w0rd"
    fi
  else
    log::warning "[ui]" "No $KUBE_UI config."
  fi
}

function add::virt() {
  # 添加kubevirt
  local TMP_DIR=${TMP_DIR}

  if [[ "$KUBE_VIRT" == "kubevirt" ]]; then
    log::info "[virt]" "add kubevirt"
    local kubevirt_operator="${TMP_DIR}/kubevirt/deploy/kubevirt-operator.yaml"
    local kubevirt_cr="${TMP_DIR}/kubevirt/deploy/kubevirt-cr.yaml"
    local multus_daemonset="${TMP_DIR}/kubevirt/deploy/multus-daemonset.yml"
    local multus_cni_macvlan="${TMP_DIR}/kubevirt/deploy/multus-cni-macvlan.yaml"
    [[ -f "${kubevirt_operator}" ]] || utils::download_file "${GITHUB_PROXY}https://raw.githubusercontent.com/kongyu666/kubeeasy/main/kubevirt/deploy/kubevirt-operator.yaml" "${kubevirt_operator}"
    [[ -f "${kubevirt_cr}" ]] || utils::download_file "${GITHUB_PROXY}https://raw.githubusercontent.com/kongyu666/kubeeasy/main/kubevirt/deploy/kubevirt-cr.yaml" "${kubevirt_cr}"
    [[ -f "${multus_daemonset}" ]] || utils::download_file "${GITHUB_PROXY}https://raw.githubusercontent.com/kongyu666/kubeeasy/main/kubevirt/deploy/multus-daemonset.yml" "${multus_daemonset}"
    [[ -f "${multus_cni_macvlan}" ]] || utils::download_file "${GITHUB_PROXY}https://raw.githubusercontent.com/kongyu666/kubeeasy/main/kubevirt/deploy/multus-cni-macvlan.yaml" "${multus_cni_macvlan}"

    kube::apply "${kubevirt_operator}"
    kube::wait "kubevirt" "kubevirt" "pods" "kubevirt.io=virt-operator"
    kube::apply "${kubevirt_cr}"
    sleep 30
    kube::wait "kubevirt" "kubevirt" "pods" "kubevirt.io=virt-api"
    kube::wait "kubevirt" "kubevirt" "pods" "kubevirt.io=virt-controller"
    kube::wait "kubevirt" "kubevirt" "pods" "kubevirt.io=virt-handler"

    kube::apply "${multus_daemonset}"
    kube::wait "kube-multus" "kube-system" "pods" "app=multus"
    kube::apply "${multus_cni_macvlan}"

    log::info "[cluster]" "kubernetes kubevirt status"
    command::exec "${MGMT_NODE}" "
       echo '+ kubectl get pod -n kubevirt -o wide'
       kubectl get pod -n kubevirt -o wide
       echo ''
    " && printf "%s \n" "${COMMAND_OUTPUT}"

  elif [[ "$KUBE_VIRT" == "kata" ]]; then
    echo "none."
  else
    log::warning "[ui]" "No $KUBE_UI config."
  fi
}

function reset::node() {
  # 重置节点

  local host=$1
  log::info "[reset]" "node $host"
  command::exec "${host}" "
    set +ex
    kubeadm reset -f
    [ -f \"\$(which kubelet)\" ] && { systemctl stop kubelet; find /var/lib/kubelet | xargs -n 1 findmnt -n -o TARGET -T | sort | uniq | xargs -r umount -v; rm -rf /usr/local/bin/{kubeadm,kubelet,kubectl,helm}; }
    [ -d /etc/kubernetes ] && rm -rf /etc/kubernetes/* /var/lib/kubelet/* /var/lib/etcd/* \$HOME/.kube /etc/cni/net.d/* /var/lib/dockershim/* /var/lib/cni/* /var/run/kubernetes/*
    docker_data_dir=\$(cat /etc/docker/daemon.json | grep data-root | awk -F '\"' '{print \$4}')
    [ -f \"\$(which docker)\" ] && { docker rm -f -v \$(docker ps | grep kube | awk '{print \$1}'); systemctl stop docker; rm -rf \$HOME/.docker /etc/docker/* /var/lib/docker/* \${docker_data_dir} /usr/bin/{containerd,containerd-shim,containerd-shim-runc-v2,ctr,docker,docker-compose,dockerd,docker-init,docker-proxy,runc};}
    [ -f \"\$(which containerd)\" ] && { crictl rm \$(crictl ps -a -q); systemctl stop containerd; rm -rf /etc/containerd/* /var/lib/containerd/*; }
    hostnamectl set-hostname localhost
    systemctl disable kubelet docker containerd && rm -rf /etc/systemd/system/{docker.service,containerd.service} /etc/systemd/system/kubelet.service*
    rm -rf /opt/cni /data/registry /opt/containerd/ /root/.kubeeasy ${TMP_DIR}/kubeeasy /root/k8s-token.txt
    sed -i -e \"/${KUBE_APISERVER}/d\" -e '/worker/d' -e '/master/d' -e "/^$/d"  -e '/dockerhub.kubeeasy.local/d' /etc/hosts
    rm -rf /etc/profile.d/ssh-login-info.sh
    sed -i '/## kubeeasy managed start/,/## kubeeasy managed end/d' /etc/hosts /etc/security/limits.conf /etc/systemd/system.conf /etc/bashrc /etc/rc.local /etc/audit/rules.d/audit.rules
    ipvsadm --clear
    iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X
    for int in kube-ipvs0 cni0 docker0 dummy0 flannel.1 cilium_host cilium_net cilium_vxlan lxc_health nodelocaldns 
    do
      [ -d /sys/class/net/\${int} ] && ip link delete \${int}
    done
    modprobe -r ipip
    echo done.
  "
  check::exit_code "$?" "reset" "$host: reset"

}

function reset::cluster() {
  # 重置所有节点

  while true; do
    read -p "Are you sure to reset this cluster? [yes/no]:" result
    case $result in
    yes | y | YES | Y)
      break
      ;;
    no | n | NO | N)
      exit 0
      break
      ;;
    *)
      echo "yes/no ?"
      ;;
    esac
  done

  local all_node=""

  command::exec "${MGMT_NODE}" "
    kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {end}'
  "
  get::command_output "all_node" "$?"
  log::info "[reset]" "all_node is ${all_node}"

  all_node=$(echo "${WORKER_NODES} ${MASTER_NODES} ${all_node}" | awk '{for (i=1;i<=NF;i++) if (!a[$i]++) printf("%s%s",$i,FS)}')

  for host in $all_node; do
    reset::node "$host"
  done

  # 重置完后重启主机
  for host in $all_node; do
    command::exec "${host}" "bash -c 'sleep 15 && reboot' &>/dev/null &"
    check::exit_code "$?" "reboot" "$host: wait for 15s to restart"
  done

}

function reset::cluster_force() {
  # 强制重置指定节点

  while true; do
    read -p "Are you sure to reset this node? [yes/no]:" result
    case $result in
    yes | y | YES | Y)
      break
      ;;
    no | n | NO | N)
      exit 0
      break
      ;;
    *) ;;

    esac
  done

  local all_node=""
  local HOSTNAME_PREFIX=${HOSTNAME_PREFIX:-}

  #  command::exec "${MGMT_NODE}" "
  #    [ -n \"$(cat /etc/hosts | egrep ${HOSTNAME_PREFIX})\" ] && cat /etc/hosts | egrep ${HOSTNAME_PREFIX} | awk '{print \$1}' 2> /dev/null ; echo 127.0.0.1
  #  "
  #  get::command_output "all_node" "$?"
  #
  #  all_node=$(echo ${all_node} | sed 's#127.0.0.1##g')
  #
  #  [ "${all_node}" == "" -o "${all_node}" == "127.0.0.1" ] && all_node=$(echo "${WORKER_NODES} ${MASTER_NODES}" | awk '{for (i=1;i<=NF;i++) if (!a[$i]++) printf("%s%s",$i,FS)}')

  all_node=$(echo "${WORKER_NODES} ${MASTER_NODES}" | awk '{for (i=1;i<=NF;i++) if (!a[$i]++) printf("%s%s",$i,FS)}')
  log::info "[reset]" "reset node is ${all_node}"
  for host in $all_node; do
    reset::node "$host"
  done

  for host in $all_node; do
    command::exec "${host}" "bash -c 'sleep 15 && reboot' &>/dev/null &"
    check::exit_code "$?" "reboot" "$host: wait for 15s to restart"
  done

}

function offline::load() {
  # 节点加载离线包

  local role="${1:-}"
  local hosts=""
  local UPGRADE_KERNEL_TAG="${UPGRADE_KERNEL_TAG:-0}"
  local OFFLINE_DIR="${TMP_DIR}/kubeeasy"

  if [[ "${role}" == "master" ]]; then
    hosts="${MASTER_NODES}"
  elif [[ "${role}" == "worker" ]]; then
    hosts="${WORKER_NODES}"
  fi

  for host in ${hosts}; do
    # 分发离线包到节点
    log::info "[offline]" "${role} ${host}: load offline file"
    #    command::exec "${host}" "mkdir -p ${OFFLINE_DIR}"
    ## 优化ssh
    command::exec "${host}" "
    sed -i -e 's/#UseDNS yes/UseDNS no/g' \
    -e 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/g' \
    /etc/ssh/sshd_config
    sed -i 's/#   StrictHostKeyChecking ask/   StrictHostKeyChecking no/g' /etc/ssh/ssh_config
    systemctl restart sshd
    "
    command::scp "${host}" "${OFFLINE_DIR}" "${TMP_DIR}"
    check::exit_code "$?" "offline" "load offline file to $host" "exit"
  done
}

function offline::cluster() {
  # 集群节点加载离线包

  [ ! -f "${OFFLINE_FILE}" ] && {
    log::error "[offline]" "not found ${OFFLINE_FILE}"
    exit 1
  }

  log::info "[offline]" "unzip offline package on local."
  [[ ! -d "${TMP_DIR}/kubeeasy" ]] && tar -zxf "${OFFLINE_FILE}" -C "${TMP_DIR}/" || true
  check::exit_code "$?" "offline" "unzip offline package"

  offline::load "master"
  offline::load "worker"
}

function offline::load_depend() {
  # 节点加载离线包

  local hosts="${HOST}"
  local RPMS_DIR=""
  RPMS_DIR="/tmp/centos-7-rpms"

  for host in ${hosts}; do
    # 优化ssh
    command::exec "${host}" "
      sed -i -e 's/#UseDNS yes/UseDNS no/g' \
      -e 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/g' \
      /etc/ssh/sshd_config
      sed -i 's/#   StrictHostKeyChecking ask/   StrictHostKeyChecking no/g' /etc/ssh/ssh_config
      systemctl restart sshd
    "
    # 分发离线包到节点
    log::info "[offline]" "${host}: load offline dependencies file"
    command::scp "${host}" "${RPMS_DIR}" "${TMP_DIR}"
    check::exit_code "$?" "offline" "load offline dependencies file to $host" "exit"

    # 安装依赖包
    log::info "[install]" "${host}: install dependencies packages in nohup"
    command::exec "${host}" "
      rm -rf /etc/yum.repos.d/*
      rpms=\$(ls ${RPMS_DIR} | grep -v repodata)
      mkdir -p /tmp/pid_temp/
      index=1
      for rpm in \${rpms}
      do
        nohup yum localinstall -y --skip-broken ${RPMS_DIR}/\${rpm}/*.rpm &> /dev/null &
        echo \$! > /tmp/pid_temp/temp\${index}.pid
        ((index++))
      done
    "
    check::exit_code "$?" "install" "${host}: install dependencies packages in nohup" "exit"
  done

  ## 等待后台任务执行完毕
  for host in ${hosts}; do
    log::info "[waiting]" "waiting dependencies job $host"
    command::exec "${host}" "
      for pidfile in \$(ls /tmp/pid_temp/*.pid)
      do
        tail --pid=\$(cat \$pidfile) -f /dev/null
      done
    "
    check::exit_code "$?" "waiting" "waiting dependencies job $host"
  done

  ## 清除临时文件
  for host in ${hosts}; do
    command::exec "${host}" "
      rm -rf ${RPMS_DIR} /tmp/pid_temp
    "
  done
}

function offline::cluster_depend() {
  # 集群节点加载离线包
  OFFLINE_FILE="${OFFLINE_FILE:-}"
  [ ! -f "${OFFLINE_FILE}" ] && {
    log::error "[offline]" "not found ${OFFLINE_FILE}"
    exit 1
  }

  log::info "[offline]" "unzip offline dependencies package on local."
  [[ ! -d "/tmp/centos-7-rpms" ]] && tar -zxf "${OFFLINE_FILE}" -C /tmp || true
  check::exit_code "$?" "offline" "unzip offline dependencies package"

  log::info "[install]" "install sshpass packages on local."
  rm -rf /etc/yum.repos.d/*
  [[ ! -f "/usr/bin/sshpass" ]] && yum localinstall -y --skip-broken /tmp/centos-7-rpms/system-base/sshpass-*.rpm &>$LOG_FILE || true
  check::exit_code "$?" "install" "install sshpass packages"

  offline::load_depend

  [[ -d "/tmp/centos-7-rpms" ]] && rm -rf /tmp/centos-7-rpms
}

function offline::load_kernel() {
  # 节点加载离线包

  local hosts="${HOST}"
  local RPMS_DIR=""
  RPMS_DIR="/tmp/kernel-rpms"

  for host in ${hosts}; do
    # 优化ssh
    command::exec "${host}" "
      sed -i -e 's/#UseDNS yes/UseDNS no/g' \
      -e 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/g' \
      /etc/ssh/sshd_config
      sed -i 's/#   StrictHostKeyChecking ask/   StrictHostKeyChecking no/g' /etc/ssh/ssh_config
      systemctl restart sshd
    "
    # 分发离线包到节点
    log::info "[offline]" "${host}: load offline kernel file"
    command::scp "${host}" "${RPMS_DIR}" "${TMP_DIR}"
    check::exit_code "$?" "offline" "load offline kernel file to $host" "exit"

    # 安装依赖包
    log::info "[install]" "${host}: install kernel packages in nohup"
    command::exec "${host}" "
      rm -rf /etc/yum.repos.d/*
      mkdir -p /tmp/pid_temp/
      index=1
      nohup yum localinstall -y --skip-broken ${RPMS_DIR}/*.rpm &> /dev/null &
      echo \$! > /tmp/pid_temp/temp\${index}.pid
    "
    check::exit_code "$?" "install" "${host}: install kernel packages in nohup" "exit"
  done

  ## 等待后台任务执行完毕
  for host in ${hosts}; do
    log::info "[waiting]" "waiting kernel job $host"
    command::exec "${host}" "
      for pidfile in \$(ls /tmp/pid_temp/*.pid)
      do
        tail --pid=\$(cat \$pidfile) -f /dev/null
      done
    "
    check::exit_code "$?" "waiting" "waiting kernel job $host"
  done

  ## 清除临时文件
  for host in ${hosts}; do
    command::exec "${host}" "
      rm -rf ${RPMS_DIR} /tmp/pid_temp
    "
  done
}

function offline::cluster_kernel() {
  # 集群节点加载离线包
  OFFLINE_FILE="${OFFLINE_FILE:-}"
  [ ! -f "${OFFLINE_FILE}" ] && {
    log::error "[offline]" "not found ${OFFLINE_FILE}"
    exit 1
  }

  log::info "[offline]" "unzip offline kernel package on local."
  [[ ! -d "/tmp/kernel-rpms" ]] && tar -zxf "${OFFLINE_FILE}" -C /tmp || true
  check::exit_code "$?" "offline" "unzip offline kernel package"

  offline::load_kernel

  [[ -d "/tmp/kernel-rpms" ]] && rm -rf /tmp/kernel-rpms
}

function offline::load_images() {
  # 专门用于集群分发并读取容器镜像

  local hosts="${MASTER_NODES} ${WORKER_NODES} ${HOST}"
  local IMAGE_FILE=""
  IMAGE_FILE="${OFFLINE_FILE}"

  for host in ${hosts}; do
    # 分发离线镜像包到节点
    log::info "[offline]" "${host}: load offline images file"
    command::rsync "${host}" "${IMAGE_FILE}" "${TMP_DIR}"
    check::exit_code "$?" "offline" "load offline images file to $host" "exit"

    # 读取容器镜像
    log::info "[load]" "${host}: load images in nohup"
    command::exec "${host}" "
      mkdir -p /tmp/pid_temp/
      index=1
      ## 读取镜像
      nohup docker load -i ${TMP_DIR}/${IMAGE_FILE} &> /dev/null &
      echo \$! > /tmp/pid_temp/temp\${index}.pid
    "
    check::exit_code "$?" "load" "${host}: load images in nohup" "exit"
  done

  ## 等待后台任务执行完毕
  for host in ${hosts}; do
    log::info "[waiting]" "waiting load images job $host"
    command::exec "${host}" "
      for pidfile in \$(ls /tmp/pid_temp/*.pid)
      do
        tail --pid=\$(cat \$pidfile) -f /dev/null
      done
    "
    check::exit_code "$?" "waiting" "waiting load images job $host"
  done

  ## 清除临时文件
  for host in ${hosts}; do
    command::exec "${host}" "
      rm -rf ${TMP_DIR}/${IMAGE_FILE} /tmp/pid_temp
    "
  done
}

function offline::cluster_images() {
  # 专门用于集群分发并读取容器镜像
  OFFLINE_FILE="${OFFLINE_FILE:-}"

  [ ! -f "${OFFLINE_FILE}" ] && {
    log::error "[offline]" "not found ${OFFLINE_FILE}"
    exit 1
  }

  offline::load_images
}

function init::cluster() {
  # 初始化集群

  MGMT_NODE=$(echo "${MASTER_NODES}" | awk '{print $1}')

  # 加载离线包
  [[ "${OFFLINE_TAG:-}" == "1" ]] && offline::cluster

  # 1. 初始化节点
  init::node
  # 2. 安装包
  install::package
  # 3. 初始化kubeadm
  kubeadm::init
  # 4. 加入集群
  kubeadm::join
  # 5. 添加network
  add::network
  # 6. 添加web ui
  add::ui
  # 7. 添加storage
  add::storage
  # 8. 查看集群状态
  kube::status
}

function add::node() {
  # 添加节点

  # 加载离线包
  [[ "${OFFLINE_TAG:-}" == "1" ]] && offline::cluster

  # KUBE_VERSION未指定时，获取集群的版本
  if [[ "${KUBE_VERSION}" == "" || "${KUBE_VERSION}" == "latest" ]]; then
    command::exec "${MGMT_NODE}" "
      kubectl get node --selector='node-role.kubernetes.io/master' -o jsonpath='{range.items[*]}{.status.nodeInfo.kubeletVersion } {end}' | awk -F'v| ' '{print \$2}'
  "
    get::command_output "KUBE_VERSION" "$?" "exit"
  fi

  # 1. 初始化节点
  init::add_node
  # 2. 安装包
  install::package
  # 3. 加入集群
  kubeadm::join
}

function del::node() {
  # 删除节点
  local cluster_nodes=""
  local del_hosts_cmd=""
  command::exec "${MGMT_NODE}" "
     kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {end}'
  "
  get::command_output "cluster_nodes_temp" "$?" exit
  log::info "[result]" "cluster_nodes is $cluster_nodes_temp"

  command::exec "${MGMT_NODE}" "
     kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {.metadata.name }\\n{end}'
  "
  get::command_output "cluster_nodes" "$?" exit

  # 确认是否删除
  while true; do
    read -p "Are you sure to delete this node? [yes/no]:" result
    case $result in
    yes | y | YES | Y)
      break
      ;;
    no | n | NO | N)
      exit 0
      break
      ;;
    *) ;;

    esac
  done

  for host in $MASTER_NODES; do
    command::exec "${MGMT_NODE}" "
       etcd_pod=\$(kubectl -n kube-system get pods -l component=etcd --field-selector=status.phase=Running -o jsonpath='{\$.items[0].metadata.name}')
       etcd_node=\$(kubectl -n kube-system exec \$etcd_pod -- sh -c \"export ETCDCTL_API=3 ETCDCTL_CACERT=/etc/kubernetes/pki/etcd/ca.crt ETCDCTL_CERT=/etc/kubernetes/pki/etcd/server.crt ETCDCTL_KEY=/etc/kubernetes/pki/etcd/server.key ETCDCTL_ENDPOINTS=https://127.0.0.1:2379; etcdctl member list\"| grep $host | awk -F, '{print \$1}')
       echo \"\$etcd_pod \$etcd_node\"
       kubectl -n kube-system exec \$etcd_pod -- sh -c \"export ETCDCTL_API=3 ETCDCTL_CACERT=/etc/kubernetes/pki/etcd/ca.crt ETCDCTL_CERT=/etc/kubernetes/pki/etcd/server.crt ETCDCTL_KEY=/etc/kubernetes/pki/etcd/server.key ETCDCTL_ENDPOINTS=https://127.0.0.1:2379; etcdctl member remove \$etcd_node; etcdctl member list\"
     "
    check::exit_code "$?" "delete" "remove $host etcd member"
  done

  for host in $MASTER_NODES $WORKER_NODES; do
    log::info "[delete]" "kubernetes node $host"

    local node_name
    node_name=$(echo -ne "${cluster_nodes}" | grep "${host}" | awk '{print $2}')
    if [[ "${node_name}" == "" ]]; then
      log::warning "[delete]" "kubernetes node $host not found."
      #      read -r -t 10 -n 1 -p "Do you need to reset the node (y/n)? " answer
      #      [[ -z "$answer" || "$answer" != "y" ]] && exit || echo
    else
      log::info "[delete]" "kubernetes drain $host"
      command::exec "${MGMT_NODE}" "kubectl drain $node_name --force --ignore-daemonsets --delete-local-data"
      check::exit_code "$?" "delete" "$host: kubernetes drain"

      log::info "[delete]" "kubernetes delete node $host"
      command::exec "${MGMT_NODE}" "kubectl delete node $node_name"
      check::exit_code "$?" "delete" "$host: kubernetes delete"
      sleep 3
    fi
    # 删除节点后重置节点
    reset::node "$host"

    del_hosts_cmd="${del_hosts_cmd}\nsed -i "/$host/d" /etc/hosts"
  done

  for host in $(echo -ne "${cluster_nodes}" | awk '{print $1}'); do
    log::info "[delete]" "$host: delete node hosts"
    command::exec "${host}" "
       $(echo -ne "${del_hosts_cmd}")
     "
    check::exit_code "$?" "delete" "delete node hosts"
  done

  for host in $MASTER_NODES $WORKER_NODES; do
    command::exec "${host}" "bash -c 'sleep 15 && reboot' &>/dev/null &"
    check::exit_code "$?" "reboot" "$host: wait for 15s to restart"
  done

  #  [ "$MASTER_NODES" != "" ] && config::etcd_snapshot
  #  kube::status
}

function remove::node() {
  # 移除k8s节点，但不删除docker
  local cluster_nodes=""
  local del_hosts_cmd=""
  command::exec "${MGMT_NODE}" "
     kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {end}'
  "
  get::command_output "cluster_nodes_temp" "$?" exit
  log::info "[result]" "cluster_nodes is $cluster_nodes_temp"

  command::exec "${MGMT_NODE}" "
     kubectl get node -o jsonpath='{range.items[*]}{.status.addresses[?(@.type==\"InternalIP\")].address} {.metadata.name }\\n{end}'
  "
  get::command_output "cluster_nodes" "$?" exit

  # 确认是否删除
  while true; do
    read -p "Are you sure to remove this node? [yes/no]:" result
    case $result in
    yes | y | YES | Y)
      break
      ;;
    no | n | NO | N)
      exit 0
      break
      ;;
    *) ;;

    esac
  done

  for host in $MASTER_NODES; do
    command::exec "${MGMT_NODE}" "
       etcd_pod=\$(kubectl -n kube-system get pods -l component=etcd --field-selector=status.phase=Running -o jsonpath='{\$.items[0].metadata.name}')
       etcd_node=\$(kubectl -n kube-system exec \$etcd_pod -- sh -c \"export ETCDCTL_API=3 ETCDCTL_CACERT=/etc/kubernetes/pki/etcd/ca.crt ETCDCTL_CERT=/etc/kubernetes/pki/etcd/server.crt ETCDCTL_KEY=/etc/kubernetes/pki/etcd/server.key ETCDCTL_ENDPOINTS=https://127.0.0.1:2379; etcdctl member list\"| grep $host | awk -F, '{print \$1}')
       echo \"\$etcd_pod \$etcd_node\"
       kubectl -n kube-system exec \$etcd_pod -- sh -c \"export ETCDCTL_API=3 ETCDCTL_CACERT=/etc/kubernetes/pki/etcd/ca.crt ETCDCTL_CERT=/etc/kubernetes/pki/etcd/server.crt ETCDCTL_KEY=/etc/kubernetes/pki/etcd/server.key ETCDCTL_ENDPOINTS=https://127.0.0.1:2379; etcdctl member remove \$etcd_node; etcdctl member list\"
     "
    check::exit_code "$?" "remove" "remove $host etcd member"
  done

  for host in $MASTER_NODES $WORKER_NODES; do
    log::info "[remove]" "kubernetes node $host"

    local node_name
    node_name=$(echo -ne "${cluster_nodes}" | grep "${host}" | awk '{print $2}')
    if [[ "${node_name}" == "" ]]; then
      log::warning "[remove]" "kubernetes node $host not found."
      #      read -r -t 10 -n 1 -p "Do you need to reset the node (y/n)? " answer
      #      [[ -z "$answer" || "$answer" != "y" ]] && exit || echo
    else
      log::info "[remove]" "kubernetes drain $host"
      command::exec "${MGMT_NODE}" "kubectl drain $node_name --force --ignore-daemonsets --delete-local-data"
      check::exit_code "$?" "remove" "$host: kubernetes drain"

      log::info "[remove]" "kubernetes delete node $host"
      command::exec "${MGMT_NODE}" "kubectl delete node $node_name"
      check::exit_code "$?" "remove" "$host: kubernetes delete"
      sleep 3
    fi
    # 删除节点后重置节点
    #    reset::node "$host"

    del_hosts_cmd="${del_hosts_cmd}\nsed -i "/$host/d" /etc/hosts"
  done

  for host in $(echo -ne "${cluster_nodes}" | awk '{print $1}'); do
    log::info "[remove]" "$host: delete node hosts"
    command::exec "${host}" "
       $(echo -ne "${del_hosts_cmd}")
     "
    check::exit_code "$?" "remove" "delete node hosts"
  done

  for host in $MASTER_NODES $WORKER_NODES; do
    command::exec "${host}" "
      kubeadm reset -f
      ipvsadm --clear
      iptables -F && iptables -t nat -F && iptables -t mangle -F && iptables -X
      for int in kube-ipvs0 cni0 dummy0 flannel.1 cilium_host cilium_net cilium_vxlan lxc_health nodelocaldns
      do
        [ -d /sys/class/net/\${int} ] && ip link delete \${int}
      done
      modprobe -r ipip
      bash -c 'sleep 15 && reboot' &>/dev/null &
    "
    check::exit_code "$?" "reboot" "$host: wait for 15s to restart"
  done

  #  [ "$MASTER_NODES" != "" ] && config::etcd_snapshot
  #  kube::status
}

function images::save() {
  # 保存镜像的文件名
  IMAGES_HEAD=("$(cat ${IMAGES_FILE} | grep '##')")
  # 镜像文件对应的镜像列表
  IMAGES_LIST=("$(cat ${IMAGES_FILE} | egrep -v '^$' | sed -e 's|##.*|#|g')")
  # 获取镜像列表并保存镜像
  index=1
  mkdir -p ${IMAGES_DIR}
  for IMAGE_HEAD in ${IMAGES_HEAD}; do
    ((index++))

    images_file=$(echo ${IMAGE_HEAD} | sed 's/##//g')
    images_list=$(echo ${IMAGES_LIST} | cut -d "#" -f ${index})

    # 判断镜像是否存在
    for image in ${images_list}; do
      image_result=$(docker images ${image} | egrep -v TAG)
      if [[ -z "${image_result}" ]]; then
#        echo "+ docker pull ${image}"
#        docker pull ${image} || {
#          echo "+ docker pull ${image} failed."
#          exit 1
#        }
        log::info "[pull]" "docker pull ${image}"
        command::exec "${MGMT_NODE}" "
          docker pull ${image}
        "
        check::exit_code "$?" "pull" "docker pull ${image}"
      fi
    done

    # 保存镜像
#    echo "+【${images_list}】 > ${IMAGES_DIR}/${images_file}.tar.gz"
#    docker save ${images_list} | gzip -c >${IMAGES_DIR}/${images_file}.tar.gz || {
#      echo "+【${images_list}】 > ${IMAGES_DIR}/${images_file}.tar.gz failed."
#      exit 1
#    }
    log::info "[save]" "docker save ${images_list} | gzip -c >${IMAGES_DIR}/${images_file}.tar.gz"
    command::exec "${MGMT_NODE}" "
      docker save ${images_list} | gzip -c >${IMAGES_DIR}/${images_file}.tar.gz
    "
    check::exit_code "$?" "save" "docker save images"

  done
}

function images::push() {
  # 保存镜像的文件名
  IMAGES_HEAD=("$(cat ${IMAGES_FILE} | grep '##')")
  # 镜像文件对应的镜像列表
  IMAGES_LIST=("$(cat ${IMAGES_FILE} | egrep -v '^$' | sed -e 's|##.*|#|g')")
  # 获取镜像列表并保存镜像
  index=1
  for IMAGE_HEAD in ${IMAGES_HEAD}; do
    ((index++))

    images_list=$(echo ${IMAGES_LIST} | cut -d "#" -f ${index})

    # 判断镜像是否存在
    for image in ${images_list}; do
      image_result=$(docker images ${image} | egrep -v TAG)
      if [[ -z "${image_result}" ]]; then
#        echo "+ docker pull ${image}"
        log::info "[pull]" "docker pull ${image}"
#        docker pull ${image} || {
#          echo "+ docker pull ${image} failed."
#          exit 1
#        }
        command::exec "${MGMT_NODE}" "
          docker pull ${image}
      "
        check::exit_code "$?" "pull" "docker pull ${image}"
      fi
    done

    # 设置镜像标签并推送仓库
    for image in ${images_list}; do
      # 获取镜像最后面的名称
      image_temp=$(echo ${image} | awk -F '/' '{print $NF}')
      # 设置镜像仓库标签
      image_registry="${REGISTRY}/${image_temp}"
#      echo "+ docker tag ${image}  ${REGISTRY}/${image_temp}"
#      docker tag ${image} ${REGISTRY}/${image_temp}
      log::info "[tag]" "docker tag ${image} ${REGISTRY}/${image_temp}"
      command::exec "${MGMT_NODE}" "
        docker tag ${image} ${REGISTRY}/${image_temp}
      "
      check::exit_code "$?" "tag" "docker tag image"
      ## 删除以前的标签
      # docker rmi ${image} || true
      # 上传镜像到仓库
#      echo "+ docker push ${image_registry}"
#      docker push ${image_registry} || {
#        echo "+ docker push ${image_registry} failed."
#        exit 1
#      }
      log::info "[push]" "docker push ${image_registry}"
      command::exec "${MGMT_NODE}" "
        docker push ${image_registry}
      "
      check::exit_code "$?" "push" "docker push image"

    done
  done
}

function utils::images() {
  # 当前目录
  CURRENT_DIR="$(pwd)"
  # 镜像列表文件
  IMAGES_FILE="${IMAGES_FILE}"
  # 存放镜像的目录
  IMAGES_DIR="${CURRENT_DIR}/${IMAGES_DIR:-./images}"
  # 仓库地址
  REGISTRY="${IMAGES_REGISTRY:-dockerhub.kubeeasy.local:5000/kongyu}"

  if [[ "$1" == "save" ]]; then
    [ ! -f "${IMAGES_FILE}" ] && {
      log::error "[images]" "not found ${IMAGES_FILE}"
      exit 1
    }
    log::info "[images]" "docker save images."
    images::save
  elif [[ "$1" == "push" ]]; then
    [ ! -f "${IMAGES_FILE}" ] && {
      log::error "[images]" "not found ${IMAGES_FILE}"
      exit 1
    }
    log::info "[images]" "docker push images."
    images::push
  elif [[ "$1" == "load" ]]; then
    log::info "[images]" "docker load images."
    offline::cluster_images
  else
    log::error "[images]" "No more options."
    exit 1
  fi

}

function utils::clear_history() {

  local hosts=${HOST:-127.0.0.1}
  # clear history
  for host in ${hosts}; do
    log::info "[clear]" "${host}: clear history."
    command::exec "${host}" "
      cat /dev/null > ~/.bash_history
      history -c
   "
    check::exit_code "$?" "clear" "${host}: clear history"
  done
}

function transform::data() {
  # 数据处理及限制
  if [ -n "$(echo ${MASTER_NODES} | grep -)" ]; then
    head1=$(echo ${MASTER_NODES} | awk -F '-' '{print $1}' | awk -F '.' '{print $1"."$2"."$3"."}')
    head2=$(echo ${MASTER_NODES} | awk -F '-' '{print $2}' | awk -F '.' '{print $1"."$2"."$3"."}')
    [ "${head1}" != "${head2}" ] && help::usage
    start=$(echo ${MASTER_NODES} | awk -F '-' '{print $1}' | awk -F '.' '{print $4}')
    end=$(echo ${MASTER_NODES} | awk -F '-' '{print $2}' | awk -F '.' '{print $4}')
    MASTER_NODES=$(for ((i = ${start}; i <= ${end}; i++)); do printf ${head1}${i},; done)
  fi
  if [ -n "$(echo ${WORKER_NODES} | grep -)" ]; then
    head1=$(echo ${WORKER_NODES} | awk -F '-' '{print $1}' | awk -F '.' '{print $1"."$2"."$3"."}')
    head2=$(echo ${WORKER_NODES} | awk -F '-' '{print $2}' | awk -F '.' '{print $1"."$2"."$3"."}')
    [ "${head1}" != "${head2}" ] && help::usage
    start=$(echo ${WORKER_NODES} | awk -F '-' '{print $1}' | awk -F '.' '{print $4}')
    end=$(echo ${WORKER_NODES} | awk -F '-' '{print $2}' | awk -F '.' '{print $4}')
    WORKER_NODES=$(for ((i = ${start}; i <= ${end}; i++)); do printf ${head1}${i},; done)
  fi
  if [ -n "$(echo ${HOST} | grep -)" ]; then
    head1=$(echo ${HOST} | awk -F '-' '{print $1}' | awk -F '.' '{print $1"."$2"."$3"."}')
    head2=$(echo ${HOST} | awk -F '-' '{print $2}' | awk -F '.' '{print $1"."$2"."$3"."}')
    [ "${head1}" != "${head2}" ] && help::usage
    start=$(echo ${HOST} | awk -F '-' '{print $1}' | awk -F '.' '{print $4}')
    end=$(echo ${HOST} | awk -F '-' '{print $2}' | awk -F '.' '{print $4}')
    HOST=$(for ((i = ${start}; i <= ${end}; i++)); do printf ${head1}${i},; done)
  fi

  MASTER_NODES=$(echo "${MASTER_NODES}" | tr ',' ' ')
  WORKER_NODES=$(echo "${WORKER_NODES}" | tr ',' ' ')
  HOST=$(echo "${HOST}" | tr ',' ' ')

  if ! utils::is_element_in_array "$KUBE_CRI" docker containerd cri-o; then
    log::error "[limit]" "$KUBE_CRI is not supported, only [docker,containerd,cri-o]"
    exit 1
  fi

  [[ "$KUBE_CRI" != "docker" && "${OFFLINE_TAG:-}" == "1" ]] && {
    log::error "[limit]" "$KUBE_CRI is not supported offline, only docker"
    exit 1
  }
  [[ "$KUBE_CRI" == "containerd" && "${KUBE_CRI_ENDPOINT}" == "/var/run/dockershim.sock" ]] && KUBE_CRI_ENDPOINT="unix:///run/containerd/containerd.sock"
  [[ "$KUBE_CRI" == "cri-o" && "${KUBE_CRI_ENDPOINT}" == "/var/run/dockershim.sock" ]] && KUBE_CRI_ENDPOINT="unix:///var/run/crio/crio.sock"

  kubelet_nodeRegistration="nodeRegistration:
  criSocket: ${KUBE_CRI_ENDPOINT:-/var/run/dockershim.sock}
  kubeletExtraArgs:
    runtime-cgroups: /system.slice/${KUBE_CRI//-/}.service
$(if [[ "${KUBE_VERSION}" == "latest" || "${KUBE_VERSION}" == *"1.21"* ]]; then
    echo "    pod-infra-container-image: $KUBE_IMAGE_REPO/pause:3.4.1"
  else
    echo "    pod-infra-container-image: $KUBE_IMAGE_REPO/pause:3.2"
  fi)
"
}

function help::usage() {
  # 使用帮助

  cat <<EOF

Script Name    : kubeeasy
Version:       : v1.3.2
Description    : Install kubernetes (HA) cluster using kubeadm.
Create Date    : 2022-06-01
Author         : KongYu
Email          : 2385569970@qq.com
Install kubernetes cluster using kubeadm.
Documentation: https://github.com/kongyu666/kubeeasy

Usage:
  $(basename "$0") [command]

Available Commands:
  install            Install Service Cluster.

Flags:
  -h, --help               help for kubeeasy

Example:
  [install k8s cluster]
  $0 install k8s \\
  --master 192.168.1.201 \\
  --worker 192.168.1.202,192.168.1.203 \\
  --user root \\
  --password 000000 \\
  --version 1.21.3

Use "$(basename "$0") [command] --help" for more information about a command.
EOF
  exit 1
}

function help::details() {
  # 使用帮助

  cat <<EOF

Script Name    : kubeeasy
Version:       : v1.3.2
Description    : Install kubernetes (HA) cluster using kubeadm.
Create Date    : 2022-06-01
Author         : KongYu
Email          : 2385569970@qq.com
Install kubernetes cluster using kubeadm.
Documentation: https://github.com/kongyu666/kubeeasy

Usage:
  $(basename "$0") [command]

Available Commands:
  install         Install cluster service.
  create          create service.
  reset           Reset Kubernetes cluster.
  add             Add node to the cluster.
  remove          Remove node from the cluster.
  delete          Delete node from the cluster.
  check           Check cluster system.
  images          docker image save or push.

Flag:
  -m,--master          master node, example: 10.24.2.10
  -w,--worker          work node, example: 10.24.2.11,10.24.2.12 or 10.24.2.10-10.24.2.20
  -host,--host         other node, example: 10.24.2.11,10.24.2.12 or 10.24.2.10-10.24.2.20
  -vip,--virtual-ip    k8s ha virtual ipaddress, example: 10.24.2.100
  -u,--user            ssh user, default: ${SSH_USER}
  -p,--password        ssh password, default: ${SSH_PASSWORD}
  -P,--port            ssh port, default: ${SSH_PORT}
  -v,--version         kube version, default: ${KUBE_VERSION}
  -d,--docker-data     docker store data root, default: ${DOCKER_DATA_ROOT}
  --pod-cidr           kube pod subnet, default: ${KUBE_POD_SUBNET}
  -U,--upgrade-kernel  upgrade kernel
  -of,--offline-file   specify the offline package file to load
  --images-file        docker images list file, default: ${IMAGES_FILE}
  --images-dir         docker images save storage dir, default: ${IMAGES_DIR}
  --images-registry    docker registry. please login first

Example:
  [install dependencies package cluster]
  $0 install dependencies \\
    --host 192.168.1.201-192.168.1.203 \\
    --user root \\
    --password 000000 \\
    --offline-file centos-7-rpms.tar.gz

  [upgrade kernel cluster]
  $0 install upgrade-kernel \\
    --host 192.168.1.201-192.168.1.203 \\
    --user root \\
    --password 000000 \\
    --offline-file kernel-rpms-v5.14.3.tar.gz

  [install k8s cluster]
  $0 install kubernetes \\
    --master 192.168.1.201 \\
    --worker 192.168.1.202,192.168.1.203 \\
    --user root \\
    --password 000000 \\
    --version 1.21.3 \\
    --pod-cidr 10.244.0.0/16 \\
    --offline-file kubeeasy-v1.3.2.tar.gz

  [install k8s ha cluster]
  $0 install kubernetes \\
    --master 192.168.1.201,192.168.1.202,192.168.1.203 \\
    --worker 192.168.1.204,192.168.1.205,192.168.1.206 \\
    --user root \\
    --password 000000 \\
    --version 1.21.3 \\
    --pod-cidr 10.244.0.0/16 \\
    --virtual-ip 192.168.1.250 \\
    --offline-file kubeeasy-v1.3.2.tar.gz

  [reset k8s cluster]
  $0 reset \\
    --user root \\
    --password 000000

  [reset force k8s node]
  $0 reset --force \\
    --master 192.168.1.201 \\
    --worker 192.168.1.202 \\
    --user root \\
    --password 000000

  [add node]
  $0 add \\
    --master 192.168.1.204,192.168.1.205
    --user root \\
    --password 000000

  $0 add \\
    --worker 192.168.1.204,192.168.1.205
    --user root \\
    --password 000000

  [delete node]
  $0 delete \\
    --master 192.168.1.201 \\
    --worker 192.168.1.202 \\
    --user root \\
    --password 000000

  [remove node]
  $0 remove \\
    --master 192.168.1.201 \\
    --worker 192.168.1.202 \\
    --user root \\
    --password 000000

  [docker push images file and load]
  $0 images load \\
    --host 192.168.1.201,192.168.1.202,192.168.1.203 \\
    --user root \\
    --password 000000 \\
    --offline-file test-images.tar.gz

  [docker images save]
  $0 images save \\
    --images-file images-list.txt \\
    --images-dir ./images

  [docker images push]
  docker login dockerhub.kubeeasy.local:5000 -u admin -p admin
  $0 images push \\
    --images-file images-list.txt \\
    --images-registry dockerhub.kubeeasy.local:5000/kongyu

  [create chronyc time]
  $0 create time \\
    --master 192.168.1.201 \\
    --worker 192.168.1.202,192.168.1.203 \\
    --user root \\
    --password 000000

  [create ssh keygen]
  $0 create ssh-keygen \\
    --master 192.168.1.201 \\
    --worker 192.168.1.202,192.168.1.203 \\
    --user root \\
    --password 000000

  [mount and mkfs disk]
  $0 create mount-disk \\
    --host 192.168.1.201-192.168.1.203 \\
    --disk /dev/sdb \\
    --mount-dir /data \\
    --user root \\
    --password 000000

  [set root password]
  $0 create password \\
    --host 192.168.1.201-192.168.1.203 \\
    --user root \\
    --password 000000 \\
    --new-password 123456

  [install system precondition]
  $0 install precondition \\
    --host 192.168.1.201-192.168.1.203 \\
    --user root \\
    --password 000000

  [get command output]
  $0 get command \\
    --host 192.168.1.201-192.168.1.203 \\
    --user root \\
    --password 000000 \\
    --cmd "hostname"

  [check node system]
  $0 check system \\
    --host 192.168.1.201-192.168.1.203 \\
    --user root \\
    --password 000000

  [check node ssh]
  $0 check ssh \\
    --host 192.168.1.201-192.168.1.203 \\
    --user root \\
    --password 000000

  [check node ping]
  $0 check ping \\
    --host 192.168.1.201-192.168.1.203

  [clear history]
  $0 set history \\
    --host 192.168.1.201-192.168.1.203 \\
    --user root \\
    --password 000000

  Please refer to the documentation for details.

EOF
  exit 1
}

######################################################################################################
# main
######################################################################################################
## 创建日志目录
[[ ! -f "/var/log/kubeeasy" ]] && mkdir -p /var/log/kubeeasy

[ "$#" == "0" ] && help::usage

while [ "${1:-}" != "" ]; do
  case $1 in
  -h | --help)
    HELP_TAG=1
    ;;
  install)
    INSTALL_TAG=1
    ;;
  create)
    CREATE_TAG=1
    ;;
  check)
    CHECK_TAG=1
    ;;
  set)
    SET_TAG=1
    ;;
  get)
    GET_TAG=1
    ;;
  reset)
    RESET_TAG=1
    ;;
  add)
    ADD_TAG=1
    ;;
  delete)
    DEL_TAG=1
    ;;
  remove)
    REMOVE_TAG=1
    ;;
  images)
    IMAGE_TAG=1
    ;;
  renew-cert)
    RENEW_CERT_TAG=1
    ;;
  upgrade)
    UPGRADE_TAG=1
    ;;
  update)
    UPDATE_TAG=1
    ;;
  # install
  k8s | kubernetes)
    KUBE_INSTALL_TAG=1
    ;;
  depend | dependencies)
    DEPEND_INSTALL_TAG=1
    ;;
  pre | precondition )
    PRE_INSTALL_TAG=1
    ;;
  keepalived)
    VIP_INSTALL_TAG=1
    ;;
  upgrade-kernel)
    UPGRADE_KERNEL_TAG=1
    ;;
  # create
  chrony | time)
    TIME_CREATE_TAG=1
    ;;
  ssh-keygen)
    SSH_CREATE_TAG=1
    ;;
  mount | mount-disk)
    DISK_CREATE_TAG=1
    ;;
  pw | password)
    PW_CREATE_TAG=1
    ;;
  # check
  ssh)
    SSH_CHECK_TAG=1
    ;;
  ping)
    PING_CHECK_TAG=1
    ;;
  system)
    SYSTEM_CHECK_TAG=1
    ;;
  # reset
  --force)
    RESET_FORCE_TAG=1
    ;;
  # add
  -i | --ingress)
    shift
    INGRESS_TAG=1
    KUBE_INGRESS=${1:-$KUBE_INGRESS}
    ;;
  -s | --storage)
    shift
    STORAGE_TAG=1
    KUBE_STORAGE=${1:-$KUBE_STORAGE}
    ;;
  -ui | --ui)
    shift
    UI_TAG=1
    KUBE_UI=${1:-$KUBE_UI}
    ;;
  -vm | --virt)
    shift
    VIRT_TAG=1
    KUBE_VIRT=${1:-$KUBE_VIRT}
    ;;
  # image
  save)
    SAVE_IMAGE_TAG=1
    ;;
  push)
    PUSH_IMAGE_TAG=1
    ;;
  load)
    LOAD_IMAGE_TAG=1
    ;;
  --images-file)
    shift
    IMAGES_FILE=${1:-./images-list.txt}
    ;;
  --images-dir)
    shift
    IMAGES_DIR=${1:-./images}
    ;;
  --images-registry)
    shift
    IMAGES_REGISTRY=${1:-dockerhub.kubeeasy.local:5000/kongyu}
    ;;
  # set
  history)
    HISTORY_SET_TAG=1
    ;;
  # get
  cmd | command)
    COMMAND_GET_TAG=1
    ;;
  --cmd)
    shift
    COMMAND_GET=${1:-"echo none."}
    ;;
  # other
  -m | --master)
    shift
    MASTER_NODES=${1:-$MASTER_NODES}
    ;;
  -w | --worker)
    shift
    WORKER_NODES=${1:-$WORKER_NODES}
    ;;
  -host | --host)
    shift
    HOST=${1:-$HOST}
    ;;
  -vip | --virtual-ip)
    shift
    VIRTUAL_IP=${1}
    ;;
  --kube-vip-port)
    shift
    KUBE_APISERVER_PORT=${1:-$KUBE_APISERVER_PORT}
    ;;
  -u | --user)
    shift
    SSH_USER=${1:-$SSH_USER}
    ;;
  -p | --password)
    shift
    SSH_PASSWORD=${1:-$SSH_PASSWORD}
    ;;
  -np | --new-password)
    shift
    NEW_SSH_PASSWORD=${1:-$NEW_SSH_PASSWORD}
    ;;
  --private-key)
    shift
    SSH_PRIVATE_KEY=${1:-$SSH_SSH_PRIVATE_KEY}
    ;;
  -P | --port)
    shift
    SSH_PORT=${1:-$SSH_PORT}
    ;;
  -v | --version)
    shift
    KUBE_VERSION=${1:-$KUBE_VERSION}
    ;;
  -d | --docker-data | --mount-dir)
    shift
    DOCKER_DATA_ROOT=${1:-$DOCKER_DATA_ROOT}
    ;;
  --disk)
    shift
    MOUNT_DISK=${1:-}
    ;;
  -n | --network)
    shift
    NETWORK_TAG=1
    KUBE_NETWORK=${1:-$KUBE_NETWORK}
    ;;
  --pod-cidr)
    shift
    KUBE_POD_SUBNET=${1:-$KUBE_POD_SUBNET}
    ;;
  --cri)
    shift
    KUBE_CRI=${1:-$KUBE_CRI}
    ;;
  --cri-version)
    shift
    KUBE_CRI_VERSION=${1:-$KUBE_CRI_VERSION}
    ;;
  --cri-endpoint)
    shift
    KUBE_CRI_ENDPOINT=${1:-$KUBE_CRI_ENDPOINT}
    ;;
  -of | --offline-file)
    shift
    OFFLINE_TAG=1
    OFFLINE_FILE=${1:-$OFFLINE_FILE}
    ;;
  --sudo)
    SUDO_TAG=1
    ;;
  --sudo-user)
    shift
    SUDO_USER=${1:-$SUDO_USER}
    ;;
  --sudo-password)
    shift
    SUDO_PASSWORD=${1:-}
    ;;
  *)
    help::usage
    exit 1
    ;;
  esac
  shift
done

# 开始
[ "${HELP_TAG}" != "1" ] && log::info "[start]" "bash $0 ${SCRIPT_PARAMETER//${SSH_PASSWORD:-${SUDO_PASSWORD:-}}/******}"

# 数据处理
[ "${HELP_TAG}" != "1" ] && transform::data

# 预检
[ "${HELP_TAG:-0}" != "1" ] && check::preflight

# 动作
if [[ "${INSTALL_TAG:-}" == "1" ]]; then
  # 安装
  [[ "${KUBE_INSTALL_TAG:-}" == "1" ]] && {
    [[ "$MASTER_NODES" == "" ]] && MASTER_NODES="127.0.0.1"
    init::cluster
    install=1
  }
  [[ "${DEPEND_INSTALL_TAG:-}" == "1" ]] && {
    offline::cluster_depend
    install=1
  }
  [[ "${VIP_INSTALL_TAG:-}" == "1" ]] && {
    install::ha-service
    install=1
  }
  [[ "${PRE_INSTALL_TAG:-}" == "1" ]] && {
    install::precondition
    install=1
  }
  [[ "${UPGRADE_KERNEL_TAG:-}" == "1" ]] && {
    [[ "${OFFLINE_TAG}" == "1" ]] && offline::cluster_kernel
    init::upgrade_kernel
    install=1
  }
  [[ "${install:-}" != "1" ]] && help::usage
elif [[ "${CREATE_TAG:-}" == "1" ]]; then
  # 创建
  [[ "${TIME_CREATE_TAG:-}" == "1" ]] && {
    install::time
    create=1
  }
  [[ "${SSH_CREATE_TAG:-}" == "1" ]] && {
    install::ssh_keygen
    create=1
  }
  [[ "${DISK_CREATE_TAG:-}" == "1" ]] && {
    utils::mount_disk
    create=1
  }
  [[ "${PW_CREATE_TAG:-}" == "1" ]] && {
    create::password
    create=1
  }
  [[ "${create:-}" != "1" ]] && help::usage

elif [[ "${CHECK_TAG:-}" == "1" ]]; then
  # 检查
  [[ "${SSH_CHECK_TAG:-}" == "1" ]] && {
    check::ssh_conn_new
    check=1
  }
  [[ "${PING_CHECK_TAG:-}" == "1" ]] && {
    check::ping_conn
    check=1
  }
  [[ "${SYSTEM_CHECK_TAG:-}" == "1" ]] && {
    check::system_metrics
    check=1
  }
  [[ "${check:-}" != "1" ]] && help::usage

elif [[ "${ADD_TAG:-}" == "1" ]]; then
  [[ "${NETWORK_TAG:-}" == "1" ]] && {
    add::network
    add=1
  }
  [[ "${STORAGE_TAG:-}" == "1" ]] && {
    add::storage
    add=1
  }
  [[ "${UI_TAG:-}" == "1" ]] && {
    add::ui
    add=1
  }
  [[ "${VIRT_TAG:-}" == "1" ]] && {
    add::virt
    add=1
  }
  [[ "$MASTER_NODES" != "" || "$WORKER_NODES" != "" ]] && {
    add::node
    add=1
  }
  [[ "${add:-}" != "1" ]] && help::usage
elif [[ "${GET_TAG:-}" == "1" ]]; then
  # 分发文件
  [[ "${COMMAND_GET_TAG:-}" == "1" ]] && {
    script::exec_command
    get=1
  }
  [[ "${get:-}" != "1" ]] && help::usage
elif [[ "${DEL_TAG:-}" == "1" ]]; then
  if [[ "$MASTER_NODES" != "" || "$WORKER_NODES" != "" ]]; then del::node; else help::usage; fi
elif [[ "${REMOVE_TAG:-}" == "1" ]]; then
  if [[ "$MASTER_NODES" != "" || "$WORKER_NODES" != "" ]]; then remove::node; else help::usage; fi
elif [[ "${RESET_TAG:-}" == "1" ]]; then
  # 重置k8s
  if [[ "${RESET_FORCE_TAG:-}" == "1" ]]; then
    reset::cluster_force
  else
    reset::cluster
  fi
elif [[ "${SET_TAG:-}" == "1" ]]; then
  # 设置
  [[ "${HISTORY_SET_TAG:-}" == "1" ]] && {
    # 清除历史命令
    utils::clear_history
    set=1
  }
  [[ "${set:-}" != "1" ]] && help::usage
elif [[ "${IMAGE_TAG:-}" == "1" ]]; then
  # 容器镜像
  [[ "${SAVE_IMAGE_TAG:-}" == "1" ]] && {
    utils::images save
    image=1
  }
  [[ "${PUSH_IMAGE_TAG:-}" == "1" ]] && {
    utils::images push
    image=1
  }
  [[ "${LOAD_IMAGE_TAG:-}" == "1" ]] && {
    utils::images load
    image=1
  }
  [[ "${image:-}" != "1" ]] && help::usage
elif [[ "${UPGRADE_TAG:-}" == "1" ]]; then
  upgrade::cluster
elif [[ "${HELP_TAG:-}" == "1" ]]; then
  # 帮助
  help::details
else
  help::usage
fi
