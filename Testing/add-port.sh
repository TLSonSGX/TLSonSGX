#!/bin/bash

if [ $# -ne 2 ]; then
    echo "usage: $0 port_num ovs_br"
    exit 1
fi

set -xe

port=p$1
ns=ns$1
br=$2
mac=00:00:00:00:00:0$1
ip=10.0.0.${1}/24

#ovs-vsctl --may-exist add-br $br
#ovs-vsctl add-port $br $port
#ovs-vsctl set Interface $port type=internal
ip netns add $ns
ip link set $port netns $ns
ip netns exec $ns ip link set $port address $mac
ip netns exec $ns ip address add $ip dev $port
ip netns exec $ns sysctl -w net.ipv6.conf.${port}.disable_ipv6=1
ip netns exec $ns ip link set $port up
