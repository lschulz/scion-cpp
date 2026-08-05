#!/bin/bash

if [[ $# -ne 5 ]]; then
    echo "Usage: $0 [namespace] [interface] [bandwidth] [burst] [delay]"
    echo "Example: $0 as0 veth3 100mbit 500k 20ms"
    exit 1
fi

set -e
sudo ip netns exec "$1" tc qdisc change dev "$2" root tbf rate "$3" burst "$4" limit 1M
sudo ip netns exec "$1" tc qdisc change dev "$2" parent 1:1 netem delay "$5"
sudo ip netns exec "$1" tc qdisc show dev "$2"
