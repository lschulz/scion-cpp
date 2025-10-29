#!/bin/sh

set -e

ip netns add host0
ip netns add host1

ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3

ip link set veth1 netns host0
ip link set veth3 netns host1

ip addr add dev veth0 10.128.0.1/24
ip addr add dev veth0 fc00:10fc:100::1/64
ip addr add dev veth2 10.128.1.1/24
ip addr add dev veth2 fc00:10fc:200::1/64
ip link set dev veth0 up
ip link set dev veth2 up

ip netns exec host0 ip addr add dev lo ::1/128
ip netns exec host0 ip addr add dev veth1 10.128.0.2/24
ip netns exec host0 ip addr add dev veth1 fc00:10fc:100::2/64
ip netns exec host0 ip link set dev lo up
ip netns exec host0 ip link set dev veth1 up

ip netns exec host1 ip addr add dev lo ::1/128
ip netns exec host1 ip addr add dev veth3 10.128.1.2/24
ip netns exec host1 ip addr add dev veth3 fc00:10fc:200::2/64
ip netns exec host1 ip link set dev lo up
ip netns exec host1 ip link set dev veth3 up
