#!/bin/sh

set -e

ip netns add scitra
ip netns add host0
ip netns add host1
ip netns add host2

ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3
ip link add veth4 type veth peer name veth5
ip link add veth6 type veth peer name veth7
ip link add veth8 type veth peer name veth9

# AS 1-64513 Bridge
ip link add name as64513 type bridge
ip link set dev veth1 up
ip link set dev veth3 up
ip link set dev veth4 up
ip link set veth1 master as64513
ip link set veth3 master as64513
ip link set veth4 master as64513
ip link set dev as64513 up

# Scitra (AS 1-64513)
ip link set veth5 netns scitra
ip netns exec scitra sysctl -w net.ipv6.conf.all.forwarding=1
ip netns exec scitra ip link set dev lo up
ip netns exec scitra ip link set dev veth5 up
ip netns exec scitra ip addr add dev veth5 fd00:10fc:100::ffff:10.128.1.1/120
ip netns exec scitra ip route add local 10.128.1.0/24 dev lo table local

ip link set veth6 netns scitra
ip netns exec scitra ip link set dev veth6 up
ip netns exec scitra ip addr add dev veth6 10.128.0.2/16

# Host 0 (AS 1-64513)
ip link set veth0 netns host0
ip netns exec host0 ip link set dev lo up
ip netns exec host0 ip link set dev veth0 up
ip netns exec host0 ip addr add dev veth0 fd00:10fc:100::ffff:10.128.1.2/120
ip netns exec host0 ip route add fc00::/8 via fd00:10fc:100::ffff:10.128.1.1 dev veth0

# Host 1 (AS 1-64513)
ip link set veth2 netns host1
ip netns exec host1 ip link set dev lo up
ip netns exec host1 ip link set dev veth2 up
ip netns exec host1 ip addr add dev veth2 fd00:10fc:100::ffff:10.128.1.3/120
ip netns exec host1 ip route add fc00::/8 via fd00:10fc:100::ffff:10.128.1.1 dev veth2

# Default Namespace
ip link set dev veth7 up
ip addr add dev veth7 10.128.0.1/16
ip route add 10.128.1.0/24 via 10.128.0.2 dev veth7

ip link set dev veth8 up
ip addr add dev veth8 fc00:10fc:200::1/64

# Host 2 (AS 1-64514)
ip link set veth9 netns host2
ip netns exec host2 ip link set dev lo up
ip netns exec host2 ip link set dev veth9 up
ip netns exec host2 ip addr add dev veth9 fc00:10fc:200::2/64
