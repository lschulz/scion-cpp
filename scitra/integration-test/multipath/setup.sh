#!/bin/sh

set -e

# Host 0
ip netns add host0
ip netns add as0

ip link add veth0 type veth peer name veth1
ip link add veth2 type veth peer name veth3
ip link add veth4 type veth peer name veth5
ip link add veth6 type veth peer name veth7

ip link set veth0 netns host0
ip link set veth1 netns as0
ip link set veth3 netns as0
ip link set veth5 netns as0
ip link set veth7 netns as0

ip netns exec host0 ip addr add dev lo ::1/128
ip netns exec host0 ip addr add dev veth0 10.128.0.2/24
ip netns exec host0 ip addr add dev veth0 fd01::2/64
ip netns exec host0 ip link set dev lo up
ip netns exec host0 ip link set dev veth0 up

ip netns exec as0 ip addr add dev veth1 10.128.0.1/24
ip netns exec as0 ip addr add dev veth1 fd01::1/64
ip netns exec as0 ip addr add dev veth3 10.128.1.1/24
ip netns exec as0 ip addr add dev veth5 10.128.2.1/24
ip netns exec as0 ip addr add dev veth7 10.128.3.1/24
ip netns exec as0 ip link set dev lo up
ip netns exec as0 ip link set dev veth1 up
ip netns exec as0 ip link set dev veth3 up
ip netns exec as0 ip link set dev veth5 up
ip netns exec as0 ip link set dev veth7 up

ip addr add dev veth2 10.128.1.2/24
ip addr add dev veth4 10.128.2.2/24
ip addr add dev veth6 10.128.3.2/24
ip link set dev veth2 up
ip link set dev veth4 up
ip link set dev veth6 up

# Host 1
ip netns add host1
ip netns add as1

ip link add veth8 type veth peer name veth9
ip link add veth10 type veth peer name veth11
ip link add veth12 type veth peer name veth13
ip link add veth14 type veth peer name veth15

ip link set veth8 netns host1
ip link set veth9 netns as1
ip link set veth11 netns as1
ip link set veth13 netns as1
ip link set veth15 netns as1

ip netns exec host1 ip addr add dev lo ::1/128
ip netns exec host1 ip addr add dev veth8 10.128.4.2/24
ip netns exec host1 ip addr add dev veth8 fd02::2/64
ip netns exec host1 ip link set dev lo up
ip netns exec host1 ip link set dev veth8 up

ip netns exec as1 ip addr add dev veth9 10.128.4.1/24
ip netns exec as1 ip addr add dev veth9 fd02::1/64
ip netns exec as1 ip addr add dev veth11 10.128.5.1/24
ip netns exec as1 ip addr add dev veth13 10.128.6.1/24
ip netns exec as1 ip addr add dev veth15 10.128.7.1/24
ip netns exec as1 ip link set dev lo up
ip netns exec as1 ip link set dev veth9 up
ip netns exec as1 ip link set dev veth11 up
ip netns exec as1 ip link set dev veth13 up
ip netns exec as1 ip link set dev veth15 up

ip addr add dev veth10 10.128.5.2/24
ip addr add dev veth12 10.128.6.2/24
ip addr add dev veth14 10.128.7.2/24
ip link set dev veth10 up
ip link set dev veth12 up
ip link set dev veth14 up

# Attach qdisc to inter-AS links
sudo ip netns exec as0 tc qdisc add dev veth3 root handle 1: tbf rate 10mbit burst 10k limit 1M
sudo ip netns exec as0 tc qdisc add dev veth3 parent 1:1 handle 2: netem delay 10ms

sudo ip netns exec as0 tc qdisc add dev veth5 root handle 1: tbf rate 10mbit burst 10k limit 1M
sudo ip netns exec as0 tc qdisc add dev veth5 parent 1:1 handle 2: netem delay 10ms

sudo ip netns exec as0 tc qdisc add dev veth7 root handle 1: tbf rate 10mbit burst 10k limit 1M
sudo ip netns exec as0 tc qdisc add dev veth7 parent 1:1 handle 2: netem delay 10ms

sudo ip netns exec as1 tc qdisc add dev veth11 root handle 1: tbf rate 10mbit burst 10k limit 1M
sudo ip netns exec as1 tc qdisc add dev veth11 parent 1:1 handle 2: netem delay 10ms

sudo ip netns exec as1 tc qdisc add dev veth13 root handle 1: tbf rate 10mbit burst 10k limit 1M
sudo ip netns exec as1 tc qdisc add dev veth13 parent 1:1 handle 2: netem delay 10ms

sudo ip netns exec as1 tc qdisc add dev veth15 root handle 1: tbf rate 10mbit burst 10k limit 1M
sudo ip netns exec as1 tc qdisc add dev veth15 parent 1:1 handle 2: netem delay 10ms

# Direct IPv6 connection between host0 and host1
ip link add vethA type veth peer name vethB
ip link set vethA netns host0
ip link set vethB netns host1
ip netns exec host0 ip addr add dev vethA fd03::1/64
ip netns exec host1 ip addr add dev vethB fd03::2/64
ip netns exec host0 ip link set dev vethA up
ip netns exec host1 ip link set dev vethB up
sudo ip netns exec host0 tc qdisc add dev vethA root handle 1: tbf rate 10mbit burst 10k limit 1M
sudo ip netns exec host0 tc qdisc add dev vethA parent 1:1 handle 2: netem delay 10ms
sudo ip netns exec host1 tc qdisc add dev vethB root handle 1: tbf rate 10mbit burst 10k limit 1M
sudo ip netns exec host1 tc qdisc add dev vethB parent 1:1 handle 2: netem delay 10ms
