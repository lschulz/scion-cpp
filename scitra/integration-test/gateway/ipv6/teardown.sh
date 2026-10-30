#!/bin/sh

ip route del fc00:10fc:100:100::/64 via fc00:10fc:100::2 dev veth7

ip netns del scitra
ip netns del host0
ip netns del host1
ip netns del host2

ip link del as64513
ip link del veth8
