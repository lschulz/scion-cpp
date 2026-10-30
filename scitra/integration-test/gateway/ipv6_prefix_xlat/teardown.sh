#!/bin/sh

ip6tables -t nat -D OUTPUT -d fc00:10fc:100::/40 -j NETMAP --to fd00:deca:100::/40
# nft delete table ip6 nat

ip route del fc00:10fc:100::/40 dev veth7
ip route del fd00:deca:100::/40 via fd00:deca:100::2 dev veth7

ip netns del scitra
ip netns del host0
ip netns del host1
ip netns del host2

ip link del as64513
ip link del veth8
