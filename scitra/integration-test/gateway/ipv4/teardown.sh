#!/bin/sh

ip route del 10.128.1.0/24 via 10.128.0.2 dev veth7

ip netns del scitra
ip netns del host0
ip netns del host1
ip netns del host2

ip link del as64513
ip link del veth8
