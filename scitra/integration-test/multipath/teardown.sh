#!/bin/sh

ip link del veth2
ip link del veth4
ip link del veth6
ip link del veth10
ip link del veth12
ip link del veth14

ip netns del host0
ip netns del host1
ip netns del as0
ip netns del as1
