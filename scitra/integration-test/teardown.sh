#!/bin/sh

set -e

ip link del veth0
ip link del veth2

ip netns del host0
ip netns del host1
