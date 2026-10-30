Scitra-TUN Gateway Test Harness
===============================

The SCION network in this directory is used for testing Scitra's gateway mode.

Network namespaces and veths are set up by the `setup_ipv[4|6].sh` script as follows:
```
                    +--------+
+-------+           |        |
| host0 |<-veth0:1->|        |                                +-----------+
+-------+           |        |           +--------+           |  Default  |           +-------+
                    | Bridge |<-veth4:5->| scitra |<-veth6:7->|  Network  |<-veth8:9->| host2 |
+-------+           |        |           +--------+           | Namespace |           +-------+
| host1 |<-veth2:3->|        |                                +-----------+
+-------+           |        |
                    +--------+
\____________________________________________________________/            \___________________/
                           AS 1-64513                                           AS 1-64514
```
* SCION border routers and control services are running in the default namespace.
* AS 1-64513 has two host namespaces `host0` and `host1` connected to a namespace for Scitra-TUN in
  gateway mode (namespace `scitra`).
* The underlay of AS 1-64513 is either IPv4 or IPv6.
* `host2` is connected to AS 1-64514.
* AS 1-64514 always has an IPv6 underlay, as the underlay of remote ASes does not influence the
  gateway's operation.

Intra-AS SCION connectivity differs between the IPv4 and IPv6 underlays. In the IPv4 case, intra-AS
traffic from the 10.128.1.0/24 subnet is routed through the Scitra gateway and translated. Traffic
within 10.128.1.0/24 is delivered directly by the bridge and not translated. The IPv6 topology does
not distinguish traffic on the bridge network (fd00:10fc:100:100::/64) and outside of it within the
local AS; both cases are not translated. Is is possible to modify this behavior by configuring
different routes.

## Test Procedure ##

### IPv4 Underlay ###

#### Step 1: Set up the network ####
```bash
sudo ipv4/setup.sh
ipv4/run_scion.sh
```
#### Step 2: Run Scitra-TUN ####

In namespace `scitra`:
```bash
sudo ip netns exec scitra sudo -u $USER bash
scitra-tun -a 10.128.0.2/16 -t fd00:10fc:100::ffff:10.128.0.2 -d 10.128.0.1:30255 \
  --mode=gateway --scmp --tui -l debug --log-file gateway.txt
```

In namespace `host2`:
```bash
sudo ip netns exec host2 sudo -u $USER bash
scitra-tun -a fc00:10fc:200::2 -t fd00::1 -d [fc00:10fc:200::1]:30255 -p 32000 --scmp \
  --tui -l debug --log-file host2.txt
```

#### Step 3: Test Inter-AS Connectivity ####

Start a server in namespace `host2`.
```bash
nc -ul fd00::1 32000
```

Connect from `scitra`, `host0`, and `host1`.
```bash
nc -u fc00:10fc:200::2 32000
```

#### Step 4: Test Intra-AS Connectivity ####

Start echo server in default namespace.
```bash
echo-udp-async -d 10.128.0.1:30255 -l 10.128.0.1:32001
```

Connect from `scitra`, `host0`, and `host1`.
```bash
nc -u fc00:10fc:100::ffff:10.128.0.1 32001
```
All inputs should be echoed back.

#### Step 5: Cleanup ####
```bash
ipv4/stop_scion.sh
sudo ipv4/teardown.sh
```

### IPv6 Underlay ###

#### Step 1: Set up the network ####
```bash
sudo ipv6/setup.sh
ipv6/run_scion.sh
```

#### Step 2: Run Scitra-TUN ####

In namespace `scitra`:
```bash
sudo ip netns exec scitra sudo -u $USER bash
scitra-tun -a fc00:10fc:100::2/48 -t fd00:10fc:100::2 -d [fc00:10fc:100::1]:30255 --mode=gateway \
  --scmp --tui -l debug --log-file gateway.txt
```

In namespace `host2`:
```bash
sudo ip netns exec host2 sudo -u $USER bash
scitra-tun -a fc00:10fc:200::2 -t fd00::1 -d [fc00:10fc:200::1]:30255 -p 32000 --scmp \
  --tui -l debug --log-file host2.txt
```

#### Step 3: Test Inter-AS Connectivity ####

Start a server in namespace `host2`.
```bash
nc -ul fd00::1 32000
```

Connect from `scitra`, `host0`, and `host1`.
```bash
nc -u fc00:10fc:200::2 32000
```

#### Step 4: Cleanup ####
```bash
ipv6/stop_scion.sh
sudo ipv6/teardown.sh
```

## IPv6 Underlay with Prefix Translation ##

Same as the IPv6 underlay, but uses a network unrelated to Scitra and SCION-mapped IPv6 addresses
(`fd00:deca:100::1/40`) between the Scitra Gateway and the border router of AS 1-64513.

#### Step 1: Set up the network ####
```bash
sudo ipv6_prefix_xlat/setup.sh
ipv6_prefix_xlat/run_scion.sh
```

The setup scripts configures 1:1 IPv6 prefix translation via nftables in the default namespace:
```bash
ip route add fc00:10fc:100::/40 dev veth7
ip6tables -t nat -A OUTPUT -d fc00:10fc:100::/40 -j NETMAP --to fd00:deca:100::/40
```

#### Step 2: Run Scitra-TUN ####

In namespace `scitra`:
```bash
sudo ip netns exec scitra sudo -u $USER bash
scitra-tun -x -a fd00:deca:100::2/40 -t fd00:10fc:100::2 -d [fd00:deca:100::1]:30255 \
  --mode=gateway --scmp --tui -l debug --log-file gateway.txt
# Alternatively test prefix translation mode in normal mode:
scitra-tun -x -a fd00:deca:100::2/64 -t fd00:10fc:100::2 -d [fd00:deca:100::1]:30255 \
  --scmp --tui -l debug --log-file gateway.txt
```

In namespace `host2`:
```bash
sudo ip netns exec host2 sudo -u $USER bash
scitra-tun -a fc00:10fc:200::2 -t fd00::1 -d [fc00:10fc:200::1]:30255 -p 32000 --scmp \
  --tui -l debug --log-file host2.txt
```

#### Step 3: Test Inter-AS Connectivity ####

Start a server in namespace `host2`.
```bash
nc -ul fd00::1 32000
```

Connect from `scitra`, `host0`, and `host1`.
```bash
nc -u fc00:10fc:200::2 32000
```

#### Step 4: Cleanup ####
```bash
ipv6_prefix_xlat/stop_scion.sh
sudo ipv6_prefix_xlat/teardown.sh
```
