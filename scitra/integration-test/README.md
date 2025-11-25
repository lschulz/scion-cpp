Scitra-TUN Test Setup
=====================

#### Step 1 ####

Create network namespaces and veth pairs using the [setup.sh](./setup.sh) script.

```bash
sudo ./setup.sh
```

#### Step 2 ####

Create and run a local SCION network that connects to the namespaces created in
Step 1. The scripts expect the environment variable `SCION_ROOT` to point to
the root of a local [SCION source](https://github.com/scionproto/scion/) tree.

With a UDP/IPv4 underlay:
```bash
./run_tiny4_bgp.sh
```

With a UDP/IPv6 underlay:
```bash
./run_tiny6_bgp.sh
```

#### Step 3 ####

Run instances of scitra-tun in namespace `host0` and `host1`. A shell in the
namespace can be obtained with:
```bash
sudo ip netns exec host0 sudo -u $USER bash
```

In namespace `host0`:
```bash
# IPv4
build/scitra/Debug/scitra-tun-d veth1 10.128.0.2 -d 10.128.0.1:30255 --dispatch --tui
# IPv6
build/scitra/Debug/scitra-tun-d veth1 fc00:10fc:100::2 -a fd00::1 -d [fc00:10fc:100::1]:30255 \
    --dispatch --tui
```

In namespace `host1`:
```bash
# IPv4
build/scitra/Debug/scitra-tun-d veth3 10.128.1.2 -d 10.128.1.1:30255 --ports=32000 --dispatch --tui
# IPv6
build/scitra/Debug/scitra-tun-d veth3 fc00:10fc:200::2 -a fd00::2 -d [fc00:10fc:200::1]:30255 \
    --ports=32000 --dispatch --tui
```

#### Step 4 ####

Run two instances of [Scapy-SCION](/python/scapy-scion-int/) in namespace
`host0` to sniff traffic on the interfaces `scion` and `veth1`. Run another two
instances in namespace `host1` sniffing packets on interface `scion` and
`veth3`.

```bash
sudo ip netns exec host0 bash
. .venv/bin/activate
cd python/scapy-scion-int
./scapy-scion
```
```python
pkts = sniff(iface="scion", prn=lambda x: x.summary())
```

Keep an eye on sockets being created in both namespaces:
```bash
watch -n 1 cat /proc/net/tcp6
watch -n 1 cat /proc/net/udp
```

#### Step 5 ####

Generate test traffic. The following examples use the IPv4 underlay. For IPv6,
replace `fc00:10fc:200::ffff:a80:102` with `fc00:10fc:200::2` etc.

**Ping:** Since border routers use the ID field in SCMP echo requests to
determine the underlay destination port some special options are required to
make ping work without issues.
```bash
sudo ip netns exec host0 sudo -u $USER bash
ping fc00:10fc:200::ffff:a80:102 -s 0 -e 30041
ping fc00:10fc:200::ffff:a80:102 -p FFFF -e 65535
```

**Netcat:** In order to expose a UDP or TCP server on SCION, the corresponding
port must be forwarded with the `--ports` option. This test setup exposes port
32000 of `host1`.

Server on `host1`:
```bash
sudo ip netns exec host0 sudo -u $USER bash
nc -6 -l 32000 # -u for UDP
```

Client on `host0`:
```bash
sudo ip netns exec host1 sudo -u $USER bash
nc fc00:10fc:200::ffff:a80:102 32000 # -u for UDP
```

**iperf3:**

Server on `host1`:
```bash
iperf3 -s -p 32000
```

Client on `host0`:
```bash
iperf3 -c fc00:10fc:200::ffff:a80:102 -p 32000
```

#### Step 6 ####

Stop the SCION network: `./stop.sh`.
Delete the network namespaces: `sudo ./teardown.sh`.

Path Failure
------------

Switch to the path via core AS 1-64512 and stop the border router of AS 1-64512:
```bash
cd $SCION_ROOT
tools/supervisor.sh mstop as1-64512:br1-64512-1
```

Flows should switch over to the peering link now and the original path is marked
as "broken" in the path selection menu.

Restart the border router:
```bash
tools/supervisor.sh mstart as1-64512:br1-64512-1
```

Selecting the path through AS 1-64512 should work again.

AS-Internal Traffic
-------------------

Test AS-internal communication with empty paths by running the `echo-udp-async`
example in (a) the same AS and same subnet as the translator, (b) the same AS
but different subnet, and (c) in a different AS.

### IPv6 ###

Start translator in `host0`.

Configure routes in `host0`:
```bash
sudo ip route add fc00::/8 via fc00:10fc:100::1 dev veth1 table 1
sudo ip -6 rule add from fc00:10fc:100::2/128 table 1
sudo ip route del fc00:10fc:100::/64 dev veth1
sudo ip route add fc00:10fc:100::/64 dev veth1 table 1
sudo ip route add fc00:10fc:100::1/128 dev veth1
sudo ip route flush cache
```

Add another address to fc00:10fc:100::/64 so the echo server is separate from
the control service and border routers.
```bash
sudo ip addr add fc00:10fc:100::3 dev veth0
```

Add a dummy interface to the default namespace to simulate another subnet:
```bash
sudo ip link add dummy0 type dummy
sudo ip addr add dev dummy0 fc00:10fc:100:100::1/64
```

Run echo servers:
```bash
build/examples/Debug/echo-udp-async --sciond [fc00:10fc:100::1]:30255 --local [fc00:10fc:100::3]:32000
build/examples/Debug/echo-udp-async --sciond [fc00:10fc:100::1]:30255 --local [fc00:10fc:100:100::1]:32000
sudo ip netns exec host1 sudo -u $USER bash
build/examples/Debug/echo-udp-async --sciond [fc00:10fc:200::1]:30255 --local [fc00:10fc:200::2]:32000
```

Packets should be echoed back:
```bash
sudo ip netns exec host0 sudo -u $USER bash
nc -u fc00:10fc:100::3 32000
nc -u fc00:10fc:100:100::1 32000
nc -u fc00:10fc:200::2 32000
```

### IPv4 ###

Start translator in `host0`.

Remove the IPv6 route in `host0` as it interferes with reaching SCION hosts in
the same subnet:
```bash
sudo ip route del fc00:10fc:100::2/64
```

Run echo servers:
```bash
build/examples/Debug/echo-udp-async --sciond 10.128.0.1:30255 --local 10.128.0.1:32000
sudo ip netns exec host1 sudo -u $USER bash
build/examples/Debug/echo-udp-async --sciond 10.128.1.1:30255 --local 10.128.1.2:32000
```

Packets should be echoed back:
```bash
sudo ip netns exec host0 sudo -u $USER bash
nc -u fc00:10fc:100::ffff:a80:101 32000
nc -u fc00:10fc:200::ffff:a80:102 32000
```
