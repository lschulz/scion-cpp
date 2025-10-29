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
build/scitra/Debug/scitra-tun veth1 10.128.0.2 -d 10.128.0.1:30255 --dispatch
# IPv6
build/scitra/Debug/scitra-tun veth1 fc00:10fc:100::2 -d [fc00:10fc:100::1]:30255 --dispatch
```

In namespace `host1`:
```bash
# IPv4
build/scitra/Debug/scitra-tun veth3 10.128.1.2 -d 10.128.1.1:30255 --ports=32000 --dispatch
# IPv6
build/scitra/Debug/scitra-tun veth3 fc00:10fc:200::2 -d [fc00:10fc:200::1]:30255 --ports=32000 --dispatch
```

Can also run scitra-tun in the default namespace:
```bash
# IPv4
build/scitra/Debug/scitra-tun veth2 10.128.1.1 -d 10.128.1.1:30255
# IPv6
build/scitra/Debug/scitra-tun veth2 fc00:10fc:200::1 -d [fc00:10fc:200::1]:30255
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
nc -u -l fc00:10fc:200::ffff:a80:102 32000 # UDP
nc -l fc00:10fc:200::ffff:a80:102 32000    # TCP
```

Client on `host0`:
```bash
sudo ip netns exec host1 sudo -u $USER bash
nc -u fc00:10fc:200::ffff:a80:102 32000 # UDP
nc fc00:10fc:200::ffff:a80:102 32000    # TCP
```

**iperf3:**

Server on `host1`:
```bash
iperf3 -s -B fc00:10fc:200::ffff:a80:102 -p 32000
```

Client on `host0`:
```bash
iperf3 -c fc00:10fc:200::ffff:a80:102 -p 32000
```

### Step 6 ###

Stop the SCION network: `./stop.sh`.
Delete the network namespaces: `./teardown.sh`.
