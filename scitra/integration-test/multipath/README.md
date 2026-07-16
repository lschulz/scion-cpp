Scitra-TUN Multipath Test Setup
===============================

Network namespaces and veths are set up by the `setup.sh` script as follows:
```
                    +---------+           +---------+             +---------+
+-------+           |         |<-veth3:2->|         |<-veth10:9-->|         |           +-------+
| host0 |<-veth0:1->| AS64513 |<-veth5:4->| AS64512 |<-veth12:11->| AS64514 |<-veth9:8->| host1 |
+-------+           |         |<-veth7:6->|         |<-veth14:13->|         |           +-------+
    ^               +---------+           +---------+             +---------+               ^
    |                                                                                       |
    +-------------------------------------- vethA:B-----------------------------------------+
```
* AS64512 is in the default namespace
* AS64513 is in namespace as0
* AS64514 is in namespace as1
* vethA (fd01::1/64) to vethB (fd01::2/64) connect the hosts directly
* The default tc settings on the inter-AS links and vethA:B are 10 Mbit/s bandwidth
  (limited by the sender) with 10 ms delay (20 ms end-to-end, because SCION paths pass two links)

#### Step 1: Set up the network ####
```bash
sudo ./setup.sh
./run_scion.sh
```

#### Step 2: Increase MPTCP limits ####
```bash
sudo ip netns exec host0 ip mptcp limits set add_addr_accepted 4 subflows 6
sudo ip netns exec host1 ip mptcp limits set add_addr_accepted 4 subflows 6
```

#### Step 3: Run Scitra-TUN ####
Host 0:
```bash
sudo ip netns exec host0 sudo -u $USER bash
build/scitra/Debug/scitra-tun-d veth0 10.128.0.2 --extra fd00::1 fd00::2 \
  -d 10.128.0.1:30255 --scmp --tui -l debug --log-file log0.txt
```

Host 1:
```bash
sudo ip netns exec host1 sudo -u $USER bash
build/scitra/Debug/scitra-tun-d veth8 10.128.4.2 --extra fd00::1 fd00::2 \
  -d 10.128.4.1:30255 --ports=32000 --scmp --tui -l debug --log-file log1.txt
```

#### Step 4: Configure MPTCP Endpoints ####
Host 0:
```bash
sudo ip mptcp endpoint flush
sudo ip mptcp endpoint add fc00:10fc:100::ffff:a80:2 dev scion subflow
sudo ip mptcp endpoint add fd00::1 dev scion subflow
sudo ip mptcp endpoint add fd00::2 dev scion subflow
```

Host 1:
```bash
sudo ip mptcp endpoint flush
sudo ip mptcp endpoint add fc00:10fc:200::ffff:a80:102 dev scion subflow
sudo ip mptcp endpoint add fd00::1 dev scion subflow
sudo ip mptcp endpoint add fd00::2 dev scion subflow
```

#### Step 5: Connection Test ####
Host 0: Client
```bash
mptcpize run nc fc00:10fc:200::ffff:a80:402 32000
```

Host 1: Server
```bash
mptcpize run nc -6 -l 32000
```

Check connection status
```bash
sudo ip netns exec host0 ss -Mani
sudo ip netns exec host1 ss -Mani
```

#### Step 6: Bandwidth Test ####
Host 0: Client
```bash
mptcpize run iperf3 -c fc00:10fc:200::ffff:a80:402 -p 32000 -t 20 -b 30M
```

Host 1: Server
```bash
mptcpize run iperf3 -s -p 32000
```

#### Step 7: Teardown ####
```bash
./stop_scion.sh
sudo ./teardown.sh
```
