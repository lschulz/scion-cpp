% scitra-tun(8) Version 0.1.0 | Scitra Manual

## NAME ##

scitra-tun - a SCION-IP packet translator

## SYNOPSIS ##

| **scitra-tun** \[**-a** _address_\] \[**--config** _config_\] \[_Options_\]

## DESCRIPTION ##

Scitra-TUN is a flexible SCION-IP translator with support for SCION over IPv4 or IPv6 underlays,
multipath transport via MPTCP, and a gateway mode. It allows IPv6 applications to connect to a SCION
network via a TUN device that accepts traffic to the SCION-mapped IPv6 prefix fc00::/8. SCION
communication with border routers and other SCION hosts is done through UDP sockets that are created
and destroyed dynamically.

Scitra-TUN has two main modes of operation: normal mode and gateway mode. In normal mode, Scitra-TUN
is deployed on an end host that is represented by a single SCION-mapped IPv6 address. In gateway
mode, an entire SCION-mapped IPv6 subnet to the translator. The translator then behaves like an IPv6
gateway router to this IPv6 subnet and as a proxy for all IPv6 hosts behind it to the SCION network.
The advantage of gateway mode is that Scitra-TUN can be deployed as a network appliance rather than
requiring SCION connectivity on each end host. However, if end host do not run Scitra-TUN
themselves, they lose path control and access to SCION multipath transport.

Scitra-TUN relies on SCION-mapped IPv6 addresses to identify SCION hosts within IPv6. SCION ASes
that use Scitra-TUN (or any other SCION-IP translator) must be able to route SCION-mapped IPv6
addresses between applications and Scitra-TUN. If Scitra-TUN is used in normal mode directly on an
end host, this is easily achieved as SCION-mapped IPv6 address only have to be routed on localhost.
In gateway mode, the AS-internal IPv6 network must be configured to route fc00::/8 to the
translator, for example by pushing a route the end hosts via NDP. Routing between Scitra-TUN and to
local border routers may use IPv4 or IPv6. If IPv6 is used, it is recommended but not required to
assign SCION-mapped IPv6 addresses to SCION hosts.

## OPTIONS ##

### Required Options ###

`-a, --address` _address_ Required. Public IP address of Scitra in the SCION-AS-internal network.
    May include a prefix length in CIDR notation in gateway mode or if underlay prefix translation
    is enabled (`-x, --xlat-underlay`).

### Address Options ###

`-i, --interface` _interface_ Network interface through which other SCION hosts can be reached. This
    interface determines the default maximum MTU. If not given, the interface is determined from
    public IP address (`-a, --address`).

`-t, --tun-addr` _addr_ Override the address assigned to the TUN device with another IPv6 address.
    By default, the TUN address is derived from the public IP address.

`-e, --tun-extra` _address_\[,_address_...\] Additional addresses assigned to the TUN interface for
    MPTCP connections as comma-separated list.

`-n, --tun-name` _name_ Name of the TUN device created by scitra-tun. Default: "scion"

`-d, --sciond` SCION daemon address. Is also read from the environment variable
    SCION_DAEMON_ADDRESS. Default: 127.0.0.1:30255

### Translation Options ###

`-m, --mode` _mode_ Operating mode, either normal or gateway. Normal mode is the default.

`-x, --xlat-underlay` Enabled underlay prefix translation. Only possible with an IPv6 underlay.

`--scmp` Accept SCMP packets at the endhost/dispatcher port (30041/UDP).

`-p, --ports` _port_\[,_port_...\] Statically forwarded TCP/UDP ports as comma-separated list. In
    gateway mode, this list may contain IP:Port pairs. If ports without an IP are given in gateway
    mode, the port is forwarded from the public address (`-a, --address`).

### MTU Options ###

`-M, --mtu` _mtu_ Override the default MTU of the TUN interface. The default value is derived from
    the MTU of public interface (see `-i, --interface`) and the underlay MTU (see `-u`). Ignored if
    zero. Values are clamped to the minimum MTU allowed for IPv6 (1280). In most cases, adjusting
    the underlay MTU should be preferred over setting the TUN interface MTU directly.

`-u, --underlay-mtu` _umtu_ The minimum link-layer underlay PMTU to any SCION router or host in the
    local AS. Ignored if zero. Setting this value causes Scitra-TUN to ignore the AS-internal MTU
    learned from the SCION daemon. The underlay MTU _umtu_ is related to the SCION MTU _smtu_
    specified in topology.json files by the formula _umtu_ = _smtu_ + 28 (for UDP/IPv4 underlays) or
    _umtu_ = _smtu_ + 40 (for UDP/IPv6 underlays). If packets are being dropped due to exceeding the
    discoverd PMTU in the underlay, lower this value.

### STUN Options ###

`-S, --stun` Attempt NAT traversal.

`--stun-port` _port_ Port at which STUN servers are expected. If set to zero or not specified, STUN
    is multiplexed on the same port as SCION.

`--stun-timeout` _timeout_ Timeout for NAT bindings. That is, after how many seconds of inactivity a
    STUN request must be repeated. Default: 30 seconds

### Path Selection Options ###

`--policy` _policy_ Path to a JSON file containing path policies.

### Performance Tuning Options ###

`-q, --queues` _queues_ Number of TUN queues and threads. Default: 1

`-t, --threads` _threads_ Number of socket worker threads. Default: 1

### Log Options ###

`-l, --log-level` _level_ Log level as string or integer from the possible values trace(0),
    debug(1), info(2), warning(3), error(4), critical(5). Default: warning

`--log-file` _log_ Path to log file. Log is written to stderr if this option is not given.

### Other Options ###

`--daemon` Run as a systemd daemon. If this flag is set, Scitra-TUN will notify systemd when
    initialization has been completed as required for services of type "notify".
    See systemd.service(5).

`--tui` Start with text/terminal user interface. If the TUI is enabled, log output should be
    redirected to a file (see -l, --log-file).

`--config` _config_ Configuration file containing command line options in ini or TOML syntax.
    If an option is given in the configuration file and on the command line, the command line option
    has precedence.

`-v, --version` Display program version and exit.

`-h, --help` Show command syntax.

## OPTION FILE ##

Command line options may be read from a file in ini or TOML syntax given by the `--config` option.
If an option is specified in the config file and on the command line, the command line takes
precedence.

## CONFIGURATION ##

Scitra-TUN is configured by command line options and/or options read from a configuration file. As
the valid configuration options depend in part on the selected operating mode (normal or gateway),
you should first determine which mode you need. The mode is selected with the `-m/--mode` option, it
defaults to normal mode if nothing else is given.

Normal mode works on any host with existing SCION connectivity. It gives applications running on the
same host access to SCION via SCION-mapped IPv6 addresses. IPv6 servers may be exposed to SCION by
"forwarding" ports. All translator features including path policies and MPTCP endpoints are
available in normal mode. In normal mode, there is a separate translator with its own set of
policies and flow states for each SCION end host address.

Gateway mode changes to 1:1 relation between translator instances and SCION host addresses to 1:n.
A single translator in gateway mode can translate for a large number of IPv6 hosts that do not need
to run their own SCION stack. In order to make proper use of gateway mode, the entire SCION AS needs
to be configured for it, hence the initial setup is more complex than with individual Scitra-TUN
instances on end hosts.

### Addresses and their Relationships ###

Scitra-TUN translates between different IPv4, IPv6, and SCION addresses in order to bridge IPv6 and
SCION networks. This section gives a short overview of the addresses involved in SCION-IP
translation.

* *Public IP Address* The IP address of a SCION host within its SCION AS. In Scitra-TUN this can
  either be an IPv4 or an IPv6 address. If the public IP is IPv6, it must either be a SCION-mapped
  IPv6 address or *underlay prefix translation* with a different IPv6 prefix must have been
  configured. In gateway mode, or if underlay prefix translation is active, this address may have
  a subnet mask different from /32 for IPv4, or /128 for IPv6, respectively. If *public IP*
  describes a subnet in gateway mode, the translator is responsible for all addresses from this
  subnet.

* *Public SCION Address* The combination of the *public IP address* with the SCION ISD and ASN of
  the local AS. Shown as `Host address` in the header of Scitra-TUN's TUI.

* *(SCION-)Mapped IP Address* The SCION-mapped IPv6 equivalent of the *public SCION address*. If
  the *public IP* is not an IPv4 address or SCION-mapped IPv6 and hence underlay prefix translation
  is active, this address derived from the local SCION ISD-ASN and the host part of *public IP*.
  The mapped SCION address is shown under `Mapped` in the TUI.

* *TUN IP* The IPv6 address that is assigned to the TUN device created by Scitra-TUN. This address
  may be equal to the *mapped IP*, but in many situations it will be different address, often a ULA.
  In gateway mode, this address belongs to the AS-internal IPv6 network that is being translated to
  SCION. *TUN IP* inherits the subnet mask (prefix length) of *public IP*. In the TUI, *TUN IP* is
  show under `Bind To`, as local IPv6 applications should select this address as source IP.

* *surrogate/extra IPs* Additional IP address can be assigned to the TUN interface to provide local
  endpoints for MPTCP. Surrogate IPs are only supported in normal mode.

### Configuration Examples ###

The following examples serve as an introduction to configuring Scitra-TUN and AS-internal SCION
routing. They cover the most common situations, but are not meant to be exhaustive. Examples are
grouped by mode (normal and gateway) and SCION underlay (UDP/IPv4 and UDP/IPV6).

### Normal Mode ###

The configuration steps for using Scitra-TUN in normal mode differ depending on whether your SCION
AS uses a UDP/IPv4 or UDP/IPv6 underlay for its internal communication. The IPv4 case is simpler, so
we start there before we look at IPv6.

#### SCION with a UDP/IPv4 Underlay ####

Required Information:
- The address of the SCION daemon is running on the system. The SCION daemon is part of any standard
  SCION installation. If not given, Scitra-TUN assumes the default of `127.0.0.1:30255`.
- The local IPv4 addresses assigned to the public interface that is used to communicate with SCION
  routers and hosts. Often a private address, but can also be routable on the Internet. This is the
  *public IP*.

Invoke Scitra-TUN as:
```bash
scitra-tun -a public_address -d daemon_address
```
Replace public_address with the *public IP* (without a prefix length or /32) and *daemon_address*
with the local SCION daemon. The identity of the local AS is learned from the SCION daemon, so if
you are connecting to multiple SCION ASes, make sure it is the correct one. If not given on the
command line or in the configuration file, the daemon address can also be loaded from the
semi-standard environment variable `SCION_DAEMON_ADDRESS`.

Scitra-TUN will create a TUN interface named `scion`, assign the SCION-mapped IPv6 representing the
local host and add a route for `fc00::/8` via interface `scion`.

#### SCION with a UDP/IPv6 Underlay ####

Required Information:
- The SCION daemon address and *public IP* which is now a SCION-mapped IPv6 address. If the AS does
  not use SCION-mapped IPv6 addresses for internal routing, read the section on **underlay prefix
  translation**.
- A routable (not link-local) IPv6 address to assign to the translator's TUN interface. Can't be the
  same as the public address. This address is never used on the network, but is must have a unique
  prefix that is only routed to the TUN interface. This address is called the *TUN address*.

Invoke Scitra-TUN as:
```bash
scitra-tun public_interface public_address -a tun_address -d daemon_address
```

Scitra-TUN will create the TUN interface with the selected address and a route for `fc00::/8`. At
this stage the translator might already be working for destinations in remote ASes, but additional
route changes are necessary to complete the configuration. The issue is that there are now two
conflicting routes in the routing table, for example:
```bash
$ ip -6 route
fc00:10fc:100::/64 dev eth0 metric 1024 pref medium      # (1)
fc00::/8 dev scion proto static metric 1024 pref medium  # (2)
```
The first route (1) is for our public interface `eth0` and comes from the SCION-mapped IPv6 address
configured on that interface. The second route (2) was created by Scitra-TUN to funnel packets that
are to be translated to SCION into the TUN interface. Together these routes create two problems:
1. Traffic to destinations in the same AS and same IP subnet (`fc00:10fc:100::/64` in the example)
is not translated as route (1) is preferred over route (2) as (1) has the longer prefix. This
behavior might be desirable as using SCION for AS-local communication incurs unnecessary overhead,
but will not work if the destination is a native SCION application.
2. More importantly, there is a routing loop if the destination is in the same AS as our host but in
a different subnet that is not directly connected. Since the underlay destination address of packets
after translation is still going to be from the `fc00::/8` subnet they are immediately routed back
into the translator instead of going out to the network. If the underlay destination is in the same
SCION subnet as our host, rule (1) matches and the loop is averted, otherwise packets enter a loop
until they become too big and are dropped.

To solve issue (2) we can employ source routing. Packets that originate from the public address used
by Scitra-TUN should be routed with a different routing table. We can set up a second routing table
as follows:
```bash
sudo ip route add fc00::/8 via fc00:10fc:100::1 dev eth0 table 1
```
Replace `fc00:10fc:100::1` with the IP of the gateway router in the SCION subnet. The example uses a
routing table at index `1`. Linux sets up the tables *default* (index 253), *main* (index 254), and
*local* (index 255) on boot. You can check how other tables are used (as far as the `ip` command is
concerned) by looking at `/etc/iproute2/rt_tables`. Check a tables contents with
`ip route show table n` where n is tha table index or name. Pick the index of an empty table for the
new route.

To use the new table, we can add a rule to the routing policy database like so
```bash
sudo ip -6 rule add from fc00:10fc:100::2/128 table 1
```
This causes packet with a source address of `fc00:10fc:100::2` to be routed according to table 1.
You should replace `fc00:10fc:100::2` with the the *public address* Scitra-TUN is configured with.
Now the routing loop is avoided.

We can address issue (1)1 by simply deleting the route for `fc00:10fc:100::/64`, thus sending all
packets addressed to a SCION-mapped IP through the translator. If you do so, you probably want to
add the route back to the alternative routing table set up above to ensure directly connected
destinations are still reachable (via SCION only).
```bash
sudo ip route del fc00:10fc:100::/64 dev eth0 table main
sudo ip route add fc00:10fc:100::/64 dev eth0 table 1
```

**Important:** If the SCION control service and/or border routers use addresses from a `fc00::/8`
subnet, it must be ensured that there still is a route to reach them in the main routing table.
Hence, if you delete the route from the public interface, more specific routes for the SCION
services have to be added back in. For example, if the control service is at `fc00:10fc:100::1` you
can add a direct route to it with `sudo ip route add fc00:10fc:100::/128 dev eth0`. The same
principle applies to any other destination in the local AS that use SCION-mapped IPv6 addresses, but
should still be exempt from translation.

Changes to the routing tables may not be applied immediately, as the kernel maintains a routing
cache that may not get updated quickly. After changing the routes it is a good practice to flush the
cache with `sudo ip route flush cache`.

### Gateway Mode ###

Whereas in normal mode you assign a single *public address* and *tun address* to the translator,
gateway mode allows routing entire IPv6 subnets to SCION. Scitra-TUN in gateway may be deployed on
a separate (router) host as a gateway network appliance, or may be colocated with a border router.
Gateway mode is also useful if you have VMs or containers that all should all share the same SCION
connection and Scitra-TUN instance.

Operating Scitra-TUN in gateway mode starts with planning the network addresses and routing on the
translator's IP side. IP hosts must have IPv6 addresses from a common private IPv6 prefix that also
includes the *TUN address*. In the IPv6 network, Scitra-TUN (via the *TUN address*) must be
configured as gateway router for the SCION-mapped IPv6 prefix `fc00::/8`. In small network, both
requirements can be achieved by running a router advertisement daemon that advertises the private
prefix for SLAAC and a route to `fc00::/8` via *TUN address* in RA messages with Route Information
Options.

The IPv6 prefix on the TUN side is derived from the *TUN address* and the prefix length given to the
*public address*. In gateway mode, the *public address* must have a prefix length < 128 (or < 32 for
IPv4 underlays). The same prefix length applies to *TUN address*. Scitra-TUN in gateway mode will
only translate the prefix of the *public* and *TUN* IPs. The bits to the right of the prefix are
left unchanged, so IPv6 host appear with the subnet and interface ID in SCION. For example, the
public address `fc00:10fc:100::2/40` would mean that the translator host itself has IP
`fc00:10fc:100::2`, but all addresses in `fc00:10fc:100::/40` are mapped to corresponding *TUN
addresses* with the lower 88 bits identical between the IP and SCION side. If the *public address*
is IPv4, it is expanded to a SCION-mapped IPv6 address with IPv4 host part before translation.

Gateway mode is enabled by setting `--mode=gateway` on teh command line or in the configuration
file. Gateway mode can be combined with **underlay prefix translation**, but is incompatible with
*extra IPs* for MPTCP.

#### Gateway Mode with a UDP/IPv6 Underlay ####

A Scitra-TUN gateway in a SCION AS with an IPv6 underlay network may look similar to the following
figure.

```
                            SCION AS 1-64513
+--------------------+--------------------------+----------------------------+
|    IPv6 Network    |       Gateway Host       | AS-internal Public Network |
+---------+--------- +--------+--- +------------+---------- +----------------+
| IP Host |<--IPv6-->| Kernel |<-->| Scitra-TUN |<-AS-int.->| Border Routers |
+---------+          +--------+    +------------+           +----------------+
        eth0       eth1        scion           pub       internal        (Interface)
fd00:x:100::2/64     |      fd00:x:2/48   fc00:x::2/48      |            (IP where x=10fc:100)
              fd00:x:100::1/64                         fc00:x::1/40
```

In this AS with ASN 1-64513, border routers are connected to the AS-internal network
`fc00:10fc:100::/40` which matches the SCION-mapped IPv6 prefix for `1-64513` exactly. The *public
address* of Scitra-TUN in the AS-internal network is `fc00:10fc:100::2/48`. The TUN interface on the
IP side has the default name `scion` and shares the /48 prefix length with the *public IP*, but the
prefix is `fd00:10fc:100::` instead of `fc00:10fc:100::`. The gateway itself has the *TUN address*
`fd00:10fc:100::2`. IPv6 hosts behind the gateway are in the subnet `fd00:10fc:100:100::/64` of
prefix `fd00:10fc:100::/48`. The address `fd00:10fc:100:100::1/64` is configured as gateway to
SCION (i.e., the prefix `fc00::/8`) on the IPv6 hosts and assigned to one of the network physical
network interfaces (eth1) of the gateway host. IPv6 forwarding must be enabled on the gateway host,
so traffic can be forwarded between the eth1 and scion interfaces.

A minimal invocation of Scitra-TUN in this network is
```bash
scitra-tun -m gateway -a fc00:10fc:100::2/48 -t fd00:10fc:100::2
```

Additionally the following routes must be configured.
```
------------------IP Hosts------------------
# Default route for SCION
ip route add fc00::/8 via fd00:10fc:100:100::1 dev eth0
--------------------------------------------

----------------Gateway Host----------------
# Enable IPv6 Forwarding
net.ipv6.conf.all.forwarding=1
# Scitra-TUN behaves as a proxy for IPv6 hosts by binding underlay UDP sockets
# to non-local addresses. In order for non-local socket to receive packets, the
# proxied SCION-mapped IPv6 addresses must be added to the local table.
ip route add local fc00:10fc:100:100::/64 dev lo table local
--------------------------------------------

----------------Border Routers--------------
# Border routers need a route to the internal IPv6 address in SCION-mapped form.
ip route add fc00:10fc:100:100::/64 via fc00:10fc:100::2 dev internal
--------------------------------------------
```

#### Gateway Mode with a UDP/IPv4 Underlay ####

Configuring gateway mode with an IPv4 underlay is very similar to IPv6 underlays, but places
constraints on the maximum size of the IPv6 network on the TUN interface side. Since Scitra-TUN
translates addresses from the IPv6 network one-to-one to public SCION addresses, the IPv6 network
cannot have more IPv6 addresses than than the AS-internal network has IPv4 addresses. For example,
if the *public address* is configured as `10.0.0.1/24`, the TUN-side network must not have a prefix
shorter (i.e. with more addresses) than /120. Scitra-TUN automatically calculates the correct prefix
length for *TUN address* when an IPv4 *public address* is used in gateway mode.

While the *TUN address* prefix can be chosen freely, the recommended convention is to use the
SCION-mapped IPv6 format for IPv4 host addresses (e.g. `fcxx:...:ffff:10.0.0.1/120`), optionally
with a substituted prefix (e.g. `fdxx:...:ffff:10.0.0.1/120`).

The following example continues the configuration of AS 1-64513, but this time with an IPv4
underlay.

```
                      SCION AS 1-64513 (IPv4 Underlay)
+--------------------+--------------------------+----------------------------+
|    IPv6 Network    |       Gateway Host       | AS-internal Public Network |
+---------+--------- +--------+--- +------------+---------- +----------------+
| IP Host |<--IPv6-->| Kernel |<-->| Scitra-TUN |<-AS-int.->| Border Routers |
+---------+          +--------+    +------------+           +----------------+
        eth0       eth1        scion           pub       internal        (Interface)
         | fd00:x:10.128.1.1/120 |        10.128.0.2/16     |            (IP where x=10fc:100::ffff)
         |              fd00:x:10.128.0.2/112          10.128.0.1/16
fd00:x:10.128.1.2/120
```

The necessary routing tables entries are:
```
------------------IP Hosts------------------
# Default route for SCION
ip route add fc00::/8 via fd00:10fc:100::ffff:10.128.1.1 dev eth0
--------------------------------------------

----------------Gateway Host----------------
# Enable IPv6 Forwarding
net.ipv6.conf.all.forwarding=1
# Scitra-TUN behaves as a proxy for IPv6 hosts by binding underlay UDP sockets
# to non-local addresses. In order for non-local socket to receive packets, the
# proxied addresses must be added to the local table.
ip route add local 10.128.1.0/24 dev lo table local
--------------------------------------------

----------------Border Routers--------------
# Border routers need a route to the internal IPv6 address in SCION-mapped form.
ip route add 10.128.1.0/24 via 10.128.0.2 dev internal
--------------------------------------------
```

### Underlay Prefix Translation ###

When used with an IPv6 underlay, Scitra-TUN expects the *public address* to be a SCION-mapped IPv6
address with the prefix corresponding to the ISD and ASN of the local AS. This way the *mapped
address* is equal to the *public address* and both addresses can contain the ISD-ASN information
while also uniquely identifying a host within the AS. The same restriction does not apply to IPv4,
because the *mapped address* is always 128 bits long and can contain the arbitrary IPv4 host
addresses alongside the ISD-ASN prefix.

While using SCION-mapped IPv6 addresses in the SCION underlay creates a clean separation between
true IP-routed traffic and encapsulated SCION packets, not all ASes follow this convention. If the
internal address of the border router cannot be set to the correct SCION-mapped IPv6 address, it is
possible to use a different IPv6 prefix between Scitra-TUN and the border router(s). To enable this
feature, use the flag `-x, --xlat-underlay` and specify the desired prefix in the *public address*.
Prefix translation available for IPv6 underlays in both normal and gateway mode.

For prefix translation to work, border routers must also translate SCION-mapped IPv6 destination
addresses to the alternate prefix configured in Scitra-TUN. In Linux this can be achieved with a
static NAT rule in Netfilter.

**Example:** AS 1-64513 has the SCION-mapped IP prefix `fc00:10fc:100::/40`, but uses
the prefix `fd00:deca:100::/40` to route between SCION hosts and border routers. To avoid renumbering
the entire AS with SCION-mapped addresses, Scitra-TUN is started with prefix translation.
```bash
scitra-tun -x -a fd00:deca:100::2/40
```

Scitra-TUN will now send SCION packets that use the prefix `fd00:deca:100::/40` in the underlay, but
still fill in the source host address in the SCION header with prefix `fc00:10fc:100::/40`. In order
for traffic from SCION to be routed correctly back to Scitra-TUN, border routers must translate
destinations addresses in `fc00:10fc:100::/40` back to the underlay prefix `fd00:deca:100::/40`
before consulting the AS-internal routing table. This can be achieved by adding a Netfilter NAT
rule to a new table and chain created with nftables.
```bash
nft add table ip6 nat
nft add chain ip6 nat output '{ type nat hook output priority -100; }'
nft add rule ip6 nat output dnat ip6 prefix to ip6 daddr map { fc00:10fc:100::/40 : fd00:deca:100::/40 }
# Delete with: nft delete table ip6 nat
```
Netfilter rules are made persistent by adding them to `/etc/nftables.conf`.
```
table ip6 nat {
  chain output {
    type nat hook output priority dstnat; policy accept;
    dnst ip6 prefix to ip6 daddr map { fc00:10fc:100::/40 : fd00:deca:100::/40 }
  }
}
```
Alternatively the same can be achieved with the legacy `ip6tables` command.
```bash
ip6tables -t nat -A OUTPUT -d fc00:10fc:100::/40 -j NETMAP --to fd00:deca:100::/40
# Delete with: ip6tables -t nat -D OUTPUT -d fc00:10fc:100::/40 -j NETMAP --to fd00:deca:100::/40
```

## TERMINAL USER INTERFACE ##

Start Scitra-TUN with the flag `--tui` to enter interactive mode. In interactive mode, a test-based
user interface is shown that can be navigated using keyboard and mouse. Pressing F1 displays a help
text with further instructions. WHen using the TUI, it is recommended to redirect log output to a
file by either redirecting stderr or specifying a file name with the `-l/--log-file` option.

## PORT FORWARDING ##

Scitra-TUN automatically opens SCION sockets for outgoing flows, but incoming flows are rejected by
default. To expose applications to the SCION network, their port(s) must be specified with the
`-p/--ports` option. Multiple ports should be separated by commas. There is no distinction between
UDP and TCP as the SCION underlay uses the same UDP port for both. Forwarded ports are known as
*persistent* in Scitra-TUN.

In gateway mode, ports from addresses other than the *public IP* can be forwarded by specifying a
an IP and port pair as `IP:Port`. If a plain port without the host IP os forwarded in gateway mode,
the IP is assumed to be *public IP* so the behavior is identical to normal mode.

**Warning:** Scitra-TUN is not a firewall. Statically and dynamically allocated underlay sockets
will forward all incoming SCION packets irrespective of whether they belong to an existing flow or
not. To prevent hosts on the SCION network from accessing services on your machine, a separate
firewall has to be placed at the TUN interface created by Scitra-TUN and optionally also between the
public network interface and Scitra-TUN.

## NAT TRAVERSAL ##

If Scitra-TUN is deployed behind a NAT, the `--stun` flag should be set to enable discovery of the
mapped external address. By default Scitra-TUN expects SCION border routers to respond to STUN
binding requests that are multiplexed on the same address and port as SCION traffic. If your routers
do not support multiplexed STUN, an alternative fixed STUN port may be set using the `--stun-port`
option. The `--nat-timeout` option sets after how much time of inactivity a flow between Scitra-TUN
and the border router may receive a new address mapping and therefore requires STUN address
discovery to be repeated.

## MULTIPATH TCP ##

Scitra-TUN can route MPTCP subflows over SCION. Since MPTCP identifies possible paths by available
addresses on multi-homed hosts, Scitra can assign *surrogate addresses* to the TUN interface in
addition to the primary IPv6 address. For each surrogate address an additional subflow and
therefore SCION path becomes available. You can assign surrogate addresses by invoking Scitra-TUN
with the `-e/--extra` option that takes one or more IPv6 unicast addresses. Surrogate addresses
should not be SCION-mapped IPv6 addresses, i.e., have a prefix different from `fc00::/8`, and should
not be routed anywhere else than into the TUN interface. Using unique local addresses (ULAs) with a
prefix under `fd00::/8` is recommended. In order for the addresses to be picked up by MPTCP, it is
usually necessary to configure MPTCP's path manager. In Linux this is possible with the
`ip mptcp endpoint` command, but may also be handled by a userspace daemon such as mptcpd or
NetworkManager. Check your operating system documentation for details on how to configure MPTCP.

Scitra-TUN can deal with MPTCP subflows even if not surrogate addresses are assigned. This can be
useful for combining subflows over the Internet with a subflow over SCION. Note however, that the
Linux implementation of MPTCP currently does not permit mixing address families, i.e., you can
combine IPv6 routing with SCION routing, but not with IPv4.

Multipath TCP with multiple SCION endpoints is only available in normal mode. However, gateway mode
can still be used to provide a (one) SCION endpoint to MPTCP for IP and SCION hybrid connections.

## PATH POLICY ##

Scitra-TUN accepts a set of traffic matchers and path policies in JSON format. The path to the
policy file is set with the `--policy` option. See scitra-policy.json(5) for a description of path
policies.

## SIGNALS ##

When Scitra-TUN receives `SIGHUP`, the path policies are reloaded from the the path specified in the
`--policy` option.

`SIGUSR1` cases Scitra-TUN to dump the state of all tracked flows to stdout.

## AUTHOR ##

Lars-Christian Schulz <lschulz@ovgu.de>

## SEE ALSO ##

scion2ip(1), scitra-policy.json(5), systemd.service(5), ip(8), nft(8)
