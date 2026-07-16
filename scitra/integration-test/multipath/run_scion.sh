#!/bin/bash

set -e

if [ -z "$SCION_ROOT" ]; then
  echo "SCION_ROOT is not set"
  exit 1
fi

# Create SCION configuration
topofile=$(mktemp /tmp/topology.XXXXXXXXXX)
cat > "$topofile" << EOF
# Tiny topology with BGP-compatible ASNs and IPv4 underlays
ASes:
  "1-64512":
    core: true
    voting: true
    authoritative: true
    issuing: true
    underlay: UDP/IPv4
    mtu: 1472
  "1-64513":
    cert_issuer: 1-64512
    underlay: UDP/IPv4
    mtu: 1472
  "1-64514":
    cert_issuer: 1-64512
    underlay: UDP/IPv4
    mtu: 1472
links:
  - {a: "1-64512-br1#1", b: "1-64513-br1#1", linkAtoB: CHILD, underlay: UDP/IPv4, mtu: 1472}
  - {a: "1-64512-br1#2", b: "1-64513-br1#2", linkAtoB: CHILD, underlay: UDP/IPv4, mtu: 1472}
  - {a: "1-64512-br1#3", b: "1-64513-br1#3", linkAtoB: CHILD, underlay: UDP/IPv4, mtu: 1472}
  - {a: "1-64512-br1#4", b: "1-64514-br1#1", linkAtoB: CHILD, underlay: UDP/IPv4, mtu: 1472}
  - {a: "1-64512-br1#5", b: "1-64514-br1#2", linkAtoB: CHILD, underlay: UDP/IPv4, mtu: 1472}
  - {a: "1-64512-br1#6", b: "1-64514-br1#3", linkAtoB: CHILD, underlay: UDP/IPv4, mtu: 1472}
EOF

set +e
(cd "$SCION_ROOT" && ./scion.sh topology -c "$topofile")
err=$?
rm "$topofile"
if [ $err -ne 0 ]; then
  exit 1
fi
set -e

# Edit configuration
jq '.border_routers["br1-64512-1"].interfaces["1"].underlay.local |= sub("[^:]+"; "10.128.1.2") |
    .border_routers["br1-64512-1"].interfaces["1"].underlay.remote |= sub("[^:]+"; "10.128.1.1") |
    .border_routers["br1-64512-1"].interfaces["2"].underlay.local |= sub("[^:]+"; "10.128.2.2") |
    .border_routers["br1-64512-1"].interfaces["2"].underlay.remote |= sub("[^:]+"; "10.128.2.1") |
    .border_routers["br1-64512-1"].interfaces["3"].underlay.local |= sub("[^:]+"; "10.128.3.2") |
    .border_routers["br1-64512-1"].interfaces["3"].underlay.remote |= sub("[^:]+"; "10.128.3.1") |
    .border_routers["br1-64512-1"].interfaces["4"].underlay.local |= sub("[^:]+"; "10.128.5.2") |
    .border_routers["br1-64512-1"].interfaces["4"].underlay.remote |= sub("[^:]+"; "10.128.5.1") |
    .border_routers["br1-64512-1"].interfaces["5"].underlay.local |= sub("[^:]+"; "10.128.6.2") |
    .border_routers["br1-64512-1"].interfaces["5"].underlay.remote |= sub("[^:]+"; "10.128.6.1") |
    .border_routers["br1-64512-1"].interfaces["6"].underlay.local |= sub("[^:]+"; "10.128.7.2") |
    .border_routers["br1-64512-1"].interfaces["6"].underlay.remote |= sub("[^:]+"; "10.128.7.1")' \
    "$SCION_ROOT/gen/AS64512/topology.json" | sponge "$SCION_ROOT/gen/AS64512/topology.json"

jq '.control_service["cs1-64513-1"].addr |= sub("[^:]+"; "10.128.0.1") |
    .discovery_service["cs1-64513-1"].addr |= sub("[^:]+"; "10.128.0.1") |
    .border_routers["br1-64513-1"].internal_addr |= sub("[^:]+"; "10.128.0.1") |
    .border_routers["br1-64513-1"].interfaces["1"].underlay.local |= sub("[^:]+"; "10.128.1.1") |
    .border_routers["br1-64513-1"].interfaces["1"].underlay.remote |= sub("[^:]+"; "10.128.1.2") |
    .border_routers["br1-64513-1"].interfaces["2"].underlay.local |= sub("[^:]+"; "10.128.2.1") |
    .border_routers["br1-64513-1"].interfaces["2"].underlay.remote |= sub("[^:]+"; "10.128.2.2") |
    .border_routers["br1-64513-1"].interfaces["3"].underlay.local |= sub("[^:]+"; "10.128.3.1") |
    .border_routers["br1-64513-1"].interfaces["3"].underlay.remote |= sub("[^:]+"; "10.128.3.2")' \
    "$SCION_ROOT/gen/AS64513/topology.json" | sponge "$SCION_ROOT/gen/AS64513/topology.json"
sed -i -E 's/127.0.0.[0-9]+/10.128.0.1/' "$SCION_ROOT/gen/AS64513/sd.toml"

jq '.control_service["cs1-64514-1"].addr |= sub("[^:]+"; "10.128.4.1") |
    .discovery_service["cs1-64514-1"].addr |= sub("[^:]+"; "10.128.4.1") |
    .border_routers["br1-64514-1"].internal_addr |= sub("[^:]+"; "10.128.4.1") |
    .border_routers["br1-64514-1"].interfaces["1"].underlay.local |= sub("[^:]+"; "10.128.5.1") |
    .border_routers["br1-64514-1"].interfaces["1"].underlay.remote |= sub("[^:]+"; "10.128.5.2") |
    .border_routers["br1-64514-1"].interfaces["2"].underlay.local |= sub("[^:]+"; "10.128.6.1") |
    .border_routers["br1-64514-1"].interfaces["2"].underlay.remote |= sub("[^:]+"; "10.128.6.2") |
    .border_routers["br1-64514-1"].interfaces["3"].underlay.local |= sub("[^:]+"; "10.128.7.1") |
    .border_routers["br1-64514-1"].interfaces["3"].underlay.remote |= sub("[^:]+"; "10.128.7.2")' \
    "$SCION_ROOT/gen/AS64514/topology.json" | sponge "$SCION_ROOT/gen/AS64514/topology.json"
sed -i -E 's/127.0.0.[0-9]+/10.128.4.1/' "$SCION_ROOT/gen/AS64514/sd.toml"

sed -E "s/command = (.*AS64512.*)/command = su $USER -c '\1' /" "$SCION_ROOT/gen/supervisord.conf" \
    | sed -E "s/command = (.*AS64513.*)/command = ip netns exec as0 su $USER -c \'\1'/" \
    | sed -E "s/command = (.*AS64514.*)/command = ip netns exec as1 su $USER -c \'\1'/" \
    | sed -n '/^\[program:dispatcher\]$/q;p' | sponge "$SCION_ROOT/gen/supervisord.conf"

# Run local SCION network
(cd "$SCION_ROOT" && sudo tools/supervisor.sh start all)
