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
  "1-64513":
    cert_issuer: 1-64512
    underlay: UDP/IPv4
  "1-64514":
    cert_issuer: 1-64512
    underlay: UDP/IPv4
links:
  - {a: "1-64512-br1#1", b: "1-64513#1", linkAtoB: CHILD, underlay: UDP/IPv4}
  - {a: "1-64512-br1#2", b: "1-64514#1", linkAtoB: CHILD, underlay: UDP/IPv4}
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
jq '.control_service["cs1-64513-1"].addr |= sub("[^:]+"; "10.128.0.1") |
    .discovery_service["cs1-64513-1"].addr |= sub("[^:]+"; "10.128.0.1") |
    .border_routers["br1-64513-1"].internal_addr |= sub("[^:]+"; "10.128.0.1")' \
    "$SCION_ROOT/gen/AS64513/topology.json" | sponge "$SCION_ROOT/gen/AS64513/topology.json"
sed -i -E 's/127.0.0.[0-9]+/10.128.0.1/' "$SCION_ROOT/gen/AS64513/sd.toml"
jq '.control_service["cs1-64514-1"].addr |= sub("[^:]+"; "10.128.1.1") |
    .discovery_service["cs1-64514-1"].addr |= sub("[^:]+"; "10.128.1.1") |
    .border_routers["br1-64514-1"].internal_addr |= sub("[^:]+"; "10.128.1.1")' \
    "$SCION_ROOT/gen/AS64514/topology.json" | sponge "$SCION_ROOT/gen/AS64514/topology.json"
sed -i -E 's/127.0.0.[0-9]+/10.128.1.1/' "$SCION_ROOT/gen/AS64514/sd.toml"

# Run local SCION network
(cd "$SCION_ROOT" && ./scion.sh run)
