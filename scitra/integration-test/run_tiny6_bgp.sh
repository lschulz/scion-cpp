#!/bin/bash

set -e

if [ -z "$SCION_ROOT" ]; then
  echo "SCION_ROOT is not set"
  exit 1
fi

# Create SCION configuration
topofile=$(mktemp /tmp/topology.XXXXXXXXXX)
cat > "$topofile" << EOF
# Tiny topology with BGP-compatible ASNs and IPv6 underlays
ASes:
  "1-64512":
    core: true
    voting: true
    authoritative: true
    issuing: true
    underlay: UDP/IPv6
  "1-64513":
    cert_issuer: 1-64512
    underlay: UDP/IPv6
  "1-64514":
    cert_issuer: 1-64512
    underlay: UDP/IPv6
links:
  - {a: "1-64512-br1#1", b: "1-64513#1", linkAtoB: CHILD, underlay: UDP/IPv6}
  - {a: "1-64512-br1#2", b: "1-64514#1", linkAtoB: CHILD, underlay: UDP/IPv6}
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
jq '.control_service["cs1-64513-1"].addr |= sub("\\[(.*)\\]"; "[fc00:10fc:100::1]") |
    .discovery_service["cs1-64513-1"].addr |= sub("\\[(.*)\\]"; "[fc00:10fc:100::1]") |
    .border_routers["br1-64513-1"].internal_addr |= sub("\\[(.*)\\]"; "[fc00:10fc:100::1]")' \
    "$SCION_ROOT/gen/AS64513/topology.json" | sponge "$SCION_ROOT/gen/AS64513/topology.json"
sed -iE 's/"\[.*\]/"[fc00:10fc:100::1]/' "$SCION_ROOT/gen/AS64513/sd.toml"
jq '.control_service["cs1-64514-1"].addr |= sub("\\[(.*)\\]"; "[fc00:10fc:200::1]") |
    .discovery_service["cs1-64514-1"].addr |= sub("\\[(.*)\\]"; "[fc00:10fc:200::1]") |
    .border_routers["br1-64514-1"].internal_addr |= sub("\\[(.*)\\]"; "[fc00:10fc:200::1]")' \
    "$SCION_ROOT/gen/AS64514/topology.json" | sponge "$SCION_ROOT/gen/AS64514/topology.json"
sed -iE 's/"\[.*\]/"[fc00:10fc:200::1]/' "$SCION_ROOT/gen/AS64514/sd.toml"

# Run local SCION network
(cd "$SCION_ROOT" && ./scion.sh run)
