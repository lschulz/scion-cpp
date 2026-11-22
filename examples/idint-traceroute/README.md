ID-INT Traceroute Example
=========================

As client, this tool sends an empty UDP packet with an ID-INT header. As server, it responds to a
client's request with a UDP packet containing a fresh ID-INT header and the original ID-INT request
from the client as payload.

Use with this [fork of SCION](https://github.com/lschulz/scion/tree/idint2026).

## Usage Example ##
This examples assumes SCION's "default" test topology.

Run server in AS 2-ff00:0:222
```bash
idint-traceroute server --sciond [fd00:f00d:cafe::7f00:54]:30255 --local [fd00:f00d:cafe::7f00:53]:32001
```

and client in AS 1-ff00:0:112
```bash
idint-traceroute client --sciond 127.0.0.60:30255 --local 127.0.0.1:32000 \
    --encrypt --nid --nc --agr-mode AS --igr --egr --af1 max --af2 last --af3 sum --af4 sum --loop \
    -1 EGRESS_LINK_TX -2 RTT_NEXT_BR -3 TOTAL_POWER -4 FWD_ENERGY \
    [2-ff00:0:222,fd00:f00d:cafe::7f00:53]:32001
```

If idint-traceroute can't get keys, make sure the `local` address in the client command matches the
address the SCION daemon responsible for the AS you want to run the client in.

If the border routers can't get level 1 keys, make sure their internal IPs are in the `idint` list
of the `drkey.delegation` section in the control services's configuration file.
