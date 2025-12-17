% scitra-policy.json(5) Version 0.0.1 | Scitra Manual

## NAME ##

scitra-policy.json - SCION path policy configuration files for Scitra

## DESCRIPTION ##

Path policies are applied to end-to-end SCION paths retrieved from a SCION daemon in order to
pre-filter and pre-sort paths that will be presented to packet schedulers, path selection
algorithms, and in some cases the user.

Policy file are JSON documents containing containing a path policy object. A path policy objects has
two sections **matchers** and **policies**. Matchers contain conditions that a packet or flow
must satisfy in order for the policy attached to the matcher to become active. Policies are
filtering rules that are applied to paths, only paths that match the policy selected by the active
matchers are considered for path selection.

A minimal path policy file looks like this:
```
{
    "matchers": [],
    "policies": {}
}
```

**Matchers**

Matchers are stored in an ordered list from which they are tried in document order until the current
packet or flow matches all clauses defined by the matcher. Every matcher must define a policy which
it applies to the set of possible paths for matching packets or flows. If the list of matchers is
exhausted before a match is found, the **default** policy is applied.

The smallest possible matcher must contain at least a **policy** attribute, e.g.,
`{"policy": "policy1"}`. Additionally, a matcher may contain any combination of the following match
clauses.

* `destination` SCION destination address of the packet in the format [ISD-ASN,IP]:Port
    Elements of the address may be replaced with zero from right to left, i.e. in order port, IP, ASN, ISD, to define wildcards.

* `source` Same as destination but for the packet's or flows' source address.

* `protocol` Either `tcp` or `udp`.

* `traffic_class` 6-bit value of the DSCP field in the IP header.

In order for a matcher to match all of its clauses must match.

**Policies**

Policies are named sets of rules that are applied to sets of paths in order to filter and sort them.
Possible rules a policy may define are:

* `acl` A list of hop predicates preceded by + or - to allow or disallow a hop from appearing
    anywhere on the path.

* `sequence` A regular expression of hop predicates that must match the path.

* `requirements` A set of conditions on path metadata that the paths has to satisfy. Available
    requirements are:
    - `min_mtu` Minimum SCION path MTU in bytes.
    - `max_meta_lat` Maximum path latency according to static metadata in milliseconds.
    - `min_meta_bw` Minimum path bandwidth according to static metadata in kbit/s.

* `ordering` A list of sort orders. Paths are sorted using the orderings from left to right with
    a stable sort, so the effect of multiple orderings may remain visible. Available orderings
    are:
    - `random` Random shuffle.
    - `hops_asc` Sort ascending by hop count.
    - `hops_desc` Sort descending by hop count.
    - `meta_latency_asc` Sort ascending by latency according to static metadata.
    - `meta_latency_desc` Sort descending by latency according to static metadata.
    - `meta_bandwidth_asc` Sort ascending by bandwidth according to static metadata.
    - `meta_bandwidth_desc` Sort descending by bandwidth according to static metadata.

Policies may extend one other policy that precedes the extending policy in document order. The
policy that is being extended must be named in an **extends** attribute. When a policy extends
another, the extending policy inherits the **acl**, **sequence**, **requirements** and **ordering**
rules from the base policy. The extending policy may add or override one or multiple of these rules.

The **default** policy uses the reserved name "default" and is implicitly defined as an empty policy
if not explicitly defined as something else. If the default policy is given explicitly, it may
extend another user defined policy, but must follow the same ordering rules as normal user defined
policies, i.e., the default policy can only extend policies that precede it in document order.

Policies may define a **failover** policy. The failover policy is used instead of the active policy
itself if application if the active policy results in an empty path set. Failover policies can be
used to define chain of policies with increasing specificity, that still returns paths even if the
most preferable policy does not match. It is possible and often desirable for a policy to name the
same base policy in its **extends** and **failover** attribute.

**Hop Predicates**

A hop predicate has the form ISD-ASN#Ig,Eg where ISD is the SCION ISD, ASN is the SCION AS number
within the ISD, Ig is the ingress interface ID, and Eg is the egress interface ID. Any element may
be replaced with zero as a wildcard. Zero elements may be omitted from right to left. Hop predicates
also accept the alternative form ISD-ASN#IF, where IF can match the ingress or egress interface.

## EXAMPLE ##

```
{
  "matchers": [
    {
      "source": "1-64512,127.0.0.1",
      "protocol": "udp",
      "traffic_class": 1,
      "policy": "p1"
    },
    {
      "destination": "[1-ff00:0:1,10.0.0.1]:22",
      "source": "1-64512",
      "protocol": "tcp",
      "policy": "p2"
    },
    {
      "destination": "[1-ff00:0:1,10.0.0.1]:80",
      "source": "1-64512",
      "protocol": "tcp",
      "policy": "p3"
    }
  ],
  "policies": {
    "default": {
      "acl": [
        "- 666",
        "+"
      ],
      "ordering": ["random", "hops_asc", "meta_bandwidth_desc"]
    },
    "p1": {
      "extends": "default",
      "requirements": {
        "min_mtu": 1420
      },
      "ordering": ["meta_latency_asc"]
    },
    "p2": {
      "extends": "default",
      "sequence": "1-64512#20 0*"
    },
    "p3": {
      "extends": "p2",
      "failover": "p2",
      "requirements": {
        "min_mtu": 1500
      }
    }
  }
}
```

## ACKNOWLEDGMENTS ##

Scitra's path policy language is based on the SCION Path Policy Language Design by Lukas
Bischofberger, Lukas Vogel and Martin Sustrik, as well as the Path Policy Language of JPAN by
Tilmann Zäschke.

## AUTHOR ##

Lars-Christian Schulz <lschulz@ovgu.de>

## SEE ALSO ##

scion2ip(1), scion-interposer(7)
