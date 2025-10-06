import pathlib
from datetime import datetime
from scapy_scion.layers.scion import SCIONPath, InfoField, HopField
from google.protobuf import duration_pb2, timestamp_pb2
from proto.daemon.v1.daemon_pb2 import (
    EpicAuths, GeoCoordinates, Interface, LinkType, Path, PathInterface, Underlay)
from tests import write_packets


raw_path = SCIONPath(
    curr_inf=0,
    curr_hf=0,
    seg0_len=3, seg1_len=0, seg2_len=0,
    info_fields=[
        InfoField(flags="C", segid=0xa9b8, timestamp=datetime.fromtimestamp(1704063600))
    ],
    hop_fields=[
        HopField(exp_time=0xc1, cons_ingress=0, cons_egress=2, mac=0x7bd910c68949),
        HopField(exp_time=0xd0, cons_ingress=5, cons_egress=4, mac=0xbd20087f1ebb),
        HopField(exp_time=0x27, cons_ingress=3, cons_egress=0, mac=0x5fc3be952300)
    ]
)

path = Path(
    raw=bytes(raw_path),
    interface=Interface(address=Underlay(address="[fd00:f00d:cafe::7f00:19]:31024")),
    interfaces=[
        PathInterface(isd_as=0x1ff0000000111, id=2),
        PathInterface(isd_as=0x2ff0000000211, id=5),
        PathInterface(isd_as=0x2ff0000000211, id=4),
        PathInterface(isd_as=0x2ff0000000222, id=3)
    ],
    mtu=1472,
    expiration=timestamp_pb2.Timestamp(seconds=1712950886, nanos=0),
    latency=[
        duration_pb2.Duration(nanos=int(5e6)),  #  5 ms
        duration_pb2.Duration(nanos=int(10e6)), # 10 ms
        duration_pb2.Duration(nanos=int(8e6)),  #  8 ms
    ],
    bandwidth=[
        int(10e6), # 10 Gbit/s
        int(1e6),  #  1 Gbit/s
        int(5e6),  #  5 Gbit/s
    ],
    geo=[
        GeoCoordinates(latitude=0, longitude=0, address=""),
        GeoCoordinates(latitude=0, longitude=0, address=""),
        GeoCoordinates(latitude=0, longitude=0, address=""),
        GeoCoordinates(latitude=0, longitude=0, address=""),
    ],
    link_type=[
        LinkType.LINK_TYPE_DIRECT,
        LinkType.LINK_TYPE_UNSPECIFIED,
    ],
    internal_hops=[2],
    notes=[
        "AS1-ff00:0:111",
        "AS2-ff00:0:211",
        "AS2-ff00:0:222",
    ],
    epic_auths=EpicAuths()
)

pb = [path.SerializeToString()]
write_packets(pb, pathlib.Path(__file__).with_suffix(".bin"))
