import pathlib
from datetime import datetime
from scapy_scion.layers.scion import SCIONPath, InfoField, HopField
from google.protobuf import duration_pb2, timestamp_pb2
from proto.daemon.v1.daemon_pb2 import Interface, Path, PathInterface, Underlay
from tests import write_packets


path1 = Path(
    interface=Interface(address=Underlay(address="[fd00:f00d:cafe::7f00:19]:31024")),
    interfaces=[
        PathInterface(isd_as=0x100000000fc00, id=2),
        PathInterface(isd_as=0x2ff0000000211, id=5),
        PathInterface(isd_as=0x2ff0000000211, id=4),
        PathInterface(isd_as=0x1ff0000000001, id=3)
    ],
    mtu=800,
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
    raw=bytes(SCIONPath(
        seg0_len=3, seg1_len=0, seg2_len=0,
        info_fields=[
            InfoField(flags="C", segid=0xa9b8, timestamp=datetime.fromtimestamp(1704063600))
        ],
        hop_fields=[
            HopField(exp_time=0xc1, cons_ingress=0, cons_egress=2),
            HopField(exp_time=0xd0, cons_ingress=5, cons_egress=4),
            HopField(exp_time=0x27, cons_ingress=3, cons_egress=0)
        ]
    ))
)

path2 = Path(
    interface=Interface(address=Underlay(address="[fd00:f00d:cafe::7f00:19]:31024")),
    interfaces=[
        PathInterface(isd_as=0x100000000fc00, id=3),
        PathInterface(isd_as=0x1ff0000000001, id=4)
    ],
    mtu=1472,
    expiration=timestamp_pb2.Timestamp(seconds=1712950886, nanos=0),
    latency=[
        duration_pb2.Duration(nanos=int(5e6)),  # 5 ms
    ],
    bandwidth=[
        int(10e6), # 10 Gbit/s
    ],
    raw=bytes(SCIONPath(
        seg0_len=2, seg1_len=0, seg2_len=0,
        info_fields=[
            InfoField(flags="C", segid=0xa9b8, timestamp=datetime.fromtimestamp(1704063600))
        ],
        hop_fields=[
            HopField(exp_time=0xc1, cons_ingress=0, cons_egress=3),
            HopField(exp_time=0x27, cons_ingress=4, cons_egress=0)
        ]
    ))
)

path3 = Path(
    interface=Interface(address=Underlay(address="[fd00:f00d:cafe::7f00:19]:31024")),
    interfaces=[
        PathInterface(isd_as=0x100000000fc00, id=20),
        PathInterface(isd_as=0x2ff0000000211, id=50),
        PathInterface(isd_as=0x2ff0000000211, id=40),
        PathInterface(isd_as=0x1ff0000000001, id=30)
    ],
    mtu=1472,
    expiration=timestamp_pb2.Timestamp(seconds=1712950886, nanos=0),
    latency=[
        duration_pb2.Duration(nanos=int(1e6)), # 1 ms
        duration_pb2.Duration(nanos=int(1e6)), # 1 ms
        duration_pb2.Duration(nanos=int(1e6)), # 1 ms
    ],
    bandwidth=[
        int(1e6), # 1 Gbit/s
        int(1e6), # 1 Gbit/s
        int(1e6), # 1 Gbit/s
    ],
    raw=bytes(SCIONPath(
        seg0_len=3, seg1_len=0, seg2_len=0,
        info_fields=[
            InfoField(flags="C", segid=0xa9b8, timestamp=datetime.fromtimestamp(1704063600))
        ],
        hop_fields=[
            HopField(exp_time=0xc1, cons_ingress=0, cons_egress=20),
            HopField(exp_time=0xd0, cons_ingress=50, cons_egress=40),
            HopField(exp_time=0x27, cons_ingress=30, cons_egress=0)
        ]
    ))
)

pb = [path1.SerializeToString(), path2.SerializeToString(), path3.SerializeToString()]
write_packets(pb, pathlib.Path(__file__).with_suffix(".bin"))
