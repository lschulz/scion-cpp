import struct
from pathlib import Path
from socket import AF_INET6
from scapy.utils import inet_aton, inet_pton
from scapy.contrib.stun import STUN, STUNGenericTlv, MAGIC_COOKIE
from tests import write_packets


request = STUN(
    stun_message_type = "Binding request",
    transaction_id = 0x1234_5678_9abc_def0_ffff_0000,
    attributes = []
)

response_ipv4 = STUN(
    stun_message_type = "Binding success response",
    transaction_id = 0x1234_5678_9abc_def0_ffff_0000,
    attributes = [
        STUNGenericTlv(
            type = 0x0001,
            value = struct.pack("!xBHI", 1,
                53794,
                int.from_bytes(inet_aton("192.0.2.1"))
            )
        ),
        STUNGenericTlv(
            type = 0x0020,
            value = struct.pack("!xBHI", 1,
                53794 ^ (MAGIC_COOKIE >> 16),
                int.from_bytes(inet_aton("192.0.2.1")) ^ MAGIC_COOKIE
            )
        )
    ]
)

response_ipv6 = STUN(
    stun_message_type = "Binding success response",
    transaction_id = 0x1234_5678_9abc_def0_ffff_0000,
    attributes = [
        STUNGenericTlv(
            type = 0x0001,
            value = struct.pack("!xBH16s", 2,
                53794,
                inet_pton(AF_INET6, "2001:db8::1")
            )
        ),
        STUNGenericTlv(
            type = 0x0020,
            value = struct.pack("!xBH16s", 2,
                53794 ^ (MAGIC_COOKIE >> 16),
                (int.from_bytes(inet_pton(AF_INET6, "2001:db8::1"))
                    ^ (MAGIC_COOKIE << 96 | 0x1234_5678_9abc_def0_ffff_0000)).to_bytes(16, 'big')
            )
        )
    ]
)

write_packets([request, response_ipv4, response_ipv6], Path(__file__).with_suffix(".bin"))
