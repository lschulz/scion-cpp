from pathlib import Path
from scapy.libs.crc import CRC_32
from scapy.contrib.stun import STUN, STUNXorMappedAddress, STUNFingerprint
from tests import write_packets

FINGERPRINT_MAGIC = 0x5354554e

request = STUN(
    stun_message_type = "Binding request",
    transaction_id = 0x1234_5678_9abc_def0_ffff_0000,
    attributes = []
)

request_fp = STUN(
    stun_message_type = "Binding request",
    transaction_id = 0x1234_5678_9abc_def0_ffff_0000,
    attributes = [STUNFingerprint()]
)
request_fp.attributes[-1].crc_32 = CRC_32(bytes(request_fp)[:-8]) ^ FINGERPRINT_MAGIC

response_ipv4 = STUN(
    stun_message_type = "Binding success response",
    transaction_id = 0x1234_5678_9abc_def0_ffff_0000,
    attributes = [
        STUNXorMappedAddress(
            xport = 53794,
            xip = "192.0.2.1"
        )
    ]
)

response_ipv4_fp = STUN(
    stun_message_type = "Binding success response",
    transaction_id = 0x1234_5678_9abc_def0_ffff_0000,
    attributes = [
        STUNXorMappedAddress(
            xport = 53794,
            xip = "192.0.2.1"
        ),
        STUNFingerprint()
    ]
)
response_ipv4_fp.attributes[-1].crc_32 = CRC_32(bytes(response_ipv4_fp)[:-8]) ^ FINGERPRINT_MAGIC

response_ipv6 = STUN(
    stun_message_type = "Binding success response",
    transaction_id = 0x1234_5678_9abc_def0_ffff_0000,
    attributes = [
        STUNXorMappedAddress(
            address_family = 2,
            xport = 53794,
            xip = "2001:db8::1"
        )
    ]
)

pkts = [request, request_fp, response_ipv4, response_ipv4_fp, response_ipv6]
write_packets(pkts, Path(__file__).with_suffix(".bin"))
