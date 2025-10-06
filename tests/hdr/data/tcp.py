from pathlib import Path
from scapy.layers.inet import IP, TCP
from tests import write_packets


# IP underlayer for TCP checksum computation
ip = IP(
    src = "0.0.0.0",
    dst = "0.0.0.0",
)

syn = ip / TCP(
    sport = 34776,
    dport = 32000,
    seq = 2060855180,
    ack = 0,
    flags = "S",
    window = 65495,
    options = [
        ('MSS', 1380),
        ('SAckOK', b''),
        ('Timestamp', (1667661695, 0)),
        ('NOP', None),
        ('WScale', 7)
    ]
)

syn_ack = ip / TCP(
    sport = 32000,
    dport = 34776,
    seq = 2615407415,
    ack = 2060855181,
    flags = "SA",
    window = 65483,
    options = [
        ('MSS', 1380),
        ('SAckOK', b''),
        ('Timestamp', (1667661695, 1667661695)),
        ('NOP', None),
        ('WScale', 7)
    ]
)

ack = ip / TCP(
    sport = 34776,
    dport = 32000,
    seq = 2060855181,
    ack = 2615407416,
    flags = "A",
    window = 512,
    options = [
        ('NOP', None),
        ('NOP', None),
        ('Timestamp', (1667661695, 1667661695)),
    ]
)

data = ip / TCP(
    sport = 34776,
    dport = 32000,
    seq = 2060855181,
    ack = 2615407416,
    flags = "PA",
    window = 512
) / b"test\n"

sel_ack = ip / TCP(
    sport = 34776,
    dport = 32000,
    seq = 2060855181,
    ack = 2615407416,
    flags = "A",
    window = 512,
    options = [
        ('NOP', None),
        ('NOP', None),
        ('SAck', (1, 2, 3, 4, 5, 6)),
    ]
)

write_packets([syn, syn_ack, ack, data, sel_ack], Path(__file__).with_suffix(".bin"))
