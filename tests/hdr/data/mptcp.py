from pathlib import Path
from scapy.layers.inet import IP, TCP
from tests import write_packets
import struct


syn_capable = IP(
    src = "10.128.0.1",
    dst = "10.128.0.2",
) / TCP(
    sport = 34802,
    dport = 5201,
    seq = 2156917410,
    ack = 0,
    flags = "S",
    window = 64240,
    options = [
        ('MSS', 1460),
        ('SAckOK', b''),
        ('Timestamp', (3301642972, 0)),
        ('NOP', None),
        ('WScale', 7),
        (30, b'\x01\x01') # MP_CAPABLE
    ]
)

synack_capable = IP(
    src = "10.128.0.2",
    dst = "10.128.0.1",
) / TCP(
    sport = 5201,
    dport = 34802,
    seq = 1960638239,
    ack = 2156917411,
    flags = "SA",
    window = 65160,
    options = [
        ('MSS', 1460),
        ('SAckOK', b''),
        ('Timestamp', (2874606264, 3301642972)),
        ('NOP', None),
        ('WScale', 7),
        (30, b"\x01\x01Q\x93'JV\x11\xd6+") # MP_CAPABLE
    ]
)

ack_capable = IP(
    src = "10.128.0.1",
    dst = "10.128.0.2",
) / TCP(
    sport = 34802,
    dport = 5201,
    seq = 2156917411,
    ack = 1960638240,
    flags = "A",
    window = 502,
    options = [
        ('NOP', None),
        ('NOP', None),
        ('Timestamp', (3301642972, 2874606264)),
        (30, b"\x01\x01\xbf|ywM[u1Q\x93'JV\x11\xd6+") # MP_CAPABLE
    ]
)

dss1 = IP(
    src = "10.128.0.2",
    dst = "10.128.0.1",
) / TCP(
    sport = 5201,
    dport = 34802,
    seq = 1960638240,
    ack = 2156917448,
    flags = "A",
    window = 509,
    options = [
        ('NOP', None),
        ('NOP', None),
        ('Timestamp', (2874606264, 3301642972)),
        (30, b' \x03!J\xf0u\xcfB\\\x04') # Data Sequence Signal
    ]
)

dss2 = IP(
    src = "10.128.0.1",
    dst = "10.128.0.2",
) / TCP(
    sport = 34802,
    dport = 5201,
    seq = 2157048520,
    ack = 1960638240,
    flags = "PA",
    window = 502,
    options = [
        ('NOP', None), ('NOP', None),
        ('Timestamp', (3301643078, 2874606265)),
        (30, b' \rje\xb3\xbf!J\xf0u\xcfD\\\x04\x00\x02\x00&\xfaP'), # Data Sequence Signal
        ('EOL', None), ('EOL', None)
    ]
)

add_addr = IP(
    src = "10.128.0.2",
    dst = "10.128.0.1",
) / TCP(
    sport = 5201,
    dport = 34802,
    seq = 3928170229,
    ack = 3710395719,
    flags = "A",
    window = 502,
    options = [
        ('NOP', None),
        ('NOP', None),
        ('Timestamp', (2874606264, 3301642972)),
        (30, b'0\x02\xfc\x00\x10\xfc\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02\xaf\x80'
             b'\x06\xb3\x8d\xab\xa6') # ADD_ADDR
    ]
)

add_addr_echo = IP(
    src = "10.128.0.1",
    dst = "10.128.0.2",
) / TCP(
    sport = 34802,
    dport = 5201,
    seq = 2156917448,
    ack = 1960638240,
    flags = "A",
    window = 509,
    options = [
        ('NOP', None),
        ('NOP', None),
        ('Timestamp', (3301642972, 2874606264)),
        (30, b'1\x02\xfc\x00\x10\xfc\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02') # ADD_ADDR
    ]
)

syn_join = IP(
    src = "10.128.0.1",
    dst = "10.128.0.2",
) / TCP(
    sport = 51435,
    dport = 5201,
    seq = 3321739861,
    ack = 0,
    flags = "S",
    window = 64896,
    options = [
        ('MSS', 1460),
        ('SAckOK', b''),
        ('Timestamp', (3318849759, 0)),
        ('NOP', None),
        ('WScale', 7),
        (30, b'\x10\x01\xa7\xd9\rH\x9e\xe6\x8es') # MP_JOIN
    ]
)

synack_join = IP(
    src = "10.128.0.2",
    dst = "10.128.0.1",
) / TCP(
    sport = 5201,
    dport = 51435,
    seq = 464174314,
    ack = 3321739862,
    flags = "SA",
    window = 65160,
    options = [
        ('MSS', 1460),
        ('SAckOK', b''),
        ('Timestamp', (2891813051, 3318849759)),
        ('NOP', None),
        ('WScale', 7),
        (30, b'\x10\x01\x1d\xfaX\x8a.m\xf1g\xa9\x95\xbe\r') # MP_JOIN
    ]
)

ack_join = IP(
    src = "10.128.0.1",
    dst = "10.128.0.2",
) / TCP(
    sport = 51435,
    dport = 5201,
    seq = 3321739862,
    ack = 464174315,
    flags = "A",
    window = 507,
    options = [
        ('NOP', None),
        ('NOP', None),
        ('Timestamp', (3318849759, 2891813051)),
        (30, b'\x10\x00p\xb2\x03\x9a\xf4@\x9d13\xae\x8b\xbd\x914\x02\xf6\xb6\x95w\xfa') # MP_JOIN
    ]
)

remove_addr1 = IP(
    src = "10.128.0.1",
    dst = "10.128.0.2",
) / TCP(
    sport = 34802,
    dport = 5201,
    flags = 0,
    window = 0,
    options = [
        # REMOVE_ADDR
        (30, struct.pack("!BB", (4 << 4), 2)),
        ('NOP', None),
        # MP_PRIO
        (30, struct.pack("!B", (5 << 4) | 1)),
    ]
)

remove_addr2 = IP(
    src = "10.128.0.1",
    dst = "10.128.0.2",
) / TCP(
    sport = 34802,
    dport = 5201,
    flags = 0,
    window = 0,
    options = [
        ('NOP', None),
        # REMOVE_ADDR
        (30, struct.pack("!BBB", (4 << 4), 1, 2)),
    ]
)

failover = IP(
    src = "10.128.0.1",
    dst = "10.128.0.2",
) / TCP(
    sport = 34802,
    dport = 5201,
    flags = 0,
    window = 0,
    options = [
        # MP_FAIL
        (30, struct.pack("!BxQ", (6 << 4), 2398994140307414020))
    ]
)

fast_close = IP(
    src = "10.128.0.1",
    dst = "10.128.0.2",
) / TCP(
    sport = 34802,
    dport = 5201,
    flags = "R",
    window = 0,
    options = [
        # MP_FASTCLOSE
        (30, struct.pack("!BxQ", (7 << 4), 0x5193274a5611d62b))
    ]
)

subflow_reset = IP(
    src = "10.128.0.1",
    dst = "10.128.0.2",
) / TCP(
    sport = 34802,
    dport = 5201,
    flags = "R",
    window = 0,
    options = [
        # MP_TCPRST
        (30, struct.pack("!BB", (8 << 4) | 1, 2))
    ]
)

packets = [
    syn_capable,
    synack_capable,
    ack_capable,
    dss1,
    dss2,
    add_addr,
    add_addr_echo,
    syn_join,
    synack_join,
    ack_join,
    remove_addr1,
    remove_addr2,
    failover,
    fast_close,
    subflow_reset
]

write_packets(packets, Path(__file__).with_suffix(".bin"))
