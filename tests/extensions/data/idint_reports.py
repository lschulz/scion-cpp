from pathlib import Path
from scapy_scion.layers.scion import HopByHopExt
from scapy_scion.layers.idint import IdIntOption, IdIntEntry
from tests import write_packets

report = HopByHopExt(options=[
    IdIntOption(
        flags="",
        aggregation="as",
        verifier="source",
        inst_flags="egif+igif+node_cnt+node_id",
        af1="last",
        af2="last",
        af3="last",
        af4="last",
        inst1="isd",
        inst2="asn",
        inst3="device_type_role",
        inst4="rtt_next_br",
        source_ts=67852596012585,
        source_port=0,
        stack_len=64,
        tos=21,
        stack = [
            IdIntEntry(flags="source", hop=0, mac=b"\x6e\x2f\xcb\xd8"),
            IdIntEntry(flags="egress", hop=0, mac=b"\x27\xf6\x7f\x0d",
                mask="egif+igif+node_cnt+node_id",
                node_id=1,
                node_cnt=1,
                igif=0,
                egif=41,
                md1=b'\x00\x01',
                md2=b'\xff\x00\x00\x00\x01\x11',
                md3=b'\x00\x00\x02\x01',
                md4=b'\x00\x00\x01t',
            ),
            IdIntEntry(flags="aggregate+egress+ingress", hop=1, mac=b"\x8e\x0d\x5d\x6a",
                mask="egif+igif+node_cnt+node_id",
                node_id=2,
                node_cnt=2,
                igif=0,
                egif=2,
                md1=b'\x00\x01',
                md2=b'\xff\x00\x00\x00\x01\x10',
                md3=b'\x00\x00\x02\x01',
                md4=b'\x00\x00\x01\n',
            ),
            IdIntEntry(flags="ingress", hop=3, mac=b"\xac\x70\xf4\x5b",
                mask="egif+igif+node_cnt+node_id",
                node_id=1,
                node_cnt=1,
                igif=1,
                egif=0,
                md1=b'\x00\x01',
                md2=b'\xff\x00\x00\x00\x01\x12',
                md3=b'\x00\x00\x02\x01',
                md4=b'',
            ),
        ]
    )
])

encrypted = HopByHopExt(options=[
    IdIntOption(
        flags="encrypted",
        aggregation="as",
        verifier="source",
        inst_flags="egif+igif+node_cnt+node_id",
        af1="last",
        af2="last",
        af3="last",
        af4="last",
        inst1="isd",
        inst2="asn",
        inst3="device_type_role",
        inst4="rtt_next_br",
        source_ts=73299619925897,
        source_port=0,
        stack_len=64,
        tos=30,
        stack = [
            IdIntEntry(flags="encrypted+source", hop=0, mac=b"\x94\xfd\x40\xc5",
                nonce=36505987264837233919905403620,
                padding=b'\xbe\xbf' # set again the packet has been built
            ),
            IdIntEntry(flags="encrypted+egress", hop=0, mac=b"\xef\x58\xb1\xe9",
                mask="egif+igif+node_cnt+node_id",
                nonce=21681912788758578866852680449,
                node_id=902006764,
                node_cnt=27304,
                igif=26908,
                egif=34927,
                md1=b'\xa0\x8c',
                md2=b'A\x1dj\xe3\r:',
                md3=b'\xba\xaf\x10\xff',
                md4=b'\xc78\x03\xba',
            ),
            IdIntEntry(flags="encrypted+aggregate+egress+ingress", hop=1, mac=b"\xb3\x9d\xd6\x83",
                mask="egif+igif+node_cnt+node_id",
                nonce=76938671960864433097505032422,
                node_id=1746753966,
                node_cnt=10148,
                igif=19809,
                egif=46957,
                md1=b'w\xc3',
                md2=b'\xd6\xc6\xd8.\x01!',
                md3=b'\xfd\x9f\xa3-',
                md4=b'p\x8b\xe0}',
            ),
            IdIntEntry(flags="encrypted+ingress", hop=3, mac=b"\x10\x4c\x83\xc7",
                mask="egif+igif+node_cnt+node_id",
                nonce=38111421817853615462441358274,
                node_id=2289289966,
                node_cnt=13523,
                igif=38658,
                egif=65374,
                md1=b'\x0f\x01',
                md2=b'\xc3\x0e\x80\xae\x07\xb9',
                md3=b'\r%md',
                md4=b'',
            ),
        ]
    )
])

enc = bytes(encrypted)
# Set encrypted padding of first stack entry, since Scapy-SCION pads with zeros.
# The padding is directly in front of the MAC.
i = enc.index(b'\x00\x00' + encrypted.options[0].stack[0].mac)
enc = enc[:i] + b'\xbe\xbf' + enc[i+2:]

write_packets([report, enc], Path(__file__).with_suffix(".bin"))
