from proto.control_plane.v1 import seg_extensions_pb2 as _seg_extensions_pb2
from proto.crypto.v1 import signed_pb2 as _signed_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SegmentType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SEGMENT_TYPE_UNSPECIFIED: _ClassVar[SegmentType]
    SEGMENT_TYPE_UP: _ClassVar[SegmentType]
    SEGMENT_TYPE_DOWN: _ClassVar[SegmentType]
    SEGMENT_TYPE_CORE: _ClassVar[SegmentType]
SEGMENT_TYPE_UNSPECIFIED: SegmentType
SEGMENT_TYPE_UP: SegmentType
SEGMENT_TYPE_DOWN: SegmentType
SEGMENT_TYPE_CORE: SegmentType

class SegmentsRequest(_message.Message):
    __slots__ = ("src_isd_as", "dst_isd_as")
    SRC_ISD_AS_FIELD_NUMBER: _ClassVar[int]
    DST_ISD_AS_FIELD_NUMBER: _ClassVar[int]
    src_isd_as: int
    dst_isd_as: int
    def __init__(self, src_isd_as: _Optional[int] = ..., dst_isd_as: _Optional[int] = ...) -> None: ...

class SegmentsResponse(_message.Message):
    __slots__ = ("segments", "deprecated_signed_revocations")
    class Segments(_message.Message):
        __slots__ = ("segments",)
        SEGMENTS_FIELD_NUMBER: _ClassVar[int]
        segments: _containers.RepeatedCompositeFieldContainer[PathSegment]
        def __init__(self, segments: _Optional[_Iterable[_Union[PathSegment, _Mapping]]] = ...) -> None: ...
    class SegmentsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: SegmentsResponse.Segments
        def __init__(self, key: _Optional[int] = ..., value: _Optional[_Union[SegmentsResponse.Segments, _Mapping]] = ...) -> None: ...
    SEGMENTS_FIELD_NUMBER: _ClassVar[int]
    DEPRECATED_SIGNED_REVOCATIONS_FIELD_NUMBER: _ClassVar[int]
    segments: _containers.MessageMap[int, SegmentsResponse.Segments]
    deprecated_signed_revocations: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, segments: _Optional[_Mapping[int, SegmentsResponse.Segments]] = ..., deprecated_signed_revocations: _Optional[_Iterable[bytes]] = ...) -> None: ...

class SegmentsRegistrationRequest(_message.Message):
    __slots__ = ("segments",)
    class Segments(_message.Message):
        __slots__ = ("segments",)
        SEGMENTS_FIELD_NUMBER: _ClassVar[int]
        segments: _containers.RepeatedCompositeFieldContainer[PathSegment]
        def __init__(self, segments: _Optional[_Iterable[_Union[PathSegment, _Mapping]]] = ...) -> None: ...
    class SegmentsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: SegmentsRegistrationRequest.Segments
        def __init__(self, key: _Optional[int] = ..., value: _Optional[_Union[SegmentsRegistrationRequest.Segments, _Mapping]] = ...) -> None: ...
    SEGMENTS_FIELD_NUMBER: _ClassVar[int]
    segments: _containers.MessageMap[int, SegmentsRegistrationRequest.Segments]
    def __init__(self, segments: _Optional[_Mapping[int, SegmentsRegistrationRequest.Segments]] = ...) -> None: ...

class SegmentsRegistrationResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class BeaconRequest(_message.Message):
    __slots__ = ("segment",)
    SEGMENT_FIELD_NUMBER: _ClassVar[int]
    segment: PathSegment
    def __init__(self, segment: _Optional[_Union[PathSegment, _Mapping]] = ...) -> None: ...

class BeaconResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PathSegment(_message.Message):
    __slots__ = ("segment_info", "as_entries")
    SEGMENT_INFO_FIELD_NUMBER: _ClassVar[int]
    AS_ENTRIES_FIELD_NUMBER: _ClassVar[int]
    segment_info: bytes
    as_entries: _containers.RepeatedCompositeFieldContainer[ASEntry]
    def __init__(self, segment_info: _Optional[bytes] = ..., as_entries: _Optional[_Iterable[_Union[ASEntry, _Mapping]]] = ...) -> None: ...

class SegmentInformation(_message.Message):
    __slots__ = ("timestamp", "segment_id")
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    SEGMENT_ID_FIELD_NUMBER: _ClassVar[int]
    timestamp: int
    segment_id: int
    def __init__(self, timestamp: _Optional[int] = ..., segment_id: _Optional[int] = ...) -> None: ...

class ASEntry(_message.Message):
    __slots__ = ("signed", "unsigned")
    SIGNED_FIELD_NUMBER: _ClassVar[int]
    UNSIGNED_FIELD_NUMBER: _ClassVar[int]
    signed: _signed_pb2.SignedMessage
    unsigned: _seg_extensions_pb2.PathSegmentUnsignedExtensions
    def __init__(self, signed: _Optional[_Union[_signed_pb2.SignedMessage, _Mapping]] = ..., unsigned: _Optional[_Union[_seg_extensions_pb2.PathSegmentUnsignedExtensions, _Mapping]] = ...) -> None: ...

class ASEntrySignedBody(_message.Message):
    __slots__ = ("isd_as", "next_isd_as", "hop_entry", "peer_entries", "mtu", "extensions")
    ISD_AS_FIELD_NUMBER: _ClassVar[int]
    NEXT_ISD_AS_FIELD_NUMBER: _ClassVar[int]
    HOP_ENTRY_FIELD_NUMBER: _ClassVar[int]
    PEER_ENTRIES_FIELD_NUMBER: _ClassVar[int]
    MTU_FIELD_NUMBER: _ClassVar[int]
    EXTENSIONS_FIELD_NUMBER: _ClassVar[int]
    isd_as: int
    next_isd_as: int
    hop_entry: HopEntry
    peer_entries: _containers.RepeatedCompositeFieldContainer[PeerEntry]
    mtu: int
    extensions: _seg_extensions_pb2.PathSegmentExtensions
    def __init__(self, isd_as: _Optional[int] = ..., next_isd_as: _Optional[int] = ..., hop_entry: _Optional[_Union[HopEntry, _Mapping]] = ..., peer_entries: _Optional[_Iterable[_Union[PeerEntry, _Mapping]]] = ..., mtu: _Optional[int] = ..., extensions: _Optional[_Union[_seg_extensions_pb2.PathSegmentExtensions, _Mapping]] = ...) -> None: ...

class HopEntry(_message.Message):
    __slots__ = ("hop_field", "ingress_mtu")
    HOP_FIELD_FIELD_NUMBER: _ClassVar[int]
    INGRESS_MTU_FIELD_NUMBER: _ClassVar[int]
    hop_field: HopField
    ingress_mtu: int
    def __init__(self, hop_field: _Optional[_Union[HopField, _Mapping]] = ..., ingress_mtu: _Optional[int] = ...) -> None: ...

class PeerEntry(_message.Message):
    __slots__ = ("peer_isd_as", "peer_interface", "peer_mtu", "hop_field")
    PEER_ISD_AS_FIELD_NUMBER: _ClassVar[int]
    PEER_INTERFACE_FIELD_NUMBER: _ClassVar[int]
    PEER_MTU_FIELD_NUMBER: _ClassVar[int]
    HOP_FIELD_FIELD_NUMBER: _ClassVar[int]
    peer_isd_as: int
    peer_interface: int
    peer_mtu: int
    hop_field: HopField
    def __init__(self, peer_isd_as: _Optional[int] = ..., peer_interface: _Optional[int] = ..., peer_mtu: _Optional[int] = ..., hop_field: _Optional[_Union[HopField, _Mapping]] = ...) -> None: ...

class HopField(_message.Message):
    __slots__ = ("ingress", "egress", "exp_time", "mac")
    INGRESS_FIELD_NUMBER: _ClassVar[int]
    EGRESS_FIELD_NUMBER: _ClassVar[int]
    EXP_TIME_FIELD_NUMBER: _ClassVar[int]
    MAC_FIELD_NUMBER: _ClassVar[int]
    ingress: int
    egress: int
    exp_time: int
    mac: bytes
    def __init__(self, ingress: _Optional[int] = ..., egress: _Optional[int] = ..., exp_time: _Optional[int] = ..., mac: _Optional[bytes] = ...) -> None: ...
