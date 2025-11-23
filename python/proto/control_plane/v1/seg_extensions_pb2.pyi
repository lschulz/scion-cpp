from proto.control_plane.experimental.v1 import seg_detached_extensions_pb2 as _seg_detached_extensions_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class LinkType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    LINK_TYPE_UNSPECIFIED: _ClassVar[LinkType]
    LINK_TYPE_DIRECT: _ClassVar[LinkType]
    LINK_TYPE_MULTI_HOP: _ClassVar[LinkType]
    LINK_TYPE_OPEN_NET: _ClassVar[LinkType]
LINK_TYPE_UNSPECIFIED: LinkType
LINK_TYPE_DIRECT: LinkType
LINK_TYPE_MULTI_HOP: LinkType
LINK_TYPE_OPEN_NET: LinkType

class PathSegmentExtensions(_message.Message):
    __slots__ = ("static_info", "hidden_path", "digests")
    STATIC_INFO_FIELD_NUMBER: _ClassVar[int]
    HIDDEN_PATH_FIELD_NUMBER: _ClassVar[int]
    DIGESTS_FIELD_NUMBER: _ClassVar[int]
    static_info: StaticInfoExtension
    hidden_path: HiddenPathExtension
    digests: DigestExtension
    def __init__(self, static_info: _Optional[_Union[StaticInfoExtension, _Mapping]] = ..., hidden_path: _Optional[_Union[HiddenPathExtension, _Mapping]] = ..., digests: _Optional[_Union[DigestExtension, _Mapping]] = ...) -> None: ...

class HiddenPathExtension(_message.Message):
    __slots__ = ("is_hidden",)
    IS_HIDDEN_FIELD_NUMBER: _ClassVar[int]
    is_hidden: bool
    def __init__(self, is_hidden: bool = ...) -> None: ...

class StaticInfoExtension(_message.Message):
    __slots__ = ("latency", "bandwidth", "geo", "link_type", "internal_hops", "note")
    class GeoEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: GeoCoordinates
        def __init__(self, key: _Optional[int] = ..., value: _Optional[_Union[GeoCoordinates, _Mapping]] = ...) -> None: ...
    class LinkTypeEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: LinkType
        def __init__(self, key: _Optional[int] = ..., value: _Optional[_Union[LinkType, str]] = ...) -> None: ...
    class InternalHopsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: int
        def __init__(self, key: _Optional[int] = ..., value: _Optional[int] = ...) -> None: ...
    LATENCY_FIELD_NUMBER: _ClassVar[int]
    BANDWIDTH_FIELD_NUMBER: _ClassVar[int]
    GEO_FIELD_NUMBER: _ClassVar[int]
    LINK_TYPE_FIELD_NUMBER: _ClassVar[int]
    INTERNAL_HOPS_FIELD_NUMBER: _ClassVar[int]
    NOTE_FIELD_NUMBER: _ClassVar[int]
    latency: LatencyInfo
    bandwidth: BandwidthInfo
    geo: _containers.MessageMap[int, GeoCoordinates]
    link_type: _containers.ScalarMap[int, LinkType]
    internal_hops: _containers.ScalarMap[int, int]
    note: str
    def __init__(self, latency: _Optional[_Union[LatencyInfo, _Mapping]] = ..., bandwidth: _Optional[_Union[BandwidthInfo, _Mapping]] = ..., geo: _Optional[_Mapping[int, GeoCoordinates]] = ..., link_type: _Optional[_Mapping[int, LinkType]] = ..., internal_hops: _Optional[_Mapping[int, int]] = ..., note: _Optional[str] = ...) -> None: ...

class LatencyInfo(_message.Message):
    __slots__ = ("intra", "inter")
    class IntraEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: int
        def __init__(self, key: _Optional[int] = ..., value: _Optional[int] = ...) -> None: ...
    class InterEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: int
        def __init__(self, key: _Optional[int] = ..., value: _Optional[int] = ...) -> None: ...
    INTRA_FIELD_NUMBER: _ClassVar[int]
    INTER_FIELD_NUMBER: _ClassVar[int]
    intra: _containers.ScalarMap[int, int]
    inter: _containers.ScalarMap[int, int]
    def __init__(self, intra: _Optional[_Mapping[int, int]] = ..., inter: _Optional[_Mapping[int, int]] = ...) -> None: ...

class BandwidthInfo(_message.Message):
    __slots__ = ("intra", "inter")
    class IntraEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: int
        def __init__(self, key: _Optional[int] = ..., value: _Optional[int] = ...) -> None: ...
    class InterEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: int
        def __init__(self, key: _Optional[int] = ..., value: _Optional[int] = ...) -> None: ...
    INTRA_FIELD_NUMBER: _ClassVar[int]
    INTER_FIELD_NUMBER: _ClassVar[int]
    intra: _containers.ScalarMap[int, int]
    inter: _containers.ScalarMap[int, int]
    def __init__(self, intra: _Optional[_Mapping[int, int]] = ..., inter: _Optional[_Mapping[int, int]] = ...) -> None: ...

class GeoCoordinates(_message.Message):
    __slots__ = ("latitude", "longitude", "address")
    LATITUDE_FIELD_NUMBER: _ClassVar[int]
    LONGITUDE_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    latitude: float
    longitude: float
    address: str
    def __init__(self, latitude: _Optional[float] = ..., longitude: _Optional[float] = ..., address: _Optional[str] = ...) -> None: ...

class DigestExtension(_message.Message):
    __slots__ = ("epic",)
    class Digest(_message.Message):
        __slots__ = ("digest",)
        DIGEST_FIELD_NUMBER: _ClassVar[int]
        digest: bytes
        def __init__(self, digest: _Optional[bytes] = ...) -> None: ...
    EPIC_FIELD_NUMBER: _ClassVar[int]
    epic: DigestExtension.Digest
    def __init__(self, epic: _Optional[_Union[DigestExtension.Digest, _Mapping]] = ...) -> None: ...

class PathSegmentUnsignedExtensions(_message.Message):
    __slots__ = ("epic",)
    EPIC_FIELD_NUMBER: _ClassVar[int]
    epic: _seg_detached_extensions_pb2.EPICDetachedExtension
    def __init__(self, epic: _Optional[_Union[_seg_detached_extensions_pb2.EPICDetachedExtension, _Mapping]] = ...) -> None: ...
