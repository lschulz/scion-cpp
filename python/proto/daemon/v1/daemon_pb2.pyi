import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf import duration_pb2 as _duration_pb2
from google.protobuf import empty_pb2 as _empty_pb2
from proto.drkey.v1 import drkey_pb2 as _drkey_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
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

class PathsRequest(_message.Message):
    __slots__ = ("source_isd_as", "destination_isd_as", "refresh", "hidden")
    SOURCE_ISD_AS_FIELD_NUMBER: _ClassVar[int]
    DESTINATION_ISD_AS_FIELD_NUMBER: _ClassVar[int]
    REFRESH_FIELD_NUMBER: _ClassVar[int]
    HIDDEN_FIELD_NUMBER: _ClassVar[int]
    source_isd_as: int
    destination_isd_as: int
    refresh: bool
    hidden: bool
    def __init__(self, source_isd_as: _Optional[int] = ..., destination_isd_as: _Optional[int] = ..., refresh: bool = ..., hidden: bool = ...) -> None: ...

class PathsResponse(_message.Message):
    __slots__ = ("paths",)
    PATHS_FIELD_NUMBER: _ClassVar[int]
    paths: _containers.RepeatedCompositeFieldContainer[Path]
    def __init__(self, paths: _Optional[_Iterable[_Union[Path, _Mapping]]] = ...) -> None: ...

class Path(_message.Message):
    __slots__ = ("raw", "interface", "interfaces", "mtu", "expiration", "latency", "bandwidth", "geo", "link_type", "internal_hops", "notes", "epic_auths")
    RAW_FIELD_NUMBER: _ClassVar[int]
    INTERFACE_FIELD_NUMBER: _ClassVar[int]
    INTERFACES_FIELD_NUMBER: _ClassVar[int]
    MTU_FIELD_NUMBER: _ClassVar[int]
    EXPIRATION_FIELD_NUMBER: _ClassVar[int]
    LATENCY_FIELD_NUMBER: _ClassVar[int]
    BANDWIDTH_FIELD_NUMBER: _ClassVar[int]
    GEO_FIELD_NUMBER: _ClassVar[int]
    LINK_TYPE_FIELD_NUMBER: _ClassVar[int]
    INTERNAL_HOPS_FIELD_NUMBER: _ClassVar[int]
    NOTES_FIELD_NUMBER: _ClassVar[int]
    EPIC_AUTHS_FIELD_NUMBER: _ClassVar[int]
    raw: bytes
    interface: Interface
    interfaces: _containers.RepeatedCompositeFieldContainer[PathInterface]
    mtu: int
    expiration: _timestamp_pb2.Timestamp
    latency: _containers.RepeatedCompositeFieldContainer[_duration_pb2.Duration]
    bandwidth: _containers.RepeatedScalarFieldContainer[int]
    geo: _containers.RepeatedCompositeFieldContainer[GeoCoordinates]
    link_type: _containers.RepeatedScalarFieldContainer[LinkType]
    internal_hops: _containers.RepeatedScalarFieldContainer[int]
    notes: _containers.RepeatedScalarFieldContainer[str]
    epic_auths: EpicAuths
    def __init__(self, raw: _Optional[bytes] = ..., interface: _Optional[_Union[Interface, _Mapping]] = ..., interfaces: _Optional[_Iterable[_Union[PathInterface, _Mapping]]] = ..., mtu: _Optional[int] = ..., expiration: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., latency: _Optional[_Iterable[_Union[datetime.timedelta, _duration_pb2.Duration, _Mapping]]] = ..., bandwidth: _Optional[_Iterable[int]] = ..., geo: _Optional[_Iterable[_Union[GeoCoordinates, _Mapping]]] = ..., link_type: _Optional[_Iterable[_Union[LinkType, str]]] = ..., internal_hops: _Optional[_Iterable[int]] = ..., notes: _Optional[_Iterable[str]] = ..., epic_auths: _Optional[_Union[EpicAuths, _Mapping]] = ...) -> None: ...

class EpicAuths(_message.Message):
    __slots__ = ("auth_phvf", "auth_lhvf")
    AUTH_PHVF_FIELD_NUMBER: _ClassVar[int]
    AUTH_LHVF_FIELD_NUMBER: _ClassVar[int]
    auth_phvf: bytes
    auth_lhvf: bytes
    def __init__(self, auth_phvf: _Optional[bytes] = ..., auth_lhvf: _Optional[bytes] = ...) -> None: ...

class PathInterface(_message.Message):
    __slots__ = ("isd_as", "id")
    ISD_AS_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    isd_as: int
    id: int
    def __init__(self, isd_as: _Optional[int] = ..., id: _Optional[int] = ...) -> None: ...

class GeoCoordinates(_message.Message):
    __slots__ = ("latitude", "longitude", "address")
    LATITUDE_FIELD_NUMBER: _ClassVar[int]
    LONGITUDE_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    latitude: float
    longitude: float
    address: str
    def __init__(self, latitude: _Optional[float] = ..., longitude: _Optional[float] = ..., address: _Optional[str] = ...) -> None: ...

class ASRequest(_message.Message):
    __slots__ = ("isd_as",)
    ISD_AS_FIELD_NUMBER: _ClassVar[int]
    isd_as: int
    def __init__(self, isd_as: _Optional[int] = ...) -> None: ...

class ASResponse(_message.Message):
    __slots__ = ("isd_as", "core", "mtu")
    ISD_AS_FIELD_NUMBER: _ClassVar[int]
    CORE_FIELD_NUMBER: _ClassVar[int]
    MTU_FIELD_NUMBER: _ClassVar[int]
    isd_as: int
    core: bool
    mtu: int
    def __init__(self, isd_as: _Optional[int] = ..., core: bool = ..., mtu: _Optional[int] = ...) -> None: ...

class InterfacesRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class InterfacesResponse(_message.Message):
    __slots__ = ("interfaces",)
    class InterfacesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: Interface
        def __init__(self, key: _Optional[int] = ..., value: _Optional[_Union[Interface, _Mapping]] = ...) -> None: ...
    INTERFACES_FIELD_NUMBER: _ClassVar[int]
    interfaces: _containers.MessageMap[int, Interface]
    def __init__(self, interfaces: _Optional[_Mapping[int, Interface]] = ...) -> None: ...

class Interface(_message.Message):
    __slots__ = ("address",)
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    address: Underlay
    def __init__(self, address: _Optional[_Union[Underlay, _Mapping]] = ...) -> None: ...

class ServicesRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ServicesResponse(_message.Message):
    __slots__ = ("services",)
    class ServicesEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: ListService
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[ListService, _Mapping]] = ...) -> None: ...
    SERVICES_FIELD_NUMBER: _ClassVar[int]
    services: _containers.MessageMap[str, ListService]
    def __init__(self, services: _Optional[_Mapping[str, ListService]] = ...) -> None: ...

class ListService(_message.Message):
    __slots__ = ("services",)
    SERVICES_FIELD_NUMBER: _ClassVar[int]
    services: _containers.RepeatedCompositeFieldContainer[Service]
    def __init__(self, services: _Optional[_Iterable[_Union[Service, _Mapping]]] = ...) -> None: ...

class Service(_message.Message):
    __slots__ = ("uri",)
    URI_FIELD_NUMBER: _ClassVar[int]
    uri: str
    def __init__(self, uri: _Optional[str] = ...) -> None: ...

class Underlay(_message.Message):
    __slots__ = ("address",)
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    address: str
    def __init__(self, address: _Optional[str] = ...) -> None: ...

class NotifyInterfaceDownRequest(_message.Message):
    __slots__ = ("isd_as", "id")
    ISD_AS_FIELD_NUMBER: _ClassVar[int]
    ID_FIELD_NUMBER: _ClassVar[int]
    isd_as: int
    id: int
    def __init__(self, isd_as: _Optional[int] = ..., id: _Optional[int] = ...) -> None: ...

class NotifyInterfaceDownResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PortRangeResponse(_message.Message):
    __slots__ = ("dispatched_port_start", "dispatched_port_end")
    DISPATCHED_PORT_START_FIELD_NUMBER: _ClassVar[int]
    DISPATCHED_PORT_END_FIELD_NUMBER: _ClassVar[int]
    dispatched_port_start: int
    dispatched_port_end: int
    def __init__(self, dispatched_port_start: _Optional[int] = ..., dispatched_port_end: _Optional[int] = ...) -> None: ...

class DRKeyHostASRequest(_message.Message):
    __slots__ = ("val_time", "protocol_id", "src_ia", "dst_ia", "src_host")
    VAL_TIME_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_ID_FIELD_NUMBER: _ClassVar[int]
    SRC_IA_FIELD_NUMBER: _ClassVar[int]
    DST_IA_FIELD_NUMBER: _ClassVar[int]
    SRC_HOST_FIELD_NUMBER: _ClassVar[int]
    val_time: _timestamp_pb2.Timestamp
    protocol_id: _drkey_pb2.Protocol
    src_ia: int
    dst_ia: int
    src_host: str
    def __init__(self, val_time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., protocol_id: _Optional[_Union[_drkey_pb2.Protocol, str]] = ..., src_ia: _Optional[int] = ..., dst_ia: _Optional[int] = ..., src_host: _Optional[str] = ...) -> None: ...

class DRKeyHostASResponse(_message.Message):
    __slots__ = ("epoch_begin", "epoch_end", "key")
    EPOCH_BEGIN_FIELD_NUMBER: _ClassVar[int]
    EPOCH_END_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    epoch_begin: _timestamp_pb2.Timestamp
    epoch_end: _timestamp_pb2.Timestamp
    key: bytes
    def __init__(self, epoch_begin: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., epoch_end: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., key: _Optional[bytes] = ...) -> None: ...

class DRKeyASHostRequest(_message.Message):
    __slots__ = ("val_time", "protocol_id", "src_ia", "dst_ia", "dst_host")
    VAL_TIME_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_ID_FIELD_NUMBER: _ClassVar[int]
    SRC_IA_FIELD_NUMBER: _ClassVar[int]
    DST_IA_FIELD_NUMBER: _ClassVar[int]
    DST_HOST_FIELD_NUMBER: _ClassVar[int]
    val_time: _timestamp_pb2.Timestamp
    protocol_id: _drkey_pb2.Protocol
    src_ia: int
    dst_ia: int
    dst_host: str
    def __init__(self, val_time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., protocol_id: _Optional[_Union[_drkey_pb2.Protocol, str]] = ..., src_ia: _Optional[int] = ..., dst_ia: _Optional[int] = ..., dst_host: _Optional[str] = ...) -> None: ...

class DRKeyASHostResponse(_message.Message):
    __slots__ = ("epoch_begin", "epoch_end", "key")
    EPOCH_BEGIN_FIELD_NUMBER: _ClassVar[int]
    EPOCH_END_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    epoch_begin: _timestamp_pb2.Timestamp
    epoch_end: _timestamp_pb2.Timestamp
    key: bytes
    def __init__(self, epoch_begin: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., epoch_end: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., key: _Optional[bytes] = ...) -> None: ...

class DRKeyHostHostRequest(_message.Message):
    __slots__ = ("val_time", "protocol_id", "src_ia", "dst_ia", "src_host", "dst_host")
    VAL_TIME_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_ID_FIELD_NUMBER: _ClassVar[int]
    SRC_IA_FIELD_NUMBER: _ClassVar[int]
    DST_IA_FIELD_NUMBER: _ClassVar[int]
    SRC_HOST_FIELD_NUMBER: _ClassVar[int]
    DST_HOST_FIELD_NUMBER: _ClassVar[int]
    val_time: _timestamp_pb2.Timestamp
    protocol_id: _drkey_pb2.Protocol
    src_ia: int
    dst_ia: int
    src_host: str
    dst_host: str
    def __init__(self, val_time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., protocol_id: _Optional[_Union[_drkey_pb2.Protocol, str]] = ..., src_ia: _Optional[int] = ..., dst_ia: _Optional[int] = ..., src_host: _Optional[str] = ..., dst_host: _Optional[str] = ...) -> None: ...

class DRKeyHostHostResponse(_message.Message):
    __slots__ = ("epoch_begin", "epoch_end", "key")
    EPOCH_BEGIN_FIELD_NUMBER: _ClassVar[int]
    EPOCH_END_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    epoch_begin: _timestamp_pb2.Timestamp
    epoch_end: _timestamp_pb2.Timestamp
    key: bytes
    def __init__(self, epoch_begin: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., epoch_end: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., key: _Optional[bytes] = ...) -> None: ...
