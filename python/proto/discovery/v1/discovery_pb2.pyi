from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GatewaysRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GatewaysResponse(_message.Message):
    __slots__ = ("gateways",)
    GATEWAYS_FIELD_NUMBER: _ClassVar[int]
    gateways: _containers.RepeatedCompositeFieldContainer[Gateway]
    def __init__(self, gateways: _Optional[_Iterable[_Union[Gateway, _Mapping]]] = ...) -> None: ...

class Gateway(_message.Message):
    __slots__ = ("control_address", "data_address", "probe_address", "allow_interfaces")
    CONTROL_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    DATA_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    PROBE_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    ALLOW_INTERFACES_FIELD_NUMBER: _ClassVar[int]
    control_address: str
    data_address: str
    probe_address: str
    allow_interfaces: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, control_address: _Optional[str] = ..., data_address: _Optional[str] = ..., probe_address: _Optional[str] = ..., allow_interfaces: _Optional[_Iterable[int]] = ...) -> None: ...

class HiddenSegmentServicesRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HiddenSegmentServicesResponse(_message.Message):
    __slots__ = ("lookup", "registration")
    LOOKUP_FIELD_NUMBER: _ClassVar[int]
    REGISTRATION_FIELD_NUMBER: _ClassVar[int]
    lookup: _containers.RepeatedCompositeFieldContainer[HiddenSegmentLookupServer]
    registration: _containers.RepeatedCompositeFieldContainer[HiddenSegmentRegistrationServer]
    def __init__(self, lookup: _Optional[_Iterable[_Union[HiddenSegmentLookupServer, _Mapping]]] = ..., registration: _Optional[_Iterable[_Union[HiddenSegmentRegistrationServer, _Mapping]]] = ...) -> None: ...

class HiddenSegmentLookupServer(_message.Message):
    __slots__ = ("address",)
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    address: str
    def __init__(self, address: _Optional[str] = ...) -> None: ...

class HiddenSegmentRegistrationServer(_message.Message):
    __slots__ = ("address",)
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    address: str
    def __init__(self, address: _Optional[str] = ...) -> None: ...
