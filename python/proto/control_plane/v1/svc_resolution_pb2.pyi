from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ServiceResolutionRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ServiceResolutionResponse(_message.Message):
    __slots__ = ("transports",)
    class TransportsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: Transport
        def __init__(self, key: _Optional[str] = ..., value: _Optional[_Union[Transport, _Mapping]] = ...) -> None: ...
    TRANSPORTS_FIELD_NUMBER: _ClassVar[int]
    transports: _containers.MessageMap[str, Transport]
    def __init__(self, transports: _Optional[_Mapping[str, Transport]] = ...) -> None: ...

class Transport(_message.Message):
    __slots__ = ("address",)
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    address: str
    def __init__(self, address: _Optional[str] = ...) -> None: ...
