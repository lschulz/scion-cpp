from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PrefixesRequest(_message.Message):
    __slots__ = ("etag",)
    ETAG_FIELD_NUMBER: _ClassVar[int]
    etag: str
    def __init__(self, etag: _Optional[str] = ...) -> None: ...

class PrefixesResponse(_message.Message):
    __slots__ = ("prefixes", "etag")
    PREFIXES_FIELD_NUMBER: _ClassVar[int]
    ETAG_FIELD_NUMBER: _ClassVar[int]
    prefixes: _containers.RepeatedCompositeFieldContainer[Prefix]
    etag: str
    def __init__(self, prefixes: _Optional[_Iterable[_Union[Prefix, _Mapping]]] = ..., etag: _Optional[str] = ...) -> None: ...

class Prefix(_message.Message):
    __slots__ = ("prefix", "mask")
    PREFIX_FIELD_NUMBER: _ClassVar[int]
    MASK_FIELD_NUMBER: _ClassVar[int]
    prefix: bytes
    mask: int
    def __init__(self, prefix: _Optional[bytes] = ..., mask: _Optional[int] = ...) -> None: ...
