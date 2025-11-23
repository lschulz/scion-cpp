from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class EPICDetachedExtension(_message.Message):
    __slots__ = ("auth_hop_entry", "auth_peer_entries")
    AUTH_HOP_ENTRY_FIELD_NUMBER: _ClassVar[int]
    AUTH_PEER_ENTRIES_FIELD_NUMBER: _ClassVar[int]
    auth_hop_entry: bytes
    auth_peer_entries: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, auth_hop_entry: _Optional[bytes] = ..., auth_peer_entries: _Optional[_Iterable[bytes]] = ...) -> None: ...
