import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ChainsRequest(_message.Message):
    __slots__ = ("isd_as", "subject_key_id", "at_least_valid_until", "at_least_valid_since")
    ISD_AS_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    AT_LEAST_VALID_UNTIL_FIELD_NUMBER: _ClassVar[int]
    AT_LEAST_VALID_SINCE_FIELD_NUMBER: _ClassVar[int]
    isd_as: int
    subject_key_id: bytes
    at_least_valid_until: _timestamp_pb2.Timestamp
    at_least_valid_since: _timestamp_pb2.Timestamp
    def __init__(self, isd_as: _Optional[int] = ..., subject_key_id: _Optional[bytes] = ..., at_least_valid_until: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., at_least_valid_since: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class ChainsResponse(_message.Message):
    __slots__ = ("chains",)
    CHAINS_FIELD_NUMBER: _ClassVar[int]
    chains: _containers.RepeatedCompositeFieldContainer[Chain]
    def __init__(self, chains: _Optional[_Iterable[_Union[Chain, _Mapping]]] = ...) -> None: ...

class Chain(_message.Message):
    __slots__ = ("as_cert", "ca_cert")
    AS_CERT_FIELD_NUMBER: _ClassVar[int]
    CA_CERT_FIELD_NUMBER: _ClassVar[int]
    as_cert: bytes
    ca_cert: bytes
    def __init__(self, as_cert: _Optional[bytes] = ..., ca_cert: _Optional[bytes] = ...) -> None: ...

class TRCRequest(_message.Message):
    __slots__ = ("isd", "base", "serial")
    ISD_FIELD_NUMBER: _ClassVar[int]
    BASE_FIELD_NUMBER: _ClassVar[int]
    SERIAL_FIELD_NUMBER: _ClassVar[int]
    isd: int
    base: int
    serial: int
    def __init__(self, isd: _Optional[int] = ..., base: _Optional[int] = ..., serial: _Optional[int] = ...) -> None: ...

class TRCResponse(_message.Message):
    __slots__ = ("trc",)
    TRC_FIELD_NUMBER: _ClassVar[int]
    trc: bytes
    def __init__(self, trc: _Optional[bytes] = ...) -> None: ...

class VerificationKeyID(_message.Message):
    __slots__ = ("isd_as", "subject_key_id", "trc_base", "trc_serial")
    ISD_AS_FIELD_NUMBER: _ClassVar[int]
    SUBJECT_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    TRC_BASE_FIELD_NUMBER: _ClassVar[int]
    TRC_SERIAL_FIELD_NUMBER: _ClassVar[int]
    isd_as: int
    subject_key_id: bytes
    trc_base: int
    trc_serial: int
    def __init__(self, isd_as: _Optional[int] = ..., subject_key_id: _Optional[bytes] = ..., trc_base: _Optional[int] = ..., trc_serial: _Optional[int] = ...) -> None: ...
