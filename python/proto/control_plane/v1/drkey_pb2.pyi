import datetime

from proto.drkey.v1 import drkey_pb2 as _drkey_pb2
from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DRKeySecretValueRequest(_message.Message):
    __slots__ = ("val_time", "protocol_id")
    VAL_TIME_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_ID_FIELD_NUMBER: _ClassVar[int]
    val_time: _timestamp_pb2.Timestamp
    protocol_id: _drkey_pb2.Protocol
    def __init__(self, val_time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., protocol_id: _Optional[_Union[_drkey_pb2.Protocol, str]] = ...) -> None: ...

class DRKeySecretValueResponse(_message.Message):
    __slots__ = ("epoch_begin", "epoch_end", "key")
    EPOCH_BEGIN_FIELD_NUMBER: _ClassVar[int]
    EPOCH_END_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    epoch_begin: _timestamp_pb2.Timestamp
    epoch_end: _timestamp_pb2.Timestamp
    key: bytes
    def __init__(self, epoch_begin: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., epoch_end: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., key: _Optional[bytes] = ...) -> None: ...

class DRKeyLevel1Request(_message.Message):
    __slots__ = ("val_time", "protocol_id")
    VAL_TIME_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_ID_FIELD_NUMBER: _ClassVar[int]
    val_time: _timestamp_pb2.Timestamp
    protocol_id: _drkey_pb2.Protocol
    def __init__(self, val_time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., protocol_id: _Optional[_Union[_drkey_pb2.Protocol, str]] = ...) -> None: ...

class DRKeyLevel1Response(_message.Message):
    __slots__ = ("epoch_begin", "epoch_end", "key")
    EPOCH_BEGIN_FIELD_NUMBER: _ClassVar[int]
    EPOCH_END_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    epoch_begin: _timestamp_pb2.Timestamp
    epoch_end: _timestamp_pb2.Timestamp
    key: bytes
    def __init__(self, epoch_begin: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., epoch_end: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., key: _Optional[bytes] = ...) -> None: ...

class DRKeyIntraLevel1Request(_message.Message):
    __slots__ = ("val_time", "protocol_id", "src_ia", "dst_ia")
    VAL_TIME_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_ID_FIELD_NUMBER: _ClassVar[int]
    SRC_IA_FIELD_NUMBER: _ClassVar[int]
    DST_IA_FIELD_NUMBER: _ClassVar[int]
    val_time: _timestamp_pb2.Timestamp
    protocol_id: _drkey_pb2.Protocol
    src_ia: int
    dst_ia: int
    def __init__(self, val_time: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., protocol_id: _Optional[_Union[_drkey_pb2.Protocol, str]] = ..., src_ia: _Optional[int] = ..., dst_ia: _Optional[int] = ...) -> None: ...

class DRKeyIntraLevel1Response(_message.Message):
    __slots__ = ("epoch_begin", "epoch_end", "key")
    EPOCH_BEGIN_FIELD_NUMBER: _ClassVar[int]
    EPOCH_END_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    epoch_begin: _timestamp_pb2.Timestamp
    epoch_end: _timestamp_pb2.Timestamp
    key: bytes
    def __init__(self, epoch_begin: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., epoch_end: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., key: _Optional[bytes] = ...) -> None: ...

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
