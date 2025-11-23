from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ControlRequest(_message.Message):
    __slots__ = ("probe",)
    PROBE_FIELD_NUMBER: _ClassVar[int]
    probe: ProbeRequest
    def __init__(self, probe: _Optional[_Union[ProbeRequest, _Mapping]] = ...) -> None: ...

class ControlResponse(_message.Message):
    __slots__ = ("probe",)
    PROBE_FIELD_NUMBER: _ClassVar[int]
    probe: ProbeResponse
    def __init__(self, probe: _Optional[_Union[ProbeResponse, _Mapping]] = ...) -> None: ...

class ProbeRequest(_message.Message):
    __slots__ = ("session_id", "data")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    session_id: int
    data: bytes
    def __init__(self, session_id: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...

class ProbeResponse(_message.Message):
    __slots__ = ("session_id", "data")
    SESSION_ID_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    session_id: int
    data: bytes
    def __init__(self, session_id: _Optional[int] = ..., data: _Optional[bytes] = ...) -> None: ...
