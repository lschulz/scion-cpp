from proto.control_plane.v1 import seg_pb2 as _seg_pb2
from proto.crypto.v1 import signed_pb2 as _signed_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Segments(_message.Message):
    __slots__ = ("segments",)
    SEGMENTS_FIELD_NUMBER: _ClassVar[int]
    segments: _containers.RepeatedCompositeFieldContainer[_seg_pb2.PathSegment]
    def __init__(self, segments: _Optional[_Iterable[_Union[_seg_pb2.PathSegment, _Mapping]]] = ...) -> None: ...

class HiddenSegmentRegistrationRequest(_message.Message):
    __slots__ = ("signed_request",)
    SIGNED_REQUEST_FIELD_NUMBER: _ClassVar[int]
    signed_request: _signed_pb2.SignedMessage
    def __init__(self, signed_request: _Optional[_Union[_signed_pb2.SignedMessage, _Mapping]] = ...) -> None: ...

class HiddenSegmentRegistrationRequestBody(_message.Message):
    __slots__ = ("segments", "group_id")
    class SegmentsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: Segments
        def __init__(self, key: _Optional[int] = ..., value: _Optional[_Union[Segments, _Mapping]] = ...) -> None: ...
    SEGMENTS_FIELD_NUMBER: _ClassVar[int]
    GROUP_ID_FIELD_NUMBER: _ClassVar[int]
    segments: _containers.MessageMap[int, Segments]
    group_id: int
    def __init__(self, segments: _Optional[_Mapping[int, Segments]] = ..., group_id: _Optional[int] = ...) -> None: ...

class HiddenSegmentRegistrationResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HiddenSegmentsRequest(_message.Message):
    __slots__ = ("group_ids", "dst_isd_as")
    GROUP_IDS_FIELD_NUMBER: _ClassVar[int]
    DST_ISD_AS_FIELD_NUMBER: _ClassVar[int]
    group_ids: _containers.RepeatedScalarFieldContainer[int]
    dst_isd_as: int
    def __init__(self, group_ids: _Optional[_Iterable[int]] = ..., dst_isd_as: _Optional[int] = ...) -> None: ...

class HiddenSegmentsResponse(_message.Message):
    __slots__ = ("segments",)
    class SegmentsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: Segments
        def __init__(self, key: _Optional[int] = ..., value: _Optional[_Union[Segments, _Mapping]] = ...) -> None: ...
    SEGMENTS_FIELD_NUMBER: _ClassVar[int]
    segments: _containers.MessageMap[int, Segments]
    def __init__(self, segments: _Optional[_Mapping[int, Segments]] = ...) -> None: ...

class AuthoritativeHiddenSegmentsRequest(_message.Message):
    __slots__ = ("signed_request",)
    SIGNED_REQUEST_FIELD_NUMBER: _ClassVar[int]
    signed_request: _signed_pb2.SignedMessage
    def __init__(self, signed_request: _Optional[_Union[_signed_pb2.SignedMessage, _Mapping]] = ...) -> None: ...

class AuthoritativeHiddenSegmentsResponse(_message.Message):
    __slots__ = ("segments",)
    class SegmentsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: int
        value: Segments
        def __init__(self, key: _Optional[int] = ..., value: _Optional[_Union[Segments, _Mapping]] = ...) -> None: ...
    SEGMENTS_FIELD_NUMBER: _ClassVar[int]
    segments: _containers.MessageMap[int, Segments]
    def __init__(self, segments: _Optional[_Mapping[int, Segments]] = ...) -> None: ...
