import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class SignatureAlgorithm(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SIGNATURE_ALGORITHM_UNSPECIFIED: _ClassVar[SignatureAlgorithm]
    SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256: _ClassVar[SignatureAlgorithm]
    SIGNATURE_ALGORITHM_ECDSA_WITH_SHA384: _ClassVar[SignatureAlgorithm]
    SIGNATURE_ALGORITHM_ECDSA_WITH_SHA512: _ClassVar[SignatureAlgorithm]
SIGNATURE_ALGORITHM_UNSPECIFIED: SignatureAlgorithm
SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256: SignatureAlgorithm
SIGNATURE_ALGORITHM_ECDSA_WITH_SHA384: SignatureAlgorithm
SIGNATURE_ALGORITHM_ECDSA_WITH_SHA512: SignatureAlgorithm

class SignedMessage(_message.Message):
    __slots__ = ("header_and_body", "signature")
    HEADER_AND_BODY_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    header_and_body: bytes
    signature: bytes
    def __init__(self, header_and_body: _Optional[bytes] = ..., signature: _Optional[bytes] = ...) -> None: ...

class Header(_message.Message):
    __slots__ = ("signature_algorithm", "verification_key_id", "timestamp", "metadata", "associated_data_length")
    SIGNATURE_ALGORITHM_FIELD_NUMBER: _ClassVar[int]
    VERIFICATION_KEY_ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    ASSOCIATED_DATA_LENGTH_FIELD_NUMBER: _ClassVar[int]
    signature_algorithm: SignatureAlgorithm
    verification_key_id: bytes
    timestamp: _timestamp_pb2.Timestamp
    metadata: bytes
    associated_data_length: int
    def __init__(self, signature_algorithm: _Optional[_Union[SignatureAlgorithm, str]] = ..., verification_key_id: _Optional[bytes] = ..., timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ..., metadata: _Optional[bytes] = ..., associated_data_length: _Optional[int] = ...) -> None: ...

class HeaderAndBodyInternal(_message.Message):
    __slots__ = ("header", "body")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    BODY_FIELD_NUMBER: _ClassVar[int]
    header: bytes
    body: bytes
    def __init__(self, header: _Optional[bytes] = ..., body: _Optional[bytes] = ...) -> None: ...
