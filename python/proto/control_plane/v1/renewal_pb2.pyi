from proto.control_plane.v1 import cppki_pb2 as _cppki_pb2
from proto.crypto.v1 import signed_pb2 as _signed_pb2
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ChainRenewalRequest(_message.Message):
    __slots__ = ("signed_request", "cms_signed_request")
    SIGNED_REQUEST_FIELD_NUMBER: _ClassVar[int]
    CMS_SIGNED_REQUEST_FIELD_NUMBER: _ClassVar[int]
    signed_request: _signed_pb2.SignedMessage
    cms_signed_request: bytes
    def __init__(self, signed_request: _Optional[_Union[_signed_pb2.SignedMessage, _Mapping]] = ..., cms_signed_request: _Optional[bytes] = ...) -> None: ...

class ChainRenewalRequestBody(_message.Message):
    __slots__ = ("csr",)
    CSR_FIELD_NUMBER: _ClassVar[int]
    csr: bytes
    def __init__(self, csr: _Optional[bytes] = ...) -> None: ...

class ChainRenewalResponse(_message.Message):
    __slots__ = ("signed_response", "cms_signed_response")
    SIGNED_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    CMS_SIGNED_RESPONSE_FIELD_NUMBER: _ClassVar[int]
    signed_response: _signed_pb2.SignedMessage
    cms_signed_response: bytes
    def __init__(self, signed_response: _Optional[_Union[_signed_pb2.SignedMessage, _Mapping]] = ..., cms_signed_response: _Optional[bytes] = ...) -> None: ...

class ChainRenewalResponseBody(_message.Message):
    __slots__ = ("chain",)
    CHAIN_FIELD_NUMBER: _ClassVar[int]
    chain: _cppki_pb2.Chain
    def __init__(self, chain: _Optional[_Union[_cppki_pb2.Chain, _Mapping]] = ...) -> None: ...
