# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# NO CHECKED-IN PROTOBUF GENCODE
# source: proto/gateway/v1/prefix.proto
# Protobuf Python Version: 5.29.0
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import runtime_version as _runtime_version
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
_runtime_version.ValidateProtobufRuntimeVersion(
    _runtime_version.Domain.PUBLIC,
    5,
    29,
    0,
    '',
    'proto/gateway/v1/prefix.proto'
)
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(b'\n\x1dproto/gateway/v1/prefix.proto\x12\x10proto.gateway.v1\"\x1f\n\x0fPrefixesRequest\x12\x0c\n\x04\x65tag\x18\x01 \x01(\t\"L\n\x10PrefixesResponse\x12*\n\x08prefixes\x18\x01 \x03(\x0b\x32\x18.proto.gateway.v1.Prefix\x12\x0c\n\x04\x65tag\x18\x02 \x01(\t\"&\n\x06Prefix\x12\x0e\n\x06prefix\x18\x01 \x01(\x0c\x12\x0c\n\x04mask\x18\x02 \x01(\r2h\n\x11IPPrefixesService\x12S\n\x08Prefixes\x12!.proto.gateway.v1.PrefixesRequest\x1a\".proto.gateway.v1.PrefixesResponse\"\x00\x42/Z-github.com/scionproto/scion/pkg/proto/gatewayb\x06proto3')

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'proto.gateway.v1.prefix_pb2', _globals)
if not _descriptor._USE_C_DESCRIPTORS:
  _globals['DESCRIPTOR']._loaded_options = None
  _globals['DESCRIPTOR']._serialized_options = b'Z-github.com/scionproto/scion/pkg/proto/gateway'
  _globals['_PREFIXESREQUEST']._serialized_start=51
  _globals['_PREFIXESREQUEST']._serialized_end=82
  _globals['_PREFIXESRESPONSE']._serialized_start=84
  _globals['_PREFIXESRESPONSE']._serialized_end=160
  _globals['_PREFIX']._serialized_start=162
  _globals['_PREFIX']._serialized_end=200
  _globals['_IPPREFIXESSERVICE']._serialized_start=202
  _globals['_IPPREFIXESSERVICE']._serialized_end=306
# @@protoc_insertion_point(module_scope)
