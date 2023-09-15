// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: mpcwalletpb/api.proto

package mpcwalletpb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type HealthCheckRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *HealthCheckRequest) Reset() {
	*x = HealthCheckRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HealthCheckRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HealthCheckRequest) ProtoMessage() {}

func (x *HealthCheckRequest) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HealthCheckRequest.ProtoReflect.Descriptor instead.
func (*HealthCheckRequest) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{0}
}

type HealthCheckResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Status string `protobuf:"bytes,1,opt,name=status,proto3" json:"status,omitempty"`
}

func (x *HealthCheckResponse) Reset() {
	*x = HealthCheckResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HealthCheckResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HealthCheckResponse) ProtoMessage() {}

func (x *HealthCheckResponse) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HealthCheckResponse.ProtoReflect.Descriptor instead.
func (*HealthCheckResponse) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{1}
}

func (x *HealthCheckResponse) GetStatus() string {
	if x != nil {
		return x.Status
	}
	return ""
}

type GenerateKeyPairRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GenerateKeyPairRequest) Reset() {
	*x = GenerateKeyPairRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateKeyPairRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateKeyPairRequest) ProtoMessage() {}

func (x *GenerateKeyPairRequest) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateKeyPairRequest.ProtoReflect.Descriptor instead.
func (*GenerateKeyPairRequest) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{2}
}

type GenerateKeyPairResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
}

func (x *GenerateKeyPairResponse) Reset() {
	*x = GenerateKeyPairResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GenerateKeyPairResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GenerateKeyPairResponse) ProtoMessage() {}

func (x *GenerateKeyPairResponse) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GenerateKeyPairResponse.ProtoReflect.Descriptor instead.
func (*GenerateKeyPairResponse) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{3}
}

func (x *GenerateKeyPairResponse) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

type GeneratePartialKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
}

func (x *GeneratePartialKeyRequest) Reset() {
	*x = GeneratePartialKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GeneratePartialKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GeneratePartialKeyRequest) ProtoMessage() {}

func (x *GeneratePartialKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GeneratePartialKeyRequest.ProtoReflect.Descriptor instead.
func (*GeneratePartialKeyRequest) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{4}
}

func (x *GeneratePartialKeyRequest) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

type GeneratePartialKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *GeneratePartialKeyResponse) Reset() {
	*x = GeneratePartialKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GeneratePartialKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GeneratePartialKeyResponse) ProtoMessage() {}

func (x *GeneratePartialKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GeneratePartialKeyResponse.ProtoReflect.Descriptor instead.
func (*GeneratePartialKeyResponse) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{5}
}

type ExchangePartialKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId      string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	Commitment string `protobuf:"bytes,2,opt,name=commitment,proto3" json:"commitment,omitempty"`
}

func (x *ExchangePartialKeyRequest) Reset() {
	*x = ExchangePartialKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExchangePartialKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExchangePartialKeyRequest) ProtoMessage() {}

func (x *ExchangePartialKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExchangePartialKeyRequest.ProtoReflect.Descriptor instead.
func (*ExchangePartialKeyRequest) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{6}
}

func (x *ExchangePartialKeyRequest) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *ExchangePartialKeyRequest) GetCommitment() string {
	if x != nil {
		return x.Commitment
	}
	return ""
}

type ExchangePartialKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId     string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	PublicKey string `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
}

func (x *ExchangePartialKeyResponse) Reset() {
	*x = ExchangePartialKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExchangePartialKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExchangePartialKeyResponse) ProtoMessage() {}

func (x *ExchangePartialKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExchangePartialKeyResponse.ProtoReflect.Descriptor instead.
func (*ExchangePartialKeyResponse) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{7}
}

func (x *ExchangePartialKeyResponse) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *ExchangePartialKeyResponse) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

type ProvePartialKeyCommitmentRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	Proof string `protobuf:"bytes,2,opt,name=proof,proto3" json:"proof,omitempty"`
}

func (x *ProvePartialKeyCommitmentRequest) Reset() {
	*x = ProvePartialKeyCommitmentRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProvePartialKeyCommitmentRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProvePartialKeyCommitmentRequest) ProtoMessage() {}

func (x *ProvePartialKeyCommitmentRequest) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProvePartialKeyCommitmentRequest.ProtoReflect.Descriptor instead.
func (*ProvePartialKeyCommitmentRequest) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{8}
}

func (x *ProvePartialKeyCommitmentRequest) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *ProvePartialKeyCommitmentRequest) GetProof() string {
	if x != nil {
		return x.Proof
	}
	return ""
}

type ProvePartialKeyCommitmentResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId    string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	Verified bool   `protobuf:"varint,2,opt,name=verified,proto3" json:"verified,omitempty"`
}

func (x *ProvePartialKeyCommitmentResponse) Reset() {
	*x = ProvePartialKeyCommitmentResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProvePartialKeyCommitmentResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProvePartialKeyCommitmentResponse) ProtoMessage() {}

func (x *ProvePartialKeyCommitmentResponse) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProvePartialKeyCommitmentResponse.ProtoReflect.Descriptor instead.
func (*ProvePartialKeyCommitmentResponse) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{9}
}

func (x *ProvePartialKeyCommitmentResponse) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *ProvePartialKeyCommitmentResponse) GetVerified() bool {
	if x != nil {
		return x.Verified
	}
	return false
}

type ExchangeKeyRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId      string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	Commitment string `protobuf:"bytes,2,opt,name=commitment,proto3" json:"commitment,omitempty"`
}

func (x *ExchangeKeyRequest) Reset() {
	*x = ExchangeKeyRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExchangeKeyRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExchangeKeyRequest) ProtoMessage() {}

func (x *ExchangeKeyRequest) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExchangeKeyRequest.ProtoReflect.Descriptor instead.
func (*ExchangeKeyRequest) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{10}
}

func (x *ExchangeKeyRequest) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *ExchangeKeyRequest) GetCommitment() string {
	if x != nil {
		return x.Commitment
	}
	return ""
}

type ExchangeKeyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId     string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	PublicKey string `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
}

func (x *ExchangeKeyResponse) Reset() {
	*x = ExchangeKeyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[11]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ExchangeKeyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ExchangeKeyResponse) ProtoMessage() {}

func (x *ExchangeKeyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[11]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ExchangeKeyResponse.ProtoReflect.Descriptor instead.
func (*ExchangeKeyResponse) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{11}
}

func (x *ExchangeKeyResponse) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *ExchangeKeyResponse) GetPublicKey() string {
	if x != nil {
		return x.PublicKey
	}
	return ""
}

type ProveKeyCommitmentRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	Proof string `protobuf:"bytes,2,opt,name=proof,proto3" json:"proof,omitempty"`
}

func (x *ProveKeyCommitmentRequest) Reset() {
	*x = ProveKeyCommitmentRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[12]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProveKeyCommitmentRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProveKeyCommitmentRequest) ProtoMessage() {}

func (x *ProveKeyCommitmentRequest) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[12]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProveKeyCommitmentRequest.ProtoReflect.Descriptor instead.
func (*ProveKeyCommitmentRequest) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{12}
}

func (x *ProveKeyCommitmentRequest) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *ProveKeyCommitmentRequest) GetProof() string {
	if x != nil {
		return x.Proof
	}
	return ""
}

type ProveKeyCommitmentResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	KeyId    string `protobuf:"bytes,1,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	Verified bool   `protobuf:"varint,2,opt,name=verified,proto3" json:"verified,omitempty"`
}

func (x *ProveKeyCommitmentResponse) Reset() {
	*x = ProveKeyCommitmentResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_mpcwalletpb_api_proto_msgTypes[13]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProveKeyCommitmentResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProveKeyCommitmentResponse) ProtoMessage() {}

func (x *ProveKeyCommitmentResponse) ProtoReflect() protoreflect.Message {
	mi := &file_mpcwalletpb_api_proto_msgTypes[13]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProveKeyCommitmentResponse.ProtoReflect.Descriptor instead.
func (*ProveKeyCommitmentResponse) Descriptor() ([]byte, []int) {
	return file_mpcwalletpb_api_proto_rawDescGZIP(), []int{13}
}

func (x *ProveKeyCommitmentResponse) GetKeyId() string {
	if x != nil {
		return x.KeyId
	}
	return ""
}

func (x *ProveKeyCommitmentResponse) GetVerified() bool {
	if x != nil {
		return x.Verified
	}
	return false
}

var File_mpcwalletpb_api_proto protoreflect.FileDescriptor

var file_mpcwalletpb_api_proto_rawDesc = []byte{
	0x0a, 0x15, 0x6d, 0x70, 0x63, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x70, 0x62, 0x2f, 0x61, 0x70,
	0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x22, 0x14, 0x0a, 0x12, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x43, 0x68, 0x65,
	0x63, 0x6b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22, 0x2d, 0x0a, 0x13, 0x48, 0x65, 0x61,
	0x6c, 0x74, 0x68, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x16, 0x0a, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x18, 0x0a, 0x16, 0x47, 0x65, 0x6e, 0x65,
	0x72, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x50, 0x61, 0x69, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x22, 0x30, 0x0a, 0x17, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x4b, 0x65,
	0x79, 0x50, 0x61, 0x69, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x15, 0x0a,
	0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6b,
	0x65, 0x79, 0x49, 0x64, 0x22, 0x32, 0x0a, 0x19, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65,
	0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x22, 0x1c, 0x0a, 0x1a, 0x47, 0x65, 0x6e, 0x65,
	0x72, 0x61, 0x74, 0x65, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65, 0x79, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x52, 0x0a, 0x19, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e,
	0x67, 0x65, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x6f,
	0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a,
	0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0x52, 0x0a, 0x1a, 0x45, 0x78,
	0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65, 0x79,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12,
	0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65, 0x79, 0x22, 0x4f,
	0x0a, 0x20, 0x50, 0x72, 0x6f, 0x76, 0x65, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65,
	0x79, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f,
	0x6f, 0x66, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x22,
	0x56, 0x0a, 0x21, 0x50, 0x72, 0x6f, 0x76, 0x65, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b,
	0x65, 0x79, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x76,
	0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x08, 0x76,
	0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x64, 0x22, 0x4b, 0x0a, 0x12, 0x45, 0x78, 0x63, 0x68, 0x61,
	0x6e, 0x67, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x15, 0x0a,
	0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6b,
	0x65, 0x79, 0x49, 0x64, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65,
	0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
	0x6d, 0x65, 0x6e, 0x74, 0x22, 0x4b, 0x0a, 0x13, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65,
	0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x6b,
	0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6b, 0x65, 0x79,
	0x49, 0x64, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6b, 0x65, 0x79,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4b, 0x65,
	0x79, 0x22, 0x48, 0x0a, 0x19, 0x50, 0x72, 0x6f, 0x76, 0x65, 0x4b, 0x65, 0x79, 0x43, 0x6f, 0x6d,
	0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x15,
	0x0a, 0x06, 0x6b, 0x65, 0x79, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x6b, 0x65, 0x79, 0x49, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x22, 0x4f, 0x0a, 0x1a, 0x50,
	0x72, 0x6f, 0x76, 0x65, 0x4b, 0x65, 0x79, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e,
	0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x15, 0x0a, 0x06, 0x6b, 0x65, 0x79,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6b, 0x65, 0x79, 0x49, 0x64,
	0x12, 0x1a, 0x0a, 0x08, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x08, 0x76, 0x65, 0x72, 0x69, 0x66, 0x69, 0x65, 0x64, 0x32, 0xbf, 0x05, 0x0a,
	0x0a, 0x4d, 0x50, 0x43, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x50, 0x0a, 0x0b, 0x48,
	0x65, 0x61, 0x6c, 0x74, 0x68, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x12, 0x1e, 0x2e, 0x6d, 0x70, 0x63,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x43, 0x68,
	0x65, 0x63, 0x6b, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x6d, 0x70, 0x63,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x48, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x43, 0x68,
	0x65, 0x63, 0x6b, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x5c, 0x0a,
	0x0f, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x50, 0x61, 0x69, 0x72,
	0x12, 0x22, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x47, 0x65,
	0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x50, 0x61, 0x69, 0x72, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x23, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79, 0x50, 0x61, 0x69,
	0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x65, 0x0a, 0x12, 0x47,
	0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65,
	0x79, 0x12, 0x25, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x47,
	0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65,
	0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x26, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x47, 0x65, 0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x50, 0x61,
	0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x22, 0x00, 0x12, 0x65, 0x0a, 0x12, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x50, 0x61,
	0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65, 0x79, 0x12, 0x25, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x50, 0x61,
	0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a,
	0x26, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x45, 0x78, 0x63,
	0x68, 0x61, 0x6e, 0x67, 0x65, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65, 0x79, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x7a, 0x0a, 0x19, 0x50, 0x72, 0x6f,
	0x76, 0x65, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65, 0x79, 0x43, 0x6f, 0x6d, 0x6d,
	0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x2c, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2e, 0x50, 0x72, 0x6f, 0x76, 0x65, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c,
	0x4b, 0x65, 0x79, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x2d, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x50, 0x72, 0x6f, 0x76, 0x65, 0x50, 0x61, 0x72, 0x74, 0x69, 0x61, 0x6c, 0x4b, 0x65,
	0x79, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x50, 0x0a, 0x0b, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67,
	0x65, 0x4b, 0x65, 0x79, 0x12, 0x1e, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x1f, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x45, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x4b, 0x65, 0x79, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x12, 0x65, 0x0a, 0x12, 0x50, 0x72, 0x6f, 0x76, 0x65,
	0x4b, 0x65, 0x79, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x12, 0x25, 0x2e,
	0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x50, 0x72, 0x6f, 0x76, 0x65,
	0x4b, 0x65, 0x79, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x26, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x50, 0x72, 0x6f, 0x76, 0x65, 0x4b, 0x65, 0x79, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74,
	0x6d, 0x65, 0x6e, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42, 0x8e,
	0x01, 0x0a, 0x0e, 0x63, 0x6f, 0x6d, 0x2e, 0x6d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x42, 0x08, 0x41, 0x70, 0x69, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x2a, 0x67,
	0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x68, 0x6e, 0x61, 0x6d, 0x7a, 0x69,
	0x61, 0x6e, 0x2f, 0x79, 0x65, 0x68, 0x75, 0x64, 0x61, 0x2d, 0x6d, 0x70, 0x63, 0x2f, 0x6d, 0x70,
	0x63, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x70, 0x62, 0xa2, 0x02, 0x03, 0x4d, 0x58, 0x58, 0xaa,
	0x02, 0x0a, 0x4d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0xca, 0x02, 0x0a, 0x4d,
	0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0xe2, 0x02, 0x16, 0x4d, 0x70, 0x63, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0xea, 0x02, 0x0a, 0x4d, 0x70, 0x63, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_mpcwalletpb_api_proto_rawDescOnce sync.Once
	file_mpcwalletpb_api_proto_rawDescData = file_mpcwalletpb_api_proto_rawDesc
)

func file_mpcwalletpb_api_proto_rawDescGZIP() []byte {
	file_mpcwalletpb_api_proto_rawDescOnce.Do(func() {
		file_mpcwalletpb_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_mpcwalletpb_api_proto_rawDescData)
	})
	return file_mpcwalletpb_api_proto_rawDescData
}

var file_mpcwalletpb_api_proto_msgTypes = make([]protoimpl.MessageInfo, 14)
var file_mpcwalletpb_api_proto_goTypes = []interface{}{
	(*HealthCheckRequest)(nil),                // 0: mpcservice.HealthCheckRequest
	(*HealthCheckResponse)(nil),               // 1: mpcservice.HealthCheckResponse
	(*GenerateKeyPairRequest)(nil),            // 2: mpcservice.GenerateKeyPairRequest
	(*GenerateKeyPairResponse)(nil),           // 3: mpcservice.GenerateKeyPairResponse
	(*GeneratePartialKeyRequest)(nil),         // 4: mpcservice.GeneratePartialKeyRequest
	(*GeneratePartialKeyResponse)(nil),        // 5: mpcservice.GeneratePartialKeyResponse
	(*ExchangePartialKeyRequest)(nil),         // 6: mpcservice.ExchangePartialKeyRequest
	(*ExchangePartialKeyResponse)(nil),        // 7: mpcservice.ExchangePartialKeyResponse
	(*ProvePartialKeyCommitmentRequest)(nil),  // 8: mpcservice.ProvePartialKeyCommitmentRequest
	(*ProvePartialKeyCommitmentResponse)(nil), // 9: mpcservice.ProvePartialKeyCommitmentResponse
	(*ExchangeKeyRequest)(nil),                // 10: mpcservice.ExchangeKeyRequest
	(*ExchangeKeyResponse)(nil),               // 11: mpcservice.ExchangeKeyResponse
	(*ProveKeyCommitmentRequest)(nil),         // 12: mpcservice.ProveKeyCommitmentRequest
	(*ProveKeyCommitmentResponse)(nil),        // 13: mpcservice.ProveKeyCommitmentResponse
}
var file_mpcwalletpb_api_proto_depIdxs = []int32{
	0,  // 0: mpcservice.MPCService.HealthCheck:input_type -> mpcservice.HealthCheckRequest
	2,  // 1: mpcservice.MPCService.GenerateKeyPair:input_type -> mpcservice.GenerateKeyPairRequest
	4,  // 2: mpcservice.MPCService.GeneratePartialKey:input_type -> mpcservice.GeneratePartialKeyRequest
	6,  // 3: mpcservice.MPCService.ExchangePartialKey:input_type -> mpcservice.ExchangePartialKeyRequest
	8,  // 4: mpcservice.MPCService.ProvePartialKeyCommitment:input_type -> mpcservice.ProvePartialKeyCommitmentRequest
	10, // 5: mpcservice.MPCService.ExchangeKey:input_type -> mpcservice.ExchangeKeyRequest
	12, // 6: mpcservice.MPCService.ProveKeyCommitment:input_type -> mpcservice.ProveKeyCommitmentRequest
	1,  // 7: mpcservice.MPCService.HealthCheck:output_type -> mpcservice.HealthCheckResponse
	3,  // 8: mpcservice.MPCService.GenerateKeyPair:output_type -> mpcservice.GenerateKeyPairResponse
	5,  // 9: mpcservice.MPCService.GeneratePartialKey:output_type -> mpcservice.GeneratePartialKeyResponse
	7,  // 10: mpcservice.MPCService.ExchangePartialKey:output_type -> mpcservice.ExchangePartialKeyResponse
	9,  // 11: mpcservice.MPCService.ProvePartialKeyCommitment:output_type -> mpcservice.ProvePartialKeyCommitmentResponse
	11, // 12: mpcservice.MPCService.ExchangeKey:output_type -> mpcservice.ExchangeKeyResponse
	13, // 13: mpcservice.MPCService.ProveKeyCommitment:output_type -> mpcservice.ProveKeyCommitmentResponse
	7,  // [7:14] is the sub-list for method output_type
	0,  // [0:7] is the sub-list for method input_type
	0,  // [0:0] is the sub-list for extension type_name
	0,  // [0:0] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_mpcwalletpb_api_proto_init() }
func file_mpcwalletpb_api_proto_init() {
	if File_mpcwalletpb_api_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_mpcwalletpb_api_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HealthCheckRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HealthCheckResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateKeyPairRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GenerateKeyPairResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GeneratePartialKeyRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GeneratePartialKeyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExchangePartialKeyRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExchangePartialKeyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProvePartialKeyCommitmentRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProvePartialKeyCommitmentResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExchangeKeyRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[11].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ExchangeKeyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[12].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProveKeyCommitmentRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_mpcwalletpb_api_proto_msgTypes[13].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProveKeyCommitmentResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_mpcwalletpb_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   14,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_mpcwalletpb_api_proto_goTypes,
		DependencyIndexes: file_mpcwalletpb_api_proto_depIdxs,
		MessageInfos:      file_mpcwalletpb_api_proto_msgTypes,
	}.Build()
	File_mpcwalletpb_api_proto = out.File
	file_mpcwalletpb_api_proto_rawDesc = nil
	file_mpcwalletpb_api_proto_goTypes = nil
	file_mpcwalletpb_api_proto_depIdxs = nil
}
