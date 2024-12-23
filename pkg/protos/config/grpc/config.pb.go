// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.0
// 	protoc        v5.28.3
// source: config/grpc/config.proto

package service

import (
	config "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	bypass "github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	dns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	listener "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type TestResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Mode          *bypass.ModeConfig     `protobuf:"bytes,1,opt,name=mode,proto3" json:"mode,omitempty"`
	Reason        string                 `protobuf:"bytes,2,opt,name=reason,proto3" json:"reason,omitempty"`
	AfterAddr     string                 `protobuf:"bytes,3,opt,name=after_addr,proto3" json:"after_addr,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TestResponse) Reset() {
	*x = TestResponse{}
	mi := &file_config_grpc_config_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TestResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TestResponse) ProtoMessage() {}

func (x *TestResponse) ProtoReflect() protoreflect.Message {
	mi := &file_config_grpc_config_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TestResponse.ProtoReflect.Descriptor instead.
func (*TestResponse) Descriptor() ([]byte, []int) {
	return file_config_grpc_config_proto_rawDescGZIP(), []int{0}
}

func (x *TestResponse) GetMode() *bypass.ModeConfig {
	if x != nil {
		return x.Mode
	}
	return nil
}

func (x *TestResponse) GetReason() string {
	if x != nil {
		return x.Reason
	}
	return ""
}

func (x *TestResponse) GetAfterAddr() string {
	if x != nil {
		return x.AfterAddr
	}
	return ""
}

type BlockHistory struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Protocol      string                 `protobuf:"bytes,1,opt,name=protocol,proto3" json:"protocol,omitempty"`
	Host          string                 `protobuf:"bytes,2,opt,name=host,proto3" json:"host,omitempty"`
	Time          *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=time,proto3" json:"time,omitempty"`
	Process       string                 `protobuf:"bytes,4,opt,name=process,proto3" json:"process,omitempty"`
	BlockCount    uint64                 `protobuf:"varint,5,opt,name=block_count,proto3" json:"block_count,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *BlockHistory) Reset() {
	*x = BlockHistory{}
	mi := &file_config_grpc_config_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BlockHistory) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BlockHistory) ProtoMessage() {}

func (x *BlockHistory) ProtoReflect() protoreflect.Message {
	mi := &file_config_grpc_config_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BlockHistory.ProtoReflect.Descriptor instead.
func (*BlockHistory) Descriptor() ([]byte, []int) {
	return file_config_grpc_config_proto_rawDescGZIP(), []int{1}
}

func (x *BlockHistory) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *BlockHistory) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *BlockHistory) GetTime() *timestamppb.Timestamp {
	if x != nil {
		return x.Time
	}
	return nil
}

func (x *BlockHistory) GetProcess() string {
	if x != nil {
		return x.Process
	}
	return ""
}

func (x *BlockHistory) GetBlockCount() uint64 {
	if x != nil {
		return x.BlockCount
	}
	return 0
}

type BlockHistoryList struct {
	state              protoimpl.MessageState `protogen:"open.v1"`
	Objects            []*BlockHistory        `protobuf:"bytes,1,rep,name=objects,proto3" json:"objects,omitempty"`
	DumpProcessEnabled bool                   `protobuf:"varint,2,opt,name=dump_process_enabled,proto3" json:"dump_process_enabled,omitempty"`
	unknownFields      protoimpl.UnknownFields
	sizeCache          protoimpl.SizeCache
}

func (x *BlockHistoryList) Reset() {
	*x = BlockHistoryList{}
	mi := &file_config_grpc_config_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *BlockHistoryList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*BlockHistoryList) ProtoMessage() {}

func (x *BlockHistoryList) ProtoReflect() protoreflect.Message {
	mi := &file_config_grpc_config_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use BlockHistoryList.ProtoReflect.Descriptor instead.
func (*BlockHistoryList) Descriptor() ([]byte, []int) {
	return file_config_grpc_config_proto_rawDescGZIP(), []int{2}
}

func (x *BlockHistoryList) GetObjects() []*BlockHistory {
	if x != nil {
		return x.Objects
	}
	return nil
}

func (x *BlockHistoryList) GetDumpProcessEnabled() bool {
	if x != nil {
		return x.DumpProcessEnabled
	}
	return false
}

type InboundsResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Names         []string               `protobuf:"bytes,1,rep,name=names,proto3" json:"names,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *InboundsResponse) Reset() {
	*x = InboundsResponse{}
	mi := &file_config_grpc_config_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *InboundsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*InboundsResponse) ProtoMessage() {}

func (x *InboundsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_config_grpc_config_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use InboundsResponse.ProtoReflect.Descriptor instead.
func (*InboundsResponse) Descriptor() ([]byte, []int) {
	return file_config_grpc_config_proto_rawDescGZIP(), []int{3}
}

func (x *InboundsResponse) GetNames() []string {
	if x != nil {
		return x.Names
	}
	return nil
}

type ResolveList struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Names         []string               `protobuf:"bytes,1,rep,name=names,proto3" json:"names,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *ResolveList) Reset() {
	*x = ResolveList{}
	mi := &file_config_grpc_config_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *ResolveList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ResolveList) ProtoMessage() {}

func (x *ResolveList) ProtoReflect() protoreflect.Message {
	mi := &file_config_grpc_config_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ResolveList.ProtoReflect.Descriptor instead.
func (*ResolveList) Descriptor() ([]byte, []int) {
	return file_config_grpc_config_proto_rawDescGZIP(), []int{4}
}

func (x *ResolveList) GetNames() []string {
	if x != nil {
		return x.Names
	}
	return nil
}

type SaveResolver struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Name          string                 `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Resolver      *dns.Dns               `protobuf:"bytes,2,opt,name=resolver,proto3" json:"resolver,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *SaveResolver) Reset() {
	*x = SaveResolver{}
	mi := &file_config_grpc_config_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *SaveResolver) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SaveResolver) ProtoMessage() {}

func (x *SaveResolver) ProtoReflect() protoreflect.Message {
	mi := &file_config_grpc_config_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SaveResolver.ProtoReflect.Descriptor instead.
func (*SaveResolver) Descriptor() ([]byte, []int) {
	return file_config_grpc_config_proto_rawDescGZIP(), []int{5}
}

func (x *SaveResolver) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *SaveResolver) GetResolver() *dns.Dns {
	if x != nil {
		return x.Resolver
	}
	return nil
}

var File_config_grpc_config_proto protoreflect.FileDescriptor

var file_config_grpc_config_proto_rawDesc = []byte{
	0x0a, 0x18, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1d, 0x79, 0x75, 0x68, 0x61,
	0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x1a, 0x13, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1a,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x2f, 0x62, 0x79,
	0x70, 0x61, 0x73, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x14, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2f, 0x64, 0x6e, 0x73, 0x2f, 0x64, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65,
	0x72, 0x2f, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77,
	0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74,
	0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x78,
	0x0a, 0x0d, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x2f, 0x0a, 0x04, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x2e, 0x6d,
	0x6f, 0x64, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x04, 0x6d, 0x6f, 0x64, 0x65,
	0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x12, 0x1e, 0x0a, 0x0a, 0x61, 0x66, 0x74, 0x65,
	0x72, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x61, 0x66,
	0x74, 0x65, 0x72, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x22, 0xab, 0x01, 0x0a, 0x0d, 0x62, 0x6c, 0x6f,
	0x63, 0x6b, 0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x2e, 0x0a, 0x04, 0x74, 0x69,
	0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73,
	0x74, 0x61, 0x6d, 0x70, 0x52, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x72,
	0x6f, 0x63, 0x65, 0x73, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x72, 0x6f,
	0x63, 0x65, 0x73, 0x73, 0x12, 0x20, 0x0a, 0x0b, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x63, 0x6f,
	0x75, 0x6e, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0b, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
	0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x22, 0x90, 0x01, 0x0a, 0x12, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
	0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x12, 0x46, 0x0a,
	0x07, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x2c,
	0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x62,
	0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x52, 0x07, 0x6f, 0x62,
	0x6a, 0x65, 0x63, 0x74, 0x73, 0x12, 0x32, 0x0a, 0x14, 0x64, 0x75, 0x6d, 0x70, 0x5f, 0x70, 0x72,
	0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x14, 0x64, 0x75, 0x6d, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73,
	0x73, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x22, 0x29, 0x0a, 0x11, 0x69, 0x6e, 0x62,
	0x6f, 0x75, 0x6e, 0x64, 0x73, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x14,
	0x0a, 0x05, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x6e,
	0x61, 0x6d, 0x65, 0x73, 0x22, 0x24, 0x0a, 0x0c, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x5f,
	0x6c, 0x69, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x05, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x22, 0x51, 0x0a, 0x0d, 0x73, 0x61,
	0x76, 0x65, 0x5f, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12,
	0x2c, 0x0a, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x10, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x64, 0x6e, 0x73, 0x2e,
	0x64, 0x6e, 0x73, 0x52, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x32, 0xb8, 0x01,
	0x0a, 0x0e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x12, 0x37, 0x0a, 0x04, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79,
	0x1a, 0x17, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2e, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x12, 0x37, 0x0a, 0x04, 0x73, 0x61, 0x76,
	0x65, 0x12, 0x17, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2e, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x12, 0x34, 0x0a, 0x04, 0x69, 0x6e, 0x66, 0x6f, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x1a, 0x14, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x69, 0x6e, 0x66, 0x6f, 0x32, 0xe2, 0x02, 0x0a, 0x06, 0x62, 0x79, 0x70,
	0x61, 0x73, 0x73, 0x12, 0x36, 0x0a, 0x04, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x16, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x1a, 0x16, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x62, 0x79,
	0x70, 0x61, 0x73, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x36, 0x0a, 0x04, 0x73,
	0x61, 0x76, 0x65, 0x12, 0x16, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x62, 0x79,
	0x70, 0x61, 0x73, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x1a, 0x16, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x12, 0x38, 0x0a, 0x06, 0x72, 0x65, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x16, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x52, 0x0a,
	0x04, 0x74, 0x65, 0x73, 0x74, 0x12, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x1a, 0x2c, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x5a, 0x0a, 0x0d, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f,
	0x72, 0x79, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x31, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x62, 0x6c, 0x6f, 0x63, 0x6b,
	0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x32, 0x99, 0x02,
	0x0a, 0x07, 0x69, 0x6e, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x12, 0x50, 0x0a, 0x04, 0x6c, 0x69, 0x73,
	0x74, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x30, 0x2e, 0x79, 0x75, 0x68, 0x61,
	0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x69, 0x6e, 0x62, 0x6f, 0x75, 0x6e,
	0x64, 0x73, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x3e, 0x0a, 0x03, 0x67,
	0x65, 0x74, 0x12, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65,
	0x1a, 0x19, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x69, 0x73, 0x74, 0x65,
	0x6e, 0x65, 0x72, 0x2e, 0x69, 0x6e, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x12, 0x3c, 0x0a, 0x04, 0x73,
	0x61, 0x76, 0x65, 0x12, 0x19, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x69,
	0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x2e, 0x69, 0x6e, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x1a, 0x19,
	0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65,
	0x72, 0x2e, 0x69, 0x6e, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x12, 0x3e, 0x0a, 0x06, 0x72, 0x65, 0x6d,
	0x6f, 0x76, 0x65, 0x12, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x32, 0x96, 0x02, 0x0a, 0x08, 0x72, 0x65,
	0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x12, 0x4b, 0x0a, 0x04, 0x6c, 0x69, 0x73, 0x74, 0x12, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x2b, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x5f, 0x6c,
	0x69, 0x73, 0x74, 0x12, 0x35, 0x0a, 0x03, 0x67, 0x65, 0x74, 0x12, 0x1c, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72,
	0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x1a, 0x10, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69,
	0x69, 0x6e, 0x2e, 0x64, 0x6e, 0x73, 0x2e, 0x64, 0x6e, 0x73, 0x12, 0x46, 0x0a, 0x04, 0x73, 0x61,
	0x76, 0x65, 0x12, 0x2c, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2e, 0x73, 0x61, 0x76, 0x65, 0x5f, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72,
	0x1a, 0x10, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x64, 0x6e, 0x73, 0x2e, 0x64,
	0x6e, 0x73, 0x12, 0x3e, 0x0a, 0x06, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x12, 0x1c, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53,
	0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x42, 0x38, 0x5a, 0x36, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x41, 0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68, 0x61, 0x69,
	0x69, 0x6e, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x63, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_config_grpc_config_proto_rawDescOnce sync.Once
	file_config_grpc_config_proto_rawDescData = file_config_grpc_config_proto_rawDesc
)

func file_config_grpc_config_proto_rawDescGZIP() []byte {
	file_config_grpc_config_proto_rawDescOnce.Do(func() {
		file_config_grpc_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_config_grpc_config_proto_rawDescData)
	})
	return file_config_grpc_config_proto_rawDescData
}

var file_config_grpc_config_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_config_grpc_config_proto_goTypes = []any{
	(*TestResponse)(nil),           // 0: yuhaiin.protos.config.service.test_response
	(*BlockHistory)(nil),           // 1: yuhaiin.protos.config.service.block_history
	(*BlockHistoryList)(nil),       // 2: yuhaiin.protos.config.service.block_history_list
	(*InboundsResponse)(nil),       // 3: yuhaiin.protos.config.service.inbounds_response
	(*ResolveList)(nil),            // 4: yuhaiin.protos.config.service.resolve_list
	(*SaveResolver)(nil),           // 5: yuhaiin.protos.config.service.save_resolver
	(*bypass.ModeConfig)(nil),      // 6: yuhaiin.bypass.mode_config
	(*timestamppb.Timestamp)(nil),  // 7: google.protobuf.Timestamp
	(*dns.Dns)(nil),                // 8: yuhaiin.dns.dns
	(*emptypb.Empty)(nil),          // 9: google.protobuf.Empty
	(*config.Setting)(nil),         // 10: yuhaiin.config.setting
	(*bypass.Config)(nil),          // 11: yuhaiin.bypass.config
	(*wrapperspb.StringValue)(nil), // 12: google.protobuf.StringValue
	(*listener.Inbound)(nil),       // 13: yuhaiin.listener.inbound
	(*config.Info)(nil),            // 14: yuhaiin.config.info
}
var file_config_grpc_config_proto_depIdxs = []int32{
	6,  // 0: yuhaiin.protos.config.service.test_response.mode:type_name -> yuhaiin.bypass.mode_config
	7,  // 1: yuhaiin.protos.config.service.block_history.time:type_name -> google.protobuf.Timestamp
	1,  // 2: yuhaiin.protos.config.service.block_history_list.objects:type_name -> yuhaiin.protos.config.service.block_history
	8,  // 3: yuhaiin.protos.config.service.save_resolver.resolver:type_name -> yuhaiin.dns.dns
	9,  // 4: yuhaiin.protos.config.service.config_service.load:input_type -> google.protobuf.Empty
	10, // 5: yuhaiin.protos.config.service.config_service.save:input_type -> yuhaiin.config.setting
	9,  // 6: yuhaiin.protos.config.service.config_service.info:input_type -> google.protobuf.Empty
	9,  // 7: yuhaiin.protos.config.service.bypass.load:input_type -> google.protobuf.Empty
	11, // 8: yuhaiin.protos.config.service.bypass.save:input_type -> yuhaiin.bypass.config
	9,  // 9: yuhaiin.protos.config.service.bypass.reload:input_type -> google.protobuf.Empty
	12, // 10: yuhaiin.protos.config.service.bypass.test:input_type -> google.protobuf.StringValue
	9,  // 11: yuhaiin.protos.config.service.bypass.block_history:input_type -> google.protobuf.Empty
	9,  // 12: yuhaiin.protos.config.service.inbound.list:input_type -> google.protobuf.Empty
	12, // 13: yuhaiin.protos.config.service.inbound.get:input_type -> google.protobuf.StringValue
	13, // 14: yuhaiin.protos.config.service.inbound.save:input_type -> yuhaiin.listener.inbound
	12, // 15: yuhaiin.protos.config.service.inbound.remove:input_type -> google.protobuf.StringValue
	9,  // 16: yuhaiin.protos.config.service.resolver.list:input_type -> google.protobuf.Empty
	12, // 17: yuhaiin.protos.config.service.resolver.get:input_type -> google.protobuf.StringValue
	5,  // 18: yuhaiin.protos.config.service.resolver.save:input_type -> yuhaiin.protos.config.service.save_resolver
	12, // 19: yuhaiin.protos.config.service.resolver.remove:input_type -> google.protobuf.StringValue
	10, // 20: yuhaiin.protos.config.service.config_service.load:output_type -> yuhaiin.config.setting
	9,  // 21: yuhaiin.protos.config.service.config_service.save:output_type -> google.protobuf.Empty
	14, // 22: yuhaiin.protos.config.service.config_service.info:output_type -> yuhaiin.config.info
	11, // 23: yuhaiin.protos.config.service.bypass.load:output_type -> yuhaiin.bypass.config
	9,  // 24: yuhaiin.protos.config.service.bypass.save:output_type -> google.protobuf.Empty
	9,  // 25: yuhaiin.protos.config.service.bypass.reload:output_type -> google.protobuf.Empty
	0,  // 26: yuhaiin.protos.config.service.bypass.test:output_type -> yuhaiin.protos.config.service.test_response
	2,  // 27: yuhaiin.protos.config.service.bypass.block_history:output_type -> yuhaiin.protos.config.service.block_history_list
	3,  // 28: yuhaiin.protos.config.service.inbound.list:output_type -> yuhaiin.protos.config.service.inbounds_response
	13, // 29: yuhaiin.protos.config.service.inbound.get:output_type -> yuhaiin.listener.inbound
	13, // 30: yuhaiin.protos.config.service.inbound.save:output_type -> yuhaiin.listener.inbound
	9,  // 31: yuhaiin.protos.config.service.inbound.remove:output_type -> google.protobuf.Empty
	4,  // 32: yuhaiin.protos.config.service.resolver.list:output_type -> yuhaiin.protos.config.service.resolve_list
	8,  // 33: yuhaiin.protos.config.service.resolver.get:output_type -> yuhaiin.dns.dns
	8,  // 34: yuhaiin.protos.config.service.resolver.save:output_type -> yuhaiin.dns.dns
	9,  // 35: yuhaiin.protos.config.service.resolver.remove:output_type -> google.protobuf.Empty
	20, // [20:36] is the sub-list for method output_type
	4,  // [4:20] is the sub-list for method input_type
	4,  // [4:4] is the sub-list for extension type_name
	4,  // [4:4] is the sub-list for extension extendee
	0,  // [0:4] is the sub-list for field type_name
}

func init() { file_config_grpc_config_proto_init() }
func file_config_grpc_config_proto_init() {
	if File_config_grpc_config_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_config_grpc_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   4,
		},
		GoTypes:           file_config_grpc_config_proto_goTypes,
		DependencyIndexes: file_config_grpc_config_proto_depIdxs,
		MessageInfos:      file_config_grpc_config_proto_msgTypes,
	}.Build()
	File_config_grpc_config_proto = out.File
	file_config_grpc_config_proto_rawDesc = nil
	file_config_grpc_config_proto_goTypes = nil
	file_config_grpc_config_proto_depIdxs = nil
}
