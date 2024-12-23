// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.0
// 	protoc        v5.28.3
// source: statistic/grpc/config.proto

package service

import (
	statistic "github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type TotalFlow struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Download      uint64                 `protobuf:"varint,1,opt,name=download,proto3" json:"download,omitempty"`
	Upload        uint64                 `protobuf:"varint,2,opt,name=upload,proto3" json:"upload,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *TotalFlow) Reset() {
	*x = TotalFlow{}
	mi := &file_statistic_grpc_config_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *TotalFlow) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TotalFlow) ProtoMessage() {}

func (x *TotalFlow) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TotalFlow.ProtoReflect.Descriptor instead.
func (*TotalFlow) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{0}
}

func (x *TotalFlow) GetDownload() uint64 {
	if x != nil {
		return x.Download
	}
	return 0
}

func (x *TotalFlow) GetUpload() uint64 {
	if x != nil {
		return x.Upload
	}
	return 0
}

type NotifyData struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Types that are valid to be assigned to Data:
	//
	//	*NotifyData_TotalFlow
	//	*NotifyData_NotifyNewConnections
	//	*NotifyData_NotifyRemoveConnections
	Data          isNotifyData_Data `protobuf_oneof:"data"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *NotifyData) Reset() {
	*x = NotifyData{}
	mi := &file_statistic_grpc_config_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *NotifyData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NotifyData) ProtoMessage() {}

func (x *NotifyData) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NotifyData.ProtoReflect.Descriptor instead.
func (*NotifyData) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{1}
}

func (x *NotifyData) GetData() isNotifyData_Data {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *NotifyData) GetTotalFlow() *TotalFlow {
	if x != nil {
		if x, ok := x.Data.(*NotifyData_TotalFlow); ok {
			return x.TotalFlow
		}
	}
	return nil
}

func (x *NotifyData) GetNotifyNewConnections() *NotifyNewConnections {
	if x != nil {
		if x, ok := x.Data.(*NotifyData_NotifyNewConnections); ok {
			return x.NotifyNewConnections
		}
	}
	return nil
}

func (x *NotifyData) GetNotifyRemoveConnections() *NotifyRemoveConnections {
	if x != nil {
		if x, ok := x.Data.(*NotifyData_NotifyRemoveConnections); ok {
			return x.NotifyRemoveConnections
		}
	}
	return nil
}

type isNotifyData_Data interface {
	isNotifyData_Data()
}

type NotifyData_TotalFlow struct {
	TotalFlow *TotalFlow `protobuf:"bytes,3,opt,name=total_flow,json=totalFlow,proto3,oneof"`
}

type NotifyData_NotifyNewConnections struct {
	NotifyNewConnections *NotifyNewConnections `protobuf:"bytes,1,opt,name=notify_new_connections,json=notifyNewConnections,proto3,oneof"`
}

type NotifyData_NotifyRemoveConnections struct {
	NotifyRemoveConnections *NotifyRemoveConnections `protobuf:"bytes,2,opt,name=notify_remove_connections,json=notifyRemoveConnections,proto3,oneof"`
}

func (*NotifyData_TotalFlow) isNotifyData_Data() {}

func (*NotifyData_NotifyNewConnections) isNotifyData_Data() {}

func (*NotifyData_NotifyRemoveConnections) isNotifyData_Data() {}

type NotifyNewConnections struct {
	state         protoimpl.MessageState  `protogen:"open.v1"`
	Connections   []*statistic.Connection `protobuf:"bytes,1,rep,name=connections,proto3" json:"connections,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *NotifyNewConnections) Reset() {
	*x = NotifyNewConnections{}
	mi := &file_statistic_grpc_config_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *NotifyNewConnections) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NotifyNewConnections) ProtoMessage() {}

func (x *NotifyNewConnections) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NotifyNewConnections.ProtoReflect.Descriptor instead.
func (*NotifyNewConnections) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{2}
}

func (x *NotifyNewConnections) GetConnections() []*statistic.Connection {
	if x != nil {
		return x.Connections
	}
	return nil
}

type NotifyRemoveConnections struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Ids           []uint64               `protobuf:"varint,1,rep,packed,name=ids,proto3" json:"ids,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *NotifyRemoveConnections) Reset() {
	*x = NotifyRemoveConnections{}
	mi := &file_statistic_grpc_config_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *NotifyRemoveConnections) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NotifyRemoveConnections) ProtoMessage() {}

func (x *NotifyRemoveConnections) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NotifyRemoveConnections.ProtoReflect.Descriptor instead.
func (*NotifyRemoveConnections) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{3}
}

func (x *NotifyRemoveConnections) GetIds() []uint64 {
	if x != nil {
		return x.Ids
	}
	return nil
}

type FailedHistory struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Protocol      string                 `protobuf:"bytes,1,opt,name=protocol,proto3" json:"protocol,omitempty"`
	Host          string                 `protobuf:"bytes,2,opt,name=host,proto3" json:"host,omitempty"`
	Error         string                 `protobuf:"bytes,3,opt,name=error,proto3" json:"error,omitempty"`
	Process       string                 `protobuf:"bytes,4,opt,name=process,proto3" json:"process,omitempty"`
	Time          *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=time,proto3" json:"time,omitempty"`
	FailedCount   uint64                 `protobuf:"varint,6,opt,name=failed_count,proto3" json:"failed_count,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FailedHistory) Reset() {
	*x = FailedHistory{}
	mi := &file_statistic_grpc_config_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FailedHistory) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FailedHistory) ProtoMessage() {}

func (x *FailedHistory) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FailedHistory.ProtoReflect.Descriptor instead.
func (*FailedHistory) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{4}
}

func (x *FailedHistory) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *FailedHistory) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *FailedHistory) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

func (x *FailedHistory) GetProcess() string {
	if x != nil {
		return x.Process
	}
	return ""
}

func (x *FailedHistory) GetTime() *timestamppb.Timestamp {
	if x != nil {
		return x.Time
	}
	return nil
}

func (x *FailedHistory) GetFailedCount() uint64 {
	if x != nil {
		return x.FailedCount
	}
	return 0
}

type FailedHistoryList struct {
	state              protoimpl.MessageState `protogen:"open.v1"`
	Objects            []*FailedHistory       `protobuf:"bytes,1,rep,name=objects,proto3" json:"objects,omitempty"`
	DumpProcessEnabled bool                   `protobuf:"varint,2,opt,name=dump_process_enabled,proto3" json:"dump_process_enabled,omitempty"`
	unknownFields      protoimpl.UnknownFields
	sizeCache          protoimpl.SizeCache
}

func (x *FailedHistoryList) Reset() {
	*x = FailedHistoryList{}
	mi := &file_statistic_grpc_config_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FailedHistoryList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FailedHistoryList) ProtoMessage() {}

func (x *FailedHistoryList) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FailedHistoryList.ProtoReflect.Descriptor instead.
func (*FailedHistoryList) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{5}
}

func (x *FailedHistoryList) GetObjects() []*FailedHistory {
	if x != nil {
		return x.Objects
	}
	return nil
}

func (x *FailedHistoryList) GetDumpProcessEnabled() bool {
	if x != nil {
		return x.DumpProcessEnabled
	}
	return false
}

type AllHistory struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Connection    *statistic.Connection  `protobuf:"bytes,1,opt,name=connection,proto3" json:"connection,omitempty"`
	Count         uint64                 `protobuf:"varint,2,opt,name=count,proto3" json:"count,omitempty"`
	Time          *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=time,proto3" json:"time,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *AllHistory) Reset() {
	*x = AllHistory{}
	mi := &file_statistic_grpc_config_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AllHistory) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AllHistory) ProtoMessage() {}

func (x *AllHistory) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AllHistory.ProtoReflect.Descriptor instead.
func (*AllHistory) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{6}
}

func (x *AllHistory) GetConnection() *statistic.Connection {
	if x != nil {
		return x.Connection
	}
	return nil
}

func (x *AllHistory) GetCount() uint64 {
	if x != nil {
		return x.Count
	}
	return 0
}

func (x *AllHistory) GetTime() *timestamppb.Timestamp {
	if x != nil {
		return x.Time
	}
	return nil
}

type AllHistoryList struct {
	state              protoimpl.MessageState `protogen:"open.v1"`
	Objects            []*AllHistory          `protobuf:"bytes,1,rep,name=objects,proto3" json:"objects,omitempty"`
	DumpProcessEnabled bool                   `protobuf:"varint,2,opt,name=dump_process_enabled,proto3" json:"dump_process_enabled,omitempty"`
	unknownFields      protoimpl.UnknownFields
	sizeCache          protoimpl.SizeCache
}

func (x *AllHistoryList) Reset() {
	*x = AllHistoryList{}
	mi := &file_statistic_grpc_config_proto_msgTypes[7]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AllHistoryList) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AllHistoryList) ProtoMessage() {}

func (x *AllHistoryList) ProtoReflect() protoreflect.Message {
	mi := &file_statistic_grpc_config_proto_msgTypes[7]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AllHistoryList.ProtoReflect.Descriptor instead.
func (*AllHistoryList) Descriptor() ([]byte, []int) {
	return file_statistic_grpc_config_proto_rawDescGZIP(), []int{7}
}

func (x *AllHistoryList) GetObjects() []*AllHistory {
	if x != nil {
		return x.Objects
	}
	return nil
}

func (x *AllHistoryList) GetDumpProcessEnabled() bool {
	if x != nil {
		return x.DumpProcessEnabled
	}
	return false
}

var File_statistic_grpc_config_proto protoreflect.FileDescriptor

var file_statistic_grpc_config_proto_rawDesc = []byte{
	0x0a, 0x1b, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2f, 0x67, 0x72, 0x70, 0x63,
	0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x20, 0x79,
	0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x1a,
	0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x16, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x40, 0x0a, 0x0a, 0x74, 0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x66,
	0x6c, 0x6f, 0x77, 0x12, 0x1a, 0x0a, 0x08, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x12,
	0x16, 0x0a, 0x06, 0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52,
	0x06, 0x75, 0x70, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0xd1, 0x02, 0x0a, 0x0b, 0x6e, 0x6f, 0x74, 0x69,
	0x66, 0x79, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x12, 0x4d, 0x0a, 0x0a, 0x74, 0x6f, 0x74, 0x61, 0x6c,
	0x5f, 0x66, 0x6c, 0x6f, 0x77, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2c, 0x2e, 0x79, 0x75,
	0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61,
	0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x74,
	0x6f, 0x74, 0x61, 0x6c, 0x5f, 0x66, 0x6c, 0x6f, 0x77, 0x48, 0x00, 0x52, 0x09, 0x74, 0x6f, 0x74,
	0x61, 0x6c, 0x46, 0x6c, 0x6f, 0x77, 0x12, 0x70, 0x0a, 0x16, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79,
	0x5f, 0x6e, 0x65, 0x77, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x38, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69,
	0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79,
	0x5f, 0x6e, 0x65, 0x77, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x48, 0x00, 0x52, 0x14, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x4e, 0x65, 0x77, 0x43, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x79, 0x0a, 0x19, 0x6e, 0x6f, 0x74, 0x69,
	0x66, 0x79, 0x5f, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x3b, 0x2e, 0x79, 0x75,
	0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61,
	0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x6e,
	0x6f, 0x74, 0x69, 0x66, 0x79, 0x5f, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x5f, 0x63, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x48, 0x00, 0x52, 0x17, 0x6e, 0x6f, 0x74, 0x69,
	0x66, 0x79, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x42, 0x06, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x22, 0x59, 0x0a, 0x16, 0x6e,
	0x6f, 0x74, 0x69, 0x66, 0x79, 0x5f, 0x6e, 0x65, 0x77, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x3f, 0x0a, 0x0b, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x63,
	0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0b, 0x63, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0x2d, 0x0a, 0x19, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79,
	0x5f, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x73, 0x12, 0x10, 0x0a, 0x03, 0x69, 0x64, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x04,
	0x52, 0x03, 0x69, 0x64, 0x73, 0x22, 0xc4, 0x01, 0x0a, 0x0e, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64,
	0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x72, 0x72, 0x6f,
	0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x18,
	0x0a, 0x07, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x07, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x12, 0x2e, 0x0a, 0x04, 0x74, 0x69, 0x6d, 0x65,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x52, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x12, 0x22, 0x0a, 0x0c, 0x66, 0x61, 0x69, 0x6c,
	0x65, 0x64, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0c,
	0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x5f, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x22, 0x95, 0x01, 0x0a,
	0x13, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x5f,
	0x6c, 0x69, 0x73, 0x74, 0x12, 0x4a, 0x0a, 0x07, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x30, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x5f,
	0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x52, 0x07, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73,
	0x12, 0x32, 0x0a, 0x14, 0x64, 0x75, 0x6d, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73,
	0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x14,
	0x64, 0x75, 0x6d, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x65, 0x6e, 0x61,
	0x62, 0x6c, 0x65, 0x64, 0x22, 0x92, 0x01, 0x0a, 0x0b, 0x61, 0x6c, 0x6c, 0x5f, 0x68, 0x69, 0x73,
	0x74, 0x6f, 0x72, 0x79, 0x12, 0x3d, 0x0a, 0x0a, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69,
	0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1d, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69,
	0x69, 0x6e, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x63, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x0a, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x12, 0x14, 0x0a, 0x05, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x05, 0x63, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x2e, 0x0a, 0x04, 0x74, 0x69, 0x6d,
	0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x04, 0x74, 0x69, 0x6d, 0x65, 0x22, 0x8f, 0x01, 0x0a, 0x10, 0x61, 0x6c,
	0x6c, 0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x12, 0x47,
	0x0a, 0x07, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x2d, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73,
	0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69,
	0x63, 0x65, 0x2e, 0x61, 0x6c, 0x6c, 0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x52, 0x07,
	0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x73, 0x12, 0x32, 0x0a, 0x14, 0x64, 0x75, 0x6d, 0x70, 0x5f,
	0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x14, 0x64, 0x75, 0x6d, 0x70, 0x5f, 0x70, 0x72, 0x6f, 0x63,
	0x65, 0x73, 0x73, 0x5f, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x32, 0xa9, 0x04, 0x0a, 0x0b,
	0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x59, 0x0a, 0x05, 0x63,
	0x6f, 0x6e, 0x6e, 0x73, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x38, 0x2e, 0x79,
	0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e,
	0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x5f, 0x6e, 0x65, 0x77, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x61, 0x0a, 0x0a, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x5f,
	0x63, 0x6f, 0x6e, 0x6e, 0x12, 0x3b, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e,
	0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x6e, 0x6f, 0x74, 0x69, 0x66, 0x79, 0x5f, 0x72,
	0x65, 0x6d, 0x6f, 0x76, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x4d, 0x0a, 0x05, 0x74, 0x6f, 0x74,
	0x61, 0x6c, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x2c, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74,
	0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x74, 0x6f,
	0x74, 0x61, 0x6c, 0x5f, 0x66, 0x6c, 0x6f, 0x77, 0x12, 0x51, 0x0a, 0x06, 0x6e, 0x6f, 0x74, 0x69,
	0x66, 0x79, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x2d, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74,
	0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x6e, 0x6f,
	0x74, 0x69, 0x66, 0x79, 0x5f, 0x64, 0x61, 0x74, 0x61, 0x30, 0x01, 0x12, 0x5f, 0x0a, 0x0e, 0x66,
	0x61, 0x69, 0x6c, 0x65, 0x64, 0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x12, 0x16, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x35, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63,
	0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x66, 0x61, 0x69, 0x6c, 0x65, 0x64, 0x5f,
	0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x12, 0x59, 0x0a, 0x0b,
	0x61, 0x6c, 0x6c, 0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f, 0x72, 0x79, 0x12, 0x16, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x1a, 0x32, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2e, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x61, 0x6c, 0x6c, 0x5f, 0x68, 0x69, 0x73, 0x74, 0x6f,
	0x72, 0x79, 0x5f, 0x6c, 0x69, 0x73, 0x74, 0x42, 0x3b, 0x5a, 0x39, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41, 0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x69, 0x73, 0x74, 0x69, 0x63, 0x2f, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_statistic_grpc_config_proto_rawDescOnce sync.Once
	file_statistic_grpc_config_proto_rawDescData = file_statistic_grpc_config_proto_rawDesc
)

func file_statistic_grpc_config_proto_rawDescGZIP() []byte {
	file_statistic_grpc_config_proto_rawDescOnce.Do(func() {
		file_statistic_grpc_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_statistic_grpc_config_proto_rawDescData)
	})
	return file_statistic_grpc_config_proto_rawDescData
}

var file_statistic_grpc_config_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_statistic_grpc_config_proto_goTypes = []any{
	(*TotalFlow)(nil),               // 0: yuhaiin.protos.statistic.service.total_flow
	(*NotifyData)(nil),              // 1: yuhaiin.protos.statistic.service.notify_data
	(*NotifyNewConnections)(nil),    // 2: yuhaiin.protos.statistic.service.notify_new_connections
	(*NotifyRemoveConnections)(nil), // 3: yuhaiin.protos.statistic.service.notify_remove_connections
	(*FailedHistory)(nil),           // 4: yuhaiin.protos.statistic.service.failed_history
	(*FailedHistoryList)(nil),       // 5: yuhaiin.protos.statistic.service.failed_history_list
	(*AllHistory)(nil),              // 6: yuhaiin.protos.statistic.service.all_history
	(*AllHistoryList)(nil),          // 7: yuhaiin.protos.statistic.service.all_history_list
	(*statistic.Connection)(nil),    // 8: yuhaiin.statistic.connection
	(*timestamppb.Timestamp)(nil),   // 9: google.protobuf.Timestamp
	(*emptypb.Empty)(nil),           // 10: google.protobuf.Empty
}
var file_statistic_grpc_config_proto_depIdxs = []int32{
	0,  // 0: yuhaiin.protos.statistic.service.notify_data.total_flow:type_name -> yuhaiin.protos.statistic.service.total_flow
	2,  // 1: yuhaiin.protos.statistic.service.notify_data.notify_new_connections:type_name -> yuhaiin.protos.statistic.service.notify_new_connections
	3,  // 2: yuhaiin.protos.statistic.service.notify_data.notify_remove_connections:type_name -> yuhaiin.protos.statistic.service.notify_remove_connections
	8,  // 3: yuhaiin.protos.statistic.service.notify_new_connections.connections:type_name -> yuhaiin.statistic.connection
	9,  // 4: yuhaiin.protos.statistic.service.failed_history.time:type_name -> google.protobuf.Timestamp
	4,  // 5: yuhaiin.protos.statistic.service.failed_history_list.objects:type_name -> yuhaiin.protos.statistic.service.failed_history
	8,  // 6: yuhaiin.protos.statistic.service.all_history.connection:type_name -> yuhaiin.statistic.connection
	9,  // 7: yuhaiin.protos.statistic.service.all_history.time:type_name -> google.protobuf.Timestamp
	6,  // 8: yuhaiin.protos.statistic.service.all_history_list.objects:type_name -> yuhaiin.protos.statistic.service.all_history
	10, // 9: yuhaiin.protos.statistic.service.connections.conns:input_type -> google.protobuf.Empty
	3,  // 10: yuhaiin.protos.statistic.service.connections.close_conn:input_type -> yuhaiin.protos.statistic.service.notify_remove_connections
	10, // 11: yuhaiin.protos.statistic.service.connections.total:input_type -> google.protobuf.Empty
	10, // 12: yuhaiin.protos.statistic.service.connections.notify:input_type -> google.protobuf.Empty
	10, // 13: yuhaiin.protos.statistic.service.connections.failed_history:input_type -> google.protobuf.Empty
	10, // 14: yuhaiin.protos.statistic.service.connections.all_history:input_type -> google.protobuf.Empty
	2,  // 15: yuhaiin.protos.statistic.service.connections.conns:output_type -> yuhaiin.protos.statistic.service.notify_new_connections
	10, // 16: yuhaiin.protos.statistic.service.connections.close_conn:output_type -> google.protobuf.Empty
	0,  // 17: yuhaiin.protos.statistic.service.connections.total:output_type -> yuhaiin.protos.statistic.service.total_flow
	1,  // 18: yuhaiin.protos.statistic.service.connections.notify:output_type -> yuhaiin.protos.statistic.service.notify_data
	5,  // 19: yuhaiin.protos.statistic.service.connections.failed_history:output_type -> yuhaiin.protos.statistic.service.failed_history_list
	7,  // 20: yuhaiin.protos.statistic.service.connections.all_history:output_type -> yuhaiin.protos.statistic.service.all_history_list
	15, // [15:21] is the sub-list for method output_type
	9,  // [9:15] is the sub-list for method input_type
	9,  // [9:9] is the sub-list for extension type_name
	9,  // [9:9] is the sub-list for extension extendee
	0,  // [0:9] is the sub-list for field type_name
}

func init() { file_statistic_grpc_config_proto_init() }
func file_statistic_grpc_config_proto_init() {
	if File_statistic_grpc_config_proto != nil {
		return
	}
	file_statistic_grpc_config_proto_msgTypes[1].OneofWrappers = []any{
		(*NotifyData_TotalFlow)(nil),
		(*NotifyData_NotifyNewConnections)(nil),
		(*NotifyData_NotifyRemoveConnections)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_statistic_grpc_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_statistic_grpc_config_proto_goTypes,
		DependencyIndexes: file_statistic_grpc_config_proto_depIdxs,
		MessageInfos:      file_statistic_grpc_config_proto_msgTypes,
	}.Build()
	File_statistic_grpc_config_proto = out.File
	file_statistic_grpc_config_proto_rawDesc = nil
	file_statistic_grpc_config_proto_goTypes = nil
	file_statistic_grpc_config_proto_depIdxs = nil
}
