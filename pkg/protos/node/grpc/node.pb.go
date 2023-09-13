// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v4.24.2
// source: node/grpc/node.proto

package service

import (
	node "github.com/Asutorufa/yuhaiin/pkg/protos/node"
	latency "github.com/Asutorufa/yuhaiin/pkg/protos/node/latency"
	point "github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	subscribe "github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	tag "github.com/Asutorufa/yuhaiin/pkg/protos/node/tag"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
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

type NowResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tcp *point.Point `protobuf:"bytes,1,opt,name=tcp,proto3" json:"tcp,omitempty"`
	Udp *point.Point `protobuf:"bytes,2,opt,name=udp,proto3" json:"udp,omitempty"`
}

func (x *NowResp) Reset() {
	*x = NowResp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_grpc_node_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NowResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NowResp) ProtoMessage() {}

func (x *NowResp) ProtoReflect() protoreflect.Message {
	mi := &file_node_grpc_node_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NowResp.ProtoReflect.Descriptor instead.
func (*NowResp) Descriptor() ([]byte, []int) {
	return file_node_grpc_node_proto_rawDescGZIP(), []int{0}
}

func (x *NowResp) GetTcp() *point.Point {
	if x != nil {
		return x.Tcp
	}
	return nil
}

func (x *NowResp) GetUdp() *point.Point {
	if x != nil {
		return x.Udp
	}
	return nil
}

type UseReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tcp  bool   `protobuf:"varint,1,opt,name=tcp,proto3" json:"tcp,omitempty"`
	Udp  bool   `protobuf:"varint,2,opt,name=udp,proto3" json:"udp,omitempty"`
	Hash string `protobuf:"bytes,3,opt,name=hash,proto3" json:"hash,omitempty"`
}

func (x *UseReq) Reset() {
	*x = UseReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_grpc_node_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UseReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UseReq) ProtoMessage() {}

func (x *UseReq) ProtoReflect() protoreflect.Message {
	mi := &file_node_grpc_node_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UseReq.ProtoReflect.Descriptor instead.
func (*UseReq) Descriptor() ([]byte, []int) {
	return file_node_grpc_node_proto_rawDescGZIP(), []int{1}
}

func (x *UseReq) GetTcp() bool {
	if x != nil {
		return x.Tcp
	}
	return false
}

func (x *UseReq) GetUdp() bool {
	if x != nil {
		return x.Udp
	}
	return false
}

func (x *UseReq) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

type SaveLinkReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Links []*subscribe.Link `protobuf:"bytes,1,rep,name=links,proto3" json:"links,omitempty"`
}

func (x *SaveLinkReq) Reset() {
	*x = SaveLinkReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_grpc_node_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SaveLinkReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SaveLinkReq) ProtoMessage() {}

func (x *SaveLinkReq) ProtoReflect() protoreflect.Message {
	mi := &file_node_grpc_node_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SaveLinkReq.ProtoReflect.Descriptor instead.
func (*SaveLinkReq) Descriptor() ([]byte, []int) {
	return file_node_grpc_node_proto_rawDescGZIP(), []int{2}
}

func (x *SaveLinkReq) GetLinks() []*subscribe.Link {
	if x != nil {
		return x.Links
	}
	return nil
}

type LinkReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Names []string `protobuf:"bytes,1,rep,name=names,proto3" json:"names,omitempty"`
}

func (x *LinkReq) Reset() {
	*x = LinkReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_grpc_node_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *LinkReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*LinkReq) ProtoMessage() {}

func (x *LinkReq) ProtoReflect() protoreflect.Message {
	mi := &file_node_grpc_node_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use LinkReq.ProtoReflect.Descriptor instead.
func (*LinkReq) Descriptor() ([]byte, []int) {
	return file_node_grpc_node_proto_rawDescGZIP(), []int{3}
}

func (x *LinkReq) GetNames() []string {
	if x != nil {
		return x.Names
	}
	return nil
}

type GetLinksResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Links map[string]*subscribe.Link `protobuf:"bytes,1,rep,name=links,proto3" json:"links,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *GetLinksResp) Reset() {
	*x = GetLinksResp{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_grpc_node_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetLinksResp) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetLinksResp) ProtoMessage() {}

func (x *GetLinksResp) ProtoReflect() protoreflect.Message {
	mi := &file_node_grpc_node_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetLinksResp.ProtoReflect.Descriptor instead.
func (*GetLinksResp) Descriptor() ([]byte, []int) {
	return file_node_grpc_node_proto_rawDescGZIP(), []int{4}
}

func (x *GetLinksResp) GetLinks() map[string]*subscribe.Link {
	if x != nil {
		return x.Links
	}
	return nil
}

type SaveTagReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tag  string      `protobuf:"bytes,1,opt,name=tag,proto3" json:"tag,omitempty"`
	Type tag.TagType `protobuf:"varint,3,opt,name=type,proto3,enum=yuhaiin.tag.TagType" json:"type,omitempty"`
	Hash string      `protobuf:"bytes,2,opt,name=hash,proto3" json:"hash,omitempty"`
}

func (x *SaveTagReq) Reset() {
	*x = SaveTagReq{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_grpc_node_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SaveTagReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SaveTagReq) ProtoMessage() {}

func (x *SaveTagReq) ProtoReflect() protoreflect.Message {
	mi := &file_node_grpc_node_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SaveTagReq.ProtoReflect.Descriptor instead.
func (*SaveTagReq) Descriptor() ([]byte, []int) {
	return file_node_grpc_node_proto_rawDescGZIP(), []int{5}
}

func (x *SaveTagReq) GetTag() string {
	if x != nil {
		return x.Tag
	}
	return ""
}

func (x *SaveTagReq) GetType() tag.TagType {
	if x != nil {
		return x.Type
	}
	return tag.TagType(0)
}

func (x *SaveTagReq) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

var File_node_grpc_node_proto protoreflect.FileDescriptor

var file_node_grpc_node_proto_rawDesc = []byte{
	0x0a, 0x14, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x6e, 0x6f, 0x64, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x1b, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x1a, 0x0f, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x16, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2f, 0x70, 0x6f,
	0x69, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x6e, 0x6f, 0x64, 0x65, 0x2f,
	0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x2f, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72,
	0x69, 0x62, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1a, 0x6e, 0x6f, 0x64, 0x65, 0x2f,
	0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x2f, 0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x12, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x74, 0x61, 0x67, 0x2f,
	0x74, 0x61, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x5a, 0x0a, 0x08, 0x6e, 0x6f, 0x77,
	0x5f, 0x72, 0x65, 0x73, 0x70, 0x12, 0x26, 0x0a, 0x03, 0x74, 0x63, 0x70, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x14, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x6f, 0x69,
	0x6e, 0x74, 0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x03, 0x74, 0x63, 0x70, 0x12, 0x26, 0x0a,
	0x03, 0x75, 0x64, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x52, 0x03, 0x75, 0x64, 0x70, 0x22, 0x41, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x5f, 0x72, 0x65, 0x71,
	0x12, 0x10, 0x0a, 0x03, 0x74, 0x63, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x03, 0x74,
	0x63, 0x70, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x64, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52,
	0x03, 0x75, 0x64, 0x70, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x22, 0x3e, 0x0a, 0x0d, 0x73, 0x61, 0x76, 0x65,
	0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x5f, 0x72, 0x65, 0x71, 0x12, 0x2d, 0x0a, 0x05, 0x6c, 0x69, 0x6e,
	0x6b, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69,
	0x69, 0x6e, 0x2e, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x2e, 0x6c, 0x69, 0x6e,
	0x6b, 0x52, 0x05, 0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x22, 0x20, 0x0a, 0x08, 0x6c, 0x69, 0x6e, 0x6b,
	0x5f, 0x72, 0x65, 0x71, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x01, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x05, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x22, 0xb1, 0x01, 0x0a, 0x0e, 0x67,
	0x65, 0x74, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x12, 0x4c, 0x0a,
	0x05, 0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x36, 0x2e, 0x79,
	0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x6e, 0x6f,
	0x64, 0x65, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x67, 0x65, 0x74, 0x5f, 0x6c,
	0x69, 0x6e, 0x6b, 0x73, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x2e, 0x4c, 0x69, 0x6e, 0x6b, 0x73, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x05, 0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x1a, 0x51, 0x0a, 0x0a, 0x4c,
	0x69, 0x6e, 0x6b, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2d, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x2e, 0x6c,
	0x69, 0x6e, 0x6b, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x5f,
	0x0a, 0x0c, 0x73, 0x61, 0x76, 0x65, 0x5f, 0x74, 0x61, 0x67, 0x5f, 0x72, 0x65, 0x71, 0x12, 0x10,
	0x0a, 0x03, 0x74, 0x61, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x74, 0x61, 0x67,
	0x12, 0x29, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x15,
	0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x74, 0x61, 0x67, 0x2e, 0x74, 0x61, 0x67,
	0x5f, 0x74, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x68,
	0x61, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x61, 0x73, 0x68, 0x32,
	0xb9, 0x03, 0x0a, 0x04, 0x6e, 0x6f, 0x64, 0x65, 0x12, 0x44, 0x0a, 0x03, 0x6e, 0x6f, 0x77, 0x12,
	0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x25, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x6e, 0x6f, 0x77, 0x5f, 0x72, 0x65, 0x73, 0x70, 0x12, 0x41,
	0x0a, 0x03, 0x75, 0x73, 0x65, 0x12, 0x24, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x73, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2e, 0x75, 0x73, 0x65, 0x5f, 0x72, 0x65, 0x71, 0x1a, 0x14, 0x2e, 0x79, 0x75,
	0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x6f, 0x69, 0x6e,
	0x74, 0x12, 0x39, 0x0a, 0x03, 0x67, 0x65, 0x74, 0x12, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e,
	0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x1a, 0x14, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x12, 0x32, 0x0a, 0x04,
	0x73, 0x61, 0x76, 0x65, 0x12, 0x14, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70,
	0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x1a, 0x14, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74,
	0x12, 0x3e, 0x0a, 0x06, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x12, 0x1c, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x53, 0x74, 0x72,
	0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79,
	0x12, 0x38, 0x0a, 0x07, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x12, 0x16, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d,
	0x70, 0x74, 0x79, 0x1a, 0x15, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6e, 0x6f,
	0x64, 0x65, 0x2e, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x12, 0x3f, 0x0a, 0x07, 0x6c, 0x61,
	0x74, 0x65, 0x6e, 0x63, 0x79, 0x12, 0x19, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x6c, 0x61, 0x74, 0x65, 0x6e, 0x63, 0x79, 0x2e, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73,
	0x1a, 0x19, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x61, 0x74, 0x65, 0x6e,
	0x63, 0x79, 0x2e, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0xb5, 0x02, 0x0a, 0x09,
	0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x12, 0x4a, 0x0a, 0x04, 0x73, 0x61, 0x76,
	0x65, 0x12, 0x2a, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x73, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e,
	0x73, 0x61, 0x76, 0x65, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x5f, 0x72, 0x65, 0x71, 0x1a, 0x16, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x47, 0x0a, 0x06, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x12,
	0x25, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73,
	0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x6c, 0x69,
	0x6e, 0x6b, 0x5f, 0x72, 0x65, 0x71, 0x1a, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x47,
	0x0a, 0x06, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x12, 0x25, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69,
	0x69, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x73,
	0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x6c, 0x69, 0x6e, 0x6b, 0x5f, 0x72, 0x65, 0x71, 0x1a,
	0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x4a, 0x0a, 0x03, 0x67, 0x65, 0x74, 0x12, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x2b, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x73, 0x65, 0x72,
	0x76, 0x69, 0x63, 0x65, 0x2e, 0x67, 0x65, 0x74, 0x5f, 0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x5f, 0x72,
	0x65, 0x73, 0x70, 0x32, 0x90, 0x01, 0x0a, 0x03, 0x74, 0x61, 0x67, 0x12, 0x49, 0x0a, 0x04, 0x73,
	0x61, 0x76, 0x65, 0x12, 0x29, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x73, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x73, 0x61, 0x76, 0x65, 0x5f, 0x74, 0x61, 0x67, 0x5f, 0x72, 0x65, 0x71, 0x1a, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x12, 0x3e, 0x0a, 0x06, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65,
	0x12, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x53, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x1a, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x42, 0x36, 0x5a, 0x34, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62,
	0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41, 0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79,
	0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x73, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x62, 0x06,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_node_grpc_node_proto_rawDescOnce sync.Once
	file_node_grpc_node_proto_rawDescData = file_node_grpc_node_proto_rawDesc
)

func file_node_grpc_node_proto_rawDescGZIP() []byte {
	file_node_grpc_node_proto_rawDescOnce.Do(func() {
		file_node_grpc_node_proto_rawDescData = protoimpl.X.CompressGZIP(file_node_grpc_node_proto_rawDescData)
	})
	return file_node_grpc_node_proto_rawDescData
}

var file_node_grpc_node_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_node_grpc_node_proto_goTypes = []interface{}{
	(*NowResp)(nil),                // 0: yuhaiin.protos.node.service.now_resp
	(*UseReq)(nil),                 // 1: yuhaiin.protos.node.service.use_req
	(*SaveLinkReq)(nil),            // 2: yuhaiin.protos.node.service.save_link_req
	(*LinkReq)(nil),                // 3: yuhaiin.protos.node.service.link_req
	(*GetLinksResp)(nil),           // 4: yuhaiin.protos.node.service.get_links_resp
	(*SaveTagReq)(nil),             // 5: yuhaiin.protos.node.service.save_tag_req
	nil,                            // 6: yuhaiin.protos.node.service.get_links_resp.LinksEntry
	(*point.Point)(nil),            // 7: yuhaiin.point.point
	(*subscribe.Link)(nil),         // 8: yuhaiin.subscribe.link
	(tag.TagType)(0),               // 9: yuhaiin.tag.tag_type
	(*emptypb.Empty)(nil),          // 10: google.protobuf.Empty
	(*wrapperspb.StringValue)(nil), // 11: google.protobuf.StringValue
	(*latency.Requests)(nil),       // 12: yuhaiin.latency.requests
	(*node.Manager)(nil),           // 13: yuhaiin.node.manager
	(*latency.Response)(nil),       // 14: yuhaiin.latency.response
}
var file_node_grpc_node_proto_depIdxs = []int32{
	7,  // 0: yuhaiin.protos.node.service.now_resp.tcp:type_name -> yuhaiin.point.point
	7,  // 1: yuhaiin.protos.node.service.now_resp.udp:type_name -> yuhaiin.point.point
	8,  // 2: yuhaiin.protos.node.service.save_link_req.links:type_name -> yuhaiin.subscribe.link
	6,  // 3: yuhaiin.protos.node.service.get_links_resp.links:type_name -> yuhaiin.protos.node.service.get_links_resp.LinksEntry
	9,  // 4: yuhaiin.protos.node.service.save_tag_req.type:type_name -> yuhaiin.tag.tag_type
	8,  // 5: yuhaiin.protos.node.service.get_links_resp.LinksEntry.value:type_name -> yuhaiin.subscribe.link
	10, // 6: yuhaiin.protos.node.service.node.now:input_type -> google.protobuf.Empty
	1,  // 7: yuhaiin.protos.node.service.node.use:input_type -> yuhaiin.protos.node.service.use_req
	11, // 8: yuhaiin.protos.node.service.node.get:input_type -> google.protobuf.StringValue
	7,  // 9: yuhaiin.protos.node.service.node.save:input_type -> yuhaiin.point.point
	11, // 10: yuhaiin.protos.node.service.node.remove:input_type -> google.protobuf.StringValue
	10, // 11: yuhaiin.protos.node.service.node.manager:input_type -> google.protobuf.Empty
	12, // 12: yuhaiin.protos.node.service.node.latency:input_type -> yuhaiin.latency.requests
	2,  // 13: yuhaiin.protos.node.service.subscribe.save:input_type -> yuhaiin.protos.node.service.save_link_req
	3,  // 14: yuhaiin.protos.node.service.subscribe.remove:input_type -> yuhaiin.protos.node.service.link_req
	3,  // 15: yuhaiin.protos.node.service.subscribe.update:input_type -> yuhaiin.protos.node.service.link_req
	10, // 16: yuhaiin.protos.node.service.subscribe.get:input_type -> google.protobuf.Empty
	5,  // 17: yuhaiin.protos.node.service.tag.save:input_type -> yuhaiin.protos.node.service.save_tag_req
	11, // 18: yuhaiin.protos.node.service.tag.remove:input_type -> google.protobuf.StringValue
	0,  // 19: yuhaiin.protos.node.service.node.now:output_type -> yuhaiin.protos.node.service.now_resp
	7,  // 20: yuhaiin.protos.node.service.node.use:output_type -> yuhaiin.point.point
	7,  // 21: yuhaiin.protos.node.service.node.get:output_type -> yuhaiin.point.point
	7,  // 22: yuhaiin.protos.node.service.node.save:output_type -> yuhaiin.point.point
	10, // 23: yuhaiin.protos.node.service.node.remove:output_type -> google.protobuf.Empty
	13, // 24: yuhaiin.protos.node.service.node.manager:output_type -> yuhaiin.node.manager
	14, // 25: yuhaiin.protos.node.service.node.latency:output_type -> yuhaiin.latency.response
	10, // 26: yuhaiin.protos.node.service.subscribe.save:output_type -> google.protobuf.Empty
	10, // 27: yuhaiin.protos.node.service.subscribe.remove:output_type -> google.protobuf.Empty
	10, // 28: yuhaiin.protos.node.service.subscribe.update:output_type -> google.protobuf.Empty
	4,  // 29: yuhaiin.protos.node.service.subscribe.get:output_type -> yuhaiin.protos.node.service.get_links_resp
	10, // 30: yuhaiin.protos.node.service.tag.save:output_type -> google.protobuf.Empty
	10, // 31: yuhaiin.protos.node.service.tag.remove:output_type -> google.protobuf.Empty
	19, // [19:32] is the sub-list for method output_type
	6,  // [6:19] is the sub-list for method input_type
	6,  // [6:6] is the sub-list for extension type_name
	6,  // [6:6] is the sub-list for extension extendee
	0,  // [0:6] is the sub-list for field type_name
}

func init() { file_node_grpc_node_proto_init() }
func file_node_grpc_node_proto_init() {
	if File_node_grpc_node_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_node_grpc_node_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NowResp); i {
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
		file_node_grpc_node_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UseReq); i {
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
		file_node_grpc_node_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SaveLinkReq); i {
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
		file_node_grpc_node_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*LinkReq); i {
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
		file_node_grpc_node_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*GetLinksResp); i {
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
		file_node_grpc_node_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SaveTagReq); i {
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
			RawDescriptor: file_node_grpc_node_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   3,
		},
		GoTypes:           file_node_grpc_node_proto_goTypes,
		DependencyIndexes: file_node_grpc_node_proto_depIdxs,
		MessageInfos:      file_node_grpc_node_proto_msgTypes,
	}.Build()
	File_node_grpc_node_proto = out.File
	file_node_grpc_node_proto_rawDesc = nil
	file_node_grpc_node_proto_goTypes = nil
	file_node_grpc_node_proto_depIdxs = nil
}
