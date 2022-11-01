// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.21.7
// source: node/node.proto

package node

import (
	point "github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	subscribe "github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
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

type Node struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Tcp     *point.Point               `protobuf:"bytes,4,opt,name=tcp,proto3" json:"tcp,omitempty"`
	Udp     *point.Point               `protobuf:"bytes,5,opt,name=udp,proto3" json:"udp,omitempty"`
	Links   map[string]*subscribe.Link `protobuf:"bytes,2,rep,name=links,proto3" json:"links,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Manager *Manager                   `protobuf:"bytes,3,opt,name=manager,proto3" json:"manager,omitempty"`
}

func (x *Node) Reset() {
	*x = Node{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_node_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Node) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Node) ProtoMessage() {}

func (x *Node) ProtoReflect() protoreflect.Message {
	mi := &file_node_node_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Node.ProtoReflect.Descriptor instead.
func (*Node) Descriptor() ([]byte, []int) {
	return file_node_node_proto_rawDescGZIP(), []int{0}
}

func (x *Node) GetTcp() *point.Point {
	if x != nil {
		return x.Tcp
	}
	return nil
}

func (x *Node) GetUdp() *point.Point {
	if x != nil {
		return x.Udp
	}
	return nil
}

func (x *Node) GetLinks() map[string]*subscribe.Link {
	if x != nil {
		return x.Links
	}
	return nil
}

func (x *Node) GetManager() *Manager {
	if x != nil {
		return x.Manager
	}
	return nil
}

type Manager struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Groups        []string                     `protobuf:"bytes,1,rep,name=groups,proto3" json:"groups,omitempty"`
	GroupNodesMap map[string]*ManagerNodeArray `protobuf:"bytes,2,rep,name=group_nodes_map,proto3" json:"group_nodes_map,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Nodes         map[string]*point.Point      `protobuf:"bytes,3,rep,name=nodes,proto3" json:"nodes,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Manager) Reset() {
	*x = Manager{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_node_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Manager) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Manager) ProtoMessage() {}

func (x *Manager) ProtoReflect() protoreflect.Message {
	mi := &file_node_node_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Manager.ProtoReflect.Descriptor instead.
func (*Manager) Descriptor() ([]byte, []int) {
	return file_node_node_proto_rawDescGZIP(), []int{1}
}

func (x *Manager) GetGroups() []string {
	if x != nil {
		return x.Groups
	}
	return nil
}

func (x *Manager) GetGroupNodesMap() map[string]*ManagerNodeArray {
	if x != nil {
		return x.GroupNodesMap
	}
	return nil
}

func (x *Manager) GetNodes() map[string]*point.Point {
	if x != nil {
		return x.Nodes
	}
	return nil
}

type ManagerNodeArray struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Group       string            `protobuf:"bytes,1,opt,name=group,json=name,proto3" json:"group,omitempty"`
	Nodes       []string          `protobuf:"bytes,2,rep,name=nodes,proto3" json:"nodes,omitempty"`
	NodeHashMap map[string]string `protobuf:"bytes,3,rep,name=node_hash_map,proto3" json:"node_hash_map,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *ManagerNodeArray) Reset() {
	*x = ManagerNodeArray{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_node_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ManagerNodeArray) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ManagerNodeArray) ProtoMessage() {}

func (x *ManagerNodeArray) ProtoReflect() protoreflect.Message {
	mi := &file_node_node_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ManagerNodeArray.ProtoReflect.Descriptor instead.
func (*ManagerNodeArray) Descriptor() ([]byte, []int) {
	return file_node_node_proto_rawDescGZIP(), []int{1, 0}
}

func (x *ManagerNodeArray) GetGroup() string {
	if x != nil {
		return x.Group
	}
	return ""
}

func (x *ManagerNodeArray) GetNodes() []string {
	if x != nil {
		return x.Nodes
	}
	return nil
}

func (x *ManagerNodeArray) GetNodeHashMap() map[string]string {
	if x != nil {
		return x.NodeHashMap
	}
	return nil
}

var File_node_node_proto protoreflect.FileDescriptor

var file_node_node_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x0c, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x1a,
	0x16, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2f, 0x70, 0x6f, 0x69, 0x6e,
	0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x6e, 0x6f, 0x64, 0x65, 0x2f, 0x73, 0x75,
	0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x2f, 0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8f, 0x02, 0x0a, 0x04, 0x6e, 0x6f, 0x64, 0x65,
	0x12, 0x26, 0x0a, 0x03, 0x74, 0x63, 0x70, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x6f,
	0x69, 0x6e, 0x74, 0x52, 0x03, 0x74, 0x63, 0x70, 0x12, 0x26, 0x0a, 0x03, 0x75, 0x64, 0x70, 0x18,
	0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x03, 0x75, 0x64, 0x70,
	0x12, 0x33, 0x0a, 0x05, 0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x1d, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x6e,
	0x6f, 0x64, 0x65, 0x2e, 0x4c, 0x69, 0x6e, 0x6b, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x05,
	0x6c, 0x69, 0x6e, 0x6b, 0x73, 0x12, 0x2f, 0x0a, 0x07, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x52, 0x07, 0x6d,
	0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x1a, 0x51, 0x0a, 0x0a, 0x4c, 0x69, 0x6e, 0x6b, 0x73, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2d, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x73, 0x75, 0x62, 0x73, 0x63, 0x72, 0x69, 0x62, 0x65, 0x2e, 0x6c, 0x69, 0x6e, 0x6b, 0x52, 0x05,
	0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0xb4, 0x04, 0x0a, 0x07, 0x6d, 0x61,
	0x6e, 0x61, 0x67, 0x65, 0x72, 0x12, 0x16, 0x0a, 0x06, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x09, 0x52, 0x06, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x12, 0x52, 0x0a,
	0x0f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x5f, 0x6d, 0x61, 0x70,
	0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x28, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x47, 0x72,
	0x6f, 0x75, 0x70, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x52, 0x0f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x5f, 0x6d, 0x61,
	0x70, 0x12, 0x36, 0x0a, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x20, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e,
	0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x52, 0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x1a, 0xd0, 0x01, 0x0a, 0x0a, 0x6e, 0x6f,
	0x64, 0x65, 0x5f, 0x61, 0x72, 0x72, 0x61, 0x79, 0x12, 0x13, 0x0a, 0x05, 0x67, 0x72, 0x6f, 0x75,
	0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x14, 0x0a,
	0x05, 0x6e, 0x6f, 0x64, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x09, 0x52, 0x05, 0x6e, 0x6f,
	0x64, 0x65, 0x73, 0x12, 0x57, 0x0a, 0x0d, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x68, 0x61, 0x73, 0x68,
	0x5f, 0x6d, 0x61, 0x70, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x31, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65,
	0x72, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x5f, 0x61, 0x72, 0x72, 0x61, 0x79, 0x2e, 0x4e, 0x6f, 0x64,
	0x65, 0x48, 0x61, 0x73, 0x68, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0d, 0x6e,
	0x6f, 0x64, 0x65, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x5f, 0x6d, 0x61, 0x70, 0x1a, 0x3e, 0x0a, 0x10,
	0x4e, 0x6f, 0x64, 0x65, 0x48, 0x61, 0x73, 0x68, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74, 0x72, 0x79,
	0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b,
	0x65, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x62, 0x0a, 0x12,
	0x47, 0x72, 0x6f, 0x75, 0x70, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x4d, 0x61, 0x70, 0x45, 0x6e, 0x74,
	0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x03, 0x6b, 0x65, 0x79, 0x12, 0x36, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6e, 0x6f,
	0x64, 0x65, 0x2e, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x5f,
	0x61, 0x72, 0x72, 0x61, 0x79, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01,
	0x1a, 0x4e, 0x0a, 0x0a, 0x4e, 0x6f, 0x64, 0x65, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10,
	0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x2a, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x14, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x2e,
	0x70, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01,
	0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41,
	0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x6e, 0x6f, 0x64, 0x65,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_node_node_proto_rawDescOnce sync.Once
	file_node_node_proto_rawDescData = file_node_node_proto_rawDesc
)

func file_node_node_proto_rawDescGZIP() []byte {
	file_node_node_proto_rawDescOnce.Do(func() {
		file_node_node_proto_rawDescData = protoimpl.X.CompressGZIP(file_node_node_proto_rawDescData)
	})
	return file_node_node_proto_rawDescData
}

var file_node_node_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_node_node_proto_goTypes = []interface{}{
	(*Node)(nil),             // 0: yuhaiin.node.node
	(*Manager)(nil),          // 1: yuhaiin.node.manager
	nil,                      // 2: yuhaiin.node.node.LinksEntry
	(*ManagerNodeArray)(nil), // 3: yuhaiin.node.manager.node_array
	nil,                      // 4: yuhaiin.node.manager.GroupNodesMapEntry
	nil,                      // 5: yuhaiin.node.manager.NodesEntry
	nil,                      // 6: yuhaiin.node.manager.node_array.NodeHashMapEntry
	(*point.Point)(nil),      // 7: yuhaiin.point.point
	(*subscribe.Link)(nil),   // 8: yuhaiin.subscribe.link
}
var file_node_node_proto_depIdxs = []int32{
	7,  // 0: yuhaiin.node.node.tcp:type_name -> yuhaiin.point.point
	7,  // 1: yuhaiin.node.node.udp:type_name -> yuhaiin.point.point
	2,  // 2: yuhaiin.node.node.links:type_name -> yuhaiin.node.node.LinksEntry
	1,  // 3: yuhaiin.node.node.manager:type_name -> yuhaiin.node.manager
	4,  // 4: yuhaiin.node.manager.group_nodes_map:type_name -> yuhaiin.node.manager.GroupNodesMapEntry
	5,  // 5: yuhaiin.node.manager.nodes:type_name -> yuhaiin.node.manager.NodesEntry
	8,  // 6: yuhaiin.node.node.LinksEntry.value:type_name -> yuhaiin.subscribe.link
	6,  // 7: yuhaiin.node.manager.node_array.node_hash_map:type_name -> yuhaiin.node.manager.node_array.NodeHashMapEntry
	3,  // 8: yuhaiin.node.manager.GroupNodesMapEntry.value:type_name -> yuhaiin.node.manager.node_array
	7,  // 9: yuhaiin.node.manager.NodesEntry.value:type_name -> yuhaiin.point.point
	10, // [10:10] is the sub-list for method output_type
	10, // [10:10] is the sub-list for method input_type
	10, // [10:10] is the sub-list for extension type_name
	10, // [10:10] is the sub-list for extension extendee
	0,  // [0:10] is the sub-list for field type_name
}

func init() { file_node_node_proto_init() }
func file_node_node_proto_init() {
	if File_node_node_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_node_node_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Node); i {
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
		file_node_node_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Manager); i {
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
		file_node_node_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ManagerNodeArray); i {
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
			RawDescriptor: file_node_node_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_node_node_proto_goTypes,
		DependencyIndexes: file_node_node_proto_depIdxs,
		MessageInfos:      file_node_node_proto_msgTypes,
	}.Build()
	File_node_node_proto = out.File
	file_node_node_proto_rawDesc = nil
	file_node_node_proto_goTypes = nil
	file_node_node_proto_depIdxs = nil
}
