// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: config/config.proto

package config

import (
	proto "github.com/golang/protobuf/proto"
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

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Setting struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//TODO all json lower case
	SystemProxy *SystemProxy `protobuf:"bytes,1,opt,name=SystemProxy,json=system_proxy,proto3" json:"SystemProxy,omitempty"`
	Bypass      *Bypass      `protobuf:"bytes,2,opt,name=Bypass,json=bypass,proto3" json:"Bypass,omitempty"`
	Proxy       *Proxy       `protobuf:"bytes,3,opt,name=Proxy,json=proxy,proto3" json:"Proxy,omitempty"`
	DNS         *DNS         `protobuf:"bytes,4,opt,name=DNS,json=dns,proto3" json:"DNS,omitempty"`
	LocalDNS    *DNS         `protobuf:"bytes,5,opt,name=LocalDNS,json=local_dns,proto3" json:"LocalDNS,omitempty"`
	// Deprecated: Do not use.
	SsrPath string `protobuf:"bytes,11,opt,name=SsrPath,json=ssr_path,proto3" json:"SsrPath,omitempty"`
}

func (x *Setting) Reset() {
	*x = Setting{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_config_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Setting) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Setting) ProtoMessage() {}

func (x *Setting) ProtoReflect() protoreflect.Message {
	mi := &file_config_config_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Setting.ProtoReflect.Descriptor instead.
func (*Setting) Descriptor() ([]byte, []int) {
	return file_config_config_proto_rawDescGZIP(), []int{0}
}

func (x *Setting) GetSystemProxy() *SystemProxy {
	if x != nil {
		return x.SystemProxy
	}
	return nil
}

func (x *Setting) GetBypass() *Bypass {
	if x != nil {
		return x.Bypass
	}
	return nil
}

func (x *Setting) GetProxy() *Proxy {
	if x != nil {
		return x.Proxy
	}
	return nil
}

func (x *Setting) GetDNS() *DNS {
	if x != nil {
		return x.DNS
	}
	return nil
}

func (x *Setting) GetLocalDNS() *DNS {
	if x != nil {
		return x.LocalDNS
	}
	return nil
}

// Deprecated: Do not use.
func (x *Setting) GetSsrPath() string {
	if x != nil {
		return x.SsrPath
	}
	return ""
}

type SystemProxy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Enabled bool `protobuf:"varint,1,opt,name=Enabled,json=enabled,proto3" json:"Enabled,omitempty"`
	HTTP    bool `protobuf:"varint,2,opt,name=HTTP,json=http,proto3" json:"HTTP,omitempty"`
	Socks5  bool `protobuf:"varint,3,opt,name=Socks5,json=socks5,proto3" json:"Socks5,omitempty"`
}

func (x *SystemProxy) Reset() {
	*x = SystemProxy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_config_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SystemProxy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SystemProxy) ProtoMessage() {}

func (x *SystemProxy) ProtoReflect() protoreflect.Message {
	mi := &file_config_config_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SystemProxy.ProtoReflect.Descriptor instead.
func (*SystemProxy) Descriptor() ([]byte, []int) {
	return file_config_config_proto_rawDescGZIP(), []int{1}
}

func (x *SystemProxy) GetEnabled() bool {
	if x != nil {
		return x.Enabled
	}
	return false
}

func (x *SystemProxy) GetHTTP() bool {
	if x != nil {
		return x.HTTP
	}
	return false
}

func (x *SystemProxy) GetSocks5() bool {
	if x != nil {
		return x.Socks5
	}
	return false
}

type Bypass struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Enabled    bool   `protobuf:"varint,1,opt,name=Enabled,json=enabled,proto3" json:"Enabled,omitempty"`
	BypassFile string `protobuf:"bytes,2,opt,name=BypassFile,json=bypass_file,proto3" json:"BypassFile,omitempty"`
}

func (x *Bypass) Reset() {
	*x = Bypass{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Bypass) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Bypass) ProtoMessage() {}

func (x *Bypass) ProtoReflect() protoreflect.Message {
	mi := &file_config_config_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Bypass.ProtoReflect.Descriptor instead.
func (*Bypass) Descriptor() ([]byte, []int) {
	return file_config_config_proto_rawDescGZIP(), []int{2}
}

func (x *Bypass) GetEnabled() bool {
	if x != nil {
		return x.Enabled
	}
	return false
}

func (x *Bypass) GetBypassFile() string {
	if x != nil {
		return x.BypassFile
	}
	return ""
}

type DNS struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host   string `protobuf:"bytes,1,opt,name=Host,json=host,proto3" json:"Host,omitempty"`
	DOH    bool   `protobuf:"varint,2,opt,name=DOH,json=doh,proto3" json:"DOH,omitempty"`
	Proxy  bool   `protobuf:"varint,3,opt,name=Proxy,json=proxy,proto3" json:"Proxy,omitempty"`
	Subnet string `protobuf:"bytes,4,opt,name=subnet,proto3" json:"subnet,omitempty"`
}

func (x *DNS) Reset() {
	*x = DNS{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DNS) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DNS) ProtoMessage() {}

func (x *DNS) ProtoReflect() protoreflect.Message {
	mi := &file_config_config_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DNS.ProtoReflect.Descriptor instead.
func (*DNS) Descriptor() ([]byte, []int) {
	return file_config_config_proto_rawDescGZIP(), []int{3}
}

func (x *DNS) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *DNS) GetDOH() bool {
	if x != nil {
		return x.DOH
	}
	return false
}

func (x *DNS) GetProxy() bool {
	if x != nil {
		return x.Proxy
	}
	return false
}

func (x *DNS) GetSubnet() string {
	if x != nil {
		return x.Subnet
	}
	return ""
}

type Proxy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HTTP   string `protobuf:"bytes,1,opt,name=HTTP,json=http,proto3" json:"HTTP,omitempty"`
	Socks5 string `protobuf:"bytes,2,opt,name=Socks5,json=socks5,proto3" json:"Socks5,omitempty"`
	Redir  string `protobuf:"bytes,3,opt,name=Redir,json=redir,proto3" json:"Redir,omitempty"`
}

func (x *Proxy) Reset() {
	*x = Proxy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Proxy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Proxy) ProtoMessage() {}

func (x *Proxy) ProtoReflect() protoreflect.Message {
	mi := &file_config_config_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Proxy.ProtoReflect.Descriptor instead.
func (*Proxy) Descriptor() ([]byte, []int) {
	return file_config_config_proto_rawDescGZIP(), []int{4}
}

func (x *Proxy) GetHTTP() string {
	if x != nil {
		return x.HTTP
	}
	return ""
}

func (x *Proxy) GetSocks5() string {
	if x != nil {
		return x.Socks5
	}
	return ""
}

func (x *Proxy) GetRedir() string {
	if x != nil {
		return x.Redir
	}
	return ""
}

var File_config_config_proto protoreflect.FileDescriptor

var file_config_config_proto_rawDesc = []byte{
	0x0a, 0x13, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61,
	0x70, 0x69, 0x22, 0x8f, 0x02, 0x0a, 0x07, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x12, 0x3b,
	0x0a, 0x0b, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x52, 0x0c, 0x73,
	0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x12, 0x2b, 0x0a, 0x06, 0x42,
	0x79, 0x70, 0x61, 0x73, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e, 0x79, 0x75,
	0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x42, 0x79, 0x70, 0x61, 0x73, 0x73,
	0x52, 0x06, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x12, 0x28, 0x0a, 0x05, 0x50, 0x72, 0x6f, 0x78,
	0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69,
	0x6e, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x52, 0x05, 0x70, 0x72, 0x6f,
	0x78, 0x79, 0x12, 0x22, 0x0a, 0x03, 0x44, 0x4e, 0x53, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x10, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x44, 0x4e,
	0x53, 0x52, 0x03, 0x64, 0x6e, 0x73, 0x12, 0x2d, 0x0a, 0x08, 0x4c, 0x6f, 0x63, 0x61, 0x6c, 0x44,
	0x4e, 0x53, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69,
	0x69, 0x6e, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x44, 0x4e, 0x53, 0x52, 0x09, 0x6c, 0x6f, 0x63, 0x61,
	0x6c, 0x5f, 0x64, 0x6e, 0x73, 0x12, 0x1d, 0x0a, 0x07, 0x53, 0x73, 0x72, 0x50, 0x61, 0x74, 0x68,
	0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x42, 0x02, 0x18, 0x01, 0x52, 0x08, 0x73, 0x73, 0x72, 0x5f,
	0x70, 0x61, 0x74, 0x68, 0x22, 0x53, 0x0a, 0x0b, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x50, 0x72,
	0x6f, 0x78, 0x79, 0x12, 0x18, 0x0a, 0x07, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x12, 0x0a,
	0x04, 0x48, 0x54, 0x54, 0x50, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x04, 0x68, 0x74, 0x74,
	0x70, 0x12, 0x16, 0x0a, 0x06, 0x53, 0x6f, 0x63, 0x6b, 0x73, 0x35, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x06, 0x73, 0x6f, 0x63, 0x6b, 0x73, 0x35, 0x22, 0x43, 0x0a, 0x06, 0x42, 0x79, 0x70,
	0x61, 0x73, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x1f, 0x0a,
	0x0a, 0x42, 0x79, 0x70, 0x61, 0x73, 0x73, 0x46, 0x69, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0b, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x22, 0x59,
	0x0a, 0x03, 0x44, 0x4e, 0x53, 0x12, 0x12, 0x0a, 0x04, 0x48, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x44, 0x4f, 0x48,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x03, 0x64, 0x6f, 0x68, 0x12, 0x14, 0x0a, 0x05, 0x50,
	0x72, 0x6f, 0x78, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x75, 0x62, 0x6e, 0x65, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x06, 0x73, 0x75, 0x62, 0x6e, 0x65, 0x74, 0x22, 0x49, 0x0a, 0x05, 0x50, 0x72, 0x6f,
	0x78, 0x79, 0x12, 0x12, 0x0a, 0x04, 0x48, 0x54, 0x54, 0x50, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x04, 0x68, 0x74, 0x74, 0x70, 0x12, 0x16, 0x0a, 0x06, 0x53, 0x6f, 0x63, 0x6b, 0x73, 0x35,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x6f, 0x63, 0x6b, 0x73, 0x35, 0x12, 0x14,
	0x0a, 0x05, 0x52, 0x65, 0x64, 0x69, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x72,
	0x65, 0x64, 0x69, 0x72, 0x42, 0x25, 0x5a, 0x23, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x41, 0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_config_config_proto_rawDescOnce sync.Once
	file_config_config_proto_rawDescData = file_config_config_proto_rawDesc
)

func file_config_config_proto_rawDescGZIP() []byte {
	file_config_config_proto_rawDescOnce.Do(func() {
		file_config_config_proto_rawDescData = protoimpl.X.CompressGZIP(file_config_config_proto_rawDescData)
	})
	return file_config_config_proto_rawDescData
}

var file_config_config_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_config_config_proto_goTypes = []interface{}{
	(*Setting)(nil),     // 0: yuhaiin.api.Setting
	(*SystemProxy)(nil), // 1: yuhaiin.api.SystemProxy
	(*Bypass)(nil),      // 2: yuhaiin.api.Bypass
	(*DNS)(nil),         // 3: yuhaiin.api.DNS
	(*Proxy)(nil),       // 4: yuhaiin.api.Proxy
}
var file_config_config_proto_depIdxs = []int32{
	1, // 0: yuhaiin.api.Setting.SystemProxy:type_name -> yuhaiin.api.SystemProxy
	2, // 1: yuhaiin.api.Setting.Bypass:type_name -> yuhaiin.api.Bypass
	4, // 2: yuhaiin.api.Setting.Proxy:type_name -> yuhaiin.api.Proxy
	3, // 3: yuhaiin.api.Setting.DNS:type_name -> yuhaiin.api.DNS
	3, // 4: yuhaiin.api.Setting.LocalDNS:type_name -> yuhaiin.api.DNS
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_config_config_proto_init() }
func file_config_config_proto_init() {
	if File_config_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_config_config_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Setting); i {
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
		file_config_config_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SystemProxy); i {
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
		file_config_config_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Bypass); i {
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
		file_config_config_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DNS); i {
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
		file_config_config_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Proxy); i {
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
			RawDescriptor: file_config_config_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_config_config_proto_goTypes,
		DependencyIndexes: file_config_config_proto_depIdxs,
		MessageInfos:      file_config_config_proto_msgTypes,
	}.Build()
	File_config_config_proto = out.File
	file_config_config_proto_rawDesc = nil
	file_config_config_proto_goTypes = nil
	file_config_config_proto_depIdxs = nil
}
