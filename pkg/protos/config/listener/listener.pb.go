// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: config/listener/listener.proto

package listener

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

type TunEndpointDriver int32

const (
	Tun_fdbased       TunEndpointDriver = 0
	Tun_channel       TunEndpointDriver = 1
	Tun_system_gvisor TunEndpointDriver = 2
)

// Enum value maps for TunEndpointDriver.
var (
	TunEndpointDriver_name = map[int32]string{
		0: "fdbased",
		1: "channel",
		2: "system_gvisor",
	}
	TunEndpointDriver_value = map[string]int32{
		"fdbased":       0,
		"channel":       1,
		"system_gvisor": 2,
	}
)

func (x TunEndpointDriver) Enum() *TunEndpointDriver {
	p := new(TunEndpointDriver)
	*p = x
	return p
}

func (x TunEndpointDriver) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (TunEndpointDriver) Descriptor() protoreflect.EnumDescriptor {
	return file_config_listener_listener_proto_enumTypes[0].Descriptor()
}

func (TunEndpointDriver) Type() protoreflect.EnumType {
	return &file_config_listener_listener_proto_enumTypes[0]
}

func (x TunEndpointDriver) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use TunEndpointDriver.Descriptor instead.
func (TunEndpointDriver) EnumDescriptor() ([]byte, []int) {
	return file_config_listener_listener_proto_rawDescGZIP(), []int{5, 0}
}

type Protocol struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name    string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Enabled bool   `protobuf:"varint,2,opt,name=enabled,proto3" json:"enabled,omitempty"`
	// Types that are assignable to Protocol:
	//
	//	*Protocol_Http
	//	*Protocol_Socks5
	//	*Protocol_Redir
	//	*Protocol_Tun
	Protocol isProtocol_Protocol `protobuf_oneof:"protocol"`
}

func (x *Protocol) Reset() {
	*x = Protocol{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_listener_listener_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Protocol) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Protocol) ProtoMessage() {}

func (x *Protocol) ProtoReflect() protoreflect.Message {
	mi := &file_config_listener_listener_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Protocol.ProtoReflect.Descriptor instead.
func (*Protocol) Descriptor() ([]byte, []int) {
	return file_config_listener_listener_proto_rawDescGZIP(), []int{0}
}

func (x *Protocol) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Protocol) GetEnabled() bool {
	if x != nil {
		return x.Enabled
	}
	return false
}

func (m *Protocol) GetProtocol() isProtocol_Protocol {
	if m != nil {
		return m.Protocol
	}
	return nil
}

func (x *Protocol) GetHttp() *Http {
	if x, ok := x.GetProtocol().(*Protocol_Http); ok {
		return x.Http
	}
	return nil
}

func (x *Protocol) GetSocks5() *Socks5 {
	if x, ok := x.GetProtocol().(*Protocol_Socks5); ok {
		return x.Socks5
	}
	return nil
}

func (x *Protocol) GetRedir() *Redir {
	if x, ok := x.GetProtocol().(*Protocol_Redir); ok {
		return x.Redir
	}
	return nil
}

func (x *Protocol) GetTun() *Tun {
	if x, ok := x.GetProtocol().(*Protocol_Tun); ok {
		return x.Tun
	}
	return nil
}

type isProtocol_Protocol interface {
	isProtocol_Protocol()
}

type Protocol_Http struct {
	Http *Http `protobuf:"bytes,3,opt,name=http,proto3,oneof"`
}

type Protocol_Socks5 struct {
	Socks5 *Socks5 `protobuf:"bytes,4,opt,name=socks5,proto3,oneof"`
}

type Protocol_Redir struct {
	Redir *Redir `protobuf:"bytes,5,opt,name=redir,proto3,oneof"`
}

type Protocol_Tun struct {
	Tun *Tun `protobuf:"bytes,6,opt,name=tun,proto3,oneof"`
}

func (*Protocol_Http) isProtocol_Protocol() {}

func (*Protocol_Socks5) isProtocol_Protocol() {}

func (*Protocol_Redir) isProtocol_Protocol() {}

func (*Protocol_Tun) isProtocol_Protocol() {}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Servers map[string]*Protocol `protobuf:"bytes,5,rep,name=servers,proto3" json:"servers,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_listener_listener_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_config_listener_listener_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_config_listener_listener_proto_rawDescGZIP(), []int{1}
}

func (x *Config) GetServers() map[string]*Protocol {
	if x != nil {
		return x.Servers
	}
	return nil
}

type Http struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host     string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	Username string `protobuf:"bytes,3,opt,name=username,proto3" json:"username,omitempty"`
	Password string `protobuf:"bytes,4,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *Http) Reset() {
	*x = Http{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_listener_listener_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Http) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Http) ProtoMessage() {}

func (x *Http) ProtoReflect() protoreflect.Message {
	mi := &file_config_listener_listener_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Http.ProtoReflect.Descriptor instead.
func (*Http) Descriptor() ([]byte, []int) {
	return file_config_listener_listener_proto_rawDescGZIP(), []int{2}
}

func (x *Http) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *Http) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *Http) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type Socks5 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host     string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	Username string `protobuf:"bytes,3,opt,name=username,proto3" json:"username,omitempty"`
	Password string `protobuf:"bytes,4,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *Socks5) Reset() {
	*x = Socks5{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_listener_listener_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Socks5) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Socks5) ProtoMessage() {}

func (x *Socks5) ProtoReflect() protoreflect.Message {
	mi := &file_config_listener_listener_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Socks5.ProtoReflect.Descriptor instead.
func (*Socks5) Descriptor() ([]byte, []int) {
	return file_config_listener_listener_proto_rawDescGZIP(), []int{3}
}

func (x *Socks5) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *Socks5) GetUsername() string {
	if x != nil {
		return x.Username
	}
	return ""
}

func (x *Socks5) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type Redir struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Host string `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
}

func (x *Redir) Reset() {
	*x = Redir{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_listener_listener_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Redir) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Redir) ProtoMessage() {}

func (x *Redir) ProtoReflect() protoreflect.Message {
	mi := &file_config_listener_listener_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Redir.ProtoReflect.Descriptor instead.
func (*Redir) Descriptor() ([]byte, []int) {
	return file_config_listener_listener_proto_rawDescGZIP(), []int{4}
}

func (x *Redir) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

type Tun struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// name of the tun device
	// eg: tun://tun0, fd://123
	Name          string            `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Mtu           int32             `protobuf:"varint,2,opt,name=mtu,proto3" json:"mtu,omitempty"`
	Gateway       string            `protobuf:"bytes,3,opt,name=gateway,proto3" json:"gateway,omitempty"`
	DnsHijacking  bool              `protobuf:"varint,4,opt,name=dns_hijacking,proto3" json:"dns_hijacking,omitempty"`
	SkipMulticast bool              `protobuf:"varint,6,opt,name=skip_multicast,proto3" json:"skip_multicast,omitempty"`
	Driver        TunEndpointDriver `protobuf:"varint,7,opt,name=driver,proto3,enum=yuhaiin.listener.TunEndpointDriver" json:"driver,omitempty"`
	Portal        string            `protobuf:"bytes,8,opt,name=portal,proto3" json:"portal,omitempty"`
}

func (x *Tun) Reset() {
	*x = Tun{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_listener_listener_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Tun) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Tun) ProtoMessage() {}

func (x *Tun) ProtoReflect() protoreflect.Message {
	mi := &file_config_listener_listener_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Tun.ProtoReflect.Descriptor instead.
func (*Tun) Descriptor() ([]byte, []int) {
	return file_config_listener_listener_proto_rawDescGZIP(), []int{5}
}

func (x *Tun) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *Tun) GetMtu() int32 {
	if x != nil {
		return x.Mtu
	}
	return 0
}

func (x *Tun) GetGateway() string {
	if x != nil {
		return x.Gateway
	}
	return ""
}

func (x *Tun) GetDnsHijacking() bool {
	if x != nil {
		return x.DnsHijacking
	}
	return false
}

func (x *Tun) GetSkipMulticast() bool {
	if x != nil {
		return x.SkipMulticast
	}
	return false
}

func (x *Tun) GetDriver() TunEndpointDriver {
	if x != nil {
		return x.Driver
	}
	return Tun_fdbased
}

func (x *Tun) GetPortal() string {
	if x != nil {
		return x.Portal
	}
	return ""
}

var File_config_listener_listener_proto protoreflect.FileDescriptor

var file_config_listener_listener_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65,
	0x72, 0x2f, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x10, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e,
	0x65, 0x72, 0x22, 0x82, 0x02, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12,
	0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x2c, 0x0a,
	0x04, 0x68, 0x74, 0x74, 0x70, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e, 0x79, 0x75,
	0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x2e, 0x68,
	0x74, 0x74, 0x70, 0x48, 0x00, 0x52, 0x04, 0x68, 0x74, 0x74, 0x70, 0x12, 0x32, 0x0a, 0x06, 0x73,
	0x6f, 0x63, 0x6b, 0x73, 0x35, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x79, 0x75,
	0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x2e, 0x73,
	0x6f, 0x63, 0x6b, 0x73, 0x35, 0x48, 0x00, 0x52, 0x06, 0x73, 0x6f, 0x63, 0x6b, 0x73, 0x35, 0x12,
	0x2f, 0x0a, 0x05, 0x72, 0x65, 0x64, 0x69, 0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17,
	0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65,
	0x72, 0x2e, 0x72, 0x65, 0x64, 0x69, 0x72, 0x48, 0x00, 0x52, 0x05, 0x72, 0x65, 0x64, 0x69, 0x72,
	0x12, 0x29, 0x0a, 0x03, 0x74, 0x75, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72,
	0x2e, 0x74, 0x75, 0x6e, 0x48, 0x00, 0x52, 0x03, 0x74, 0x75, 0x6e, 0x42, 0x0a, 0x0a, 0x08, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x22, 0xa1, 0x01, 0x0a, 0x06, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x12, 0x3f, 0x0a, 0x07, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x18, 0x05, 0x20,
	0x03, 0x28, 0x0b, 0x32, 0x25, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x69,
	0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x53, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x07, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x73, 0x1a, 0x56, 0x0a, 0x0c, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x45, 0x6e,
	0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x30, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c,
	0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c,
	0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x22, 0x52, 0x0a, 0x04, 0x68,
	0x74, 0x74, 0x70, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x75, 0x73, 0x65, 0x72, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x22,
	0x54, 0x0a, 0x06, 0x73, 0x6f, 0x63, 0x6b, 0x73, 0x35, 0x12, 0x12, 0x0a, 0x04, 0x68, 0x6f, 0x73,
	0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12, 0x1a, 0x0a,
	0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x08, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73,
	0x73, 0x77, 0x6f, 0x72, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73,
	0x73, 0x77, 0x6f, 0x72, 0x64, 0x22, 0x1b, 0x0a, 0x05, 0x72, 0x65, 0x64, 0x69, 0x72, 0x12, 0x12,
	0x0a, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f,
	0x73, 0x74, 0x22, 0xaa, 0x02, 0x0a, 0x03, 0x74, 0x75, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x10,
	0x0a, 0x03, 0x6d, 0x74, 0x75, 0x18, 0x02, 0x20, 0x01, 0x28, 0x05, 0x52, 0x03, 0x6d, 0x74, 0x75,
	0x12, 0x18, 0x0a, 0x07, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x12, 0x24, 0x0a, 0x0d, 0x64, 0x6e,
	0x73, 0x5f, 0x68, 0x69, 0x6a, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67, 0x18, 0x04, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x0d, 0x64, 0x6e, 0x73, 0x5f, 0x68, 0x69, 0x6a, 0x61, 0x63, 0x6b, 0x69, 0x6e, 0x67,
	0x12, 0x26, 0x0a, 0x0e, 0x73, 0x6b, 0x69, 0x70, 0x5f, 0x6d, 0x75, 0x6c, 0x74, 0x69, 0x63, 0x61,
	0x73, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0e, 0x73, 0x6b, 0x69, 0x70, 0x5f, 0x6d,
	0x75, 0x6c, 0x74, 0x69, 0x63, 0x61, 0x73, 0x74, 0x12, 0x3d, 0x0a, 0x06, 0x64, 0x72, 0x69, 0x76,
	0x65, 0x72, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x25, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69,
	0x69, 0x6e, 0x2e, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x2e, 0x74, 0x75, 0x6e, 0x2e,
	0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x52,
	0x06, 0x64, 0x72, 0x69, 0x76, 0x65, 0x72, 0x12, 0x16, 0x0a, 0x06, 0x70, 0x6f, 0x72, 0x74, 0x61,
	0x6c, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x70, 0x6f, 0x72, 0x74, 0x61, 0x6c, 0x22,
	0x3e, 0x0a, 0x0f, 0x65, 0x6e, 0x64, 0x70, 0x6f, 0x69, 0x6e, 0x74, 0x5f, 0x64, 0x72, 0x69, 0x76,
	0x65, 0x72, 0x12, 0x0b, 0x0a, 0x07, 0x66, 0x64, 0x62, 0x61, 0x73, 0x65, 0x64, 0x10, 0x00, 0x12,
	0x0b, 0x0a, 0x07, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x10, 0x01, 0x12, 0x11, 0x0a, 0x0d,
	0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x67, 0x76, 0x69, 0x73, 0x6f, 0x72, 0x10, 0x02, 0x42,
	0x39, 0x5a, 0x37, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41, 0x73,
	0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2f,
	0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2f, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x33,
}

var (
	file_config_listener_listener_proto_rawDescOnce sync.Once
	file_config_listener_listener_proto_rawDescData = file_config_listener_listener_proto_rawDesc
)

func file_config_listener_listener_proto_rawDescGZIP() []byte {
	file_config_listener_listener_proto_rawDescOnce.Do(func() {
		file_config_listener_listener_proto_rawDescData = protoimpl.X.CompressGZIP(file_config_listener_listener_proto_rawDescData)
	})
	return file_config_listener_listener_proto_rawDescData
}

var file_config_listener_listener_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_config_listener_listener_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_config_listener_listener_proto_goTypes = []interface{}{
	(TunEndpointDriver)(0), // 0: yuhaiin.listener.tun.endpoint_driver
	(*Protocol)(nil),       // 1: yuhaiin.listener.protocol
	(*Config)(nil),         // 2: yuhaiin.listener.config
	(*Http)(nil),           // 3: yuhaiin.listener.http
	(*Socks5)(nil),         // 4: yuhaiin.listener.socks5
	(*Redir)(nil),          // 5: yuhaiin.listener.redir
	(*Tun)(nil),            // 6: yuhaiin.listener.tun
	nil,                    // 7: yuhaiin.listener.config.ServersEntry
}
var file_config_listener_listener_proto_depIdxs = []int32{
	3, // 0: yuhaiin.listener.protocol.http:type_name -> yuhaiin.listener.http
	4, // 1: yuhaiin.listener.protocol.socks5:type_name -> yuhaiin.listener.socks5
	5, // 2: yuhaiin.listener.protocol.redir:type_name -> yuhaiin.listener.redir
	6, // 3: yuhaiin.listener.protocol.tun:type_name -> yuhaiin.listener.tun
	7, // 4: yuhaiin.listener.config.servers:type_name -> yuhaiin.listener.config.ServersEntry
	0, // 5: yuhaiin.listener.tun.driver:type_name -> yuhaiin.listener.tun.endpoint_driver
	1, // 6: yuhaiin.listener.config.ServersEntry.value:type_name -> yuhaiin.listener.protocol
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_config_listener_listener_proto_init() }
func file_config_listener_listener_proto_init() {
	if File_config_listener_listener_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_config_listener_listener_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Protocol); i {
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
		file_config_listener_listener_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config); i {
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
		file_config_listener_listener_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Http); i {
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
		file_config_listener_listener_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Socks5); i {
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
		file_config_listener_listener_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Redir); i {
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
		file_config_listener_listener_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Tun); i {
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
	file_config_listener_listener_proto_msgTypes[0].OneofWrappers = []interface{}{
		(*Protocol_Http)(nil),
		(*Protocol_Socks5)(nil),
		(*Protocol_Redir)(nil),
		(*Protocol_Tun)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_config_listener_listener_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_config_listener_listener_proto_goTypes,
		DependencyIndexes: file_config_listener_listener_proto_depIdxs,
		EnumInfos:         file_config_listener_listener_proto_enumTypes,
		MessageInfos:      file_config_listener_listener_proto_msgTypes,
	}.Build()
	File_config_listener_listener_proto = out.File
	file_config_listener_listener_proto_rawDesc = nil
	file_config_listener_listener_proto_goTypes = nil
	file_config_listener_listener_proto_depIdxs = nil
}
