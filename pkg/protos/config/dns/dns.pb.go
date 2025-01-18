// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.0
// 	protoc        v5.29.2
// source: config/dns/dns.proto

package dns

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

type Type int32

const (
	Type_reserve Type = 0
	Type_udp     Type = 1
	Type_tcp     Type = 2
	Type_doh     Type = 3
	Type_dot     Type = 4
	Type_doq     Type = 5
	Type_doh3    Type = 6
)

// Enum value maps for Type.
var (
	Type_name = map[int32]string{
		0: "reserve",
		1: "udp",
		2: "tcp",
		3: "doh",
		4: "dot",
		5: "doq",
		6: "doh3",
	}
	Type_value = map[string]int32{
		"reserve": 0,
		"udp":     1,
		"tcp":     2,
		"doh":     3,
		"dot":     4,
		"doq":     5,
		"doh3":    6,
	}
)

func (x Type) Enum() *Type {
	p := new(Type)
	*p = x
	return p
}

func (x Type) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Type) Descriptor() protoreflect.EnumDescriptor {
	return file_config_dns_dns_proto_enumTypes[0].Descriptor()
}

func (Type) Type() protoreflect.EnumType {
	return &file_config_dns_dns_proto_enumTypes[0]
}

func (x Type) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Type.Descriptor instead.
func (Type) EnumDescriptor() ([]byte, []int) {
	return file_config_dns_dns_proto_rawDescGZIP(), []int{0}
}

type Dns struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Host          string                 `protobuf:"bytes,1,opt,name=host,proto3" json:"host,omitempty"`
	Type          Type                   `protobuf:"varint,5,opt,name=type,proto3,enum=yuhaiin.dns.Type" json:"type,omitempty"`
	Subnet        string                 `protobuf:"bytes,4,opt,name=subnet,proto3" json:"subnet,omitempty"`
	TlsServername string                 `protobuf:"bytes,2,opt,name=tls_servername,proto3" json:"tls_servername,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Dns) Reset() {
	*x = Dns{}
	mi := &file_config_dns_dns_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Dns) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Dns) ProtoMessage() {}

func (x *Dns) ProtoReflect() protoreflect.Message {
	mi := &file_config_dns_dns_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Dns.ProtoReflect.Descriptor instead.
func (*Dns) Descriptor() ([]byte, []int) {
	return file_config_dns_dns_proto_rawDescGZIP(), []int{0}
}

func (x *Dns) GetHost() string {
	if x != nil {
		return x.Host
	}
	return ""
}

func (x *Dns) GetType() Type {
	if x != nil {
		return x.Type
	}
	return Type_reserve
}

func (x *Dns) GetSubnet() string {
	if x != nil {
		return x.Subnet
	}
	return ""
}

func (x *Dns) GetTlsServername() string {
	if x != nil {
		return x.TlsServername
	}
	return ""
}

type DnsConfig struct {
	state            protoimpl.MessageState `protogen:"open.v1"`
	Server           string                 `protobuf:"bytes,4,opt,name=server,proto3" json:"server,omitempty"`
	Fakedns          bool                   `protobuf:"varint,5,opt,name=fakedns,proto3" json:"fakedns,omitempty"`
	FakednsIpRange   string                 `protobuf:"bytes,6,opt,name=fakedns_ip_range,proto3" json:"fakedns_ip_range,omitempty"`
	FakednsIpv6Range string                 `protobuf:"bytes,13,opt,name=fakedns_ipv6_range,proto3" json:"fakedns_ipv6_range,omitempty"`
	FakednsWhitelist []string               `protobuf:"bytes,9,rep,name=fakedns_whitelist,proto3" json:"fakedns_whitelist,omitempty"`
	Hosts            map[string]string      `protobuf:"bytes,8,rep,name=hosts,proto3" json:"hosts,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	Resolver         map[string]*Dns        `protobuf:"bytes,10,rep,name=resolver,proto3" json:"resolver,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value"`
	unknownFields    protoimpl.UnknownFields
	sizeCache        protoimpl.SizeCache
}

func (x *DnsConfig) Reset() {
	*x = DnsConfig{}
	mi := &file_config_dns_dns_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *DnsConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DnsConfig) ProtoMessage() {}

func (x *DnsConfig) ProtoReflect() protoreflect.Message {
	mi := &file_config_dns_dns_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DnsConfig.ProtoReflect.Descriptor instead.
func (*DnsConfig) Descriptor() ([]byte, []int) {
	return file_config_dns_dns_proto_rawDescGZIP(), []int{1}
}

func (x *DnsConfig) GetServer() string {
	if x != nil {
		return x.Server
	}
	return ""
}

func (x *DnsConfig) GetFakedns() bool {
	if x != nil {
		return x.Fakedns
	}
	return false
}

func (x *DnsConfig) GetFakednsIpRange() string {
	if x != nil {
		return x.FakednsIpRange
	}
	return ""
}

func (x *DnsConfig) GetFakednsIpv6Range() string {
	if x != nil {
		return x.FakednsIpv6Range
	}
	return ""
}

func (x *DnsConfig) GetFakednsWhitelist() []string {
	if x != nil {
		return x.FakednsWhitelist
	}
	return nil
}

func (x *DnsConfig) GetHosts() map[string]string {
	if x != nil {
		return x.Hosts
	}
	return nil
}

func (x *DnsConfig) GetResolver() map[string]*Dns {
	if x != nil {
		return x.Resolver
	}
	return nil
}

type FakednsConfig struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Enabled       bool                   `protobuf:"varint,1,opt,name=enabled,proto3" json:"enabled,omitempty"`
	Ipv4Range     string                 `protobuf:"bytes,2,opt,name=ipv4_range,proto3" json:"ipv4_range,omitempty"`
	Ipv6Range     string                 `protobuf:"bytes,3,opt,name=ipv6_range,proto3" json:"ipv6_range,omitempty"`
	Whitelist     []string               `protobuf:"bytes,4,rep,name=whitelist,proto3" json:"whitelist,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *FakednsConfig) Reset() {
	*x = FakednsConfig{}
	mi := &file_config_dns_dns_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *FakednsConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FakednsConfig) ProtoMessage() {}

func (x *FakednsConfig) ProtoReflect() protoreflect.Message {
	mi := &file_config_dns_dns_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FakednsConfig.ProtoReflect.Descriptor instead.
func (*FakednsConfig) Descriptor() ([]byte, []int) {
	return file_config_dns_dns_proto_rawDescGZIP(), []int{2}
}

func (x *FakednsConfig) GetEnabled() bool {
	if x != nil {
		return x.Enabled
	}
	return false
}

func (x *FakednsConfig) GetIpv4Range() string {
	if x != nil {
		return x.Ipv4Range
	}
	return ""
}

func (x *FakednsConfig) GetIpv6Range() string {
	if x != nil {
		return x.Ipv6Range
	}
	return ""
}

func (x *FakednsConfig) GetWhitelist() []string {
	if x != nil {
		return x.Whitelist
	}
	return nil
}

var File_config_dns_dns_proto protoreflect.FileDescriptor

var file_config_dns_dns_proto_rawDesc = []byte{
	0x0a, 0x14, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x64, 0x6e, 0x73, 0x2f, 0x64, 0x6e, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x64, 0x6e, 0x73, 0x22, 0x80, 0x01, 0x0a, 0x03, 0x64, 0x6e, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x68,
	0x6f, 0x73, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x68, 0x6f, 0x73, 0x74, 0x12,
	0x25, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x11, 0x2e,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x64, 0x6e, 0x73, 0x2e, 0x74, 0x79, 0x70, 0x65,
	0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x75, 0x62, 0x6e, 0x65, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x75, 0x62, 0x6e, 0x65, 0x74, 0x12, 0x26,
	0x0a, 0x0e, 0x74, 0x6c, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x74, 0x6c, 0x73, 0x5f, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x97, 0x04, 0x0a, 0x0a, 0x64, 0x6e, 0x73, 0x5f, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x18, 0x0a,
	0x07, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x08, 0x52, 0x07,
	0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x12, 0x2a, 0x0a, 0x10, 0x66, 0x61, 0x6b, 0x65, 0x64,
	0x6e, 0x73, 0x5f, 0x69, 0x70, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x10, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x5f, 0x69, 0x70, 0x5f, 0x72, 0x61,
	0x6e, 0x67, 0x65, 0x12, 0x2e, 0x0a, 0x12, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x5f, 0x69,
	0x70, 0x76, 0x36, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x0d, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x12, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x5f, 0x69, 0x70, 0x76, 0x36, 0x5f, 0x72, 0x61,
	0x6e, 0x67, 0x65, 0x12, 0x2c, 0x0a, 0x11, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x5f, 0x77,
	0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x09, 0x20, 0x03, 0x28, 0x09, 0x52, 0x11,
	0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x5f, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73,
	0x74, 0x12, 0x38, 0x0a, 0x05, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x18, 0x08, 0x20, 0x03, 0x28, 0x0b,
	0x32, 0x22, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x64, 0x6e, 0x73, 0x2e, 0x64,
	0x6e, 0x73, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x05, 0x68, 0x6f, 0x73, 0x74, 0x73, 0x12, 0x41, 0x0a, 0x08, 0x72,
	0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x18, 0x0a, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x25, 0x2e,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x64, 0x6e, 0x73, 0x2e, 0x64, 0x6e, 0x73, 0x5f,
	0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x52, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x52, 0x08, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x72, 0x1a, 0x38,
	0x0a, 0x0a, 0x48, 0x6f, 0x73, 0x74, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03,
	0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x14,
	0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x1a, 0x4d, 0x0a, 0x0d, 0x52, 0x65, 0x73, 0x6f,
	0x6c, 0x76, 0x65, 0x72, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x26, 0x0a, 0x05, 0x76,
	0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x64, 0x6e, 0x73, 0x2e, 0x64, 0x6e, 0x73, 0x52, 0x05, 0x76, 0x61,
	0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x4a, 0x04, 0x08, 0x07, 0x10, 0x08, 0x4a, 0x04, 0x08,
	0x01, 0x10, 0x02, 0x4a, 0x04, 0x08, 0x02, 0x10, 0x03, 0x4a, 0x04, 0x08, 0x03, 0x10, 0x04, 0x52,
	0x15, 0x72, 0x65, 0x73, 0x6f, 0x6c, 0x76, 0x65, 0x5f, 0x72, 0x65, 0x6d, 0x6f, 0x74, 0x65, 0x5f,
	0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x52, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x52, 0x06, 0x72,
	0x65, 0x6d, 0x6f, 0x74, 0x65, 0x52, 0x09, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70,
	0x22, 0x88, 0x01, 0x0a, 0x0e, 0x66, 0x61, 0x6b, 0x65, 0x64, 0x6e, 0x73, 0x5f, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x12, 0x18, 0x0a, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x08, 0x52, 0x07, 0x65, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x64, 0x12, 0x1e, 0x0a,
	0x0a, 0x69, 0x70, 0x76, 0x34, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0a, 0x69, 0x70, 0x76, 0x34, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x1e, 0x0a,
	0x0a, 0x69, 0x70, 0x76, 0x36, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x0a, 0x69, 0x70, 0x76, 0x36, 0x5f, 0x72, 0x61, 0x6e, 0x67, 0x65, 0x12, 0x1c, 0x0a,
	0x09, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x18, 0x04, 0x20, 0x03, 0x28, 0x09,
	0x52, 0x09, 0x77, 0x68, 0x69, 0x74, 0x65, 0x6c, 0x69, 0x73, 0x74, 0x2a, 0x4a, 0x0a, 0x04, 0x74,
	0x79, 0x70, 0x65, 0x12, 0x0b, 0x0a, 0x07, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x10, 0x00,
	0x12, 0x07, 0x0a, 0x03, 0x75, 0x64, 0x70, 0x10, 0x01, 0x12, 0x07, 0x0a, 0x03, 0x74, 0x63, 0x70,
	0x10, 0x02, 0x12, 0x07, 0x0a, 0x03, 0x64, 0x6f, 0x68, 0x10, 0x03, 0x12, 0x07, 0x0a, 0x03, 0x64,
	0x6f, 0x74, 0x10, 0x04, 0x12, 0x07, 0x0a, 0x03, 0x64, 0x6f, 0x71, 0x10, 0x05, 0x12, 0x08, 0x0a,
	0x04, 0x64, 0x6f, 0x68, 0x33, 0x10, 0x06, 0x42, 0x34, 0x5a, 0x32, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41, 0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x64, 0x6e, 0x73, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_config_dns_dns_proto_rawDescOnce sync.Once
	file_config_dns_dns_proto_rawDescData = file_config_dns_dns_proto_rawDesc
)

func file_config_dns_dns_proto_rawDescGZIP() []byte {
	file_config_dns_dns_proto_rawDescOnce.Do(func() {
		file_config_dns_dns_proto_rawDescData = protoimpl.X.CompressGZIP(file_config_dns_dns_proto_rawDescData)
	})
	return file_config_dns_dns_proto_rawDescData
}

var file_config_dns_dns_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_config_dns_dns_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_config_dns_dns_proto_goTypes = []any{
	(Type)(0),             // 0: yuhaiin.dns.type
	(*Dns)(nil),           // 1: yuhaiin.dns.dns
	(*DnsConfig)(nil),     // 2: yuhaiin.dns.dns_config
	(*FakednsConfig)(nil), // 3: yuhaiin.dns.fakedns_config
	nil,                   // 4: yuhaiin.dns.dns_config.HostsEntry
	nil,                   // 5: yuhaiin.dns.dns_config.ResolverEntry
}
var file_config_dns_dns_proto_depIdxs = []int32{
	0, // 0: yuhaiin.dns.dns.type:type_name -> yuhaiin.dns.type
	4, // 1: yuhaiin.dns.dns_config.hosts:type_name -> yuhaiin.dns.dns_config.HostsEntry
	5, // 2: yuhaiin.dns.dns_config.resolver:type_name -> yuhaiin.dns.dns_config.ResolverEntry
	1, // 3: yuhaiin.dns.dns_config.ResolverEntry.value:type_name -> yuhaiin.dns.dns
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_config_dns_dns_proto_init() }
func file_config_dns_dns_proto_init() {
	if File_config_dns_dns_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_config_dns_dns_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_config_dns_dns_proto_goTypes,
		DependencyIndexes: file_config_dns_dns_proto_depIdxs,
		EnumInfos:         file_config_dns_dns_proto_enumTypes,
		MessageInfos:      file_config_dns_dns_proto_msgTypes,
	}.Build()
	File_config_dns_dns_proto = out.File
	file_config_dns_dns_proto_rawDesc = nil
	file_config_dns_dns_proto_goTypes = nil
	file_config_dns_dns_proto_depIdxs = nil
}
