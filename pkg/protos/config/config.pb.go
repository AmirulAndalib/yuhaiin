// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        v5.28.3
// source: config/config.proto

package config

import (
	bypass "github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	dns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	listener "github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	log "github.com/Asutorufa/yuhaiin/pkg/protos/config/log"
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

type Setting struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ipv6                       bool `protobuf:"varint,7,opt,name=ipv6,proto3" json:"ipv6,omitempty"`
	Ipv6LocalAddrPreferUnicast bool `protobuf:"varint,10,opt,name=ipv6_local_addr_prefer_unicast,proto3" json:"ipv6_local_addr_prefer_unicast,omitempty"`
	// net_interface, eg: eth0
	NetInterface  string                  `protobuf:"bytes,6,opt,name=net_interface,proto3" json:"net_interface,omitempty"`
	SystemProxy   *SystemProxy            `protobuf:"bytes,1,opt,name=system_proxy,proto3" json:"system_proxy,omitempty"`
	Bypass        *bypass.Config          `protobuf:"bytes,2,opt,name=bypass,proto3" json:"bypass,omitempty"`
	Dns           *dns.DnsConfig          `protobuf:"bytes,4,opt,name=dns,proto3" json:"dns,omitempty"`
	Server        *listener.InboundConfig `protobuf:"bytes,5,opt,name=server,proto3" json:"server,omitempty"`
	Logcat        *log.Logcat             `protobuf:"bytes,8,opt,name=logcat,proto3" json:"logcat,omitempty"`
	ConfigVersion *ConfigVersion          `protobuf:"bytes,9,opt,name=config_version,proto3" json:"config_version,omitempty"`
	Platform      *Platform               `protobuf:"bytes,11,opt,name=platform,proto3" json:"platform,omitempty"`
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

func (x *Setting) GetIpv6() bool {
	if x != nil {
		return x.Ipv6
	}
	return false
}

func (x *Setting) GetIpv6LocalAddrPreferUnicast() bool {
	if x != nil {
		return x.Ipv6LocalAddrPreferUnicast
	}
	return false
}

func (x *Setting) GetNetInterface() string {
	if x != nil {
		return x.NetInterface
	}
	return ""
}

func (x *Setting) GetSystemProxy() *SystemProxy {
	if x != nil {
		return x.SystemProxy
	}
	return nil
}

func (x *Setting) GetBypass() *bypass.Config {
	if x != nil {
		return x.Bypass
	}
	return nil
}

func (x *Setting) GetDns() *dns.DnsConfig {
	if x != nil {
		return x.Dns
	}
	return nil
}

func (x *Setting) GetServer() *listener.InboundConfig {
	if x != nil {
		return x.Server
	}
	return nil
}

func (x *Setting) GetLogcat() *log.Logcat {
	if x != nil {
		return x.Logcat
	}
	return nil
}

func (x *Setting) GetConfigVersion() *ConfigVersion {
	if x != nil {
		return x.ConfigVersion
	}
	return nil
}

func (x *Setting) GetPlatform() *Platform {
	if x != nil {
		return x.Platform
	}
	return nil
}

type SystemProxy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Http   bool `protobuf:"varint,2,opt,name=http,proto3" json:"http,omitempty"`
	Socks5 bool `protobuf:"varint,3,opt,name=socks5,proto3" json:"socks5,omitempty"`
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

func (x *SystemProxy) GetHttp() bool {
	if x != nil {
		return x.Http
	}
	return false
}

func (x *SystemProxy) GetSocks5() bool {
	if x != nil {
		return x.Socks5
	}
	return false
}

type Info struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version   string   `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	Commit    string   `protobuf:"bytes,2,opt,name=commit,proto3" json:"commit,omitempty"`
	BuildTime string   `protobuf:"bytes,3,opt,name=build_time,proto3" json:"build_time,omitempty"`
	GoVersion string   `protobuf:"bytes,4,opt,name=go_version,proto3" json:"go_version,omitempty"`
	Arch      string   `protobuf:"bytes,5,opt,name=arch,proto3" json:"arch,omitempty"`
	Platform  string   `protobuf:"bytes,6,opt,name=platform,proto3" json:"platform,omitempty"`
	Os        string   `protobuf:"bytes,7,opt,name=os,proto3" json:"os,omitempty"`
	Compiler  string   `protobuf:"bytes,8,opt,name=compiler,proto3" json:"compiler,omitempty"`
	Build     []string `protobuf:"bytes,9,rep,name=build,proto3" json:"build,omitempty"`
}

func (x *Info) Reset() {
	*x = Info{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_config_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Info) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Info) ProtoMessage() {}

func (x *Info) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use Info.ProtoReflect.Descriptor instead.
func (*Info) Descriptor() ([]byte, []int) {
	return file_config_config_proto_rawDescGZIP(), []int{2}
}

func (x *Info) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *Info) GetCommit() string {
	if x != nil {
		return x.Commit
	}
	return ""
}

func (x *Info) GetBuildTime() string {
	if x != nil {
		return x.BuildTime
	}
	return ""
}

func (x *Info) GetGoVersion() string {
	if x != nil {
		return x.GoVersion
	}
	return ""
}

func (x *Info) GetArch() string {
	if x != nil {
		return x.Arch
	}
	return ""
}

func (x *Info) GetPlatform() string {
	if x != nil {
		return x.Platform
	}
	return ""
}

func (x *Info) GetOs() string {
	if x != nil {
		return x.Os
	}
	return ""
}

func (x *Info) GetCompiler() string {
	if x != nil {
		return x.Compiler
	}
	return ""
}

func (x *Info) GetBuild() []string {
	if x != nil {
		return x.Build
	}
	return nil
}

type ConfigVersion struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version uint64 `protobuf:"varint,1,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *ConfigVersion) Reset() {
	*x = ConfigVersion{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_config_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigVersion) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigVersion) ProtoMessage() {}

func (x *ConfigVersion) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use ConfigVersion.ProtoReflect.Descriptor instead.
func (*ConfigVersion) Descriptor() ([]byte, []int) {
	return file_config_config_proto_rawDescGZIP(), []int{3}
}

func (x *ConfigVersion) GetVersion() uint64 {
	if x != nil {
		return x.Version
	}
	return 0
}

type Platform struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AndroidApp bool `protobuf:"varint,1,opt,name=android_app,proto3" json:"android_app,omitempty"`
}

func (x *Platform) Reset() {
	*x = Platform{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_config_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Platform) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Platform) ProtoMessage() {}

func (x *Platform) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use Platform.ProtoReflect.Descriptor instead.
func (*Platform) Descriptor() ([]byte, []int) {
	return file_config_config_proto_rawDescGZIP(), []int{4}
}

func (x *Platform) GetAndroidApp() bool {
	if x != nil {
		return x.AndroidApp
	}
	return false
}

var File_config_config_proto protoreflect.FileDescriptor

var file_config_config_proto_rawDesc = []byte{
	0x0a, 0x13, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x1a, 0x14, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x6c, 0x6f,
	0x67, 0x2f, 0x6c, 0x6f, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1a, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2f, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x2f, 0x62, 0x79, 0x70, 0x61, 0x73,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x14, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f,
	0x64, 0x6e, 0x73, 0x2f, 0x64, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x2f, 0x6c,
	0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8d, 0x04,
	0x0a, 0x07, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x12, 0x12, 0x0a, 0x04, 0x69, 0x70, 0x76,
	0x36, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x04, 0x69, 0x70, 0x76, 0x36, 0x12, 0x46, 0x0a,
	0x1e, 0x69, 0x70, 0x76, 0x36, 0x5f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x5f, 0x61, 0x64, 0x64, 0x72,
	0x5f, 0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x5f, 0x75, 0x6e, 0x69, 0x63, 0x61, 0x73, 0x74, 0x18,
	0x0a, 0x20, 0x01, 0x28, 0x08, 0x52, 0x1e, 0x69, 0x70, 0x76, 0x36, 0x5f, 0x6c, 0x6f, 0x63, 0x61,
	0x6c, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x5f, 0x70, 0x72, 0x65, 0x66, 0x65, 0x72, 0x5f, 0x75, 0x6e,
	0x69, 0x63, 0x61, 0x73, 0x74, 0x12, 0x24, 0x0a, 0x0d, 0x6e, 0x65, 0x74, 0x5f, 0x69, 0x6e, 0x74,
	0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x6e, 0x65,
	0x74, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x66, 0x61, 0x63, 0x65, 0x12, 0x40, 0x0a, 0x0c, 0x73,
	0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x1c, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2e, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x52,
	0x0c, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x12, 0x2e, 0x0a,
	0x06, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16, 0x2e,
	0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x2e, 0x63,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x06, 0x62, 0x79, 0x70, 0x61, 0x73, 0x73, 0x12, 0x29, 0x0a,
	0x03, 0x64, 0x6e, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x79, 0x75, 0x68,
	0x61, 0x69, 0x69, 0x6e, 0x2e, 0x64, 0x6e, 0x73, 0x2e, 0x64, 0x6e, 0x73, 0x5f, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x52, 0x03, 0x64, 0x6e, 0x73, 0x12, 0x38, 0x0a, 0x06, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x20, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69,
	0x69, 0x6e, 0x2e, 0x6c, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x65, 0x72, 0x2e, 0x69, 0x6e, 0x62, 0x6f,
	0x75, 0x6e, 0x64, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x06, 0x73, 0x65, 0x72, 0x76,
	0x65, 0x72, 0x12, 0x2b, 0x0a, 0x06, 0x6c, 0x6f, 0x67, 0x63, 0x61, 0x74, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x13, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x6f, 0x67,
	0x2e, 0x6c, 0x6f, 0x67, 0x63, 0x61, 0x74, 0x52, 0x06, 0x6c, 0x6f, 0x67, 0x63, 0x61, 0x74, 0x12,
	0x46, 0x0a, 0x0e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1e, 0x2e, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69,
	0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x0e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x5f,
	0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x34, 0x0a, 0x08, 0x70, 0x6c, 0x61, 0x74, 0x66,
	0x6f, 0x72, 0x6d, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x79, 0x75, 0x68, 0x61,
	0x69, 0x69, 0x6e, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x70, 0x6c, 0x61, 0x74, 0x66,
	0x6f, 0x72, 0x6d, 0x52, 0x08, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x22, 0x3a, 0x0a,
	0x0c, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x12, 0x12, 0x0a,
	0x04, 0x68, 0x74, 0x74, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x04, 0x68, 0x74, 0x74,
	0x70, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x6f, 0x63, 0x6b, 0x73, 0x35, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x08, 0x52, 0x06, 0x73, 0x6f, 0x63, 0x6b, 0x73, 0x35, 0x22, 0xea, 0x01, 0x0a, 0x04, 0x69, 0x6e,
	0x66, 0x6f, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x16, 0x0a, 0x06,
	0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x63, 0x6f,
	0x6d, 0x6d, 0x69, 0x74, 0x12, 0x1e, 0x0a, 0x0a, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f, 0x74, 0x69,
	0x6d, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x5f,
	0x74, 0x69, 0x6d, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x67, 0x6f, 0x5f, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x67, 0x6f, 0x5f, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x12, 0x12, 0x0a, 0x04, 0x61, 0x72, 0x63, 0x68, 0x18, 0x05, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x61, 0x72, 0x63, 0x68, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x6c, 0x61, 0x74,
	0x66, 0x6f, 0x72, 0x6d, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x6c, 0x61, 0x74,
	0x66, 0x6f, 0x72, 0x6d, 0x12, 0x0e, 0x0a, 0x02, 0x6f, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x02, 0x6f, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x63, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72,
	0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63, 0x6f, 0x6d, 0x70, 0x69, 0x6c, 0x65, 0x72,
	0x12, 0x14, 0x0a, 0x05, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x18, 0x09, 0x20, 0x03, 0x28, 0x09, 0x52,
	0x05, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x22, 0x2a, 0x0a, 0x0e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x5f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69,
	0x6f, 0x6e, 0x22, 0x2c, 0x0a, 0x08, 0x70, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x12, 0x20,
	0x0a, 0x0b, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x5f, 0x61, 0x70, 0x70, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x0b, 0x61, 0x6e, 0x64, 0x72, 0x6f, 0x69, 0x64, 0x5f, 0x61, 0x70, 0x70,
	0x42, 0x30, 0x5a, 0x2e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41,
	0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e,
	0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
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
var file_config_config_proto_goTypes = []any{
	(*Setting)(nil),                // 0: yuhaiin.config.setting
	(*SystemProxy)(nil),            // 1: yuhaiin.config.system_proxy
	(*Info)(nil),                   // 2: yuhaiin.config.info
	(*ConfigVersion)(nil),          // 3: yuhaiin.config.config_version
	(*Platform)(nil),               // 4: yuhaiin.config.platform
	(*bypass.Config)(nil),          // 5: yuhaiin.bypass.config
	(*dns.DnsConfig)(nil),          // 6: yuhaiin.dns.dns_config
	(*listener.InboundConfig)(nil), // 7: yuhaiin.listener.inbound_config
	(*log.Logcat)(nil),             // 8: yuhaiin.log.logcat
}
var file_config_config_proto_depIdxs = []int32{
	1, // 0: yuhaiin.config.setting.system_proxy:type_name -> yuhaiin.config.system_proxy
	5, // 1: yuhaiin.config.setting.bypass:type_name -> yuhaiin.bypass.config
	6, // 2: yuhaiin.config.setting.dns:type_name -> yuhaiin.dns.dns_config
	7, // 3: yuhaiin.config.setting.server:type_name -> yuhaiin.listener.inbound_config
	8, // 4: yuhaiin.config.setting.logcat:type_name -> yuhaiin.log.logcat
	3, // 5: yuhaiin.config.setting.config_version:type_name -> yuhaiin.config.config_version
	4, // 6: yuhaiin.config.setting.platform:type_name -> yuhaiin.config.platform
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_config_config_proto_init() }
func file_config_config_proto_init() {
	if File_config_config_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_config_config_proto_msgTypes[0].Exporter = func(v any, i int) any {
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
		file_config_config_proto_msgTypes[1].Exporter = func(v any, i int) any {
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
		file_config_config_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*Info); i {
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
		file_config_config_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*ConfigVersion); i {
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
		file_config_config_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*Platform); i {
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
