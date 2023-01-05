// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.21.12
// source: config/log/log.proto

package log

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

type LogLevel int32

const (
	LogLevel_verbose LogLevel = 0
	LogLevel_debug   LogLevel = 1
	LogLevel_info    LogLevel = 2
	LogLevel_warning LogLevel = 3
	LogLevel_error   LogLevel = 4
	LogLevel_fatal   LogLevel = 5
)

// Enum value maps for LogLevel.
var (
	LogLevel_name = map[int32]string{
		0: "verbose",
		1: "debug",
		2: "info",
		3: "warning",
		4: "error",
		5: "fatal",
	}
	LogLevel_value = map[string]int32{
		"verbose": 0,
		"debug":   1,
		"info":    2,
		"warning": 3,
		"error":   4,
		"fatal":   5,
	}
)

func (x LogLevel) Enum() *LogLevel {
	p := new(LogLevel)
	*p = x
	return p
}

func (x LogLevel) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (LogLevel) Descriptor() protoreflect.EnumDescriptor {
	return file_config_log_log_proto_enumTypes[0].Descriptor()
}

func (LogLevel) Type() protoreflect.EnumType {
	return &file_config_log_log_proto_enumTypes[0]
}

func (x LogLevel) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use LogLevel.Descriptor instead.
func (LogLevel) EnumDescriptor() ([]byte, []int) {
	return file_config_log_log_proto_rawDescGZIP(), []int{0}
}

type Logcat struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Level LogLevel `protobuf:"varint,1,opt,name=level,proto3,enum=yuhaiin.log.LogLevel" json:"level,omitempty"`
	Save  bool     `protobuf:"varint,2,opt,name=save,proto3" json:"save,omitempty"`
}

func (x *Logcat) Reset() {
	*x = Logcat{}
	if protoimpl.UnsafeEnabled {
		mi := &file_config_log_log_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Logcat) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Logcat) ProtoMessage() {}

func (x *Logcat) ProtoReflect() protoreflect.Message {
	mi := &file_config_log_log_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Logcat.ProtoReflect.Descriptor instead.
func (*Logcat) Descriptor() ([]byte, []int) {
	return file_config_log_log_proto_rawDescGZIP(), []int{0}
}

func (x *Logcat) GetLevel() LogLevel {
	if x != nil {
		return x.Level
	}
	return LogLevel_verbose
}

func (x *Logcat) GetSave() bool {
	if x != nil {
		return x.Save
	}
	return false
}

var File_config_log_log_proto protoreflect.FileDescriptor

var file_config_log_log_proto_rawDesc = []byte{
	0x0a, 0x14, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x6c, 0x6f, 0x67, 0x2f, 0x6c, 0x6f, 0x67,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0b, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e,
	0x6c, 0x6f, 0x67, 0x22, 0x4a, 0x0a, 0x06, 0x6c, 0x6f, 0x67, 0x63, 0x61, 0x74, 0x12, 0x2c, 0x0a,
	0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x79,
	0x75, 0x68, 0x61, 0x69, 0x69, 0x6e, 0x2e, 0x6c, 0x6f, 0x67, 0x2e, 0x6c, 0x6f, 0x67, 0x5f, 0x6c,
	0x65, 0x76, 0x65, 0x6c, 0x52, 0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x12, 0x0a, 0x04, 0x73,
	0x61, 0x76, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x52, 0x04, 0x73, 0x61, 0x76, 0x65, 0x2a,
	0x50, 0x0a, 0x09, 0x6c, 0x6f, 0x67, 0x5f, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x0b, 0x0a, 0x07,
	0x76, 0x65, 0x72, 0x62, 0x6f, 0x73, 0x65, 0x10, 0x00, 0x12, 0x09, 0x0a, 0x05, 0x64, 0x65, 0x62,
	0x75, 0x67, 0x10, 0x01, 0x12, 0x08, 0x0a, 0x04, 0x69, 0x6e, 0x66, 0x6f, 0x10, 0x02, 0x12, 0x0b,
	0x0a, 0x07, 0x77, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67, 0x10, 0x03, 0x12, 0x09, 0x0a, 0x05, 0x65,
	0x72, 0x72, 0x6f, 0x72, 0x10, 0x04, 0x12, 0x09, 0x0a, 0x05, 0x66, 0x61, 0x74, 0x61, 0x6c, 0x10,
	0x05, 0x42, 0x34, 0x5a, 0x32, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x41, 0x73, 0x75, 0x74, 0x6f, 0x72, 0x75, 0x66, 0x61, 0x2f, 0x79, 0x75, 0x68, 0x61, 0x69, 0x69,
	0x6e, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2f, 0x6c, 0x6f, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_config_log_log_proto_rawDescOnce sync.Once
	file_config_log_log_proto_rawDescData = file_config_log_log_proto_rawDesc
)

func file_config_log_log_proto_rawDescGZIP() []byte {
	file_config_log_log_proto_rawDescOnce.Do(func() {
		file_config_log_log_proto_rawDescData = protoimpl.X.CompressGZIP(file_config_log_log_proto_rawDescData)
	})
	return file_config_log_log_proto_rawDescData
}

var file_config_log_log_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_config_log_log_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_config_log_log_proto_goTypes = []interface{}{
	(LogLevel)(0),  // 0: yuhaiin.log.log_level
	(*Logcat)(nil), // 1: yuhaiin.log.logcat
}
var file_config_log_log_proto_depIdxs = []int32{
	0, // 0: yuhaiin.log.logcat.level:type_name -> yuhaiin.log.log_level
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_config_log_log_proto_init() }
func file_config_log_log_proto_init() {
	if File_config_log_log_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_config_log_log_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Logcat); i {
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
			RawDescriptor: file_config_log_log_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_config_log_log_proto_goTypes,
		DependencyIndexes: file_config_log_log_proto_depIdxs,
		EnumInfos:         file_config_log_log_proto_enumTypes,
		MessageInfos:      file_config_log_log_proto_msgTypes,
	}.Build()
	File_config_log_log_proto = out.File
	file_config_log_log_proto_rawDesc = nil
	file_config_log_log_proto_goTypes = nil
	file_config_log_log_proto_depIdxs = nil
}
