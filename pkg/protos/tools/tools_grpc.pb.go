// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.3.0
// - protoc             v4.25.2
// source: tools/tools.proto

package tools

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

const (
	Tools_SaveRemoteBypassFile_FullMethodName = "/yuhaiin.tools.tools/save_remote_bypass_file"
)

// ToolsClient is the client API for Tools service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ToolsClient interface {
	// req: url
	SaveRemoteBypassFile(ctx context.Context, in *wrapperspb.StringValue, opts ...grpc.CallOption) (*emptypb.Empty, error)
}

type toolsClient struct {
	cc grpc.ClientConnInterface
}

func NewToolsClient(cc grpc.ClientConnInterface) ToolsClient {
	return &toolsClient{cc}
}

func (c *toolsClient) SaveRemoteBypassFile(ctx context.Context, in *wrapperspb.StringValue, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	out := new(emptypb.Empty)
	err := c.cc.Invoke(ctx, Tools_SaveRemoteBypassFile_FullMethodName, in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ToolsServer is the server API for Tools service.
// All implementations must embed UnimplementedToolsServer
// for forward compatibility
type ToolsServer interface {
	// req: url
	SaveRemoteBypassFile(context.Context, *wrapperspb.StringValue) (*emptypb.Empty, error)
	mustEmbedUnimplementedToolsServer()
}

// UnimplementedToolsServer must be embedded to have forward compatible implementations.
type UnimplementedToolsServer struct {
}

func (UnimplementedToolsServer) SaveRemoteBypassFile(context.Context, *wrapperspb.StringValue) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SaveRemoteBypassFile not implemented")
}
func (UnimplementedToolsServer) mustEmbedUnimplementedToolsServer() {}

// UnsafeToolsServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ToolsServer will
// result in compilation errors.
type UnsafeToolsServer interface {
	mustEmbedUnimplementedToolsServer()
}

func RegisterToolsServer(s grpc.ServiceRegistrar, srv ToolsServer) {
	s.RegisterService(&Tools_ServiceDesc, srv)
}

func _Tools_SaveRemoteBypassFile_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(wrapperspb.StringValue)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ToolsServer).SaveRemoteBypassFile(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: Tools_SaveRemoteBypassFile_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ToolsServer).SaveRemoteBypassFile(ctx, req.(*wrapperspb.StringValue))
	}
	return interceptor(ctx, in, info, handler)
}

// Tools_ServiceDesc is the grpc.ServiceDesc for Tools service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Tools_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "yuhaiin.tools.tools",
	HandlerType: (*ToolsServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "save_remote_bypass_file",
			Handler:    _Tools_SaveRemoteBypassFile_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "tools/tools.proto",
}
