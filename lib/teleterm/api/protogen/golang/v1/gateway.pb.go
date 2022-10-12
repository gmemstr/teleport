// Copyright 2021 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        (unknown)
// source: v1/gateway.proto

package v1

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

// Gateway is Teleterm's name for a connection to a resource like a database or a web app
// established through our ALPN proxy.
//
// The term "gateway" is used to avoid using the term "proxy" itself which could be confusing as
// "proxy" means a couple of different things depending on the context. But for Teleterm, a gateway
// is always an ALPN proxy connection.
//
// See RFD 39 for more info on ALPN.
type Gateway struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// uri is the gateway uri
	Uri string `protobuf:"bytes,1,opt,name=uri,proto3" json:"uri,omitempty"`
	// target_name is the target resource name
	TargetName string `protobuf:"bytes,2,opt,name=target_name,json=targetName,proto3" json:"target_name,omitempty"`
	// target_uri is the target uri
	TargetUri string `protobuf:"bytes,3,opt,name=target_uri,json=targetUri,proto3" json:"target_uri,omitempty"`
	// target_user is the target user
	TargetUser string `protobuf:"bytes,4,opt,name=target_user,json=targetUser,proto3" json:"target_user,omitempty"`
	// local_address is the gateway address on localhost
	LocalAddress string `protobuf:"bytes,5,opt,name=local_address,json=localAddress,proto3" json:"local_address,omitempty"`
	// local_port is the gateway address on localhost
	LocalPort string `protobuf:"bytes,6,opt,name=local_port,json=localPort,proto3" json:"local_port,omitempty"`
	// protocol is the gateway protocol
	Protocol string `protobuf:"bytes,7,opt,name=protocol,proto3" json:"protocol,omitempty"`
	// cli_command is a command that the user can execute to connect to the resource within a CLI,
	// if the given resource has a CLI client.
	//
	// Instead of generating those commands in in the frontend code, the tsh daemon returns them.
	// This means that the Database Access team can add support for a new protocol and Teleterm will
	// support it right away without any changes to Teleterm's code.
	CliCommand string `protobuf:"bytes,8,opt,name=cli_command,json=cliCommand,proto3" json:"cli_command,omitempty"`
	// target_subresource_name points at a subresource of the remote resource, for example a
	// database name on a database server.
	TargetSubresourceName string `protobuf:"bytes,9,opt,name=target_subresource_name,json=targetSubresourceName,proto3" json:"target_subresource_name,omitempty"`
}

func (x *Gateway) Reset() {
	*x = Gateway{}
	if protoimpl.UnsafeEnabled {
		mi := &file_v1_gateway_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Gateway) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Gateway) ProtoMessage() {}

func (x *Gateway) ProtoReflect() protoreflect.Message {
	mi := &file_v1_gateway_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Gateway.ProtoReflect.Descriptor instead.
func (*Gateway) Descriptor() ([]byte, []int) {
	return file_v1_gateway_proto_rawDescGZIP(), []int{0}
}

func (x *Gateway) GetUri() string {
	if x != nil {
		return x.Uri
	}
	return ""
}

func (x *Gateway) GetTargetName() string {
	if x != nil {
		return x.TargetName
	}
	return ""
}

func (x *Gateway) GetTargetUri() string {
	if x != nil {
		return x.TargetUri
	}
	return ""
}

func (x *Gateway) GetTargetUser() string {
	if x != nil {
		return x.TargetUser
	}
	return ""
}

func (x *Gateway) GetLocalAddress() string {
	if x != nil {
		return x.LocalAddress
	}
	return ""
}

func (x *Gateway) GetLocalPort() string {
	if x != nil {
		return x.LocalPort
	}
	return ""
}

func (x *Gateway) GetProtocol() string {
	if x != nil {
		return x.Protocol
	}
	return ""
}

func (x *Gateway) GetCliCommand() string {
	if x != nil {
		return x.CliCommand
	}
	return ""
}

func (x *Gateway) GetTargetSubresourceName() string {
	if x != nil {
		return x.TargetSubresourceName
	}
	return ""
}

var File_v1_gateway_proto protoreflect.FileDescriptor

var file_v1_gateway_proto_rawDesc = []byte{
	0x0a, 0x10, 0x76, 0x31, 0x2f, 0x67, 0x61, 0x74, 0x65, 0x77, 0x61, 0x79, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x14, 0x74, 0x65, 0x6c, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x2e, 0x74, 0x65, 0x72,
	0x6d, 0x69, 0x6e, 0x61, 0x6c, 0x2e, 0x76, 0x31, 0x22, 0xb5, 0x02, 0x0a, 0x07, 0x47, 0x61, 0x74,
	0x65, 0x77, 0x61, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x72, 0x69, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x75, 0x72, 0x69, 0x12, 0x1f, 0x0a, 0x0b, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
	0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x1d, 0x0a, 0x0a, 0x74, 0x61, 0x72, 0x67, 0x65,
	0x74, 0x5f, 0x75, 0x72, 0x69, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x55, 0x72, 0x69, 0x12, 0x1f, 0x0a, 0x0b, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74,
	0x5f, 0x75, 0x73, 0x65, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x74, 0x61, 0x72,
	0x67, 0x65, 0x74, 0x55, 0x73, 0x65, 0x72, 0x12, 0x23, 0x0a, 0x0d, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
	0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c,
	0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x1d, 0x0a, 0x0a,
	0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x1a, 0x0a, 0x08, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f, 0x6c, 0x12, 0x1f, 0x0a, 0x0b, 0x63, 0x6c, 0x69, 0x5f, 0x63,
	0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0a, 0x63, 0x6c,
	0x69, 0x43, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64, 0x12, 0x36, 0x0a, 0x17, 0x74, 0x61, 0x72, 0x67,
	0x65, 0x74, 0x5f, 0x73, 0x75, 0x62, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x6e,
	0x61, 0x6d, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x15, 0x74, 0x61, 0x72, 0x67, 0x65,
	0x74, 0x53, 0x75, 0x62, 0x72, 0x65, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4e, 0x61, 0x6d, 0x65,
	0x42, 0x33, 0x5a, 0x31, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67,
	0x72, 0x61, 0x76, 0x69, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x6c, 0x2f, 0x74, 0x65, 0x6c,
	0x65, 0x70, 0x6f, 0x72, 0x74, 0x2f, 0x6c, 0x69, 0x62, 0x2f, 0x74, 0x65, 0x6c, 0x65, 0x74, 0x65,
	0x72, 0x6d, 0x2f, 0x76, 0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_v1_gateway_proto_rawDescOnce sync.Once
	file_v1_gateway_proto_rawDescData = file_v1_gateway_proto_rawDesc
)

func file_v1_gateway_proto_rawDescGZIP() []byte {
	file_v1_gateway_proto_rawDescOnce.Do(func() {
		file_v1_gateway_proto_rawDescData = protoimpl.X.CompressGZIP(file_v1_gateway_proto_rawDescData)
	})
	return file_v1_gateway_proto_rawDescData
}

var file_v1_gateway_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_v1_gateway_proto_goTypes = []interface{}{
	(*Gateway)(nil), // 0: teleport.terminal.v1.Gateway
}
var file_v1_gateway_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_v1_gateway_proto_init() }
func file_v1_gateway_proto_init() {
	if File_v1_gateway_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_v1_gateway_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Gateway); i {
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
			RawDescriptor: file_v1_gateway_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_v1_gateway_proto_goTypes,
		DependencyIndexes: file_v1_gateway_proto_depIdxs,
		MessageInfos:      file_v1_gateway_proto_msgTypes,
	}.Build()
	File_v1_gateway_proto = out.File
	file_v1_gateway_proto_rawDesc = nil
	file_v1_gateway_proto_goTypes = nil
	file_v1_gateway_proto_depIdxs = nil
}
