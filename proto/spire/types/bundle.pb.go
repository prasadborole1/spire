// Code generated by protoc-gen-go. DO NOT EDIT.
// source: spire/types/bundle.proto

package types

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Bundle struct {
	// The name of the trust domain the bundle belongs to (e.g., "example.org").
	TrustDomain string `protobuf:"bytes,1,opt,name=trust_domain,json=trustDomain,proto3" json:"trust_domain,omitempty"`
	// X.509 authorities for authenticating X509-SVIDs.
	X509Authorities []*X509Certificate `protobuf:"bytes,2,rep,name=x509_authorities,json=x509Authorities,proto3" json:"x509_authorities,omitempty"`
	// JWT authorities for authenticating JWT-SVIDs.
	JwtAuthorities []*JWTKey `protobuf:"bytes,3,rep,name=jwt_authorities,json=jwtAuthorities,proto3" json:"jwt_authorities,omitempty"`
	// A hint on how often the bundle should be refreshed from the bundle
	// provider, in seconds. Can be zero (meaning no hint available).
	RefreshHint int64 `protobuf:"varint,4,opt,name=refresh_hint,json=refreshHint,proto3" json:"refresh_hint,omitempty"`
	// The sequence number of the bundle.
	SequenceNumber       uint64   `protobuf:"varint,5,opt,name=sequence_number,json=sequenceNumber,proto3" json:"sequence_number,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Bundle) Reset()         { *m = Bundle{} }
func (m *Bundle) String() string { return proto.CompactTextString(m) }
func (*Bundle) ProtoMessage()    {}
func (*Bundle) Descriptor() ([]byte, []int) {
	return fileDescriptor_b2e29b9c8a236a2b, []int{0}
}

func (m *Bundle) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Bundle.Unmarshal(m, b)
}
func (m *Bundle) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Bundle.Marshal(b, m, deterministic)
}
func (m *Bundle) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Bundle.Merge(m, src)
}
func (m *Bundle) XXX_Size() int {
	return xxx_messageInfo_Bundle.Size(m)
}
func (m *Bundle) XXX_DiscardUnknown() {
	xxx_messageInfo_Bundle.DiscardUnknown(m)
}

var xxx_messageInfo_Bundle proto.InternalMessageInfo

func (m *Bundle) GetTrustDomain() string {
	if m != nil {
		return m.TrustDomain
	}
	return ""
}

func (m *Bundle) GetX509Authorities() []*X509Certificate {
	if m != nil {
		return m.X509Authorities
	}
	return nil
}

func (m *Bundle) GetJwtAuthorities() []*JWTKey {
	if m != nil {
		return m.JwtAuthorities
	}
	return nil
}

func (m *Bundle) GetRefreshHint() int64 {
	if m != nil {
		return m.RefreshHint
	}
	return 0
}

func (m *Bundle) GetSequenceNumber() uint64 {
	if m != nil {
		return m.SequenceNumber
	}
	return 0
}

type X509Certificate struct {
	// The ASN.1 DER encoded bytes of the X.509 certificate.
	Asn1                 []byte   `protobuf:"bytes,1,opt,name=asn1,proto3" json:"asn1,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *X509Certificate) Reset()         { *m = X509Certificate{} }
func (m *X509Certificate) String() string { return proto.CompactTextString(m) }
func (*X509Certificate) ProtoMessage()    {}
func (*X509Certificate) Descriptor() ([]byte, []int) {
	return fileDescriptor_b2e29b9c8a236a2b, []int{1}
}

func (m *X509Certificate) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_X509Certificate.Unmarshal(m, b)
}
func (m *X509Certificate) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_X509Certificate.Marshal(b, m, deterministic)
}
func (m *X509Certificate) XXX_Merge(src proto.Message) {
	xxx_messageInfo_X509Certificate.Merge(m, src)
}
func (m *X509Certificate) XXX_Size() int {
	return xxx_messageInfo_X509Certificate.Size(m)
}
func (m *X509Certificate) XXX_DiscardUnknown() {
	xxx_messageInfo_X509Certificate.DiscardUnknown(m)
}

var xxx_messageInfo_X509Certificate proto.InternalMessageInfo

func (m *X509Certificate) GetAsn1() []byte {
	if m != nil {
		return m.Asn1
	}
	return nil
}

type JWTKey struct {
	// The PKIX encoded public key.
	PublicKey []byte `protobuf:"bytes,1,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	// The key identifier.
	KeyId string `protobuf:"bytes,2,opt,name=key_id,json=keyId,proto3" json:"key_id,omitempty"`
	// When the key expires (seconds since Unix epoch). If zero, the key does
	// not expire.
	ExpiresAt            int64    `protobuf:"varint,3,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *JWTKey) Reset()         { *m = JWTKey{} }
func (m *JWTKey) String() string { return proto.CompactTextString(m) }
func (*JWTKey) ProtoMessage()    {}
func (*JWTKey) Descriptor() ([]byte, []int) {
	return fileDescriptor_b2e29b9c8a236a2b, []int{2}
}

func (m *JWTKey) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_JWTKey.Unmarshal(m, b)
}
func (m *JWTKey) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_JWTKey.Marshal(b, m, deterministic)
}
func (m *JWTKey) XXX_Merge(src proto.Message) {
	xxx_messageInfo_JWTKey.Merge(m, src)
}
func (m *JWTKey) XXX_Size() int {
	return xxx_messageInfo_JWTKey.Size(m)
}
func (m *JWTKey) XXX_DiscardUnknown() {
	xxx_messageInfo_JWTKey.DiscardUnknown(m)
}

var xxx_messageInfo_JWTKey proto.InternalMessageInfo

func (m *JWTKey) GetPublicKey() []byte {
	if m != nil {
		return m.PublicKey
	}
	return nil
}

func (m *JWTKey) GetKeyId() string {
	if m != nil {
		return m.KeyId
	}
	return ""
}

func (m *JWTKey) GetExpiresAt() int64 {
	if m != nil {
		return m.ExpiresAt
	}
	return 0
}

type BundleMask struct {
	// x509_authorities field mask.
	X509Authorities bool `protobuf:"varint,2,opt,name=x509_authorities,json=x509Authorities,proto3" json:"x509_authorities,omitempty"`
	// jwt_authorities field mask.
	JwtAuthorities bool `protobuf:"varint,3,opt,name=jwt_authorities,json=jwtAuthorities,proto3" json:"jwt_authorities,omitempty"`
	// refresh_hint field mask.
	RefreshHint bool `protobuf:"varint,4,opt,name=refresh_hint,json=refreshHint,proto3" json:"refresh_hint,omitempty"`
	// sequence_number field mask.
	SequenceNumber       bool     `protobuf:"varint,5,opt,name=sequence_number,json=sequenceNumber,proto3" json:"sequence_number,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *BundleMask) Reset()         { *m = BundleMask{} }
func (m *BundleMask) String() string { return proto.CompactTextString(m) }
func (*BundleMask) ProtoMessage()    {}
func (*BundleMask) Descriptor() ([]byte, []int) {
	return fileDescriptor_b2e29b9c8a236a2b, []int{3}
}

func (m *BundleMask) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BundleMask.Unmarshal(m, b)
}
func (m *BundleMask) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BundleMask.Marshal(b, m, deterministic)
}
func (m *BundleMask) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BundleMask.Merge(m, src)
}
func (m *BundleMask) XXX_Size() int {
	return xxx_messageInfo_BundleMask.Size(m)
}
func (m *BundleMask) XXX_DiscardUnknown() {
	xxx_messageInfo_BundleMask.DiscardUnknown(m)
}

var xxx_messageInfo_BundleMask proto.InternalMessageInfo

func (m *BundleMask) GetX509Authorities() bool {
	if m != nil {
		return m.X509Authorities
	}
	return false
}

func (m *BundleMask) GetJwtAuthorities() bool {
	if m != nil {
		return m.JwtAuthorities
	}
	return false
}

func (m *BundleMask) GetRefreshHint() bool {
	if m != nil {
		return m.RefreshHint
	}
	return false
}

func (m *BundleMask) GetSequenceNumber() bool {
	if m != nil {
		return m.SequenceNumber
	}
	return false
}

func init() {
	proto.RegisterType((*Bundle)(nil), "spire.types.Bundle")
	proto.RegisterType((*X509Certificate)(nil), "spire.types.X509Certificate")
	proto.RegisterType((*JWTKey)(nil), "spire.types.JWTKey")
	proto.RegisterType((*BundleMask)(nil), "spire.types.BundleMask")
}

func init() {
	proto.RegisterFile("spire/types/bundle.proto", fileDescriptor_b2e29b9c8a236a2b)
}

var fileDescriptor_b2e29b9c8a236a2b = []byte{
	// 380 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x92, 0x5d, 0x6b, 0xe2, 0x40,
	0x14, 0x86, 0x89, 0xd1, 0xa0, 0x13, 0x31, 0xcb, 0x2c, 0x0b, 0xb9, 0xd8, 0x85, 0x18, 0x58, 0x8c,
	0x2c, 0x24, 0xee, 0x2e, 0x5e, 0x08, 0x7b, 0xa3, 0xbb, 0xb0, 0x5f, 0xb4, 0x17, 0xa1, 0xd0, 0x52,
	0x28, 0x21, 0x1f, 0x27, 0xcd, 0x18, 0x4d, 0xd2, 0x99, 0x09, 0x9a, 0xff, 0xd4, 0xdf, 0x58, 0x4a,
	0x26, 0x96, 0xaa, 0xf5, 0xc2, 0xbb, 0xf0, 0x9c, 0x73, 0x5e, 0x4e, 0x9e, 0x39, 0x48, 0x67, 0x05,
	0xa1, 0xe0, 0xf0, 0xaa, 0x00, 0xe6, 0x04, 0x65, 0x16, 0xad, 0xc0, 0x2e, 0x68, 0xce, 0x73, 0xac,
	0x8a, 0x8a, 0x2d, 0x2a, 0xe6, 0x93, 0x84, 0x94, 0x85, 0xa8, 0xe2, 0x21, 0xea, 0x73, 0x5a, 0x32,
	0xee, 0x45, 0xf9, 0xda, 0x27, 0x99, 0x2e, 0x19, 0x92, 0xd5, 0x73, 0x55, 0xc1, 0x7e, 0x09, 0x84,
	0x7f, 0xa3, 0x77, 0xdb, 0xe9, 0x64, 0xe6, 0xf9, 0x25, 0x4f, 0x72, 0x4a, 0x38, 0x01, 0xa6, 0xb7,
	0x0c, 0xd9, 0x52, 0xbf, 0x7d, 0xb4, 0xf7, 0x52, 0xed, 0x9b, 0xe9, 0x64, 0xf6, 0x13, 0x28, 0x27,
	0x31, 0x09, 0x7d, 0x0e, 0xae, 0x56, 0x4f, 0xcd, 0x5f, 0x87, 0xf0, 0x0f, 0xa4, 0x2d, 0x37, 0xfc,
	0x20, 0x47, 0x16, 0x39, 0xef, 0x0f, 0x72, 0xfe, 0x5d, 0x5f, 0xfd, 0x87, 0xca, 0x1d, 0x2c, 0x37,
	0x7c, 0x7f, 0x7a, 0x88, 0xfa, 0x14, 0x62, 0x0a, 0x2c, 0xf1, 0x12, 0x92, 0x71, 0xbd, 0x6d, 0x48,
	0x96, 0xec, 0xaa, 0x3b, 0xf6, 0x87, 0x64, 0x1c, 0x8f, 0x90, 0xc6, 0xe0, 0xa1, 0x84, 0x2c, 0x04,
	0x2f, 0x2b, 0xd7, 0x01, 0x50, 0xbd, 0x63, 0x48, 0x56, 0xdb, 0x1d, 0xbc, 0xe0, 0x4b, 0x41, 0xcd,
	0xcf, 0x48, 0x3b, 0xda, 0x16, 0x63, 0xd4, 0xf6, 0x59, 0xf6, 0x55, 0x08, 0xe8, 0xbb, 0xe2, 0xdb,
	0xbc, 0x43, 0x4a, 0xb3, 0x0c, 0xfe, 0x84, 0x50, 0x51, 0x06, 0x2b, 0x12, 0x7a, 0x29, 0x54, 0xbb,
	0x9e, 0x5e, 0x43, 0xea, 0xf2, 0x07, 0xa4, 0xa4, 0x50, 0x79, 0x24, 0xd2, 0x5b, 0xc2, 0x5f, 0x27,
	0x85, 0xea, 0x6f, 0x54, 0x4f, 0xc1, 0xb6, 0xfe, 0x33, 0xe6, 0xf9, 0x5c, 0x97, 0xc5, 0xc2, 0xbd,
	0x1d, 0x99, 0x73, 0xf3, 0x51, 0x42, 0xa8, 0x79, 0x86, 0x0b, 0x9f, 0xa5, 0x78, 0x7c, 0xd2, 0xb3,
	0x64, 0x75, 0xdf, 0x9a, 0x1c, 0x9d, 0x32, 0x59, 0x77, 0x9e, 0x23, 0xad, 0x7b, 0x96, 0xb4, 0xee,
	0xb1, 0xb4, 0xc5, 0x97, 0xdb, 0xf1, 0x3d, 0xe1, 0x49, 0x19, 0xd8, 0x61, 0xbe, 0x76, 0x58, 0x41,
	0xe2, 0x18, 0x9c, 0xe6, 0xe0, 0xc4, 0x8d, 0x39, 0x7b, 0xc7, 0x17, 0x28, 0x02, 0x7d, 0x7f, 0x0e,
	0x00, 0x00, 0xff, 0xff, 0x28, 0x30, 0x16, 0x52, 0x92, 0x02, 0x00, 0x00,
}