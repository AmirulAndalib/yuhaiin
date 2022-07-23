package protocol

import (
	"bytes"
	"crypto"
	"encoding/binary"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
)

func init() {
	register("verify_sha1", NewVerifySHA1)
	register("ota", NewVerifySHA1)
}

type verifySHA1 struct {
	ProtocolInfo
	hasSentHeader bool
	chunkId       uint32
	hmac          hmacMethod
}

const (
	oneTimeAuthMask byte = 0x10
)

func NewVerifySHA1(info ProtocolInfo) IProtocol {
	a := &verifySHA1{
		ProtocolInfo: info,
		hmac:         func(key, data, buf []byte) []byte { return ssr.Hmac(crypto.SHA1, key, data, buf) },
	}
	return a
}

func (v *verifySHA1) otaConnectAuth(data []byte) []byte {
	return append(data, v.hmac(append(v.IV, v.Key...), data, nil)...)
}

func (v *verifySHA1) otaReqChunkAuth(buffer *bytes.Buffer, chunkId uint32, data []byte) {
	nb := make([]byte, 2)
	binary.BigEndian.PutUint16(nb, uint16(len(data)))
	chunkIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkIdBytes, chunkId)

	buffer.Write(nb)
	buffer.Write(v.hmac(append(v.IV, chunkIdBytes...), data, nil))
	buffer.Write(data)
}

func (v *verifySHA1) otaVerifyAuth(iv []byte, chunkId uint32, data []byte, expectedHmacSha1 []byte) bool {
	chunkIdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkIdBytes, chunkId)
	actualHmacSha1 := v.hmac(append(iv, chunkIdBytes...), data, nil)
	return bytes.Equal(expectedHmacSha1, actualHmacSha1)
}

func (v *verifySHA1) getAndIncreaseChunkId() (chunkId uint32) {
	chunkId = v.chunkId
	v.chunkId += 1
	return
}

func (v *verifySHA1) EncryptStream(buffer *bytes.Buffer, data []byte) (err error) {
	dataLength := len(data)
	offset := 0
	if !v.hasSentHeader {
		data[0] |= oneTimeAuthMask
		buffer.Write(v.otaConnectAuth(data[:v.HeadSize]))
		v.hasSentHeader = true
		dataLength -= v.HeadSize
		offset += v.HeadSize
	}
	const blockSize = 4096
	for dataLength > blockSize {
		chunkId := v.getAndIncreaseChunkId()
		v.otaReqChunkAuth(buffer, chunkId, data[offset:offset+blockSize])
		dataLength -= blockSize
		offset += blockSize
	}
	if dataLength > 0 {
		chunkId := v.getAndIncreaseChunkId()
		v.otaReqChunkAuth(buffer, chunkId, data[offset:])
	}
	return nil
}

func (v *verifySHA1) DecryptStream(dst *bytes.Buffer, data []byte) (int, error) {
	return dst.Write(data)
}

func (v *verifySHA1) GetOverhead() int {
	return 0
}

func (a *verifySHA1) EncryptPacket(b []byte) ([]byte, error) {
	return b, nil
}
func (a *verifySHA1) DecryptPacket(b []byte) ([]byte, error) {
	return b, nil
}
