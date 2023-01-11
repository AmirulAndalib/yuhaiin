package obfs

import (
	"math/rand"
	"net"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type randomHead struct {
	rawTransSent     bool
	rawTransReceived bool
	hasSentHeader    bool
	dataBuffer       []byte

	net.Conn
}

func newRandomHead(conn net.Conn, _ Obfs) net.Conn { return &randomHead{Conn: conn} }

func (r *randomHead) encode(data []byte) (encodedData []byte) {
	if r.rawTransSent {
		return data
	}

	if r.hasSentHeader {
		if len(data) > 0 {
			r.dataBuffer = append(r.dataBuffer, data...)
		} else {
			encodedData = r.dataBuffer
			r.dataBuffer = nil
			r.rawTransSent = true
		}

		return
	}

	size := rand.Intn(96) + 8
	encodedData = make([]byte, size)
	rand.Read(encodedData)
	ssr.SetCRC32(encodedData, size)
	r.dataBuffer = append(r.dataBuffer, data...)
	r.hasSentHeader = true
	return
}

func (r *randomHead) Write(b []byte) (int, error) {
	if r.rawTransSent {
		return r.Conn.Write(b)
	}

	_, err := r.Conn.Write(r.encode(b))
	return len(b), err
}

func (r *randomHead) Read(b []byte) (n int, err error) {
	if r.rawTransReceived {
		return r.Conn.Read(b)
	}

	buf := pool.GetBytes(pool.DefaultSize)
	defer pool.PutBytes(buf)
	r.Conn.Read(buf)
	r.rawTransReceived = true
	r.Conn.Write(nil)
	return 0, nil
}

func (r *randomHead) GetOverhead() int { return 0 }
