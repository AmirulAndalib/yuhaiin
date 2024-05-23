package trojan

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/relay"
)

const (
	MaxPacketSize = 1024 * 8
)

type Command byte

const (
	Connect   Command = 1 // TCP
	Associate Command = 3 // UDP
	Mux       Command = 0x7f
)

var crlf = []byte{'\r', '\n'}

func (c *Client) WriteHeader(conn net.Conn, cmd Command, addr netapi.Address) (err error) {
	buf := pool.GetBytesWriter(pool.DefaultSize)
	defer buf.Free()

	_, _ = buf.Write(c.password)
	_, _ = buf.Write(crlf)
	buf.WriteByte(byte(cmd))
	tools.EncodeAddr(addr, buf)
	_, _ = buf.Write(crlf)

	_, err = conn.Write(buf.Bytes())
	return
}

// modified from https://github.com/p4gefau1t/trojan-go/blob/master/tunnel/trojan/client.go
type Client struct {
	proxy netapi.Proxy
	netapi.EmptyDispatch
	password []byte
}

func init() {
	point.RegisterProtocol(NewClient)
}

func NewClient(config *protocol.Protocol_Trojan) point.WrapProxy {
	return func(dialer netapi.Proxy) (netapi.Proxy, error) {
		return &Client{
			password: hexSha224([]byte(config.Trojan.Password)),
			proxy:    dialer,
		}, nil
	}
}

func (c *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	conn, err := c.proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	if err = c.WriteHeader(conn, Connect, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write header failed: %w", err)
	}
	return conn, nil
}

func (c *Client) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	conn, err := c.proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}
	if err = c.WriteHeader(conn, Associate, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write header failed: %w", err)
	}
	return &PacketConn{Conn: conn}, nil
}

type PacketConn struct {
	net.Conn

	mux sync.Mutex
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	taddr, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}

	w := pool.GetBuffer()
	defer pool.PutBuffer(w)

	tools.EncodeAddr(taddr, w)

	payload = payload[:min(len(payload), MaxPacketSize)]

	_ = binary.Write(w, binary.BigEndian, uint16(len(payload)))

	w.Write(crlf) // crlf

	w.Write(payload)

	_, err = c.Conn.Write(w.Bytes())
	if err != nil {
		return 0, err
	}

	return len(payload), nil
}

func (c *PacketConn) ReadFrom(payload []byte) (n int, _ net.Addr, err error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	addr, err := tools.ResolveAddr(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve udp packet addr: %w", err)
	}

	var length uint16
	if err = binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
		return 0, nil, fmt.Errorf("read length failed: %w", err)
	}

	crlf := [2]byte{}
	if _, err := io.ReadFull(c.Conn, crlf[:]); err != nil {
		return 0, nil, fmt.Errorf("read crlf failed: %w", err)
	}

	n, err = io.ReadFull(c.Conn, payload[:min(int(length), len(payload))])

	if length > uint16(n) {
		_, _ = relay.CopyN(io.Discard, c.Conn, int64(int(length)-n))
	}

	return n, addr.Address(statistic.Type_udp), err
}

func hexSha224(data []byte) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	hash.Write(data)
	hex.Encode(buf, hash.Sum(nil))
	return buf
}
