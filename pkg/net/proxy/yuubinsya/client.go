package yuubinsya

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type conn struct {
	net.Conn

	cmd        byte
	addr       proxy.Address
	handshaker handshaker
}

func newConn(con net.Conn, cmd byte, addr proxy.Address, handshaker handshaker) net.Conn {
	return &conn{
		Conn:       con,
		cmd:        cmd,
		addr:       addr,
		handshaker: handshaker,
	}
}

func (c *conn) Write(b []byte) (int, error) {
	if c.cmd == 0 {
		return c.Conn.Write(b)
	}

	buf := pool.GetBuffer()
	defer pool.PutBuffer(buf)

	c.handshaker.header(buf, c.cmd, c.addr)
	c.cmd = 0
	buf.Write(b)

	if _, err := c.Conn.Write(buf.Bytes()); err != nil {
		return 0, err
	}

	return len(b), nil
}

type Client struct {
	proxy proxy.Proxy

	handshaker handshaker
}

func New(config *protocol.Protocol_Yuubinsya) protocol.WrapProxy {
	return func(dialer proxy.Proxy) (proxy.Proxy, error) {
		c := &Client{
			proxy:      dialer,
			handshaker: NewHandshaker(false, []byte(config.Yuubinsya.Password), protocol.ParseTLSConfig(config.Yuubinsya.Tls)),
		}

		return c, nil
	}
}

func (c *Client) conn(addr proxy.Address) (net.Conn, error) {
	conn, err := c.proxy.Conn(addr)
	if err != nil {
		return nil, err
	}

	return c.handshaker.handshake(conn)
}

func (c *Client) Conn(addr proxy.Address) (net.Conn, error) {
	conn, err := c.conn(addr)
	if err != nil {
		return nil, err
	}

	return newConn(conn, tcp, addr, c.handshaker), nil
}

func (c *Client) PacketConn(addr proxy.Address) (net.PacketConn, error) {
	conn, err := c.conn(addr)
	if err != nil {
		return nil, err
	}

	return &PacketConn{Conn: newConn(conn, udp, nil, c.handshaker)}, nil
}

type PacketConn struct {
	net.Conn

	remain int
	addr   proxy.Address
	rmux   sync.Mutex
	wmux   sync.Mutex
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	taddr, err := proxy.ParseSysAddr(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse addr: %w", err)
	}
	s5Addr := s5c.ParseAddr(taddr)

	w := pool.GetBuffer()
	defer pool.PutBuffer(w)

	b := bytes.NewBuffer(payload)

	for b.Len() > 0 {
		data := b.Next(MaxPacketSize)
		w.Write(s5Addr)
		binary.Write(w, binary.BigEndian, uint16(len(data)))
		w.Write(data)
	}

	c.wmux.Lock()
	// because of aead will increment nonce two times,
	// so we must make sure the data complete wrote then
	// write next data
	_, err = c.Conn.Write(w.Bytes())
	defer c.wmux.Unlock()
	if err != nil {
		return 0, fmt.Errorf("write to %v failed: %w", addr, err)
	}
	return len(payload), nil
}

func (c *PacketConn) ReadFrom(payload []byte) (n int, _ net.Addr, err error) {
	c.rmux.Lock()
	defer c.rmux.Unlock()

	if c.remain > 0 {
		var z int
		if c.remain > len(payload) {
			z = len(payload)
		} else {
			z = c.remain
		}

		n, err := c.Conn.Read(payload[:z])
		if err != nil {
			return 0, c.addr, err
		}

		c.remain -= n
		return n, c.addr, err
	}

	addr, err := s5c.ResolveAddr(c.Conn)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to resolve udp packet addr: %w", err)
	}
	c.addr = addr.Address(statistic.Type_udp)

	var length uint16
	if err = binary.Read(c.Conn, binary.BigEndian, &length); err != nil {
		return 0, nil, fmt.Errorf("read length failed: %w", err)
	}

	plen := len(payload)
	if int(length) < plen {
		plen = int(length)
	} else {
		c.remain = int(length) - plen
	}

	n, err = io.ReadFull(c.Conn, payload[:plen])
	return n, c.addr, err
}
