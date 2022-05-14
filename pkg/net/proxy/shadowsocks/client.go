package shadowsocks

import (
	"bytes"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	ss5client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	ss5server "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	"github.com/shadowsocks/go-shadowsocks2/core"
)

var (
	//OBFS plugin
	OBFS = "obfs-local"
	//V2RAY websocket and quic plugin
	V2RAY = "v2ray"
)

//Shadowsocks shadowsocks
type Shadowsocks struct {
	cipher core.Cipher
	server string
	port   string

	p       proxy.Proxy
	udpAddr net.Addr
}

func NewShadowsocks(cipherName string, password string, server, port string) func(proxy.Proxy) (proxy.Proxy, error) {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		cipher, err := core.PickCipher(strings.ToUpper(cipherName), nil, password)
		if err != nil {
			return nil, err
		}

		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(server, port))
		if err != nil {
			return nil, fmt.Errorf("resolve udp addr failed: %v", err)
		}

		return &Shadowsocks{cipher: cipher, server: server, port: port, p: p, udpAddr: addr}, nil
	}
}

//Conn .
func (s *Shadowsocks) Conn(host string) (conn net.Conn, err error) {
	conn, err = s.p.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial to %s failed: %v", s.server, err)
	}

	if x, ok := conn.(*net.TCPConn); ok {
		_ = x.SetKeepAlive(true)
	}

	conn = s.cipher.StreamConn(conn)

	target, err := ss5client.ParseAddr(host)
	if err != nil {
		return nil, fmt.Errorf("parse host failed: %v", err)
	}

	if _, err = conn.Write(target); err != nil {
		return nil, fmt.Errorf("shadowsocks write target failed: %v", err)
	}
	return conn, nil
}

//PacketConn .
func (s *Shadowsocks) PacketConn(tar string) (net.PacketConn, error) {
	pc, err := s.p.PacketConn(s.server)
	if err != nil {
		return nil, fmt.Errorf("create packet conn failed")
	}
	pc = s.cipher.PacketConn(pc)

	addr, err := ss5client.ParseAddr(tar)
	if err != nil {
		return nil, fmt.Errorf("parse target failed: %v", err)
	}
	return &ssPacketConn{PacketConn: pc, add: s.udpAddr, target: addr}, nil
}

type ssPacketConn struct {
	net.PacketConn
	add    net.Addr
	target []byte
}

func (v *ssPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := v.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, fmt.Errorf("read udp from shadowsocks failed: %v", err)
	}

	host, port, addrSize, err := ss5server.ResolveAddr(b[:n])
	if err != nil {
		return 0, nil, fmt.Errorf("resolve address failed: %v", err)
	}

	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.FormatInt(int64(port), 10)))
	if err != nil {
		return 0, nil, fmt.Errorf("resolve udp address failed: %v", err)
	}

	copy(b, b[addrSize:])
	return n - addrSize, addr, nil
}

func (v *ssPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return v.PacketConn.WriteTo(bytes.Join([][]byte{v.target, b}, []byte{}), v.add)
}
