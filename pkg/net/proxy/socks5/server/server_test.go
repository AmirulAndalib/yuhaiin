package socks5server

import (
	"bytes"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	s5c "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
)

func TestResolveAddr(t *testing.T) {
	port := proxy.ParsePort(443)

	x := s5c.ParseAddr(proxy.ParseAddressSplit("tcp", "www.baidu.com", port))
	t.Log(s5c.ResolveAddr(bytes.NewBuffer(x)))

	x = s5c.ParseAddr(proxy.ParseAddressSplit("tcp", "127.0.0.1", port))
	t.Log(x[0], x[1], x[2], x[3], x[4], x[3:], x[:3], x[:])
	t.Log(s5c.ResolveAddr(bytes.NewBuffer(x)))

	x = s5c.ParseAddr(proxy.ParseAddressSplit("tcp", "[ff::ff]", port))
	t.Log(s5c.ResolveAddr(bytes.NewBuffer(x)))

	addr, err := net.ResolveIPAddr("ip", "www.baidu.com")
	if err != nil {
		t.Error(err)
	}
	t.Log(addr.IP)
}
