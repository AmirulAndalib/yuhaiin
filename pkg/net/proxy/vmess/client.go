package vmess

import (
	"fmt"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	gcvmess "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vmess/gitsrcvmess"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

// Vmess vmess client
type Vmess struct {
	client *gcvmess.Client
	dial   proxy.Proxy
}

func New(config *protocol.Protocol_Vmess) protocol.WrapProxy {
	alterID, err := strconv.Atoi(config.Vmess.AlterId)
	if err != nil {
		return protocol.ErrConn(fmt.Errorf("convert AlterId to int failed: %v", err))
	}
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		client, err := gcvmess.NewClient(config.Vmess.Uuid, config.Vmess.Security, alterID)
		if err != nil {
			return nil, fmt.Errorf("new vmess client failed: %v", err)
		}

		return &Vmess{client: client, dial: p}, nil
	}
}

// Conn create a connection for host
func (v *Vmess) Conn(host proxy.Address) (conn net.Conn, err error) {
	c, err := v.dial.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %w", err)
	}
	conn, err = v.client.NewConn(c, host)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("new conn failed: %w", err)
	}

	return conn, nil
}

// PacketConn packet transport connection
func (v *Vmess) PacketConn(host proxy.Address) (conn net.PacketConn, err error) {
	c, err := v.dial.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("get conn failed: %w", err)
	}

	conn, err = v.client.NewPacketConn(c, host)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("new conn failed: %w", err)
	}

	return conn, nil
}
