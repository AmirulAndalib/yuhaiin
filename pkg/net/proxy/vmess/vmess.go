package vmess

import (
	"context"
	"fmt"
	"net"
	"strconv"

	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
)

// Vmess  client
type Vmess struct {
	client *Client
	proxy.Proxy
}

func New(config *protocol.Protocol_Vmess) protocol.WrapProxy {
	alterID, err := strconv.Atoi(config.Vmess.AlterId)
	if err != nil {
		return protocol.ErrConn(fmt.Errorf("convert AlterId to int failed: %w", err))
	}
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		client, err := NewClient(config.Vmess.Uuid, config.Vmess.Security, alterID)
		if err != nil {
			return nil, fmt.Errorf("new vmess client failed: %w", err)
		}

		return &Vmess{client, p}, nil
	}
}

// Conn create a connection for host
func (v *Vmess) Conn(ctx context.Context, host proxy.Address) (conn net.Conn, err error) {
	c, err := v.Proxy.Conn(ctx, host)
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
func (v *Vmess) PacketConn(ctx context.Context, host proxy.Address) (conn net.PacketConn, err error) {
	c, err := v.Proxy.Conn(ctx, host)
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
