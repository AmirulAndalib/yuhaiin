package node

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/node/register"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
)

type outbound struct {
	manager *manager
	// 0: tcp, 1: udp
	ps  [2]proxy.Proxy
	pps [2]*node.Point

	lock sync.RWMutex
}

func NewOutbound(tcp, udp *node.Point, mamanager *manager) *outbound {
	return &outbound{
		manager: mamanager,
		pps:     [2]*node.Point{tcp, udp},
	}
}

func (o *outbound) Save(p *node.Point, udp bool) {
	o.lock.Lock()
	defer o.lock.Unlock()
	var i int
	if udp {
		i = 1
	} else {
		i = 0
	}
	if o.pps[i].Hash != p.Hash {
		o.pps[i] = p
		o.ps[i] = nil
	}
}

func (o *outbound) Point(udp bool) *node.Point {
	var now *node.Point

	if udp {
		now = o.pps[1]
	} else {
		now = o.pps[0]
	}

	if now == nil {
		return &node.Point{}
	}

	p, ok := o.manager.GetNodeByName(now.Group, now.Name)
	if !ok {
		return now
	}

	return p
}
func (o *outbound) Conn(host proxy.Address) (net.Conn, error) {
	if o.ps[0] == nil {
		z, err := register.Dialer(o.Point(false))
		if err != nil {
			return nil, err
		}

		o.ps[0] = z
	}

	return o.ps[0].Conn(host)
}

func (o *outbound) PacketConn(host proxy.Address) (net.PacketConn, error) {
	if o.ps[1] == nil {
		z, err := register.Dialer(o.Point(true))
		if err != nil {
			return nil, err
		}

		o.ps[1] = z
	}

	return o.ps[1].PacketConn(host)
}

func (o *outbound) HTTPClient() *http.Client {
	return &http.Client{
		Timeout: time.Minute * 2,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				log.Println("dial:", network, addr)
				ad, err := proxy.ParseAddress(network, addr)
				if err != nil {
					return nil, fmt.Errorf("parse address failed: %v", err)
				}

				conn, err := direct.Default.Conn(ad)
				if err == nil {
					return conn, nil
				}

				return o.Conn(ad)
			},
		},
	}
}
