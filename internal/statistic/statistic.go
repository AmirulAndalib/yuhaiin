package statistic

import (
	"context"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/syncmap"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

var _ proxy.Proxy = (*Statistic)(nil)

type Statistic struct {
	statistic.UnimplementedConnectionsServer

	accountant

	idSeed        idGenerater
	conns         syncmap.SyncMap[int64, observer]
	proxy, direct proxy.Proxy
	mapper        func(string) MODE
}

func NewStatistic(conf config.ConfigObserver, dialer proxy.Proxy) *Statistic {
	if dialer == nil {
		dialer = &proxy.Default{}
	}

	c := &Statistic{proxy: dialer}

	shunt := NewShunt(conf, WithProxy(c))

	conf.AddObserverAndExec(
		func(current, old *protoconfig.Setting) bool { return diffDNS(current.Dns.Local, old.Dns.Local) },
		func(current *protoconfig.Setting) {
			c.direct = direct.NewDirect(direct.WithLookup(getDNS(current.Dns.Local, nil).LookupIP))
		},
	)

	conf.AddObserverAndExec(
		func(current, old *protoconfig.Setting) bool { return current.Bypass.Enabled != old.Bypass.Enabled },
		func(current *protoconfig.Setting) {
			if !current.Bypass.Enabled {
				c.mapper = func(s string) MODE { return OTHERS }
			} else {
				c.mapper = shunt.Get
			}
		})

	return c
}

func (c *Statistic) Conns(context.Context, *emptypb.Empty) (*statistic.ConnResp, error) {
	resp := &statistic.ConnResp{}
	c.conns.Range(func(key int64, v observer) bool {
		resp.Connections = append(resp.Connections, v.GetStatistic())
		return true
	})

	return resp, nil
}

func (c *Statistic) CloseConn(_ context.Context, x *statistic.CloseConnsReq) (*emptypb.Empty, error) {
	for _, x := range x.Conns {
		if z, ok := c.conns.Load(x); ok {
			z.Close()
		}
	}
	return &emptypb.Empty{}, nil
}

func (c *Statistic) Statistic(_ *emptypb.Empty, srv statistic.Connections_StatisticServer) error {
	logasfmt.Println("Start Send Flow Message to Client.")
	id := c.accountant.AddClient(srv.Send)
	<-srv.Context().Done()
	c.accountant.RemoveClient(id)
	logasfmt.Println("Client is Hidden, Close Stream.")
	return srv.Context().Err()
}

func (c *Statistic) delete(id int64) {
	if z, ok := c.conns.LoadAndDelete(id); ok {
		logasfmt.Printf("close %v| <%s[%v]>: %v, %s <-> %s\n",
			z.GetId(), z.GetType(), z.GetMark(), z.GetAddr(), z.GetLocal(), z.GetRemote())
	}
}

func (c *Statistic) Conn(host string) (net.Conn, error) {
	dialer, mark := c.marry(host)

	con, err := dialer.Conn(host)
	if err != nil {
		return nil, err
	}

	s := &conn{
		Connection: &statistic.Connection{
			Id:     c.idSeed.Generate(),
			Addr:   host,
			Mark:   mark.String(),
			Local:  con.LocalAddr().String(),
			Remote: con.RemoteAddr().String(),
			Type:   "Stream",
		},
		Conn:    con,
		manager: c,
	}
	c.storeConnection(s)
	return s, nil
}

func (c *Statistic) PacketConn(host string) (net.PacketConn, error) {
	dialer, mark := c.marry(host)

	con, err := dialer.PacketConn(host)
	if err != nil {
		return nil, err
	}

	s := &packetConn{
		PacketConn: con,
		manager:    c,
		Connection: &statistic.Connection{
			Addr:   host,
			Id:     c.idSeed.Generate(),
			Local:  con.LocalAddr().String(),
			Remote: host,
			Mark:   mark.String(),
			Type:   "Packet",
		},
	}
	c.storeConnection(s)
	return s, nil
}

func (c *Statistic) storeConnection(o observer) {
	logasfmt.Printf("%v| <%s[%v]>: %v, %s <-> %s\n",
		o.GetId(), o.GetType(), o.GetMark(), o.GetAddr(), o.GetLocal(), o.GetRemote())
	c.conns.Store(o.GetId(), o)
}

func (m *Statistic) marry(host string) (dialer proxy.Proxy, mark MODE) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		return proxy.NewErrProxy(fmt.Errorf("split host [%s] failed: %v", host, err)), UNKNOWN
	}

	mark = m.mapper(hostname)

	switch mark {
	case BLOCK:
		dialer = proxy.NewErrProxy(fmt.Errorf("BLOCK: %v", host))
	case DIRECT:
		dialer = m.direct
	default:
		dialer = m.proxy
	}

	return
}
