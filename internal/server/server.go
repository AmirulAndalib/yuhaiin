package server

import (
	"log"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	iserver "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	hs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http/server"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

func init() {
	protoconfig.RegisterProtocol(func(p *protoconfig.ServerProtocol_Http, dialer proxy.Proxy) (iserver.Server, error) {
		return hs.NewServer(p.Http.Host, p.Http.Username, p.Http.Password, dialer)
	})
	protoconfig.RegisterProtocol(func(t *protoconfig.ServerProtocol_Socks5, dialer proxy.Proxy) (iserver.Server, error) {
		return ss.NewServer(t.Socks5.Host, t.Socks5.Username, t.Socks5.Password, dialer)
	})
}

type listener struct {
	lock  sync.Mutex
	store map[string]struct {
		config proto.Message
		server iserver.Server
	}

	pro proxy.Proxy
}

func NewListener(pro proxy.Proxy) *listener {
	if pro == nil {
		pro = direct.Default
	}
	l := &listener{
		store: make(map[string]struct {
			config proto.Message
			server iserver.Server
		}),
		pro: pro,
	}

	return l
}

func (l *listener) Update(current *protoconfig.Setting) {
	l.lock.Lock()
	defer l.lock.Unlock()
	for k, v := range l.store {
		if _, ok := current.Server.Servers[k]; !ok {
			v.server.Close()
			delete(l.store, k)
		}
	}

	for k, v := range current.Server.Servers {
		l.update(k, l.pro, v)
	}
}

func (l *listener) update(name string, pro proxy.Proxy, config *protoconfig.ServerProtocol) {
	v, ok := l.store[name]
	if !ok {
		l.start(name, pro, config)
		return
	}

	if proto.Equal(v.config, config) {
		return
	}

	v.server.Close()
	delete(l.store, name)

	l.start(name, pro, config)
}

func (l *listener) start(name string, pro proxy.Proxy, config *protoconfig.ServerProtocol) {
	server, err := protoconfig.CreateServer(config.Protocol, pro)
	if err != nil {
		log.Printf("create server %s failed: %v\n", name, err)
		return
	}

	l.store[name] = struct {
		config proto.Message
		server iserver.Server
	}{
		config: config,
		server: server,
	}
}

func (l *listener) Close() error {
	l.lock.Lock()
	defer l.lock.Unlock()

	for _, v := range l.store {
		v.server.Close()
	}

	l.store = make(map[string]struct {
		config proto.Message
		server iserver.Server
	})

	return nil
}
