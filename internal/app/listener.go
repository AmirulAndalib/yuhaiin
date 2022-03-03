package app

import (
	"sync"

	"github.com/Asutorufa/yuhaiin/internal/config"
	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	hs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	rs "github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/server"
	ss "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
)

type Listener struct {
	lock sync.Mutex
	ps   map[string]proxy.Server
}

var creatorMap = map[config.ProxyProxyType]func(h string) (proxy.Server, error){
	config.Proxy_socks5: func(h string) (proxy.Server, error) { return ss.NewServer(h, "", "") },
	config.Proxy_http:   func(h string) (proxy.Server, error) { return hs.NewServer(h, "", "") },
	config.Proxy_redir:  func(h string) (proxy.Server, error) { return rs.NewServer(h) },
}

func NewListener(c *config.Config, pro proxy.Proxy) (l *Listener) {
	if pro == nil {
		pro = &proxy.DefaultProxy{}
	}
	l = &Listener{
		ps: make(map[string]proxy.Server),
	}

	c.AddObserverAndExec(func(_, _ *config.Setting) bool { return true }, func(current *config.Setting) {
		l.lock.Lock()
		defer l.lock.Unlock()
		for k, v := range creatorMap {
			z := l.ps[k.String()]
			if z != nil {
				z.SetServer(current.Proxy.Proxy[k.String()])
				continue
			}

			h := current.Proxy.Proxy[k.String()]
			if h == "" {
				logasfmt.Println("proxy", k.String(), "host is empty")
				continue
			}
			z, err := v(current.Proxy.Proxy[k.String()])
			if err != nil {
				logasfmt.Printf("create %s proxy server failed: %v\n", k.String(), err)
				continue
			}
			z.SetProxy(pro)
			l.ps[k.String()] = z
		}
	})

	return l
}
