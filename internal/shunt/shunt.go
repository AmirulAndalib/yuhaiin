package shunt

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/resolver"
	"github.com/Asutorufa/yuhaiin/pkg/node"
	pconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
)

type modeMarkKey struct{}

func (modeMarkKey) String() string { return "MODE" }

type DOMAIN_MARK_KEY struct{}

type IP_MARK_KEY struct{}

func (IP_MARK_KEY) String() string { return "IP" }

type ForceModeKey struct{}

type Shunt struct {
	resolveRemoteDomain bool
	defaultMode         bypass.Mode
	config              *bypass.Config
	mapper              *mapper.Combine[bypass.ModeEnum]
	lock                sync.RWMutex
	modeStore           map[bypass.Mode]Mode

	tags []string
}

type Mode struct {
	Default  bool
	Mode     bypass.Mode
	Dialer   proxy.Proxy
	Resolver dns.DNS
}

func NewShunt(modes []Mode) *Shunt {
	s := &Shunt{
		mapper: mapper.NewMapper[bypass.ModeEnum](),
		config: &bypass.Config{
			Tcp:        bypass.Mode_bypass,
			Udp:        bypass.Mode_bypass,
			BypassFile: "",
		},
		modeStore: make(map[bypass.Mode]Mode, len(bypass.Mode_value)),
	}

	for _, mode := range modes {
		s.modeStore[mode.Mode] = mode
		if mode.Default {
			s.defaultMode = mode.Mode
		}
	}

	return s
}

func (s *Shunt) Update(c *pconfig.Setting) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.resolveRemoteDomain = c.Dns.ResolveRemoteDomain

	diff := (s.config == nil && c != nil) || s.config.BypassFile != c.Bypass.BypassFile
	s.config = c.Bypass

	if diff {
		s.mapper.Clear()
		s.tags = nil
		rangeRule(s.config.BypassFile, func(s1 string, s2 bypass.ModeEnum) {
			s.mapper.Insert(s1, s2)
			if s2.GetTag() != "" {
				s.tags = append(s.tags, s2.GetTag())
			}
		})
	}

	for k, v := range c.Bypass.CustomRuleV2 {
		if v.Mode == bypass.Mode_proxy && len(v.GetTag()) != 0 {
			s.mapper.Insert(k, bypass.Tag(v.GetTag()))
			s.tags = append(s.tags, v.GetTag())
		} else {
			s.mapper.Insert(k, v.Mode)
		}
	}
}

func (s *Shunt) Tags() []string { return s.tags }

func (s *Shunt) Conn(host proxy.Address) (net.Conn, error) {
	host, mode := s.bypass(s.config.Tcp, host)

	conn, err := mode.Dialer.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, err
}

func (s *Shunt) PacketConn(host proxy.Address) (net.PacketConn, error) {
	host, mode := s.bypass(s.config.Udp, host)

	conn, err := mode.Dialer.PacketConn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return conn, err
}

var errMode = Mode{
	Mode:     bypass.Mode(-1),
	Dialer:   proxy.NewErrProxy(errors.New("can't find mode")),
	Resolver: dns.NewErrorDNS(errors.New("can't find mode")),
}

func (s *Shunt) bypass(networkMode bypass.Mode, host proxy.Address) (proxy.Address, Mode) {
	mode := proxy.Value(host, ForceModeKey{}, bypass.Mode_bypass)

	if mode == bypass.Mode_bypass {
		mode = networkMode
	}

	if mode == bypass.Mode_bypass {
		host.WithResolver(s.resolver(s.defaultMode), true)
		fields := s.search(host)
		mode = fields.Mode()

		if tag := fields.GetTag(); len(tag) != 0 {
			host.WithValue(node.TagKey{}, tag)
		}
	}

	m, ok := s.modeStore[mode]
	if !ok {
		m = errMode
	}

	host.WithValue(modeMarkKey{}, mode)
	host.WithResolver(m.Resolver, true)

	if !s.resolveRemoteDomain || host.Type() != proxy.DOMAIN || mode != bypass.Mode_proxy {
		return host, m
	}

	ip, err := host.IP()
	if err == nil {
		host.WithValue(DOMAIN_MARK_KEY{}, host.String())
		host = host.OverrideHostname(ip.String())
		host.WithValue(IP_MARK_KEY{}, host.String())
	} else {
		log.Warningln("resolve remote domain failed: %w", err)
	}

	return host, m
}

var skipResolve = dns.NewErrorDNS(mapper.ErrSkipResolveDomain)

func (s *Shunt) Resolver(host proxy.Address) dns.DNS {
	host.WithResolver(skipResolve, true)
	return s.resolver(s.search(host))
}

func (s *Shunt) resolver(m bypass.ModeEnum) dns.DNS {
	d, ok := s.modeStore[m.Mode()]
	if ok {
		return d.Resolver
	}

	return resolver.Bootstrap
}

func (s *Shunt) search(host proxy.Address) bypass.ModeEnum {
	m, ok := s.mapper.Search(host)
	if !ok {
		return s.defaultMode
	}

	return m
}
