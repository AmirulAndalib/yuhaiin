package statistic

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	imapper "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/mapper"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
	protoconfig "github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/proto"
)

//go:embed statics/bypass.gz
var BYPASS_DATA []byte

func writeDefaultBypassData(target string) error {
	_, err := os.Stat(target)
	if err == nil {
		return nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat bypass file failed: %w", err)
	}

	err = os.MkdirAll(filepath.Dir(target), os.ModePerm)
	if err != nil {
		return fmt.Errorf("create bypass dir failed: %w", err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(BYPASS_DATA))
	if err != nil {
		return fmt.Errorf("create gzip reader failed: %w", err)
	}
	defer gr.Close()

	data, err := ioutil.ReadAll(gr)
	if err != nil {
		return fmt.Errorf("read gzip data failed: %w", err)
	}

	return ioutil.WriteFile(target, data, os.ModePerm)
}

type MODE string

var (
	OTHERS MODE = "OTHERS"
	BLOCK  MODE = "BLOCK"
	DIRECT MODE = "DIRECT"
	PROXY  MODE = "PROXY"
	MAX    MODE = "MAX"

	UNKNOWN MODE = "UNKNOWN"

	MODE_MARK = "MODE_MARK"
)

func (m MODE) String() string { return string(m) }

var Mode = map[string]*MODE{"direct": &DIRECT /* "proxy":  PROXY,*/, "block": &BLOCK}

type shunt struct {
	mapper imapper.Mapper[string, proxy.Address, *MODE]

	config *protoconfig.Bypass
	lock   sync.RWMutex

	conns conns

	dialers  map[MODE]proxy.Proxy
	resolver map[MODE]dns.DNS
}

func newShunt(resolver dns.DNS, conns conns) *shunt {
	return &shunt{
		mapper: mapper.NewMapper[*MODE](resolver),
		conns:  conns,
		config: &protoconfig.Bypass{Enabled: true, BypassFile: ""},
	}
}

func (s *shunt) Update(c *protoconfig.Setting) {
	s.lock.Lock()
	defer s.lock.Unlock()

	diff := !proto.Equal(s.config, c.Bypass)
	s.config = c.Bypass

	if !s.config.Enabled {
		s.mapper.Clear()
	}

	if diff && s.config.Enabled {
		if err := s.refresh(); err != nil {
			log.Println("refresh bypass file failed:", err)
		}
	}
}

func (s *shunt) refresh() error {
	err := writeDefaultBypassData(s.config.BypassFile)
	if err != nil {
		return fmt.Errorf("copy bypass file failed: %w", err)
	}

	f, err := os.Open(s.config.BypassFile)
	if err != nil {
		return fmt.Errorf("open bypass file failed: %w", err)
	}
	defer f.Close()

	s.mapper.Clear()

	br := bufio.NewScanner(f)
	for {
		if !br.Scan() {
			break
		}

		a := br.Bytes()

		i := bytes.IndexByte(a, '#')
		if i != -1 {
			a = a[:i]
		}

		i = bytes.IndexByte(a, ' ')
		if i == -1 {
			continue
		}

		c, b := a[:i], a[i+1:]

		if bytes.Equal(b, []byte{}) {
			continue
		}

		s.mapper.Insert(string(c), Mode[strings.ToLower(*(*string)(unsafe.Pointer(&b)))])
	}
	return nil
}

func (s *shunt) match(addr proxy.Address, resolveDomain bool) MODE {
	if !s.config.Enabled {
		return PROXY
	}

	var m *MODE
	if resolveDomain {
		m, _ = s.mapper.Search(addr)
	} else {
		r := s.mapper
		if z, ok := s.mapper.(interface {
			Domain() imapper.Mapper[string, proxy.Address, *MODE]
		}); ok {
			r = z.Domain()
		}
		m, _ = r.Search(addr)
	}
	if m == nil {
		return PROXY
	}
	return *m
}

func (s *shunt) AddMode(m MODE, p proxy.Proxy, resolver dns.DNS) {
	if s.dialers == nil {
		s.dialers = make(map[MODE]proxy.Proxy)
	}

	s.dialers[m] = p

	if s.resolver == nil {
		s.resolver = make(map[MODE]dns.DNS)
	}

	s.resolver[m] = resolver
}

func (s *shunt) GetDialer(m MODE) proxy.Proxy {
	if s.dialers != nil {
		d, ok := s.dialers[m]
		if ok {
			return d
		}
	}
	return proxy.NewErrProxy(fmt.Errorf("no dialer for mode: %s", m))
}

func (s *shunt) Conn(host proxy.Address) (net.Conn, error) {
	m := s.match(host, true)
	dialer, ok := s.dialers[m]
	if !ok {
		return nil, fmt.Errorf("not found dialer for %s", m)
	}
	resolv, ok := s.resolver[m]
	if !ok {
		return nil, fmt.Errorf("not found resolver for %s", m)
	}

	host.WithResolver(resolv)
	host.AddMark(MODE_MARK, m.String())

	conn, err := dialer.Conn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return s.conns.AddConn(conn, host), nil
}

func (s *shunt) PacketConn(host proxy.Address) (net.PacketConn, error) {
	m := s.match(host, true)
	dialer, ok := s.dialers[m]
	if !ok {
		return nil, fmt.Errorf("not found dialer for %s", m)
	}
	resolv, ok := s.resolver[m]
	if !ok {
		return nil, fmt.Errorf("not found resolver for %s", m)
	}

	host.WithResolver(resolv)
	host.AddMark(MODE_MARK, m.String())

	conn, err := dialer.PacketConn(host)
	if err != nil {
		return nil, fmt.Errorf("dial %s failed: %w", host, err)
	}

	return s.conns.AddPacketConn(conn, host), nil
}

func (s *shunt) GetResolver(host proxy.Address) (dns.DNS, MODE) {
	m := s.match(host, false)
	if s.resolver != nil {
		d, ok := s.resolver[m]
		if ok {
			return d, m
		}
	}
	return resolver.Bootstrap, m
}
