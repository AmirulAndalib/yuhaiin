package simple

import (
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
)

//Simple .
type Simple struct {
	address  string
	port     string
	isDomain bool
	host     string

	lookupIP  func(host string) ([]net.IP, error)
	tlsConfig *tls.Config
}

func WithLookupIP(f func(host string) ([]net.IP, error)) func(*Simple) {
	return func(cu *Simple) {
		if f == nil {
			return
		}
		cu.lookupIP = f
	}
}

func WithTLS(t *tls.Config) func(*Simple) {
	return func(c *Simple) {
		c.tlsConfig = t
	}
}

//NewSimple .
func NewSimple(address, port string, opts ...func(*Simple)) *Simple {
	c := &Simple{
		address:  address,
		port:     port,
		host:     net.JoinHostPort(address, port),
		isDomain: net.ParseIP(address) == nil,
		lookupIP: resolver.LookupIP,
	}

	for i := range opts {
		opts[i](c)
	}

	return c
}

var clientDialer = net.Dialer{Timeout: time.Second * 5}

func (c *Simple) Conn(host string) (net.Conn, error) {
	address := c.host

	if c.isDomain {
		x, err := c.lookupIP(c.address)
		if err != nil {
			return nil, err
		}

		address = net.JoinHostPort(x[rand.Intn(len(x))].String(), c.port)
	}

	conn, err := clientDialer.Dial("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("simple dial failed: %w", err)
	}

	if c.tlsConfig != nil {
		conn = tls.Client(conn, c.tlsConfig)
	}

	return conn, nil
}

func (c *Simple) PacketConn(host string) (net.PacketConn, error) {
	return net.ListenPacket("udp", "")
}
