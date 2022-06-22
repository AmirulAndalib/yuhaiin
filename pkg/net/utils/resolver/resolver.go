package resolver

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
)

var Bootstrap dns.DNS = &System{}

type System struct{}

func (d *System) LookupIP(domain string) (dns.IPResponse, error) {
	ips, err := net.DefaultResolver.LookupIP(context.TODO(), "ip4", domain)
	return dns.NewIPResponse(ips, 600), err
}

func (d *System) Close() error              { return nil }
func (d *System) Do([]byte) ([]byte, error) { return nil, fmt.Errorf("system dns not support") }

func LookupIP(domain string) (dns.IPResponse, error) { return Bootstrap.LookupIP(domain) }

func ResolveUDPAddr(address string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", address)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		x, err := Bootstrap.LookupIP(host)
		if err != nil {
			return nil, err
		}

		ip = x.IPs()[rand.Intn(len(x.IPs()))]
	}

	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", port)
	}
	return &net.UDPAddr{IP: ip, Port: p}, nil
}
