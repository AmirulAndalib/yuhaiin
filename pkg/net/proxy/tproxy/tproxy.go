//go:build linux
// +build linux

package tproxy

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	is "github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
)

// modified from https://github.com/LiamHaworth/go-tproxy

func NewServer(h string, dialer proxy.Proxy) (is.Server, error) {
	t, err := newTCPServer(h, dialer)
	if err != nil {
		return nil, fmt.Errorf("create tcp server failed: %w", err)
	}
	u, err := newUDPServer(h, dialer)
	if err != nil {
		return nil, fmt.Errorf("create udp server failed: %w", err)
	}
	return &tproxy{tcp: t, udp: u}, nil
}

type tproxy struct {
	tcp is.Server
	udp is.Server
}

func (s *tproxy) Close() error {
	err := s.tcp.Close()
	if err != nil {
		return fmt.Errorf("socks5 tcp close server failed: %w", err)
	}
	err = s.udp.Close()
	if err != nil {
		return fmt.Errorf("socks5 udp close server failed: %w", err)
	}
	return nil
}
