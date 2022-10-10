package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
)

// tcpserver tcp server common
type tcpserver struct {
	listener net.Listener
}

// NewTCPServer create new TCP listener
func NewTCPServer(host string, handle func(net.Conn)) (server.Server, error) {
	if host == "" {
		return nil, fmt.Errorf("host is empty")
	}

	if handle == nil {
		return nil, fmt.Errorf("handle is empty")
	}

	tcp := &tcpserver{}
	err := tcp.run(host, handle)
	if err != nil {
		return nil, fmt.Errorf("tcp server run failed: %v", err)
	}
	return tcp, nil
}

func (t *tcpserver) run(host string, handle func(net.Conn)) (err error) {
	t.listener, err = dialer.ListenContext(context.Background(), "tcp", host)
	if err != nil {
		return fmt.Errorf("tcp server listen failed: %v", err)
	}

	log.Debugln("new tcp server listen at:", host)

	go func() {
		err := t.process(handle)
		if err != nil {
			log.Errorln(err)
		}
	}()
	return
}

func (t *tcpserver) process(handle func(net.Conn)) error {
	var tempDelay time.Duration
	for {
		c, err := t.listener.Accept()
		if err != nil {
			// from https://golang.org/src/net/http/server.go?s=93655:93701#L2977
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}

				if max := 5 * time.Second; tempDelay > max {
					tempDelay = max
				}

				log.Warningln("tcp sever: Accept error: %v; retrying in %v\n", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}

			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("checked tcp server closed: %w", err)
			} else {
				return fmt.Errorf("tcp server accept failed: %w", err)
			}
		}

		tempDelay = 0

		go func(c net.Conn) {
			defer c.Close()
			handle(c)
		}(c)
	}
}

func (t *tcpserver) Close() error {
	if t.listener == nil {
		return nil
	}
	return t.listener.Close()
}

func (t *tcpserver) Addr() net.Addr {
	if t.listener == nil {
		return &net.TCPAddr{}
	}

	return t.listener.Addr()
}
