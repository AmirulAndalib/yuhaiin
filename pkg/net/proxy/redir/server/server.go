package server

import (
	"context"
	"io"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
)

type redir struct {
	lis    net.Listener
	ctx    context.Context
	cancel context.CancelFunc

	tcpChannel chan *netapi.StreamMeta
}

func (r *redir) Close() error {
	r.cancel()
	return r.lis.Close()
}

func (r *redir) AcceptStream() (*netapi.StreamMeta, error) {
	select {
	case <-r.ctx.Done():
		return nil, r.ctx.Err()
	case meta := <-r.tcpChannel:
		return meta, nil
	}
}

func (r *redir) AcceptPacket() (*netapi.Packet, error) {
	return nil, io.EOF
}

func NewServer(o *listener.Inbound_Redir) func(netapi.Listener) (netapi.ProtocolServer, error) {
	return func(ii netapi.Listener) (netapi.ProtocolServer, error) {
		ctx, cancel := context.WithCancel(context.Background())

		lis, err := ii.Stream(ctx)
		if err != nil {
			cancel()
			return nil, err
		}

		t := &redir{
			lis:        lis,
			ctx:        ctx,
			cancel:     cancel,
			tcpChannel: make(chan *netapi.StreamMeta, 100),
		}

		go func() {
			for {
				conn, err := lis.Accept()
				if err != nil {
					log.Error("redir accept failed", "err", err)
					break
				}

				go func() {
					if err := t.handle(conn); err != nil {
						log.Error("redir handle failed", "err", err)
					}
				}()
			}
		}()

		return t, nil
	}
}
