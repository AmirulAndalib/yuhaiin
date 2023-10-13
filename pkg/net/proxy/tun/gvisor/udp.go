package tun

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func udpForwarder(s *stack.Stack, opt *listener.Opts[*listener.Protocol_Tun]) *udp.Forwarder {
	handle := func(ctx context.Context, srcpconn net.PacketConn, dst netapi.Address) error {
		buf := pool.GetBytesV2(opt.Protocol.Tun.Mtu)

		for {
			srcpconn.SetReadDeadline(time.Now().Add(time.Minute))
			n, src, err := srcpconn.ReadFrom(buf.Bytes())
			if err != nil {
				if ne, ok := err.(net.Error); (ok && ne.Timeout()) || err == io.EOF {
					return nil /* ignore I/O timeout & EOF */
				}

				return err
			}

			opt.Handler.Packet(
				ctx,
				&netapi.Packet{
					Src:     src,
					Dst:     dst,
					Payload: buf.Bytes()[:n],
					WriteBack: func(b []byte, addr net.Addr) (int, error) {
						defer pool.PutBytesV2(buf)
						from, err := netapi.ParseSysAddr(addr)
						if err != nil {
							return 0, err
						}

						// Symmetric NAT
						// gVisor udp.NewForwarder only support Symmetric NAT,
						// can't set source in udp header
						// TODO: rewrite HandlePacket() to support full cone NAT
						if from.String() != dst.String() {
							return 0, nil
						}
						return srcpconn.WriteTo(b, src)
					},
				},
			)
		}
	}

	return udp.NewForwarder(s, func(fr *udp.ForwarderRequest) {
		var wq waiter.Queue
		ep, err := fr.CreateEndpoint(&wq)
		if err != nil {
			log.Error("create endpoint failed:", "err", err)
			return
		}

		local := gonet.NewUDPConn(s, &wq, ep)

		go func(local net.PacketConn, id stack.TransportEndpointID) {
			defer local.Close()

			ctx, cancel := context.WithTimeout(context.TODO(), time.Second*5)
			defer cancel()

			if IsHandleDNS(opt, id.LocalAddress.String(), id.LocalPort) {
				if err := opt.DNSHandler.HandleUDP(ctx, local); err != nil {
					log.Error("dns handle udp failed", "err", err)
				}
				return
			}

			dst := netapi.ParseAddressPort(statistic.Type_udp, id.LocalAddress.String(), netapi.ParsePort(id.LocalPort))
			if opt.Protocol.Tun.SkipMulticast && dst.Type() == netapi.IP {
				if ip, _ := dst.IP(context.TODO()); !ip.IsGlobalUnicast() {
					buf := pool.GetBytes(1024)
					defer pool.PutBytes(buf)

					for {
						local.SetReadDeadline(time.Now().Add(time.Minute))
						if _, _, err := local.ReadFrom(buf); err != nil {
							return
						}
					}
				}
			}

			if err := handle(ctx, local, dst); err != nil && !errors.Is(err, os.ErrClosed) {
				log.Error("handle udp request failed", "err", err)
			}

		}(local, fr.ID())
	})
}
