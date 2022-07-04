package tun

import (
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func open(name string, driver config.TunEndpointDriver, mtu int) (_ stack.LinkEndpoint, err error) {
	return nil, fmt.Errorf("not implemented")
	// if !strings.HasPrefix(name, "tun://") {
	// 	return nil, fmt.Errorf("invalid tun name: %s", name)
	// }

	// dev, err := tun.CreateTUN(name[6:], 1500)
	// if err != nil {
	// 	return nil, fmt.Errorf("create tun failed: %w", err)
	// }

	// return New(&wrapDev{4, dev}, 1500, 4)
}

type wrapDev struct {
	offset int
	tun.Device
}

func (t *wrapDev) Read(packet []byte) (int, error) {
	return t.Device.Read(packet, t.offset)
}

func (t *wrapDev) Write(packet []byte) (int, error) {
	return t.Device.Write(packet, t.offset)
}
