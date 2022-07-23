package dns

import (
	"crypto/tls"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
)

func init() {
	Register(config.Dns_dot, NewDoT)
}

func NewDoT(config Config) dns.DNS {
	d := newTCP(config, "853")
	if config.Servername == "" {
		config.Servername = d.host.Hostname()
	}
	d.tls = &tls.Config{ServerName: config.Servername}
	return d
}
