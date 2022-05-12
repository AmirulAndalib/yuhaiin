package config

import (
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestJsonPb(t *testing.T) {
	s := &config.Setting{
		SystemProxy: &config.SystemProxy{
			Http:   true,
			Socks5: false,
		},
		Bypass: &config.Bypass{
			Enabled:    true,
			BypassFile: filepath.Join("/tmp/yuhaiin/setting", "yuhaiin.conf"),
		},
		Dns: &config.DnsSetting{
			Remote: &config.Dns{
				Host:   "cloudflare-dns.com",
				Type:   config.Dns_doh,
				Proxy:  false,
				Subnet: "0.0.0.0/32",
			},
			Local: &config.Dns{
				Host: "223.5.5.5",
				Type: config.Dns_doh,
			},
		},
	}
	data, err := protojson.MarshalOptions{Multiline: true, Indent: "\t"}.Marshal(s)
	if err != nil {
		t.Error(err)
	}
	t.Log(string(data))

	s2 := &config.Setting{}
	err = protojson.Unmarshal([]byte(data), s2)
	if err != nil {
		t.Error(err)
	}

	s3 := &config.Setting{}
	err = protojson.UnmarshalOptions{DiscardUnknown: true, AllowPartial: true}.Unmarshal([]byte(`{"system_proxy":{"enabled":true,"http":true,"unknowTest":""}}`), s3)
	if err != nil {
		t.Log(err)
	}
	t.Log(s3)
}

func TestLoad(t *testing.T) {
	x := load("")

	t.Log(x)
}

func TestCheckDNS(t *testing.T) {
	z := &config.Dns{
		Host: "example.com",
	}

	t.Log(CheckBootstrapDns(z))

	z.Host = "1.1.1.1"
	t.Log(CheckBootstrapDns(z))

	z.Host = "1.1.1.1:53"
	t.Log(CheckBootstrapDns(z))

	z.Host = "ff::ff"
	t.Log(CheckBootstrapDns(z))

	z.Host = "[ff::ff]:53"
	t.Log(CheckBootstrapDns(z))

	z.Host = "1.1.1.1/dns-query"
	t.Log(CheckBootstrapDns(z))
}
