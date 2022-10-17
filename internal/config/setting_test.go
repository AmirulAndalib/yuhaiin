package config

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/bypass"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestJsonPb(t *testing.T) {
	s := &config.Setting{
		SystemProxy: &config.SystemProxy{
			Http:   true,
			Socks5: false,
		},
		Bypass: &bypass.Config{
			BypassFile: filepath.Join("/tmp/yuhaiin/setting", "yuhaiin.conf"),
		},
		Dns: &dns.Config{
			Remote: &dns.Dns{
				Host:   "cloudflare-dns.com",
				Type:   dns.Type_doh,
				Subnet: "0.0.0.0/32",
			},
			Local: &dns.Dns{
				Host: "223.5.5.5",
				Type: dns.Type_doh,
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

func TestCheckDNS(t *testing.T) {
	z := &dns.Dns{
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

func TestSetDefault(t *testing.T) {
	def := map[string]any{
		"a": map[string]any{
			"aa": "aa",
		},
		"b": "b",
		"c": map[string]any{
			"cc": "cc",
		},
	}

	j := map[string]any{
		"c": map[string]any{
			"dd": "dd",
		},
	}

	setDefault(j, def)

	z, _ := json.Marshal(j)
	t.Log(string(z))
}
