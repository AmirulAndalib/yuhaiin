package dns

import (
	"context"
	"github.com/Asutorufa/SsrMicroClient/net/proxy/socks5/client"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
)

func TestDNSOverHTTPS(t *testing.T) {
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		x := &socks5client.Client{Server: "127.0.0.1", Port: "1080", Address: addr}
		return x.NewSocks5Client()
	}
	t.Log(DNSOverHTTPS("https://dns.rubyfish.cn/dns-query", "dict.hjenglish.com", dialContext))
	t.Log(DNSOverHTTPS("https://dns.rubyfish.cn/dns-query", "i0.hdslb.com", nil))
	t.Log(DNSOverHTTPS("https://dns.rubyfish.cn/dns-query", "cm.bilibili.com", nil))
	t.Log(DNSOverHTTPS("https://dns.google/resolve", "dict.hjenglish.com", dialContext))
	t.Log(DNSOverHTTPS("https://dns.google/resolve", "i0.hdslb.com", dialContext))
	t.Log(DNSOverHTTPS("https://cloudflare-dns.com/dns-query", "cm.bilibili.com", nil))
}

func TestC(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://cloudflare-dns.com/dns-query"+"?dns="+"q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB", nil)
	req.Header.Set("accept", "application/dns-message")
	//res, err := http.Get("https://cloudflare-dns.com/dns-query"+"?dns="+base64.URLEncoding.EncodeToString([]byte("cm.bilibili.com")))
	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		t.Log(err)
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Log("Read error", err)
	}
	t.Log(string(body))
}
