package parser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
)

func init() {
	store.Store(subscribe.Type_vmess, func(data []byte) (*point.Point, error) {
		//ParseLink parse vmess link
		// eg: vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnV
		//             lLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcC
		//             IsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY
		//             2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg

		n := struct {
			// address
			Address string `json:"add,omitempty"`
			Port    any    `json:"port,omitempty"`
			// uuid
			Uuid     string `json:"id,omitempty"`
			Security string `json:"security,omitempty"`
			// alter id
			AlterId any `json:"aid,omitempty"`

			// name
			Ps     string `json:"ps,omitempty"`
			Remark string `json:"remark,omitempty"`

			// (tcp\kcp\ws\h2\quic)
			Net string `json:"net,omitempty"`

			// fake type [(none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC]
			Type       string `json:"type,omitempty"`
			HeaderType string `json:"headerType,omitempty"`

			Tls        string `json:"tls,omitempty"`
			Sni        string `json:"sni,omitempty"`
			VerifyCert bool   `json:"verify_cert,omitempty"`

			// 1)http host(cut up with (,) )
			// 2)ws host
			// 3)h2 host
			// 4)QUIC security
			Host string `json:"host,omitempty"`
			// 1)ws path
			// 2)h2 path
			// 3)QUIC key/Kcp seed
			Path string `json:"path,omitempty"`

			V     string `json:"v,omitempty"`
			Class int64  `json:"class,omitempty"`
		}{}

		data = bytes.TrimRight(bytes.TrimSpace(bytes.TrimPrefix(data, []byte("vmess://"))), "=")
		dst := make([]byte, base64.RawStdEncoding.DecodedLen(len(data)))
		_, err := base64.RawStdEncoding.Decode(dst, data)
		if err != nil {
			log.Warningln("base64 decode failed: ", err, string(data), len(data))
		}
		if err := json.Unmarshal(trimJSON(dst, '{', '}'), &n); err != nil {
			return nil, err
		}

		if n.Ps == "" {
			n.Ps = n.Remark
		}

		port, err := strconv.ParseUint(fmt.Sprint(n.Port), 10, 16)
		if err != nil {
			return nil, fmt.Errorf("vmess port is not a number: %w", err)
		}

		if n.HeaderType == "" {
			n.HeaderType = n.Type
		}
		switch n.HeaderType {
		case "none":
		default:
			return nil, fmt.Errorf("vmess type is not supported: %v", n.Type)
		}

		var netProtocol *protocol.Protocol
		switch n.Net {
		case "ws":
			if n.Host == "" {
				n.Host = net.JoinHostPort(n.Address, fmt.Sprint(n.Port))
			}
			if n.Sni == "" {
				n.Sni, _, err = net.SplitHostPort(n.Host)
				if err != nil {
					log.Warningf("split host and port failed: %v", err)
					n.Sni = n.Host
				}
			}

			netProtocol = &protocol.Protocol{
				Protocol: &protocol.Protocol_Websocket{
					Websocket: &protocol.Websocket{
						Host: n.Host,
						Path: n.Path,
						Tls: &protocol.TlsConfig{
							ServerName:         n.Sni,
							InsecureSkipVerify: !n.VerifyCert,
							Enable:             n.Tls == "tls",
							CaCert:             nil,
						},
					},
				},
			}
		case "tcp":
			netProtocol = &protocol.Protocol{Protocol: &protocol.Protocol_None{None: &protocol.None{}}}
		default:
			return nil, fmt.Errorf("vmess net is not supported: %v", n.Net)
		}

		return &point.Point{
			Name:   "[vmess]" + n.Ps,
			Origin: point.Origin_remote,
			Protocols: []*protocol.Protocol{
				{
					Protocol: &protocol.Protocol_Simple{
						Simple: &protocol.Simple{
							Host: n.Address,
							Port: int32(port),
						},
					},
				},
				netProtocol,
				{
					Protocol: &protocol.Protocol_Vmess{
						Vmess: &protocol.Vmess{
							Uuid:     n.Uuid,
							AlterId:  fmt.Sprint(n.AlterId),
							Security: n.Security,
						},
					},
				},
			},
		}, nil
	})
}
