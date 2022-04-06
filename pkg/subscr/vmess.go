package subscr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

type vmess struct {
	get  func(interface{}) string
	trim func([]byte) []byte
}

var DefaultVmess = &vmess{}

//ParseLink parse vmess link
// eg: vmess://eyJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiIsInZlcmlmeV9jZXJ0Ijp0cnV
//             lLCJhZGQiOiIxMjcuMC4wLjEiLCJwb3J0IjowLCJhaWQiOjIsIm5ldCI6InRjcC
//             IsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Im5hbWUiLCJpZCI6ImNjY2MtY
//             2NjYy1kZGRkLWFhYS00NmExYWFhYWFhIiwiY2xhc3MiOjF9Cg
func (v *vmess) ParseLink(link []byte) (*Point, error) {
	if v.get == nil {
		v.get = func(p interface{}) string {
			switch p.(type) {
			case string:
				return p.(string)
			case float64:
				return strconv.Itoa(int(p.(float64)))
			}

			return ""
		}
	}

	if v.trim == nil {
		v.trim = func(b []byte) []byte { return trimJSON(b, '{', '}') }
	}

	n := struct {
		// address
		Address string      `json:"add,omitempty"`
		Port    interface{} `json:"port,omitempty"`
		// uuid
		Uuid string `json:"id,omitempty"`
		// alter id
		AlterId interface{} `json:"aid,omitempty"`
		// name
		Ps string `json:"ps,omitempty"`
		// (tcp\kcp\ws\h2\quic)
		Net string `json:"net,omitempty"`
		// fake type [(none\http\srtp\utp\wechat-video) *tcp or kcp or QUIC]
		Type string `json:"type,omitempty"`
		Tls  string `json:"tls,omitempty"`
		// 1)http host(cut up with (,) )
		// 2)ws host
		// 3)h2 host
		// 4)QUIC security
		Host string `json:"host,omitempty"`
		// 1)ws path
		// 2)h2 path
		// 3)QUIC key/Kcp seed
		Path       string `json:"path,omitempty"`
		V          string `json:"v,omitempty"`
		VerifyCert bool   `json:"verify_cert,omitempty"`
		Class      int64  `json:"class,omitempty"`
		Security   string `json:"security,omitempty"`
	}{}
	err := json.Unmarshal(v.trim(DecodeBase64Bytes(bytes.TrimPrefix(link, []byte("vmess://")))), &n)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(v.get(n.Port))
	if err != nil {
		return nil, fmt.Errorf("vmess port is not a number: %v", err)
	}

	switch n.Type {
	case "none":
	default:
		return nil, fmt.Errorf("vmess type is not supported: %v", n.Type)
	}

	var net *PointProtocol
	switch n.Net {
	case "ws":
		net = &PointProtocol{
			Protocol: &PointProtocol_Websocket{
				&Websocket{
					Host:               n.Host,
					Path:               n.Path,
					InsecureSkipVerify: !n.VerifyCert,
					TlsEnable:          n.Tls == "tls",
					TlsCaCert:          "",
				},
			},
		}
	case "tcp":
		net = &PointProtocol{Protocol: &PointProtocol_None{&None{}}}
	default:
		return nil, fmt.Errorf("vmess net is not supported: %v", n.Net)
	}

	return &Point{
		Name:   "[vmess]" + n.Ps,
		Origin: Point_remote,
		Protocols: []*PointProtocol{
			{
				Protocol: &PointProtocol_Simple{
					&Simple{
						Host: n.Address,
						Port: int32(port),
					},
				},
			},
			net,
			{
				Protocol: &PointProtocol_Vmess{
					&Vmess{
						Uuid:     n.Uuid,
						AlterId:  v.get(n.AlterId),
						Security: n.Security,
					},
				},
			},
		},
	}, nil
}

func trimJSON(b []byte, start, end byte) []byte {
	s := bytes.IndexByte(b, start)
	e := bytes.LastIndexByte(b, end)
	if s == -1 || e == -1 {
		return b
	}
	return b[s : e+1]
}
