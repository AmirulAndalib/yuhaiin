package parser

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/point"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/subscribe"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

func init() {
	store.Store(subscribe.Type_shadowsocksr, func(data []byte) (*point.Point, error) {
		data = bytes.TrimPrefix(data, []byte("ssr://"))
		dst := make([]byte, base64.RawStdEncoding.DecodedLen(len(data)))
		_, err := base64.RawURLEncoding.Decode(dst, data)
		if err != nil {
			log.Warningf("parse shadowsocksr failed: %v, %v", err, string(data))
		}
		// ParseLink parse a base64 encode ssr link
		decodeStr := bytes.Split(dst, []byte{'/', '?'})

		x := strings.Split(string(decodeStr[0]), ":")
		if len(x) != 6 {
			return nil, errors.New("link: " + string(decodeStr[0]) + " is not shadowsocksr link")
		}
		if len(decodeStr) <= 1 {
			decodeStr = append(decodeStr, []byte{})
		}
		query, _ := url.ParseQuery(string(decodeStr[1]))

		port, err := strconv.ParseUint(x[1], 10, 16)
		if err != nil {
			return nil, errors.New("invalid port")
		}

		password, err := base64.RawURLEncoding.DecodeString(x[5])
		if err != nil {
			log.Warningln("parse shadowsocksr password failed:", err)
		}

		return &point.Point{
			Origin: point.Origin_remote,
			Name:   "[ssr]" + string(yerror.Ignore(base64.RawURLEncoding.DecodeString(query.Get("remarks")))),
			Protocols: []*protocol.Protocol{
				{
					Protocol: &protocol.Protocol_Simple{
						Simple: &protocol.Simple{
							Host: x[0],
							Port: int32(port),
						},
					},
				},
				{
					Protocol: &protocol.Protocol_Shadowsocksr{
						Shadowsocksr: &protocol.Shadowsocksr{
							Server:     x[0],
							Port:       x[1],
							Protocol:   x[2],
							Method:     x[3],
							Obfs:       x[4],
							Password:   string(password),
							Obfsparam:  string(yerror.Ignore(base64.RawURLEncoding.DecodeString(query.Get("obfsparam")))),
							Protoparam: string(yerror.Ignore(base64.RawURLEncoding.DecodeString(query.Get("protoparam")))),
						},
					},
				},
			},
		}, nil
	})
}
