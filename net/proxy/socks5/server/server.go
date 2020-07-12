package socks5server

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/net/common"
	socks5client "github.com/Asutorufa/yuhaiin/net/proxy/socks5/client"
)

type Option struct {
	Username string
	Password string
}

func Socks5Handle(modeOption ...func(*Option)) func(net.Conn, func(string) (net.Conn, error)) {
	o := &Option{}
	for index := range modeOption {
		if modeOption[index] == nil {
			continue
		}
		modeOption[index](o)
	}
	return func(conn net.Conn, f func(string) (net.Conn, error)) {
		handle(o.Username, o.Password, conn, f)
	}
}

func handle(user, key string, client net.Conn, dst func(string) (net.Conn, error)) {
	var err error
	b := common.BuffPool.Get().([]byte)
	defer common.BuffPool.Put(b)

	//socks5 first handshake
	if _, err = client.Read(b[:]); err != nil {
		return
	}

	if b[0] != 0x05 { //只处理Socks5协议
		writeFirstResp(client, 0xff)
		return
	}

	writeFirstResp(client, 0x00)

	if b[1] == 0x01 && b[2] == 0x02 {
		// 对用户名密码进行判断
		if _, err = client.Read(b[:]); err != nil {
			return
		}
		username := b[2 : 2+b[1]]
		password := b[3+b[1] : 3+b[1]+b[2+b[1]]]
		if user != string(username) || key != string(password) {
			writeFirstResp(client, 0x01)
			return
		}
		writeFirstResp(client, 0x00)
	}

	// socks5 second handshake
	_, err = client.Read(b[:])
	if err != nil {
		return
	}

	host, port, _, err := ResolveAddr(b[3:])
	if err != nil {
		return
	}

	var server net.Conn
	switch b[1] {
	case 0x01:
		if server, err = dst(net.JoinHostPort(host, strconv.Itoa(port))); err != nil {
			writeSecondResp(client, 0x04, client.LocalAddr().String())
			return
		}

	case 0x03: // udp
		writeSecondResp(client, 0x00, client.LocalAddr().String())
		for {
			_, err := client.Read(b[:2])
			if err, ok := err.(net.Error); ok && err.Timeout() {
				continue
			}
			return
		}

	case 0x02: // bind request
		fallthrough

	default:
		writeSecondResp(client, 0x07, client.LocalAddr().String())
		return
	}
	defer server.Close()

	writeSecondResp(client, 0x00, client.LocalAddr().String()) // response to connect successful

	// handshake successful
	common.Forward(client, server)
}

func ResolveAddr(raw []byte) (dst string, port, size int, err error) {
	if len(raw) <= 0 {
		return "", 0, 0, fmt.Errorf("ResolveAddr() -> raw byte array is empty")
	}
	targetAddrRawSize := 1
	switch raw[0] {
	case 0x01:
		dst = net.IP(raw[targetAddrRawSize : targetAddrRawSize+4]).String()
		targetAddrRawSize += 4
	case 0x04:
		if len(raw) < 1+16+2 {
			return "", 0, 0, errors.New("errShortAddrRaw")
		}
		dst = net.IP(raw[1 : 1+16]).String()
		targetAddrRawSize += 16
	case 0x03:
		addrLen := int(raw[1])
		if len(raw) < 1+1+addrLen+2 {
			// errShortAddrRaw
			return "", 0, 0, errors.New("error short address raw")
		}
		dst = string(raw[1+1 : 1+1+addrLen])
		targetAddrRawSize += 1 + addrLen
	default:
		// errUnrecognizedAddrType
		return "", 0, 0, errors.New("udp socks: Failed to get UDP package header")
	}
	port = (int(raw[targetAddrRawSize]) << 8) | int(raw[targetAddrRawSize+1])
	targetAddrRawSize += 2
	return dst, port, targetAddrRawSize, nil
}

func writeFirstResp(conn net.Conn, errREP byte) {
	_, _ = conn.Write([]byte{0x05, errREP})
}

func writeSecondResp(conn net.Conn, errREP byte, addr string) {
	requestlistenAddr, err := socks5client.ParseAddr(addr)
	if err != nil {
		return
	}
	_, _ = conn.Write(append([]byte{0x05, errREP, 0x00}, requestlistenAddr...))
}
