package dns

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"golang.org/x/net/dns/dnsmessage"
)

type dnsServer struct {
	server      string
	processor   func(proxy.Address) dns.DNS
	listener    net.PacketConn
	tcpListener net.Listener
}

func NewDnsServer(server string, process func(proxy.Address) dns.DNS) server.Server {
	d := &dnsServer{server: server, processor: process}
	go func() {
		if err := d.start(); err != nil {
			log.Println(err)
		}
	}()

	go func() {
		if err := d.startTCP(); err != nil {
			log.Println(err)
		}
	}()

	return d
}

func (d *dnsServer) Close() error {
	if d.listener != nil {
		d.listener.Close()
	}
	if d.tcpListener != nil {
		d.tcpListener.Close()
	}

	return nil
}

func (d *dnsServer) start() (err error) {
	d.listener, err = net.ListenPacket("udp", d.server)
	if err != nil {
		return fmt.Errorf("dns udp server listen failed: %w", err)
	}
	defer d.listener.Close()
	log.Println("new udp dns server listen at:", d.server)

	for {
		p := utils.GetBytes(utils.DefaultSize)
		n, addr, err := d.listener.ReadFrom(p)
		if err != nil {
			if e, ok := err.(net.Error); ok {
				if e.Temporary() {
					continue
				}
			}
			return fmt.Errorf("dns server read failed: %w", err)
		}

		go func(b []byte, n int, addr net.Addr, l net.PacketConn) {
			defer utils.PutBytes(b)
			data, err := d.handle(b[:n])
			if err != nil {
				log.Println(err)
				return
			}
			l.WriteTo(data, addr)
		}(p, n, addr, d.listener)
	}

}

func (d *dnsServer) startTCP() (err error) {
	d.tcpListener, err = net.Listen("tcp", d.server)
	if err != nil {
		return fmt.Errorf("dns server listen failed: %w", err)
	}
	log.Println("new tcp dns server listen at:", d.server)
	for {
		conn, err := d.tcpListener.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok {
				if e.Temporary() {
					continue
				}
			}
			return fmt.Errorf("dns server accept failed: %w", err)
		}

		go func(c net.Conn) {
			defer c.Close()
			l := make([]byte, 2)
			_, err := io.ReadFull(c, l)
			if err != nil {
				log.Println(err)
				return
			}

			length := int(binary.BigEndian.Uint16(l))
			data := utils.GetBytes(length)
			defer utils.PutBytes(data)

			n, err := io.ReadFull(c, data[:length])
			if err != nil {
				log.Println(err)
				return
			}

			data, err = d.handle(data[:n])
			if err != nil {
				log.Println(err)
				return
			}

			binary.Write(c, binary.BigEndian, uint16(len(data)))
			c.Write(data)
		}(conn)
	}
}

func (d *dnsServer) handle(b []byte) ([]byte, error) {
	log.Println("handle----------", b)
	var parse dnsmessage.Parser

	h, err := parse.Start(b)
	if err != nil {
		return nil, fmt.Errorf("dns server parse failed: %w", err)
	}

	q, err := parse.Question()
	if err != nil {
		return nil, fmt.Errorf("dns server parse failed: %w", err)
	}

	add := proxy.ParseAddressSplit("", strings.TrimSuffix(q.Name.String(), "."), 0)

	if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA {
		log.Println("not a or aaaa")
		return d.processor(add).Do(b)
	}

	ips, err := d.processor(add).LookupIP(strings.TrimSuffix(q.Name.String(), "."))
	if err != nil {
		log.Println(err)
	}

	resp := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:                 h.ID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RCode:              dnsmessage.RCodeSuccess,
			RecursionAvailable: true,
		},
		Questions: []dnsmessage.Question{
			{
				Name:  q.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
			},
		},
	}

	for _, ip := range ips {
		resource := dnsmessage.AResource{}
		copy(resource.A[:], ip)
		resp.Answers = append(resp.Answers, dnsmessage.Resource{
			Header: dnsmessage.ResourceHeader{
				Name:  q.Name,
				Class: dnsmessage.ClassINET,
				TTL:   600,
			},
			Body: &resource,
		})
	}

	return resp.Pack()
}
