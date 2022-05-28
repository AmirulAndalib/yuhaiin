package simplehttp

import (
	"context"
	_ "embed"
	"fmt"
	"io/ioutil"
	"net/http"
	"sort"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

//go:embed node.js
var nodeJS []byte

//go:embed sub.js
var subJS []byte

func initNode(mux *http.ServeMux, nm node.NodeManagerServer) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		point, err := nm.Now(context.TODO(), &emptypb.Empty{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := protojson.MarshalOptions{Indent: "  "}.Marshal(point)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte(createHTML(fmt.Sprintf(`<pre>%s</pre>`, string(data)))))
	})

	mux.HandleFunc("/group", func(w http.ResponseWriter, r *http.Request) {
		ns, err := nm.GetManager(context.TODO(), &wrapperspb.StringValue{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sort.Strings(ns.Groups)

		str := utils.GetBuffer()
		defer utils.PutBuffer(str)

		for _, n := range ns.GetGroups() {
			str.WriteString(fmt.Sprintf(`<a href="/nodes?group=%s">%s</a>`, n, n))
			str.WriteString("<br/>")
			str.WriteByte('\n')
		}

		str.WriteString("<hr/>")
		str.WriteString(`<a href="/node/add">Add New Node</a>`)

		w.Write([]byte(createHTML(str.String())))
	})

	mux.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) {
		group := r.URL.Query().Get("group")

		ns, err := nm.GetManager(context.TODO(), &wrapperspb.StringValue{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		nhm := ns.GroupNodesMap[group].NodeHashMap
		nds := ns.GroupNodesMap[group].Nodes
		sort.Strings(nds)

		str := utils.GetBuffer()
		defer utils.PutBuffer(str)

		str.WriteString(fmt.Sprintf(`<script>%s</script>`, nodeJS))
		for _, v := range nds {
			str.WriteString(fmt.Sprintf("<li id=%s>", "i"+nhm[v]))
			str.WriteString(fmt.Sprintf(`<a href="/node?hash=%s">%s</a>`, nhm[v], v))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(`TCP: <a class="tcp">N/A</a>`)
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(`UDP: <a class="udp">N/A</a>`)
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a class="test" href='javascript:latency("%s")'>Test</a>`, nhm[v]))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='/use?hash=%s'>Use This</a>`, nhm[v]))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='javascript: del("%s");'>Delete</a>`, nhm[v]))
			str.WriteString("</li>")
			if os == "android" {
				str.WriteByte('\n')
			}
		}
		w.Write([]byte(createHTML(str.String())))
	})

	mux.HandleFunc("/node", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")

		n, err := nm.GetNode(context.TODO(), &wrapperspb.StringValue{Value: hash})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(n)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		str := utils.GetBuffer()
		defer utils.PutBuffer(str)

		str.WriteString("<script>")
		str.Write(configJS)
		str.WriteString("</script>")
		str.WriteString(fmt.Sprintf(`<pre id="node" contenteditable="false">%s</pre>`, string(data)))
		str.WriteString("<p>")
		str.WriteString(`<a href='javascript: document.getElementById("node").setAttribute("contenteditable", "true"); '>Edit</a>`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`<a href='javascript: save("node","/node/save");'>Save</a>`)
		str.WriteString("</p>")
		str.WriteString(`<pre id="error"></pre>`)

		w.Write([]byte(createHTML(str.String())))
	})

	mux.HandleFunc("/node/add", func(w http.ResponseWriter, r *http.Request) {
		str := utils.GetBuffer()
		defer utils.PutBuffer(str)

		str.WriteString("<script>")
		str.Write(configJS)
		str.WriteString("</script>")

		data, _ := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(&node.Point{
			Name:   "xxx",
			Group:  "xxx",
			Origin: node.Point_manual,
			Protocols: []*node.PointProtocol{
				{
					Protocol: &node.PointProtocol_Simple{
						Simple: &node.Simple{
							Tls: &node.TlsConfig{},
						},
					},
				},
				{
					Protocol: &node.PointProtocol_None{},
				},
			},
		})
		str.WriteString(`<pre contenteditable="true" id="node">`)
		str.Write(data)
		str.WriteString("</pre>")
		str.WriteString(`<a href='javascript: save("node","/node/save");'>Save</a>`)
		str.WriteString("&nbsp;&nbsp;&nbsp;&nbsp;")
		str.WriteString(`<a href="/node/template">Protocols Template</a>`)

		w.Write([]byte(createHTML(str.String())))
	})

	mux.HandleFunc("/node/save", func(w http.ResponseWriter, r *http.Request) {
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		point := &node.Point{}
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, point)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = nm.SaveNode(context.TODO(), point)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("successful"))
	})

	mux.HandleFunc("/node/delete", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")
		if hash == "" {
			http.Error(w, "hash is empty", http.StatusInternalServerError)
			return
		}

		_, err := nm.DeleteNode(context.TODO(), &wrapperspb.StringValue{Value: hash})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write(nil)
	})

	mux.HandleFunc("/node/template", func(w http.ResponseWriter, r *http.Request) {
		create := func(name string, data proto.Message) string {
			b, _ := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(data)
			str := utils.GetBuffer()
			defer utils.PutBuffer(str)

			str.WriteString("<hr/>")
			str.WriteString(name)
			str.WriteString("<pre>")
			str.Write(b)
			str.WriteString("</pre>")

			return str.String()
		}

		str := utils.GetBuffer()
		defer utils.PutBuffer(str)

		str.WriteString("TEMPLATE")
		str.WriteString(create("simple", &node.PointProtocol{Protocol: &node.PointProtocol_Simple{Simple: &node.Simple{Tls: &node.TlsConfig{CaCert: [][]byte{{0x0, 0x01}}}}}}))
		str.WriteString(create("none", &node.PointProtocol{Protocol: &node.PointProtocol_None{}}))
		str.WriteString(create("websocket", &node.PointProtocol{Protocol: &node.PointProtocol_Websocket{Websocket: &node.Websocket{Tls: &node.TlsConfig{CaCert: [][]byte{{0x0, 0x01}}}}}}))
		str.WriteString(create("quic", &node.PointProtocol{Protocol: &node.PointProtocol_Quic{Quic: &node.Quic{Tls: &node.TlsConfig{CaCert: [][]byte{{0x0, 0x01}}}}}}))
		str.WriteString(create("shadowsocks", &node.PointProtocol{Protocol: &node.PointProtocol_Shadowsocks{}}))
		str.WriteString(create("obfshttp", &node.PointProtocol{Protocol: &node.PointProtocol_ObfsHttp{}}))
		str.WriteString(create("shadowsocksr", &node.PointProtocol{Protocol: &node.PointProtocol_Shadowsocksr{}}))
		str.WriteString(create("vmess", &node.PointProtocol{Protocol: &node.PointProtocol_Vmess{}}))
		str.WriteString(create("trojan", &node.PointProtocol{Protocol: &node.PointProtocol_Trojan{}}))
		str.WriteString(create("socks5", &node.PointProtocol{Protocol: &node.PointProtocol_Socks5{}}))
		str.WriteString(create("http", &node.PointProtocol{Protocol: &node.PointProtocol_Http{}}))

		w.Write([]byte(createHTML(str.String())))
	})

	mux.HandleFunc("/latency", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")
		t := r.URL.Query().Get("type")
		lt, err := nm.Latency(context.TODO(), &node.LatencyReq{
			Requests: []*node.LatencyReqRequest{{Hash: hash, Tcp: t == "tcp", Udp: t == "udp"}}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if _, ok := lt.HashLatencyMap[hash]; !ok {
			http.Error(w, "test latency timeout or can't connect", http.StatusInternalServerError)
			return
		}

		var resp string
		if t == "tcp" {
			resp = lt.HashLatencyMap[hash].Tcp
		} else if t == "udp" {
			resp = lt.HashLatencyMap[hash].Udp
		}

		w.Write([]byte(resp))
	})

	mux.HandleFunc("/use", func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")

		p, err := nm.Use(context.TODO(), &wrapperspb.StringValue{Value: hash})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := protojson.MarshalOptions{Indent: "  "}.Marshal(p)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte(createHTML(fmt.Sprintf(`<pre>%s</pre>`, string(data)))))
	})

	// sub

	mux.HandleFunc("/sub", func(w http.ResponseWriter, r *http.Request) {
		links, err := nm.GetLinks(context.TODO(), &emptypb.Empty{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		str := utils.GetBuffer()
		defer utils.PutBuffer(str)

		str.Write(toastHTML)
		str.WriteString("<script>")
		str.Write(subJS)
		str.WriteString("</script>")
		ls := make([]string, 0, len(links.Links))
		for v := range links.Links {
			ls = append(ls, v)
		}
		sort.Strings(ls)

		for _, v := range ls {
			l := links.Links[v]
			str.WriteString("<li>")
			str.WriteString(fmt.Sprintf(`<a href='javascript: copy("%s");'>%s</a>`, l.GetUrl(), l.GetName()))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='/sub/delete?name=%s'>Delete</a>`, l.GetName()))
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(fmt.Sprintf(`<a href='/sub/update?name=%s'>Update</a>`, l.GetName()))
			str.WriteString("</li>")
		}

		str.WriteString("<hr/>")
		str.WriteString("Add a New Link<br/><br/>")
		str.WriteString(`Name:`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`<input type="text" id="name" value="">`)
		str.WriteString("<br/>")
		str.WriteString(`Link:`)
		str.WriteString("&nbsp;&nbsp;")
		str.WriteString(`<input type="text" id="link" value="">`)
		str.WriteString("<br/>")
		str.WriteString(`<a href="javascript: add();">ADD</a>`)
		w.Write([]byte(createHTML(str.String())))
	})

	mux.HandleFunc("/sub/add", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		link := r.URL.Query().Get("link")

		if name == "" || link == "" {
			http.Error(w, "name or link is empty", http.StatusInternalServerError)
			return
		}

		_, err := nm.SaveLinks(context.TODO(), &node.SaveLinkReq{
			Links: []*node.NodeLink{
				{
					Name: name,
					Url:  link,
				},
			},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/sub", http.StatusFound)
	})

	mux.HandleFunc("/sub/delete", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Redirect(w, r, "/sub", http.StatusFound)
			return
		}

		_, err := nm.DeleteLinks(context.TODO(), &node.LinkReq{Names: []string{name}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/sub", http.StatusFound)
	})

	mux.HandleFunc("/sub/update", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Redirect(w, r, "/sub", http.StatusFound)
			return
		}

		_, err := nm.UpdateLinks(context.TODO(), &node.LinkReq{Names: []string{name}})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/sub", http.StatusFound)
	})
}
