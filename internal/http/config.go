package simplehttp

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	grpcconfig "github.com/Asutorufa/yuhaiin/pkg/protos/grpc/config"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

//go:embed config.js
var configJS []byte

func initConfig(mux *http.ServeMux, cf grpcconfig.ConfigDaoServer) {
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		c, err := cf.Load(context.TODO(), &emptypb.Empty{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(c)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		str := utils.GetBuffer()
		defer utils.PutBuffer(str)
		str.WriteString("<script>")
		str.Write(configJS)
		str.WriteString("</script>")
		str.WriteString("<p>1. local dns not support proxy</p>")
		str.WriteString("<p>2. bootstrap dns to resolve proxy,localdns and remotedns domain</p>")
		str.WriteString("<p>3. bootstrap dns only support ip address and not support proxy</p>")
		str.WriteString("<hr/>")
		str.WriteString(fmt.Sprintf(`<pre id="config" contenteditable="false">%s</pre>`, string(data)))
		if strings.ToLower(runtime.GOOS) != "android" {
			str.WriteString("<p>")
			str.WriteString(`<a href='javascript: document.getElementById("config").setAttribute("contenteditable", "true"); '>Edit</a>`)
			str.WriteString("&nbsp;&nbsp;")
			str.WriteString(`<a href='javascript: save("config","/config/save");'>Save</a>`)
			str.WriteString("</p>")
		}
		str.WriteString(`<pre id="error"></pre>`)
		w.Write([]byte(createHTML(str.String())))
	})

	mux.HandleFunc("/config/save", func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		config := &config.Setting{}
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, config)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = cf.Save(context.TODO(), config)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte("successful"))
	})
}
