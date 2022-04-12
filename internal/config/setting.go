package config

import (
	context "context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/protos/config"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

//go:generate  protoc --go_out=. --go-grpc_out=. --go-grpc_opt=paths=source_relative --go_opt=paths=source_relative config.proto

// settingDecodeJSON decode setting json to struct
func settingDecodeJSON(dir string) (*config.Setting, error) {
	p := map[string]string{
		config.Proxy_http.String():   "127.0.0.1:8188",
		config.Proxy_socks5.String(): "127.0.0.1:1080",
		config.Proxy_redir.String():  "127.0.0.1:8088",
	}

	pa := &config.Setting{
		SystemProxy: &config.SystemProxy{
			Http:   true,
			Socks5: false,
			// linux system set socks5 will make firfox websocket can't connect
			// https://askubuntu.com/questions/890274/slack-desktop-client-on-16-04-behind-proxy-server
		},
		Bypass: &config.Bypass{
			Enabled:    true,
			BypassFile: filepath.Join(dir, "yuhaiin.conf"),
		},
		Proxy: &config.Proxy{
			Proxy: p,
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
	data, err := ioutil.ReadFile(filepath.Join(dir, "yuhaiinConfig.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return pa, settingEnCodeJSON(pa, dir)
		}
		return pa, fmt.Errorf("read config file failed: %v", err)
	}
	err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, pa)
	if err == nil {
		if pa.Proxy.Proxy == nil {
			pa.Proxy.Proxy = make(map[string]string)
		}

		for k, v := range p {
			if pa.Proxy.Proxy[k] == "" {
				pa.Proxy.Proxy[k] = v
			}
		}
	}
	return pa, err
}

// settingEnCodeJSON encode setting struct to json
func settingEnCodeJSON(pa *config.Setting, dir string) error {
	_, err := os.Stat(filepath.Join(dir, "yuhaiinConfig.json"))
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return fmt.Errorf("make dir failed: %v", err)
		}
	}

	data, err := protojson.MarshalOptions{Multiline: true, Indent: "\t"}.Marshal(pa)
	if err != nil {
		return fmt.Errorf("marshal setting failed: %v", err)
	}

	return ioutil.WriteFile(filepath.Join(dir, "yuhaiinConfig.json"), data, os.ModePerm)
}

type observer struct {
	diff func(current, old *config.Setting) bool
	exec func(current *config.Setting)
}
type Config struct {
	config.UnimplementedConfigDaoServer
	current *config.Setting
	old     *config.Setting
	path    string
	exec    map[string]InitFunc

	os []observer

	lock     sync.RWMutex
	execlock sync.RWMutex
}

type InitFunc func(*config.Setting) error

func NewConfig(dir string) (*Config, error) {
	c, err := settingDecodeJSON(dir)
	if err != nil {
		return nil, fmt.Errorf("decode setting failed: %v", err)
	}

	cf := &Config{current: c, old: c, path: dir, exec: make(map[string]InitFunc)}

	return cf, nil
}

func (c *Config) Load(context.Context, *emptypb.Empty) (*config.Setting, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return c.current, nil
}

func (c *Config) Save(_ context.Context, s *config.Setting) (*emptypb.Empty, error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	err := settingEnCodeJSON(s, c.path)
	if err != nil {
		return &emptypb.Empty{}, fmt.Errorf("save settings failed: %v", err)
	}

	c.old = proto.Clone(c.current).(*config.Setting)
	c.current = proto.Clone(s).(*config.Setting)

	wg := sync.WaitGroup{}
	for i := range c.os {
		wg.Add(1)
		go func(o observer) {
			wg.Done()
			if o.diff(proto.Clone(c.current).(*config.Setting), proto.Clone(c.old).(*config.Setting)) {
				o.exec(proto.Clone(c.current).(*config.Setting))
			}
		}(c.os[i])
	}
	wg.Wait()

	return &emptypb.Empty{}, nil
}

func (c *Config) AddObserver(diff func(current, old *config.Setting) bool, exec func(current *config.Setting)) {
	if diff == nil || exec == nil {
		return
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	c.os = append(c.os, observer{diff, exec})
}

type ConfigObserver interface {
	AddObserverAndExec(func(current, old *config.Setting) bool, func(current *config.Setting))
	AddExecCommand(string, InitFunc)
}

func (c *Config) AddObserverAndExec(diff func(current, old *config.Setting) bool, exec func(current *config.Setting)) {
	c.AddObserver(diff, exec)
	exec(c.current)
}

func (c *Config) AddExecCommand(key string, o InitFunc) error {
	if o == nil {
		return nil
	}

	c.execlock.Lock()
	defer c.execlock.Unlock()
	_, ok := c.exec[key]
	if ok {
		return fmt.Errorf("already exist command %v", key)
	}

	c.exec[key] = o
	return nil
}

func (c *Config) ExecCommand(key string) error {
	c.execlock.RLock()
	defer c.execlock.RUnlock()
	e, ok := c.exec[key]
	if !ok {
		return fmt.Errorf("command %v is not exist", key)
	}

	return e(c.current)
}

func (c *Config) DeleteExecCommand(key string) {
	c.execlock.Lock()
	defer c.execlock.Unlock()
	delete(c.exec, key)
}
