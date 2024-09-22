package yuhaiin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Asutorufa/yuhaiin/internal/app"
	"github.com/Asutorufa/yuhaiin/internal/appapi"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	service "github.com/Asutorufa/yuhaiin/pkg/protos/statistic/grpc"
	"github.com/Asutorufa/yuhaiin/pkg/utils/unit"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type App struct {
	app *appapi.Components
	lis *http.Server

	mu      sync.Mutex
	started atomic.Bool
}

func (a *App) Start(opt *Opts) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.started.Load() {
		return errors.New("yuhaiin is already running")
	}

	errChan := make(chan error)

	go func() {
		defer a.started.Store(false)

		dialer.DefaultMarkSymbol = opt.TUN.SocketProtect.Protect

		app, err := app.Start(
			appapi.Start{
				ConfigPath: opt.Savepath,
				Setting:    fakeSetting(opt, app.PathGenerator.Config(opt.Savepath)),
				Host: net.JoinHostPort(ifOr(opt.MapStore.GetBoolean(AllowLanKey), "0.0.0.0", "127.0.0.1"),
					fmt.Sprint(opt.MapStore.GetInt(YuhaiinPortKey))),
				ProcessDumper: NewUidDumper(opt.TUN.UidDumper),
			})
		if err != nil {
			errChan <- err
			return
		}
		defer app.Close()

		a.app = app

		lis := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Debug("http request", "host", r.Host, "method", r.Method, "path", r.URL.Path)
			app.Mux.ServeHTTP(w, r)
		})}
		defer lis.Close()

		a.lis = lis
		a.started.Store(true)

		close(errChan)
		defer opt.CloseFallback.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go a.notifyFlow(ctx, app, opt)

		if err := a.lis.Serve(app.HttpListener); err != nil {
			log.Error("yuhaiin serve failed", "err", err)
		}
	}()

	return <-errChan
}

func (a *App) notifyFlow(ctx context.Context, app *appapi.Components, opt *Opts) {
	if opt.NotifySpped == nil || !opt.NotifySpped.NotifyEnable() {
		return
	}

	ticker := time.NewTicker(time.Second * 2)
	defer ticker.Stop()

	var last *service.TotalFlow
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			flow, err := app.Connections.Total(ctx, &emptypb.Empty{})
			if err != nil {
				log.Error("get connections failed", "err", err)
				continue
			}

			if last == nil {
				last = flow
				continue
			}

			dr := reduceUnit((flow.Download - last.Download) / 2)
			ur := reduceUnit((flow.Upload - last.Upload) / 2)
			download, upload := reduceUnit(flow.Download), reduceUnit(flow.Upload)
			last = flow
			opt.NotifySpped.Notify(flowString(download, upload, ur, dr))
		}
	}
}

func (a *App) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.Running() {
		return nil
	}

	if a.lis != nil {
		err := a.lis.Close()
		if err != nil {
			return err
		}
	}

	for a.Running() {
		runtime.Gosched()
	}

	a.app = nil
	a.lis = nil

	return nil
}

func (a *App) Running() bool { return a.started.Load() }

func (a *App) SaveNewBypass(link string) error {
	if !a.Running() || a.app == nil || a.app.Tools == nil {
		return fmt.Errorf("proxy service is not start")
	}

	_, err := a.app.Tools.SaveRemoteBypassFile(context.TODO(), &wrapperspb.StringValue{Value: link})
	return err
}

func reduceUnit(v uint64) string {
	x, unit := unit.ReducedUnit(float64(v))
	return fmt.Sprintf("%.2f %v", x, unit)
}

func flowString(download, upload, ur, dr string) string {
	totalMaxLen := "%" + strconv.Itoa(max(len(download), len(upload))) + "s"
	rateMaxLen := "%" + strconv.Itoa(max(len(ur), len(dr))) + "s"

	return fmt.Sprintf(
		"Download("+totalMaxLen+"): "+rateMaxLen+"/S\n Upload ("+totalMaxLen+"): "+rateMaxLen+"/S",
		download,
		ur,
		upload,
		dr,
	)
}
