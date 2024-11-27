package echox

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"unsafe"

	"github.com/danielgtaylor/huma/v2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/gowool/echox/api"
)

type areaKey struct{}

func CtxArea(ctx context.Context) string {
	area, _ := ctx.Value(areaKey{}).(string)
	return area
}

type EchoParams struct {
	fx.In
	Config         RouterConfig
	Logger         *zap.Logger
	ErrorHandler   echo.HTTPErrorHandler
	Renderer       echo.Renderer
	Validator      echo.Validator
	IPExtractor    echo.IPExtractor
	Filesystem     fs.FS            `name:"echo-fs"`
	Handlers       []Handler        `group:"handler"`
	Middlewares    []Middleware     `group:"middleware"`
	APIHandlers    []api.Handler    `group:"api-handler"`
	APIMiddlewares []api.Middleware `group:"api-middleware"`
}

func NewEcho(params EchoParams) *echo.Echo {
	e := echo.New()
	e.Debug = false
	e.HideBanner = true
	e.HidePort = true
	e.Renderer = params.Renderer
	e.Validator = params.Validator
	e.IPExtractor = params.IPExtractor
	e.Filesystem = params.Filesystem
	e.HTTPErrorHandler = params.ErrorHandler
	e.StdLogger = zap.NewStdLog(params.Logger)
	e.Logger.SetOutput(&loggerWriter{echo: e.Logger, zap: params.Logger})

	middlewares := make(map[string]echo.MiddlewareFunc)
	for _, middleware := range params.Middlewares {
		middlewares[middleware.Name] = middleware.Middleware
	}

	apiMiddlewares := make(map[string]func(huma.API) func(huma.Context, func(huma.Context)))
	for _, middleware := range params.APIMiddlewares {
		apiMiddlewares[middleware.Name] = middleware.Middleware
	}

	handlers := make(map[string][]Handler)
	for _, handler := range params.Handlers {
		handlers[handler.Area()] = append(handlers[handler.Area()], handler)
	}

	apiHandlers := make(map[string][]api.Handler)
	for _, apiHandler := range params.APIHandlers {
		key := fmt.Sprintf("%s-%s", apiHandler.Area(), apiHandler.Version())
		apiHandlers[key] = append(apiHandlers[key], apiHandler)
	}

	for _, name := range params.Config.Middlewares.Before {
		if middleware, ok := middlewares[name]; ok {
			e.Pre(middleware)
		}
	}

	for _, name := range params.Config.Middlewares.After {
		if middleware, ok := middlewares[name]; ok {
			e.Use(middleware)
		}
	}

	for area, cfg := range params.Config.Areas {
		if !cfg.Enabled {
			continue
		}

		group := e.Group(cfg.Path, func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				c.Set("area", area)
				c.SetRequest(c.Request().WithContext(context.WithValue(c.Request().Context(), areaKey{}, area)))
				return next(c)
			}
		})
		for _, name := range cfg.Middlewares {
			if middleware, ok := middlewares[name]; ok {
				group.Use(middleware)
			}
		}
		for _, h := range handlers[area] {
			h.Register(e, group)
		}

		if cfg.API == nil {
			continue
		}

		for version, cfgAPI := range cfg.API {
			if !cfgAPI.Enabled {
				continue
			}
			cfgAPI.setDefaults()

			humaConfig := huma.DefaultConfig("", "")
			humaConfig.Servers = []*huma.Server{{URL: cfg.Path + cfgAPI.Path}}
			humaConfig.DocsPath = cfgAPI.DocsPath
			humaConfig.Info = &cfgAPI.Info

			schemas := humaConfig.Components.Schemas
			humaConfig.Components = &cfgAPI.Components
			humaConfig.Components.Schemas = schemas

			humaAPI := huma.NewAPI(humaConfig, api.NewAdapter(e, group.Group(cfgAPI.Path)))

			for _, name := range cfgAPI.Middlewares {
				if mdw, ok := apiMiddlewares[name]; ok {
					humaAPI.UseMiddleware(mdw(humaAPI))
				}
			}

			for _, h := range apiHandlers[fmt.Sprintf("%s-%s", area, version)] {
				h.Register(e, humaAPI)
			}
		}
	}

	return e
}

func IPExtractor() echo.IPExtractor {
	return func(r *http.Request) string {
		if ip := r.Header.Get(echo.HeaderXForwardedFor); ip != "" {
			i := strings.IndexAny(ip, ",")
			if i > 0 {
				xffip := strings.TrimSpace(ip[:i])
				xffip = strings.TrimPrefix(xffip, "[")
				xffip = strings.TrimSuffix(xffip, "]")
				return xffip
			}
			return ip
		}
		if ip := r.Header.Get(echo.HeaderXRealIP); ip != "" {
			ip = strings.TrimPrefix(ip, "[")
			ip = strings.TrimSuffix(ip, "]")
			return ip
		}
		ra, _, _ := net.SplitHostPort(r.RemoteAddr)
		return ra
	}
}

type loggerWriter struct {
	echo echo.Logger
	zap  *zap.Logger
}

func (w *loggerWriter) Write(p []byte) (n int, err error) {
	msg := unsafe.String(unsafe.SliceData(p), len(p))

	switch w.echo.Level() {
	case log.DEBUG:
		w.zap.Debug(msg, zap.Any("lvl", w.echo.Level()))
	case log.INFO:
		w.zap.Info(msg, zap.Any("lvl", w.echo.Level()))
	case log.WARN:
		w.zap.Warn(msg, zap.Any("lvl", w.echo.Level()))
	case log.OFF:
	default:
		w.zap.Error(msg, zap.Any("lvl", w.echo.Level()))
	}
	return len(p), nil
}
