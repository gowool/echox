package echox

import (
	"context"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humaecho"
	"github.com/labstack/echo/v4"
	"go.uber.org/fx"
)

type areaKey struct{}

func CtxArea(ctx context.Context) string {
	return ctx.Value(areaKey{}).(string)
}

type EchoParams struct {
	fx.In
	Config         Config
	ErrorHandler   echo.HTTPErrorHandler
	Renderer       echo.Renderer
	Validator      echo.Validator
	IPExtractor    echo.IPExtractor
	Filesystem     fs.FS           `name:"echo-fs"`
	Handlers       []Handler       `group:"handler"`
	Middlewares    []Middleware    `group:"middleware"`
	APIHandlers    []APIHandler    `group:"api-handler"`
	APIMiddlewares []APIMiddleware `group:"api-middleware"`
}

func NewEcho(params EchoParams) *echo.Echo {
	e := echo.New()
	e.Debug = false
	e.HideBanner = true
	e.HidePort = true
	e.Server.Handler = nil
	e.Server = nil
	e.TLSServer.Handler = nil
	e.TLSServer = nil
	e.StdLogger = nil
	e.Logger = nil
	e.Renderer = params.Renderer
	e.Validator = params.Validator
	e.IPExtractor = params.IPExtractor
	e.Filesystem = params.Filesystem
	e.HTTPErrorHandler = params.ErrorHandler

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

	apiHandlers := make(map[string][]APIHandler)
	for _, handler := range params.APIHandlers {
		apiHandlers[handler.Area()] = append(apiHandlers[handler.Area()], handler)
	}

	for _, name := range params.Config.Middlewares.Router.Before {
		if middleware, ok := middlewares[name]; ok {
			e.Pre(middleware)
		}
	}

	for _, name := range params.Config.Middlewares.Router.After {
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

		for key, cfgAPI := range cfg.API {
			if !cfgAPI.Enabled {
				continue
			}

			humaConfig := huma.DefaultConfig("", "")
			humaConfig.Servers = []*huma.Server{{URL: cfg.Path + cfgAPI.Path}}
			humaConfig.DocsPath = cfgAPI.DocsPath
			humaConfig.Info = &cfgAPI.Info

			schemas := humaConfig.Components.Schemas
			humaConfig.Components = &cfgAPI.Components
			humaConfig.Components.Schemas = schemas

			api := humaecho.NewWithGroup(e, group.Group(cfgAPI.Path), humaConfig)

			for _, name := range cfgAPI.Middlewares {
				if mdw, ok := apiMiddlewares[name]; ok {
					api.UseMiddleware(mdw(api))
				}
			}

			for _, h := range apiHandlers[fmt.Sprintf("%s-%s", area, key)] {
				h.Register(e, api)
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
