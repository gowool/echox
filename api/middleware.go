package api

import (
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/labstack/echo/v4"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type Middleware struct {
	Name       string
	Middleware func(huma.API) func(huma.Context, func(huma.Context))
}

func NewMiddleware(name string, middleware func(huma.API) func(huma.Context, func(huma.Context))) Middleware {
	return Middleware{
		Name:       name,
		Middleware: middleware,
	}
}

func AsMiddleware(middleware any) any {
	return fx.Annotate(
		middleware,
		fx.ResultTags(`group:"api-middleware"`),
	)
}

func AsMiddlewareFunc(name string, middleware func(huma.API) func(ctx huma.Context, next func(huma.Context))) any {
	return AsMiddleware(NewMiddleware(name, middleware))
}

type Authorizer func(huma.Context) error

func AuthorizationMiddleware(authorizer Authorizer, logger *zap.Logger) Middleware {
	return NewMiddleware("authorization", func(api huma.API) func(huma.Context, func(huma.Context)) {
		unauthorized := func(ctx huma.Context, errs ...error) {
			status := http.StatusUnauthorized
			message := http.StatusText(status)

			if strings.HasPrefix(strings.ToLower(ctx.Header(echo.HeaderAuthorization)), "basic ") {
				ctx.SetHeader(echo.HeaderWWWAuthenticate, "basic realm=Restricted")
			}

			if err := huma.WriteErr(api, ctx, status, message, errs...); err != nil {
				logger.Error("huma api: failed to write error", zap.Error(err))
			}
		}

		return func(ctx huma.Context, next func(huma.Context)) {
			if err := authorizer(ctx); err != nil {
				unauthorized(ctx)
				logger.Error("huma api: failed to authorize", zap.Error(err))
				return
			}
			next(ctx)
		}
	})
}
