package echox

import (
	"github.com/danielgtaylor/huma/v2"
	"github.com/labstack/echo/v4"
	"go.uber.org/fx"
)

type Handler interface {
	Area() string
	Register(*echo.Echo, *echo.Group)
}

func AsHandler(f any) any {
	return fx.Annotate(
		f,
		fx.As(new(Handler)),
		fx.ResultTags(`group:"handler"`),
	)
}

type APIHandler interface {
	Area() string
	Version() string
	Register(*echo.Echo, huma.API)
}

func AsAPIHandler(f any) any {
	return fx.Annotate(
		f,
		fx.As(new(APIHandler)),
		fx.ResultTags(`group:"api-handler"`),
	)
}
