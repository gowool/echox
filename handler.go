package echox

import (
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
