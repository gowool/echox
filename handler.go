package echox

import (
	"github.com/labstack/echo/v4"
	"go.uber.org/fx"
)

var DefaultAnnotations = []fx.Annotation{
	fx.As(new(Handler)),
	fx.ResultTags(`group:"handler"`),
}

type Handler interface {
	Area() string
	Register(*echo.Echo, *echo.Group)
}

func AsHandler(f any, anns ...fx.Annotation) any {
	annotations := make([]fx.Annotation, len(DefaultAnnotations)+len(anns))
	copy(annotations, DefaultAnnotations)
	copy(annotations[len(DefaultAnnotations):], anns)

	return fx.Annotate(f, annotations...)
}
