package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/labstack/echo/v4"
)

type UpdateInput[B any, ID any] struct {
	ID   ID `path:"id"`
	Body B
}

type Update[B interface {
	Decode(context.Context, *M) error
}, M any, ID any] struct {
	Finder           func(context.Context, ID) (M, error)
	Saver            func(context.Context, *M) error
	ErrorTransformer ErrorTransformerFunc
	Operation        huma.Operation
}

func NewUpdate[B interface {
	Decode(context.Context, *M) error
}, M any, ID any](
	finder func(context.Context, ID) (M, error),
	saver func(context.Context, *M) error,
	errorTransformer ErrorTransformerFunc,
	operation huma.Operation,
) Update[B, M, ID] {
	if operation.Method == "" {
		operation.Method = http.MethodPut
	}
	if operation.DefaultStatus <= 0 {
		operation.DefaultStatus = http.StatusNoContent
	}
	return Update[B, M, ID]{
		Finder:           finder,
		Saver:            saver,
		ErrorTransformer: errorTransformer,
		Operation:        operation,
	}
}

func (h Update[B, M, ID]) Register(_ *echo.Echo, api huma.API) {
	Register(api, Transform(h.ErrorTransformer, h.Handler), h.Operation)
}

func (h Update[B, M, ID]) Handler(ctx context.Context, in *UpdateInput[B, ID]) (*struct{}, error) {
	m, err := h.Finder(ctx, in.ID)
	if err != nil {
		return nil, err
	}

	if err = in.Body.Decode(ctx, &m); err != nil {
		return nil, err
	}

	err = h.Saver(ctx, &m)
	return nil, err
}
