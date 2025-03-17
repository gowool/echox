package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/labstack/echo/v4"
)

type IDInput[ID any] struct {
	ID ID `path:"id"`
}

type Delete[ID any] struct {
	Deleter          func(context.Context, ...ID) error
	ErrorTransformer ErrorTransformerFunc
	Operation        huma.Operation
}

func NewDelete[ID any](
	deleter func(context.Context, ...ID) error,
	errorTransformer ErrorTransformerFunc,
	operation huma.Operation,
) Delete[ID] {
	if operation.Method == "" {
		operation.Method = http.MethodDelete
	}
	if operation.DefaultStatus <= 0 {
		operation.DefaultStatus = http.StatusNoContent
	}
	return Delete[ID]{
		Deleter:          deleter,
		ErrorTransformer: errorTransformer,
		Operation:        operation,
	}
}

func (h Delete[ID]) Register(_ *echo.Echo, api huma.API) {
	Register(api, Transform(h.ErrorTransformer, h.Handler), h.Operation)
}

func (h Delete[ID]) Handler(ctx context.Context, in *IDInput[ID]) (*struct{}, error) {
	err := h.Deleter(ctx, in.ID)
	return nil, err
}

type IDsInput[ID any] struct {
	IDs []ID `query:"ids" required:"true" minItems:"1" nullable:"false"`
}

type DeleteMany[ID any] struct {
	Deleter          func(context.Context, ...ID) error
	ErrorTransformer ErrorTransformerFunc
	Operation        huma.Operation
}

func NewDeleteMany[ID any](
	deleter func(context.Context, ...ID) error,
	errorTransformer ErrorTransformerFunc,
	operation huma.Operation,
) DeleteMany[ID] {
	if operation.Method == "" {
		operation.Method = http.MethodDelete
	}
	if operation.DefaultStatus <= 0 {
		operation.DefaultStatus = http.StatusNoContent
	}
	return DeleteMany[ID]{
		Deleter:          deleter,
		ErrorTransformer: errorTransformer,
		Operation:        operation,
	}
}

func (h DeleteMany[ID]) Register(_ *echo.Echo, api huma.API) {
	Register(api, Transform(h.ErrorTransformer, h.Handler), h.Operation)
}

func (h DeleteMany[ID]) Handler(ctx context.Context, in *IDsInput[ID]) (*struct{}, error) {
	err := h.Deleter(ctx, in.IDs...)
	return nil, err
}
