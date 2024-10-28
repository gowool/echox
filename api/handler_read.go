package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/gowool/cr"
	"github.com/labstack/echo/v4"
)

type Response[B any] struct {
	Body B
}

type Read[M any, ID any] struct {
	Finder           func(context.Context, ID) (M, error)
	ErrorTransformer ErrorTransformerFunc
	Operation        huma.Operation
}

func NewRead[T any, ID any](
	finder func(context.Context, ID) (T, error),
	errorTransformer ErrorTransformerFunc,
	operation huma.Operation,
) Read[T, ID] {
	if operation.Method == "" {
		operation.Method = http.MethodGet
	}
	return Read[T, ID]{
		Finder:           finder,
		ErrorTransformer: errorTransformer,
		Operation:        operation,
	}
}

func (h Read[M, ID]) Register(_ *echo.Echo, api huma.API) {
	Register(api, Transform(h.ErrorTransformer, h.Handler), h.Operation)
}

func (h Read[M, ID]) Handler(ctx context.Context, in *IDInput[ID]) (*Response[M], error) {
	item, err := h.Finder(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	return &Response[M]{Body: item}, nil
}

type ListInput struct {
	Page   int    `query:"page" json:"page,omitempty" yaml:"page,omitempty" required:"false"`
	Limit  int    `query:"limit" json:"limit,omitempty" yaml:"limit,omitempty" required:"false"`
	Sort   string `query:"sort" json:"sort,omitempty" yaml:"sort,omitempty" required:"false"`
	Filter string `query:"filter" json:"filter,omitempty" yaml:"filter,omitempty" required:"false"`
}

func (in *ListInput) Resolve(huma.Context) []error {
	if in.Page < 1 {
		in.Page = 1
	}
	if in.Limit < 1 || in.Limit > 100 {
		in.Limit = 100
	}
	if in.Sort == "" {
		in.Sort = "-id"
	}
	return nil
}

func (in *ListInput) criteria() *cr.Criteria {
	return cr.New(in.Filter, in.Sort).SetOffset((in.Page - 1) * in.Limit).SetSize(in.Limit)
}

type ListOutput[E any] struct {
	ListInput
	Items []E `json:"items,omitempty" yaml:"items,omitempty" required:"false"`
	Total int `json:"total,omitempty" yaml:"total,omitempty" required:"false"`
}

type List[M any] struct {
	Finder           func(context.Context, *cr.Criteria) ([]M, int, error)
	ErrorTransformer ErrorTransformerFunc
	Operation        huma.Operation
}

func NewList[T any](
	finder func(context.Context, *cr.Criteria) ([]T, int, error),
	errorTransformer ErrorTransformerFunc,
	operation huma.Operation,
) List[T] {
	if operation.Method == "" {
		operation.Method = http.MethodGet
	}
	return List[T]{
		Finder:           finder,
		ErrorTransformer: errorTransformer,
		Operation:        operation,
	}
}

func (h List[M]) Register(_ *echo.Echo, api huma.API) {
	Register(api, Transform(h.ErrorTransformer, h.Handler), h.Operation)
}

func (h List[M]) Handler(ctx context.Context, in *ListInput) (*Response[ListOutput[M]], error) {
	items, total, err := h.Finder(ctx, in.criteria())
	if err != nil {
		return nil, err
	}
	return &Response[ListOutput[M]]{
		Body: ListOutput[M]{
			ListInput: *in,
			Items:     items,
			Total:     total,
		},
	}, nil
}
