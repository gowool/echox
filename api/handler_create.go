package api

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/danielgtaylor/huma/v2"
	"github.com/labstack/echo/v4"
)

type CreateResponse struct {
	Location string `header:"Content-Location"`
}

func Location[ID any](path string, m any) *CreateResponse {
	var id ID
	switch m := m.(type) {
	case interface{ PK() ID }:
		id = m.PK()
	case interface{ GetPK() ID }:
		id = m.GetPK()
	case interface{ ID() ID }:
		id = m.ID()
	case interface{ GetID() ID }:
		id = m.GetID()
	default:
		t := reflect.ValueOf(m)
		if t.Kind() != reflect.Struct {
			panic("model is not a struct")
		}

		var v reflect.Value
		if v = t.FieldByName("ID"); v.IsZero() {
			if v = t.FieldByName("PK"); v.IsZero() {
				panic("no ID field found")
			}
		}
		id = v.Interface().(ID)
	}

	return &CreateResponse{
		Location: fmt.Sprintf("%s/%v", path, id),
	}
}

type CreateInput[B any] struct {
	Body B
}

type Create[B interface {
	Decode(context.Context, *M) error
}, M any, ID any] struct {
	Saver            func(context.Context, *M) error
	Location         func(string, M) *CreateResponse
	ErrorTransformer ErrorTransformerFunc
	Operation        huma.Operation
}

func NewCreate[B interface {
	Decode(context.Context, *M) error
}, M any, ID any](
	saver func(context.Context, *M) error,
	errorTransformer ErrorTransformerFunc,
	operation huma.Operation,
) Create[B, M, ID] {
	if operation.Method == "" {
		operation.Method = http.MethodPost
	}
	if operation.DefaultStatus <= 0 {
		operation.DefaultStatus = http.StatusCreated
	}
	return Create[B, M, ID]{
		Saver:            saver,
		ErrorTransformer: errorTransformer,
		Operation:        operation,
	}
}

func (h Create[B, M, ID]) Register(_ *echo.Echo, api huma.API) {
	Register(api, Transform(h.ErrorTransformer, h.Handler), h.Operation)
}

func (h Create[B, M, ID]) Handler(ctx context.Context, in *CreateInput[B]) (*CreateResponse, error) {
	var m M
	if err := in.Body.Decode(ctx, &m); err != nil {
		return nil, err
	}
	if err := h.Saver(ctx, &m); err != nil {
		return nil, err
	}
	if h.Location == nil {
		return Location[ID](h.Operation.Path, m), nil
	}
	return h.Location(h.Operation.Path, m), nil
}
