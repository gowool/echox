package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/labstack/echo/v4"
	"go.uber.org/fx"
)

type Handler interface {
	Area() string
	Version() string
	Register(*echo.Echo, huma.API)
}

func AsHandler(f any) any {
	return fx.Annotate(
		f,
		fx.As(new(Handler)),
		fx.ResultTags(`group:"api-handler"`),
	)
}

type ErrorTransformerFunc func(context.Context, error) error

type CRUDInfo struct {
	Area    string
	Version string
}

type CRUD[
	CB interface {
		Decode(context.Context, *M) error
	},
	UB interface {
		Decode(context.Context, *M) error
	},
	M interface{ GetID() ID },
	ID any,
] struct {
	Info CRUDInfo
	List[M]
	Read[M, ID]
	Create[CB, M, ID]
	Update[UB, M, ID]
	Delete[ID]
	DeleteMany[ID]
}

func (h CRUD[CB, UB, M, ID]) Area() string {
	return h.Info.Area
}

func (h CRUD[CB, UB, M, ID]) Version() string {
	return h.Info.Version
}

func (h CRUD[CB, UB, M, ID]) Register(e *echo.Echo, api huma.API) {
	h.List.Register(e, api)
	h.Read.Register(e, api)
	h.Create.Register(e, api)
	h.Update.Register(e, api)
	h.Delete.Register(e, api)
	h.DeleteMany.Register(e, api)
}

func Transform[I, O any](errorTransform ErrorTransformerFunc, handler func(context.Context, *I) (*O, error)) func(context.Context, *I) (*O, error) {
	return func(ctx context.Context, i *I) (*O, error) {
		o, err := handler(ctx, i)
		if err != nil {
			return o, errorTransform(ctx, err)
		}
		return o, nil
	}
}

func Register[I, O any](api huma.API, handler func(context.Context, *I) (*O, error), operation huma.Operation) {
	var o *O
	if operation.OperationID == "" {
		operation.OperationID = huma.GenerateOperationID(operation.Method, operation.Path, o)
	}
	if operation.Summary == "" {
		operation.Summary = huma.GenerateSummary(operation.Method, operation.Path, o)
	}
	huma.Register(api, operation, handler)
}

type Option func(*huma.Operation)

func WithCreated(op *huma.Operation) {
	op.DefaultStatus = http.StatusCreated
}

func WithNoContent(op *huma.Operation) {
	op.DefaultStatus = http.StatusNoContent
}

func WithOK(op *huma.Operation) {
	op.DefaultStatus = http.StatusOK
}

func WithGet(op *huma.Operation) {
	op.Method = http.MethodGet
}

func WithPost(op *huma.Operation) {
	op.Method = http.MethodPost
}

func WithPut(op *huma.Operation) {
	op.Method = http.MethodPut
}

func WithPatch(op *huma.Operation) {
	op.Method = http.MethodPatch
}

func WithDelete(op *huma.Operation) {
	op.Method = http.MethodDelete
}

func WithMethod(method string) Option {
	return func(op *huma.Operation) {
		op.Method = method
	}
}

func WithPath(path string) Option {
	return func(op *huma.Operation) {
		op.Path = path
	}
}

func WithAddPath(path string) Option {
	return func(op *huma.Operation) {
		op.Path += path
	}
}

func WithDefaultStatus(status int) Option {
	return func(op *huma.Operation) {
		op.DefaultStatus = status
	}
}

func WithTags(tags ...string) Option {
	return func(op *huma.Operation) {
		op.Tags = tags
	}
}

func WithAddTags(tags ...string) Option {
	return func(op *huma.Operation) {
		op.Tags = append(op.Tags, tags...)
	}
}

func WithOperationID(operationID string) Option {
	return func(op *huma.Operation) {
		op.OperationID = operationID
	}
}

func WithDescription(description string) Option {
	return func(op *huma.Operation) {
		op.Description = description
	}
}

func WithMetadata(metadata map[string]any) Option {
	return func(op *huma.Operation) {
		op.Metadata = metadata
	}
}

func WithMetadataItem(key string, value any) Option {
	return func(op *huma.Operation) {
		if op.Metadata == nil {
			op.Metadata = make(map[string]any)
		}
		op.Metadata[key] = value
	}
}

func WithSecurity(security []map[string][]string) Option {
	return func(op *huma.Operation) {
		op.Security = security
	}
}

func WithSummary(summary string) Option {
	return func(op *huma.Operation) {
		op.Summary = summary
	}
}

func Operation(base ...Option) func(...Option) huma.Operation {
	return func(options ...Option) huma.Operation {
		op := huma.Operation{
			Method: http.MethodGet,
		}

		for _, o := range base {
			o(&op)
		}

		for _, o := range options {
			o(&op)
		}

		return op
	}
}
