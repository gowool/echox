package echox

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/alexedwards/scs/v2"
	"github.com/danielgtaylor/huma/v2"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/gowool/echox/rbac"
)

type Middleware struct {
	Name       string
	Middleware echo.MiddlewareFunc
}

func NewMiddleware(name string, middleware echo.MiddlewareFunc) Middleware {
	return Middleware{
		Name:       name,
		Middleware: middleware,
	}
}

func AsMiddleware(middleware any) any {
	return fx.Annotate(
		middleware,
		fx.ResultTags(`group:"middleware"`),
	)
}

func AsMiddlewareFunc(name string, middleware echo.MiddlewareFunc) any {
	return AsMiddleware(NewMiddleware(name, middleware))
}

type APIMiddleware struct {
	Name       string
	Middleware func(huma.API) func(huma.Context, func(huma.Context))
}

func NewAPIMiddleware(name string, middleware func(huma.API) func(huma.Context, func(huma.Context))) APIMiddleware {
	return APIMiddleware{
		Name:       name,
		Middleware: middleware,
	}
}

func AsAPIMiddleware(middleware any) any {
	return fx.Annotate(
		middleware,
		fx.ResultTags(`group:"api-middleware"`),
	)
}

func AsAPIMiddlewareFunc(name string, middleware func(huma.API) func(ctx huma.Context, next func(huma.Context))) any {
	return AsAPIMiddleware(NewAPIMiddleware(name, middleware))
}

func RecoverMiddleware(cfg RecoverConfig, logger *zap.Logger) Middleware {
	return NewMiddleware("recover", middleware.RecoverWithConfig(middleware.RecoverConfig{
		Skipper:             cfg.Skipper,
		StackSize:           cfg.StackSize,
		DisableStackAll:     cfg.DisableStackAll,
		DisableErrorHandler: true,
		LogErrorFunc: func(_ echo.Context, err error, stack []byte) error {
			logger.Error("recover middleware", zap.Error(err), zap.String("stack", string(stack)))
			return err
		},
	}))
}

func BodyLimitMiddleware(cfg BodyLimitConfig) Middleware {
	return NewMiddleware("body_limit", middleware.BodyLimitWithConfig(middleware.BodyLimitConfig{
		Skipper: cfg.Skipper,
		Limit:   cfg.Limit,
	}))
}

func CompressMiddleware(cfg GzipConfig) Middleware {
	return NewMiddleware("compress", middleware.GzipWithConfig(middleware.GzipConfig{
		Skipper:   cfg.Skipper,
		Level:     cfg.Level,
		MinLength: cfg.MinLength,
	}))
}

func DecompressMiddleware() Middleware {
	return NewMiddleware("decompress", middleware.Decompress())
}

func RequestIDMiddleware() Middleware {
	return NewMiddleware("request_id", middleware.RequestIDWithConfig(middleware.RequestIDConfig{
		Generator: uuid.NewString,
	}))
}

func LoggerMiddleware(cfg RequestLoggerConfig, logger *zap.Logger) Middleware {
	return NewMiddleware("logger", middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		Skipper:          cfg.Skipper,
		HandleError:      cfg.HandleError,
		LogLatency:       cfg.LogLatency,
		LogProtocol:      cfg.LogProtocol,
		LogRemoteIP:      cfg.LogRemoteIP,
		LogHost:          cfg.LogHost,
		LogMethod:        cfg.LogMethod,
		LogURI:           cfg.LogURI,
		LogURIPath:       cfg.LogURIPath,
		LogRoutePath:     cfg.LogRoutePath,
		LogRequestID:     cfg.LogRequestID,
		LogReferer:       cfg.LogReferer,
		LogUserAgent:     cfg.LogUserAgent,
		LogStatus:        cfg.LogStatus,
		LogError:         cfg.LogError,
		LogContentLength: cfg.LogContentLength,
		LogResponseSize:  cfg.LogResponseSize,
		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
			attributes := []zap.Field{
				zap.Time("start-time", v.StartTime),
				zap.Duration("latency", v.Latency),
				zap.String("protocol", v.Protocol),
				zap.String("ip", v.RemoteIP),
				zap.String("host", v.Host),
				zap.String("method", v.Method),
				zap.String("uri", v.URI),
				zap.String("path", v.URIPath),
				zap.String("route", v.RoutePath),
				zap.String("request-id", v.RequestID),
				zap.String("referer", v.Referer),
				zap.String("user-agent", v.UserAgent),
				zap.Int("status", v.Status),
				zap.String("content-length", v.ContentLength),
				zap.Int64("response-size", v.ResponseSize),
			}

			if cfg.AdditionalFieldsFunc != nil {
				attributes = append(attributes, cfg.AdditionalFieldsFunc(c)...)
			}

			if v.Error != nil {
				attributes = append(attributes, zap.Error(v.Error))
			}

			switch {
			case v.Status >= http.StatusBadRequest && v.Status < http.StatusInternalServerError:
				logger.Warn("incoming request", attributes...)
			case v.Status >= http.StatusInternalServerError:
				logger.Error("incoming request", attributes...)
			default:
				logger.Info("incoming request", attributes...)
			}
			return nil
		},
	}))
}

func SecureMiddleware(cfg SecureConfig) Middleware {
	return NewMiddleware("secure", middleware.SecureWithConfig(middleware.SecureConfig{
		Skipper:               cfg.Skipper,
		XSSProtection:         cfg.XSSProtection,
		ContentTypeNosniff:    cfg.ContentTypeNosniff,
		XFrameOptions:         cfg.XFrameOptions,
		HSTSMaxAge:            cfg.HSTSMaxAge,
		HSTSExcludeSubdomains: cfg.HSTSExcludeSubdomains,
		ContentSecurityPolicy: cfg.ContentSecurityPolicy,
		CSPReportOnly:         cfg.CSPReportOnly,
		HSTSPreloadEnabled:    cfg.HSTSPreloadEnabled,
		ReferrerPolicy:        cfg.ReferrerPolicy,
	}))
}

func CORSMiddleware(cfg CORSConfig) Middleware {
	return NewMiddleware("cors", middleware.CORSWithConfig(middleware.CORSConfig{
		Skipper:                                  cfg.Skipper,
		AllowOrigins:                             cfg.AllowOrigins,
		AllowOriginFunc:                          cfg.AllowOriginFunc,
		AllowMethods:                             cfg.AllowMethods,
		AllowHeaders:                             cfg.AllowHeaders,
		AllowCredentials:                         cfg.AllowCredentials,
		UnsafeWildcardOriginWithAllowCredentials: cfg.UnsafeWildcardOriginWithAllowCredentials,
		ExposeHeaders:                            cfg.ExposeHeaders,
		MaxAge:                                   cfg.MaxAge,
	}))
}

func CSRFMiddleware(cfg CSRFConfig) Middleware {
	return NewMiddleware("csrf", middleware.CSRFWithConfig(middleware.CSRFConfig{
		Skipper:        cfg.Skipper,
		ErrorHandler:   cfg.ErrorHandler,
		TokenLength:    cfg.TokenLength,
		TokenLookup:    cfg.TokenLookup,
		ContextKey:     cfg.ContextKey,
		CookieName:     cfg.Cookie.Name,
		CookieDomain:   cfg.Cookie.Domain,
		CookiePath:     cfg.Cookie.Path,
		CookieMaxAge:   int(cfg.Cookie.MaxAge.Seconds()),
		CookieSecure:   cfg.Cookie.Secure,
		CookieHTTPOnly: cfg.Cookie.HTTPOnly,
		CookieSameSite: cfg.Cookie.SameSite.HTTP(),
	}))
}

func SessionMiddleware(cfg SessionConfig, sessionManager *scs.SessionManager) Middleware {
	if cfg.Skipper == nil {
		cfg.Skipper = middleware.DefaultSkipper
	}

	return NewMiddleware("session", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) (err error) {
			if cfg.Skipper(c) {
				return next(c)
			}

			sessionManager.ErrorFunc = func(_ http.ResponseWriter, _ *http.Request, err1 error) {
				err = errors.Join(err, err1)
			}

			sessionManager.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c.SetRequest(r)
				c.SetResponse(echo.NewResponse(w, c.Echo()))
				err = next(c)
			})).ServeHTTP(c.Response(), c.Request())
			return
		}
	})
}

func BasicAuthMiddleware(validator middleware.BasicAuthValidator) Middleware {
	return NewMiddleware("basic_auth", middleware.BasicAuthWithConfig(middleware.BasicAuthConfig{
		Skipper: func(c echo.Context) bool {
			h := c.Request().Header.Get(echo.HeaderAuthorization)
			return !strings.HasPrefix(strings.ToLower(h), "basic ")
		},
		Validator: validator,
	}))
}

func BearerAuthMiddleware(validator middleware.KeyAuthValidator) Middleware {
	return NewMiddleware("bearer_auth", middleware.KeyAuthWithConfig(middleware.KeyAuthConfig{
		Skipper: func(c echo.Context) bool {
			h := c.Request().Header.Get(echo.HeaderAuthorization)
			return !strings.HasPrefix(strings.ToLower(h), "bearer ")
		},
		Validator: validator,
	}))
}

func AuthorizationMiddleware(authorizer Authorizer) Middleware {
	pool := &sync.Pool{
		New: func() any {
			return new(Target)
		},
	}

	unauthorized := func(c echo.Context, errs ...error) error {
		h := c.Request().Header.Get(echo.HeaderAuthorization)
		if strings.HasPrefix(strings.ToLower(h), "basic ") {
			c.Response().Header().Set(echo.HeaderWWWAuthenticate, "basic realm=Restricted")
		}
		return echo.ErrUnauthorized.WithInternal(errors.Join(errs...))
	}

	fn := func(c echo.Context) (err error) {
		var decision Decision = DecisionDeny
		defer func() {
			if decision == DecisionDeny && err == nil {
				err = ErrDeny
			}
		}()

		ctx := c.Request().Context()
		claims := CtxClaims(ctx)
		assertions := CtxAssertions(ctx)

		target := pool.Get().(*Target)
		defer pool.Put(target)

		for _, action := range permissions(c.Request().Method, c.Request().URL.Path) {
			target.Action = action
			target.Assertions = assertions

			if decision, err = authorizer.Authorize(ctx, claims, target); decision == DecisionAllow {
				return nil
			}
		}
		return
	}

	return NewMiddleware("authorization", func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if err := fn(c); err != nil {
				return unauthorized(c, err)
			}
			return next(c)
		}
	})
}

func AuthorizationAPIMiddleware(authorizer Authorizer, logger *zap.Logger) APIMiddleware {
	pool := &sync.Pool{
		New: func() any {
			return new(Target)
		},
	}

	return NewAPIMiddleware("authorization", func(api huma.API) func(huma.Context, func(huma.Context)) {
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

		fn := func(c huma.Context) (err error) {
			var decision Decision = DecisionDeny
			defer func() {
				if decision == DecisionDeny && err == nil {
					err = ErrDeny
				}
			}()

			claims := CtxClaims(c.Context())
			assertions := CtxAssertions(c.Context())

			if o := c.Operation(); o.Metadata != nil {
				for _, value := range o.Metadata {
					switch value := value.(type) {
					case *Target:
						value.Assertions = append(assertions, value.Assertions...)
						decision, err = authorizer.Authorize(c.Context(), claims, value)
						return
					case rbac.Assertion:
						assertions = append(assertions, value)
					case []rbac.Assertion:
						assertions = append(assertions, value...)
					}
				}
			}

			target := pool.Get().(*Target)
			defer pool.Put(target)

			for _, action := range permissions(c.Method(), c.URL().Path) {
				target.Action = action
				target.Assertions = assertions

				if decision, err = authorizer.Authorize(c.Context(), claims, target); decision == DecisionAllow {
					return nil
				}
			}
			return
		}

		return func(ctx huma.Context, next func(huma.Context)) {
			if err := fn(ctx); err != nil {
				unauthorized(ctx)
				logger.Error("huma api: failed to authorize", zap.Error(err))
				return
			}
			next(ctx)
		}
	})
}

func permissions(method, path string) []string {
	if path == "" {
		path = "/"
	}
	return []string{
		"*",
		method,
		path,
		fmt.Sprintf("%s %s", method, path),
	}
}
