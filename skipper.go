package echox

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

var re = regexp.MustCompile(`^(\S*)\s+(.*)$`)

func ChainSkipper(skippers ...middleware.Skipper) middleware.Skipper {
	return func(c echo.Context) bool {
		for _, skipper := range skippers {
			if skipper(c) {
				return true
			}
		}
		return false
	}
}

func PrefixPathSkipper(prefixes ...string) middleware.Skipper {
	for i := range prefixes {
		prefixes[i] = strings.ToLower(prefixes[i])
	}
	return func(c echo.Context) bool {
		p := strings.ToLower(c.Request().URL.Path)
		m := strings.ToLower(c.Request().Method)
		for _, prefix := range prefixes {
			if prefix, ok := CheckMethod(m, prefix); ok && strings.HasPrefix(p, prefix) {
				return true
			}
		}
		return false
	}
}

func SuffixPathSkipper(suffixes ...string) middleware.Skipper {
	for i := range suffixes {
		suffixes[i] = strings.ToLower(suffixes[i])
	}
	return func(c echo.Context) bool {
		p := strings.ToLower(c.Request().URL.Path)
		m := strings.ToLower(c.Request().Method)
		for _, suffix := range suffixes {
			if suffix, ok := CheckMethod(m, suffix); ok && strings.HasSuffix(p, suffix) {
				return true
			}
		}
		return false
	}
}

func EqualPathSkipper(paths ...string) middleware.Skipper {
	return func(c echo.Context) bool {
		for _, path := range paths {
			if path, ok := CheckMethod(c.Request().Method, path); ok && strings.EqualFold(c.Request().URL.Path, path) {
				return true
			}
		}
		return false
	}
}

func CheckMethod(method, skip string) (string, bool) {
	if matches := re.FindStringSubmatch(skip); len(matches) > 2 {
		if matches[1] == method {
			return matches[2], true
		}
		return "", false
	}
	return skip, true
}

type Env struct {
	Pattern        string
	Proto          string
	Scheme         string
	Host           string
	Method         string
	URL            url.URL
	RequestURI     string
	HandlerPath    string
	ParamNames     []string
	ParamValues    []string
	QueryString    string
	QueryParams    map[string][]string
	Headers        map[string][]string
	ContentLength  int64
	Cookies        []*http.Cookie
	RealIP         string
	IsTLS          bool
	IsWebSocket    bool
	FormValue      func(name string) string
	EchoContextGet func(name string) any
	ContextValue   func(name any) any
}

func ExpressionSkipper(expressions ...string) middleware.Skipper {
	programs := make([]*vm.Program, len(expressions))
	for i, expression := range expressions {
		program, err := expr.Compile(expression, expr.Env(Env{}), expr.AsBool())
		if err != nil {
			continue
		}
		programs[i] = program
	}

	return func(c echo.Context) bool {
		env := Env{
			Pattern:        c.Request().Pattern,
			Proto:          c.Request().Proto,
			Scheme:         c.Scheme(),
			Host:           c.Request().Host,
			Method:         c.Request().Method,
			URL:            *c.Request().URL,
			RequestURI:     c.Request().RequestURI,
			HandlerPath:    c.Path(),
			ParamNames:     c.ParamNames(),
			ParamValues:    c.ParamValues(),
			QueryString:    c.QueryString(),
			QueryParams:    c.QueryParams(),
			Headers:        c.Request().Header,
			ContentLength:  c.Request().ContentLength,
			Cookies:        c.Cookies(),
			RealIP:         c.RealIP(),
			IsTLS:          c.IsTLS(),
			IsWebSocket:    c.IsWebSocket(),
			FormValue:      c.FormValue,
			EchoContextGet: c.Get,
			ContextValue:   c.Request().Context().Value,
		}

		for _, program := range programs {
			if ok, err := expr.Run(program, env); err == nil && ok.(bool) {
				return true
			}
		}
		return false
	}
}
