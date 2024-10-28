package echox

import (
	"regexp"
	"strings"

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
