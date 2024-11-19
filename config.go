package echox

import (
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

type MiddlewaresConfig struct {
	fx.Out
	Recover   RecoverConfig       `json:"recover,omitempty" yaml:"recover,omitempty"`
	BodyLimit BodyLimitConfig     `json:"bodyLimit,omitempty" yaml:"bodyLimit,omitempty"`
	Compress  GzipConfig          `json:"compress,omitempty" yaml:"compress,omitempty"`
	Secure    SecureConfig        `json:"secure,omitempty" yaml:"secure,omitempty"`
	CORS      CORSConfig          `json:"cors,omitempty" yaml:"cors,omitempty"`
	CSRF      CSRFConfig          `json:"csrf,omitempty" yaml:"csrf,omitempty"`
	Logger    RequestLoggerConfig `json:"logger,omitempty" yaml:"logger,omitempty"`
}

type APIConfig struct {
	Enabled     bool            `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Path        string          `json:"path,omitempty" yaml:"path,omitempty"`
	OpenAPIPath string          `json:"openAPIPath,omitempty" yaml:"openAPIPath,omitempty"`
	DocsPath    string          `json:"docsPath,omitempty" yaml:"docsPath,omitempty"`
	SchemasPath string          `json:"schemasPath,omitempty" yaml:"schemasPath,omitempty"`
	Middlewares []string        `json:"middlewares,omitempty" yaml:"middlewares,omitempty"`
	Info        huma.Info       `json:"info,omitempty" yaml:"info,omitempty"`
	Components  huma.Components `json:"components,omitempty" yaml:"components,omitempty"`
}

func (cfg *APIConfig) setDefaults() {
	if cfg.OpenAPIPath == "" {
		cfg.OpenAPIPath = "/openapi"
	}
	if cfg.SchemasPath == "" {
		cfg.SchemasPath = "/schemas"
	}
}

type AreaConfig struct {
	Enabled     bool                 `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Path        string               `json:"path,omitempty" yaml:"path,omitempty"`
	Middlewares []string             `json:"middlewares,omitempty" yaml:"middlewares,omitempty"`
	Additional  map[string]any       `json:"additional,omitempty" yaml:"additional,omitempty"`
	API         map[string]APIConfig `json:"api,omitempty" yaml:"api,omitempty"`
}

type RoleHierarchyConfig struct {
	Role     string   `json:"role,omitempty" yaml:"role,omitempty"`
	Parents  []string `json:"parents,omitempty" yaml:"parents,omitempty"`
	Children []string `json:"children,omitempty" yaml:"children,omitempty"`
}

type RouterConfig struct {
	Middlewares struct {
		Before []string `json:"before,omitempty" yaml:"before,omitempty"`
		After  []string `json:"after,omitempty" yaml:"after,omitempty"`
	} `json:"middlewares,omitempty" yaml:"middlewares,omitempty"`
	Areas map[string]AreaConfig `json:"areas,omitempty" yaml:"areas,omitempty"`
}

type Config struct {
	Middlewares MiddlewaresConfig `json:"middlewares,omitempty" yaml:"middlewares,omitempty"`
	Router      RouterConfig      `json:"router,omitempty" yaml:"router,omitempty"`
}

type SameSiteType string

const (
	SameSiteDefault SameSiteType = "default"
	SameSiteLax     SameSiteType = "lax"
	SameSiteStrict  SameSiteType = "strict"
	SameSiteNone    SameSiteType = "none"
)

func (s SameSiteType) HTTP() http.SameSite {
	switch s {
	case SameSiteDefault:
		return http.SameSiteDefaultMode
	case SameSiteLax:
		return http.SameSiteLaxMode
	case SameSiteStrict:
		return http.SameSiteStrictMode
	case SameSiteNone:
		return http.SameSiteNoneMode
	default:
		panic("invalid same site")
	}
}

type RecoverConfig struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper

	// Size of the stack to be printed.
	// Optional. Default value 4KB.
	StackSize int `json:"stackSize,omitempty" yaml:"stackSize,omitempty"`

	// DisableStackAll disables formatting stack traces of all other goroutines
	// into buffer after the trace for the current goroutine.
	// Optional. Default value false.
	DisableStackAll bool `json:"disableStackAll,omitempty" yaml:"disableStackAll,omitempty"`
}

type BodyLimitConfig struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper `json:"-" yaml:"-"`

	// Maximum allowed size for a request body, it can be specified
	// as `4x` or `4xB`, where x is one of the multiple from K, M, G, T or P.
	Limit string `json:"limit,omitempty" yaml:"limit,omitempty"`
}

func (cfg *BodyLimitConfig) setDefaults() {
	if cfg.Limit == "" {
		cfg.Limit = "4KB"
	}
}

type GzipConfig struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper `json:"-" yaml:"-"`

	// Gzip compression level.
	// Optional. Default value -1.
	Level int `json:"level,omitempty" yaml:"level,omitempty"`

	// Length threshold before gzip compression is applied.
	// Optional. Default value 0.
	//
	// Most of the time you will not need to change the default. Compressing
	// a short response might increase the transmitted data because of the
	// gzip format overhead. Compressing the response will also consume CPU
	// and time on the server and the client (for decompressing). Depending on
	// your use case such a threshold might be useful.
	//
	// See also:
	// https://webmasters.stackexchange.com/questions/31750/what-is-recommended-minimum-object-size-for-gzip-performance-benefits
	MinLength int `json:"minLength,omitempty" yaml:"minLength,omitempty"`
}

func (cfg *GzipConfig) setDefaults() {
	if cfg.MinLength <= 0 {
		cfg.MinLength = 1024
	}
}

type SecureConfig struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper `json:"-" yaml:"-"`

	// XSSProtection provides protection against cross-site scripting attack (XSS)
	// by setting the `X-XSS-Protection` header.
	// Optional. Default value "1; mode=block".
	XSSProtection string `json:"xssProtection,omitempty" yaml:"xssProtection,omitempty"`

	// ContentTypeNosniff provides protection against overriding Content-Type
	// header by setting the `X-Content-Type-Options` header.
	// Optional. Default value "nosniff".
	ContentTypeNosniff string `json:"contentTypeNosniff,omitempty" yaml:"contentTypeNosniff,omitempty"`

	// XFrameOptions can be used to indicate whether or not a browser should
	// be allowed to render a page in a <frame>, <iframe> or <object> .
	// Sites can use this to avoid clickjacking attacks, by ensuring that their
	// content is not embedded into other sites.provides protection against
	// clickjacking.
	// Optional. Default value "SAMEORIGIN".
	// Possible values:
	// - "SAMEORIGIN" - The page can only be displayed in a frame on the same origin as the page itself.
	// - "DENY" - The page cannot be displayed in a frame, regardless of the site attempting to do so.
	// - "ALLOW-FROM uri" - The page can only be displayed in a frame on the specified origin.
	XFrameOptions string `json:"xFrameOptions,omitempty" yaml:"xFrameOptions,omitempty"`

	// HSTSMaxAge sets the `Strict-Transport-Security` header to indicate how
	// long (in seconds) browsers should remember that this site is only to
	// be accessed using HTTPS. This reduces your exposure to some SSL-stripping
	// man-in-the-middle (MITM) attacks.
	// Optional. Default value 0.
	HSTSMaxAge int `json:"hstsMaxAge,omitempty" yaml:"hstsMaxAge,omitempty"`

	// HSTSExcludeSubdomains won't include subdomains tag in the `Strict Transport Security`
	// header, excluding all subdomains from security policy. It has no effect
	// unless HSTSMaxAge is set to a non-zero value.
	// Optional. Default value false.
	HSTSExcludeSubdomains bool `json:"hstsExcludeSubdomains,omitempty" yaml:"hstsExcludeSubdomains,omitempty"`

	// ContentSecurityPolicy sets the `Content-Security-Policy` header providing
	// security against cross-site scripting (XSS), clickjacking and other code
	// injection attacks resulting from execution of malicious content in the
	// trusted web page context.
	// Optional. Default value "".
	ContentSecurityPolicy string `json:"contentSecurityPolicy,omitempty" yaml:"contentSecurityPolicy,omitempty"`

	// CSPReportOnly would use the `Content-Security-Policy-Report-Only` header instead
	// of the `Content-Security-Policy` header. This allows iterative updates of the
	// content security policy by only reporting the violations that would
	// have occurred instead of blocking the resource.
	// Optional. Default value false.
	CSPReportOnly bool `json:"cspReportOnly,omitempty" yaml:"cspReportOnly,omitempty"`

	// HSTSPreloadEnabled will add the preload tag in the `Strict Transport Security`
	// header, which enables the domain to be included in the HSTS preload list
	// maintained by Chrome (and used by Firefox and Safari): https://hstspreload.org/
	// Optional.  Default value false.
	HSTSPreloadEnabled bool `json:"hstsPreloadEnabled,omitempty" yaml:"hstsPreloadEnabled,omitempty"`

	// ReferrerPolicy sets the `Referrer-Policy` header providing security against
	// leaking potentially sensitive request paths to third parties.
	// Optional. Default value "".
	ReferrerPolicy string `json:"referrerPolicy,omitempty" yaml:"referrerPolicy,omitempty"`
}

func (cfg *SecureConfig) setDefaults() {
	if cfg.XSSProtection == "" {
		cfg.XSSProtection = middleware.DefaultSecureConfig.XSSProtection
	}
	if cfg.ContentTypeNosniff == "" {
		cfg.ContentTypeNosniff = middleware.DefaultSecureConfig.ContentTypeNosniff
	}
	if cfg.XFrameOptions == "" {
		cfg.XFrameOptions = middleware.DefaultSecureConfig.XFrameOptions
	}
}

type CORSConfig struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper `json:"-" yaml:"-"`

	// AllowOrigins determines the value of the Access-Control-Allow-Origin
	// response header.  This header defines a list of origins that may access the
	// resource.  The wildcard characters '*' and '?' are supported and are
	// converted to regex fragments '.*' and '.' accordingly.
	//
	// Security: use extreme caution when handling the origin, and carefully
	// validate any logic. Remember that attackers may register hostile domain names.
	// See https://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html
	//
	// Optional. Default value []string{"*"}.
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
	AllowOrigins []string `json:"allowOrigins,omitempty" yaml:"allowOrigins,omitempty"`

	// AllowOriginFunc is a custom function to validate the origin. It takes the
	// origin as an argument and returns true if allowed or false otherwise. If
	// an error is returned, it is returned by the handler. If this option is
	// set, AllowOrigins is ignored.
	//
	// Security: use extreme caution when handling the origin, and carefully
	// validate any logic. Remember that attackers may register hostile domain names.
	// See https://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html
	//
	// Optional.
	AllowOriginFunc func(origin string) (bool, error) `json:"-" yaml:"-"`

	// AllowMethods determines the value of the Access-Control-Allow-Methods
	// response header.  This header specified the list of methods allowed when
	// accessing the resource.  This is used in response to a preflight request.
	//
	// Optional. Default value DefaultCORSConfig.AllowMethods.
	// If `allowMethods` is left empty, this middleware will fill for preflight
	// request `Access-Control-Allow-Methods` header value
	// from `Allow` header that echo.Router set into context.
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods
	AllowMethods []string `json:"allowMethods,omitempty" yaml:"allowMethods,omitempty"`

	// AllowHeaders determines the value of the Access-Control-Allow-Headers
	// response header.  This header is used in response to a preflight request to
	// indicate which HTTP headers can be used when making the actual request.
	//
	// Optional. Default value []string{}.
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers
	AllowHeaders []string `json:"allowHeaders,omitempty" yaml:"allowHeaders,omitempty"`

	// AllowCredentials determines the value of the
	// Access-Control-Allow-Credentials response header.  This header indicates
	// whether or not the response to the request can be exposed when the
	// credentials mode (Request.credentials) is true. When used as part of a
	// response to a preflight request, this indicates whether or not the actual
	// request can be made using credentials.  See also
	// [MDN: Access-Control-Allow-Credentials].
	//
	// Optional. Default value false, in which case the header is not set.
	//
	// Security: avoid using `AllowCredentials = true` with `AllowOrigins = *`.
	// See "Exploiting CORS misconfigurations for Bitcoins and bounties",
	// https://blog.portswigger.net/2016/10/exploiting-cors-misconfigurations-for.html
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials
	AllowCredentials bool `json:"allowCredentials,omitempty" yaml:"allowCredentials,omitempty"`

	// UnsafeWildcardOriginWithAllowCredentials UNSAFE/INSECURE: allows wildcard '*' origin to be used with AllowCredentials
	// flag. In that case we consider any origin allowed and send it back to the client with `Access-Control-Allow-Origin` header.
	//
	// This is INSECURE and potentially leads to [cross-origin](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
	// attacks. See: https://github.com/labstack/echo/issues/2400 for discussion on the subject.
	//
	// Optional. Default value is false.
	UnsafeWildcardOriginWithAllowCredentials bool `json:"unsafeWildcardOriginWithAllowCredentials,omitempty" yaml:"unsafeWildcardOriginWithAllowCredentials,omitempty"`

	// ExposeHeaders determines the value of Access-Control-Expose-Headers, which
	// defines a list of headers that clients are allowed to access.
	//
	// Optional. Default value []string{}, in which case the header is not set.
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Expose-Header
	ExposeHeaders []string `json:"exposeHeaders,omitempty" yaml:"exposeHeaders,omitempty"`

	// MaxAge determines the value of the Access-Control-Max-Age response header.
	// This header indicates how long (in seconds) the results of a preflight
	// request can be cached.
	// The header is set only if MaxAge != 0, negative value sends "0" which instructs browsers not to cache that response.
	//
	// Optional. Default value 0 - meaning header is not sent.
	//
	// See also: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age
	MaxAge int `json:"maxAge,omitempty" yaml:"maxAge,omitempty"`
}

type CSRFConfig struct {
	// Skipper defines a function to skip middleware.
	Skipper middleware.Skipper `json:"-" yaml:"-"`

	// ErrorHandler defines a function which is executed for returning custom errors.
	ErrorHandler middleware.CSRFErrorHandler `json:"-" yaml:"-"`

	// TokenLength is the length of the generated token.
	TokenLength uint8 `json:"tokenLength,omitempty" yaml:"tokenLength,omitempty"`
	// Optional. Default value 32.

	// TokenLookup is a string in the form of "<source>:<name>" or "<source>:<name>,<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:X-CSRF-Token".
	// Possible values:
	// - "header:<name>" or "header:<name>:<cut-prefix>"
	// - "query:<name>"
	// - "form:<name>"
	// Multiple sources example:
	// - "header:X-CSRF-Token,query:csrf"
	TokenLookup string `json:"tokenLookup,omitempty" yaml:"tokenLookup,omitempty"`

	// Context key to store generated CSRF token into context.
	// Optional. Default value "csrf".
	ContextKey string `json:"contextKey,omitempty" yaml:"contextKey,omitempty"`

	Cookie struct {
		Name     string        `json:"name,omitempty" yaml:"name,omitempty"`
		Domain   string        `json:"domain,omitempty" yaml:"domain,omitempty"`
		Path     string        `json:"path,omitempty" yaml:"path,omitempty"`
		MaxAge   time.Duration `json:"maxAge,omitempty" yaml:"maxAge,omitempty"`
		Secure   bool          `json:"secure,omitempty" yaml:"secure,omitempty"`
		HTTPOnly bool          `json:"httpOnly,omitempty" yaml:"httpOnly,omitempty"`
		SameSite SameSiteType  `json:"sameSite,omitempty" yaml:"sameSite,omitempty"`
	} `json:"cookie" yaml:"cookie"`
}

type RequestLoggerConfig struct {
	Skipper              middleware.Skipper             `json:"-" yaml:"-"`
	AdditionalFieldsFunc func(echo.Context) []zap.Field `json:"-" yaml:"-"`
	HandleError          bool                           `json:"handleError,omitempty" yaml:"handleError,omitempty"`
	LogLatency           bool                           `json:"latency,omitempty" yaml:"latency,omitempty"`
	LogProtocol          bool                           `json:"protocol,omitempty" yaml:"protocol,omitempty"`
	LogRemoteIP          bool                           `json:"remoteIP,omitempty" yaml:"remoteIP,omitempty"`
	LogHost              bool                           `json:"host,omitempty" yaml:"host,omitempty"`
	LogMethod            bool                           `json:"method,omitempty" yaml:"method,omitempty"`
	LogURI               bool                           `json:"uri,omitempty" yaml:"uri,omitempty"`
	LogURIPath           bool                           `json:"uriPath,omitempty" yaml:"uriPath,omitempty"`
	LogRoutePath         bool                           `json:"routePath,omitempty" yaml:"routePath,omitempty"`
	LogRequestID         bool                           `json:"requestID,omitempty" yaml:"requestID,omitempty"`
	LogReferer           bool                           `json:"referer,omitempty" yaml:"referer,omitempty"`
	LogUserAgent         bool                           `json:"userAgent,omitempty" yaml:"userAgent,omitempty"`
	LogStatus            bool                           `json:"status,omitempty" yaml:"status,omitempty"`
	LogError             bool                           `json:"error,omitempty" yaml:"error,omitempty"`
	LogContentLength     bool                           `json:"contentLength,omitempty" yaml:"contentLength,omitempty"`
	LogResponseSize      bool                           `json:"responseSize,omitempty" yaml:"responseSize,omitempty"`
	LogHeaders           []string                       `json:"headers,omitempty" yaml:"headers,omitempty"`
	LogQueryParams       []string                       `json:"queryParams,omitempty" yaml:"queryParams,omitempty"`
	LogFormValues        []string                       `json:"formValues,omitempty" yaml:"formValues,omitempty"`
}
