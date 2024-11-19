package echox

import (
	"go.uber.org/fx"

	"github.com/gowool/echox/api"
)

var (
	OptionEcho        = fx.Provide(NewEcho)
	OptionIPExtractor = fx.Provide(IPExtractor)

	OptionRecoverMiddleware       = fx.Provide(AsMiddleware(RecoverMiddleware))
	OptionBodyLimitMiddleware     = fx.Provide(AsMiddleware(BodyLimitMiddleware))
	OptionCompressMiddleware      = fx.Provide(AsMiddleware(CompressMiddleware))
	OptionDecompressMiddleware    = fx.Provide(AsMiddleware(DecompressMiddleware))
	OptionRequestIDMiddleware     = fx.Provide(AsMiddleware(RequestIDMiddleware))
	OptionLoggerMiddleware        = fx.Provide(AsMiddleware(LoggerMiddleware))
	OptionSecureMiddleware        = fx.Provide(AsMiddleware(SecureMiddleware))
	OptionCORSMiddleware          = fx.Provide(AsMiddleware(CORSMiddleware))
	OptionCSRFMiddleware          = fx.Provide(AsMiddleware(CSRFMiddleware))
	OptionBasicAuthMiddleware     = fx.Provide(AsMiddleware(BasicAuthMiddleware))
	OptionBearerAuthMiddleware    = fx.Provide(AsMiddleware(BearerAuthMiddleware))
	OptionAuthorizationMiddleware = fx.Provide(AsMiddleware(AuthorizationMiddleware))

	OptionAPIAuthorizationMiddleware = fx.Provide(api.AsMiddleware(api.AuthorizationMiddleware))
)
