package echox

import (
	"go.uber.org/fx"

	"github.com/gowool/echox/rbac"
)

var (
	OptionEcho        = fx.Provide(NewEcho)
	OptionIPExtractor = fx.Provide(IPExtractor)

	OptionRBAC                 = fx.Provide(rbac.New)
	OptionRBACWithConfig       = fx.Provide(rbac.NewWithConfig)
	OptionAuthorizationChecker = fx.Provide(func(rbac *rbac.RBAC) rbac.AuthorizationChecker { return rbac })
	OptionAuthorizer           = fx.Provide(fx.Annotate(NewDefaultAuthorizer, fx.As(new(Authorizer))))

	OptionSessionManager = fx.Provide(NewSessionManager)

	OptionRecoverMiddleware       = fx.Provide(AsMiddleware(RecoverMiddleware))
	OptionBodyLimitMiddleware     = fx.Provide(AsMiddleware(BodyLimitMiddleware))
	OptionCompressMiddleware      = fx.Provide(AsMiddleware(CompressMiddleware))
	OptionDecompressMiddleware    = fx.Provide(AsMiddleware(DecompressMiddleware))
	OptionRequestIDMiddleware     = fx.Provide(AsMiddleware(RequestIDMiddleware))
	OptionLoggerMiddleware        = fx.Provide(AsMiddleware(LoggerMiddleware))
	OptionSecureMiddleware        = fx.Provide(AsMiddleware(SecureMiddleware))
	OptionCORSMiddleware          = fx.Provide(AsMiddleware(CORSMiddleware))
	OptionCSRFMiddleware          = fx.Provide(AsMiddleware(CSRFMiddleware))
	OptionSessionMiddleware       = fx.Provide(AsMiddleware(SessionMiddleware))
	OptionBasicAuthMiddleware     = fx.Provide(AsMiddleware(BasicAuthMiddleware))
	OptionBearerAuthMiddleware    = fx.Provide(AsMiddleware(BearerAuthMiddleware))
	OptionAuthorizationMiddleware = fx.Provide(AsMiddleware(AuthorizationMiddleware))

	OptionAuthorizationAPIMiddleware = fx.Provide(AsAPIMiddleware(AuthorizationAPIMiddleware))
)
