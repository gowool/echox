package echox

import (
	"time"

	"github.com/alexedwards/scs/v2"
	"go.uber.org/fx"
)

type SessionManagerParams struct {
	fx.In
	Config SessionConfig
	Store  scs.Store
}

func NewSessionManager(params SessionManagerParams) *scs.SessionManager {
	cfg := params.Config
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 5 * time.Minute
	}
	if cfg.Lifetime == 0 {
		cfg.Lifetime = 24 * time.Hour
	}
	if cfg.Cookie.Name == "" {
		cfg.Cookie.Name = "session"
	}
	if cfg.Cookie.Path == "" {
		cfg.Cookie.Path = "/"
	}
	if cfg.Cookie.SameSite == "" {
		cfg.Cookie.SameSite = SameSiteLax
	}

	sm := scs.New()
	sm.Store = params.Store
	sm.IdleTimeout = cfg.IdleTimeout
	sm.Lifetime = cfg.Lifetime
	sm.Cookie = scs.SessionCookie{
		Name:     cfg.Cookie.Name,
		Persist:  cfg.Cookie.Persist,
		Domain:   cfg.Cookie.Domain,
		Path:     cfg.Cookie.Path,
		HttpOnly: cfg.Cookie.HTTPOnly,
		Secure:   cfg.Cookie.Secure,
		SameSite: cfg.Cookie.SameSite.HTTP(),
	}
	return sm
}
