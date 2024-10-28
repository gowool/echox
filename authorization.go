package echox

import (
	"context"
	"errors"

	"github.com/gowool/echox/rbac"
)

var ErrDeny = errors.New("huma api: authorizer decision `deny`")

type (
	claimsKey     struct{}
	assertionsKey struct{}
)

type Subject interface {
	Identifier() string
	Roles() []string
}

type Claims struct {
	Subject  Subject
	Metadata map[string]any
}

func WithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

func CtxClaims(ctx context.Context) *Claims {
	claims, _ := ctx.Value(claimsKey{}).(*Claims)
	return claims
}

func WithAssertions(ctx context.Context, assertions ...rbac.Assertion) context.Context {
	return context.WithValue(ctx, assertionsKey{}, assertions)
}

func CtxAssertions(ctx context.Context) []rbac.Assertion {
	assertions, _ := ctx.Value(assertionsKey{}).([]rbac.Assertion)
	return append(make([]rbac.Assertion, 0, len(assertions)), assertions...)
}

type Target struct {
	Action     string
	Assertions []rbac.Assertion
	Metadata   map[string]any
}

type Decision int8

const (
	DecisionDeny = iota + 1
	DecisionAllow
)

func (d Decision) String() string {
	switch d {
	case DecisionDeny:
		return "deny"
	case DecisionAllow:
		return "allow"
	default:
		return "unknown"
	}
}

type Authorizer interface {
	Authorize(ctx context.Context, claims *Claims, target *Target) (Decision, error)
}

type DefaultAuthorizer struct {
	rbac *rbac.RBAC
}

func NewDefaultAuthorizer(rbac *rbac.RBAC) *DefaultAuthorizer {
	return &DefaultAuthorizer{rbac: rbac}
}

func (a *DefaultAuthorizer) Authorize(ctx context.Context, claims *Claims, target *Target) (d Decision, err error) {
	d = DecisionDeny
	err = ErrDeny

	if target == nil || target.Action == "" {
		return
	}

	if claims == nil || claims.Subject == nil {
		return
	}

	roles := make([]string, 0, len(claims.Subject.Roles())+1)
	roles = append(roles, claims.Subject.Identifier())
	roles = append(roles, claims.Subject.Roles()...)

	for _, role := range roles {
		granted, err1 := a.rbac.IsGrantedE(ctx, role, target.Action, target.Assertions...)
		if granted && err1 == nil {
			return DecisionAllow, nil
		}
		err = errors.Join(err, err1)
	}
	return
}
