package session

import (
	"context"
	"github.com/sparrow-community/pkgs/auth"
	"net/http"
	"time"
)

type Session struct {
	Cookie http.Cookie
	N      *auth.Authenticate
}

func New(opt ...Option) *Session {
	opts := Options{}
	for _, o := range opt {
		o(&opts)
	}

	s := &Session{
		Cookie: http.Cookie{
			Name:     "session",
			Value:    "",
			Path:     "/",
			Domain:   "",
			Expires:  time.Time{},
			MaxAge:   0,
			Secure:   false,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		}}

	if len(opts.CookieName) > 0 {
		s.Cookie.Name = opts.CookieName
	}

	if opts.N != nil {
		s.N = opts.N
	}

	return s
}

func (s *Session) WriteSessionCookie(ctx context.Context, w http.ResponseWriter, token string) {
	s.Cookie.Value = token

	w.Header().Add("Set-Cookie", s.Cookie.String())
	w.Header().Add("Cache-Control", `no-cache="Set-Cookie"`)
}
