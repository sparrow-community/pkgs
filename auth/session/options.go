package session

import "github.com/sparrow-community/pkgs/auth"

type Options struct {
	CookieName string
	N          *auth.Authenticate
}

type Option func(*Options)

func WithCookieName(name string) Option {
	return func(options *Options) {
		options.CookieName = name
	}
}

func WithAuth(auth *auth.Authenticate) Option {
	return func(options *Options) {
		if auth != nil {
			options.N = auth
		}
	}
}
