package session

type Options struct {
	CookieName string
}

type Option func(*Options)

func WithCookieName(name string) Option {
	return func(options *Options) {
		options.CookieName = name
	}
}
