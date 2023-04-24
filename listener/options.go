package listener

import "net"

type Options struct {
	listener net.Listener
	address  string
}

type Option func(*Options)

func WithListener(listener net.Listener) Option {
	return func(o *Options) {
		o.listener = listener
	}
}

func WithAddress(address string) Option {
	return func(o *Options) {
		o.address = address
	}
}
