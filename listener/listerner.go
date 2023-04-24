package listener

import "net"
import "github.com/soheilhy/cmux"

type MicroListener struct {
	opts Options
	cm   cmux.CMux
}

func (m *MicroListener) Grpc() net.Listener {
	return m.cm.MatchWithWriters(
		cmux.HTTP2MatchHeaderFieldSendSettings("content-type", "application/grpc"),
		cmux.HTTP2MatchHeaderFieldSendSettings("x-content-type", "application/grpc+proto"),
	)
}

func (m *MicroListener) Http() net.Listener {
	return m.cm.Match(cmux.HTTP1Fast())
}

func (m *MicroListener) Serve() error {
	return m.cm.Serve()
}

func New(opt ...Option) (*MicroListener, error) {
	opts := Options{
		address: ":0",
	}
	for _, o := range opt {
		o(&opts)
	}

	if opts.listener == nil {
		listener, err := net.Listen("tcp", opts.address)
		if err != nil {
			return nil, err
		}
		opts.listener = listener
	}

	return &MicroListener{
		opts: opts,
		cm:   cmux.New(opts.listener),
	}, nil
}
