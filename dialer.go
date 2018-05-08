package quicwrapper

import (
	"context"
	"crypto/tls"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
)

// a QuicDialFN is a function that may be used to establish a new QUIC Session
type QuicDialFN func(addr string, tlsConf *tls.Config, config *quic.Config) (quic.Session, error)

var (
	defaultQuicDial QuicDialFN = quic.DialAddr
)

// NewClient returns a client that creates multiplexed
// QUIC connections in a single Session with the given address using
// the provided configuration. The Session is created using the
// QuickDialFN given, but is not established until
// the first call to Dial(), DialContext() or WarmUp()
//
// if dial is nil, the default quic dialer is used
func NewClient(addr string, tlsConf *tls.Config, config *Config, dial QuicDialFN) *Client {

	if dial == nil {
		dial = defaultQuicDial
	}

	return &Client{
		session: nil,
		address: addr,
		tlsConf: tlsConf,
		config:  config,
		dial:    dial,
	}
}

type Client struct {
	session      quic.Session
	handshakeErr error
	address      string
	tlsConf      *tls.Config
	config       *Config
	dialOnce     sync.Once
	dial         QuicDialFN
	mx           sync.Mutex
}

// DialContext creates a new multiplexed QUIC connection to the
// server configured in the client. The given Context governs
// cancellation / timeout.  If initial handshaking is performed,
// the operation is additionally governed by HandshakeTimeout
// value given in the client Config.
func (c *Client) DialContext(ctx context.Context) (*Conn, error) {
	// There is no direct support for Contexts
	// during handshaking / stream creation, so this is done
	// on a goroutine.

	var conn *Conn
	var err error

	done := make(chan struct{})

	go func() {
		defer close(done)

		if err = c.WarmUp(); err != nil {
			return
		}

		stream, err1 := c.session.OpenStreamSync()
		if err1 != nil {
			err = err1
			return
		}
		conn = newConn(stream, c.session, nil)
	}()

	select {
	case <-done:
		return conn, err
	case <-ctx.Done():
		// context expired
		// cleanup when/if call returns
		go func() {
			<-done
			if conn != nil {
				conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// Dial creates a new multiplexed QUIC connection to the
// server configured for the client.
func (c *Client) Dial() (*Conn, error) {
	return c.DialContext(context.Background())
}

// WarmUp requests immediate handshaking regardless of
// whether any specific Dial has been initiated.
// It is called lazily on the first Dial if not
// otherwise called.
//
// This can serve to pre-establish a multiplexed
// session, but will also initiate idle timeout
// tracking, keepalives etc. Returns any error
// encountered during handshake.
//
// This may safely be called concurrently
// with Dial.  The handshake is performed exactly
// once regardless of the number of calls, and
// is guaranteed to be completed when the call
// returns to any caller.
func (c *Client) WarmUp() error {
	c.dialOnce.Do(func() {
		c.session, c.handshakeErr = c.dial(c.address, c.tlsConf, c.config)
	})
	return c.handshakeErr
}

// closes the session established by this client
// (and all multiplexed connections)
func (c *Client) Close() error {
	if c.session != nil {
		return c.session.Close(nil)
	}
	return nil
}
