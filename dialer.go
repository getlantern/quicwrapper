package quicwrapper

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"sync"

	"github.com/getlantern/netx"
	quic "github.com/getlantern/quic-go"
)

// a QuicDialFN is a function that may be used to establish a new QUIC Session
type QuicDialFN func(ctx context.Context, addr string, tlsConf *tls.Config, config *quic.Config) (quic.Session, error)

var (
	defaultQuicDial QuicDialFN = quic.DialAddrContext
)

// Alternative QuicDial using netx swapped functions
func DialWithNetx(ctx context.Context, addr string, tlsConf *tls.Config, config *quic.Config) (quic.Session, error) {
	udpAddr, err := netx.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	// XXX any reason to use an netx alternative here ?
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return quic.DialContext(ctx, udpConn, udpAddr, addr, tlsConf, config)
}

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

func NewClientWithPinnedCert(addr string, tlsConf *tls.Config, config *Config, dial QuicDialFN, cert *x509.Certificate) *Client {
	if dial == nil {
		dial = defaultQuicDial
	}

	return &Client{
		session:    nil,
		address:    addr,
		tlsConf:    tlsConf,
		config:     config,
		dial:       dial,
		pinnedCert: cert,
	}

}

type Client struct {
	session      quic.Session
	handshakeErr error
	address      string
	tlsConf      *tls.Config
	pinnedCert   *x509.Certificate
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
	// during stream creation, so this is done
	// on a goroutine.

	var conn *Conn
	var err error

	done := make(chan struct{})

	go func() {
		defer close(done)

		if err = c.WarmUp(ctx); err != nil {
			return
		}

		stream, err1 := c.session.OpenStreamSync()
		if err1 != nil {
			err = err1
			return
		}
		conn = newConn(stream, c.session, c.session, nil)
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
func (c *Client) WarmUp(ctx context.Context) error {
	c.dialOnce.Do(func() {
		c.session, c.handshakeErr = c.dial(ctx, c.address, c.tlsConf, c.config)
		if c.handshakeErr == nil && c.pinnedCert != nil {
			c.handshakeErr = c.verifyPinnedCert()
			if c.handshakeErr != nil {
				c.session.Close()
				c.session = nil
			}
		}
	})
	return c.handshakeErr
}

// closes the session established by this client
// (and all multiplexed connections)
func (c *Client) Close() error {
	if c.session != nil {
		return c.session.Close()
	}
	return nil
}

func (c *Client) verifyPinnedCert() error {
	serverCert := c.session.ConnectionState().PeerCertificates[0]
	if !serverCert.Equal(c.pinnedCert) {
		received := pem.EncodeToMemory(&pem.Block{
			Type:    "CERTIFICATE",
			Headers: nil,
			Bytes:   serverCert.Raw,
		})

		expected := pem.EncodeToMemory(&pem.Block{
			Type:    "CERTIFICATE",
			Headers: nil,
			Bytes:   c.pinnedCert.Raw,
		})

		return fmt.Errorf("Server's certificate didn't match expected! Server had\n%v\nbut expected:\n%v", received, expected)
	}
	return nil
}
