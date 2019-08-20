package quicwrapper

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/getlantern/netx"
	"github.com/getlantern/ops"
	quic "github.com/lucas-clemente/quic-go"
	"golang.org/x/sync/semaphore"
)

// a QuicDialFn is a function that may be used to establish a new QUIC Session
type QuicDialFn func(ctx context.Context, addr string, tlsConf *tls.Config, config *quic.Config) (quic.Session, error)
type UDPDialFn func(addr string) (net.PacketConn, *net.UDPAddr, error)

const (
	maxPendingStreamRequests = 1024
)

var (
	DialWithNetx     QuicDialFn = newDialerWithUDPDialer(DialUDPNetx)
	DialWithoutNetx  QuicDialFn = quic.DialAddrContext
	defaultQuicDial  QuicDialFn = DialWithNetx
	streamRequestCap atomic.Value
)

func init() {
	resetStreamRequestCap(maxPendingStreamRequests)
}

func getStreamRequestCap() *semaphore.Weighted {
	return streamRequestCap.Load().(*semaphore.Weighted)
}

func resetStreamRequestCap(n int64) {
	streamRequestCap.Store(semaphore.NewWeighted(n))
}

type wrappedSession struct {
	quic.Session
	conn net.PacketConn
}

func (w wrappedSession) Close() error {
	err := w.Session.Close()
	err2 := w.conn.Close()
	if err == nil {
		err = err2
	}
	return err
}

// Creates a new QuicDialFn that uses the UDPDialFn given to
// create the underlying net.PacketConn
func newDialerWithUDPDialer(dial UDPDialFn) QuicDialFn {
	return func(ctx context.Context, addr string, tlsConf *tls.Config, config *quic.Config) (quic.Session, error) {
		udpConn, udpAddr, err := dial(addr)
		if err != nil {
			return nil, err
		}
		ses, err := quic.DialContext(ctx, udpConn, udpAddr, addr, tlsConf, config)
		if err != nil {
			udpConn.Close()
			return nil, err
		}
		return wrappedSession{ses, udpConn}, nil
	}
}

// DialUDPNetx is a UDPDialFn that resolves addresses and obtains
// the net.PacketConn using the netx package.
func DialUDPNetx(addr string) (net.PacketConn, *net.UDPAddr, error) {
	udpAddr, err := netx.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, err
	}
	udpConn, err := netx.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil, err
	}
	return udpConn, udpAddr, nil
}

// NewClient returns a client that creates multiplexed
// QUIC connections in a single Session with the given address using
// the provided configuration.
//
// The Session is created using the
// QuicDialFn given, but is not established until
// the first call to Dial(), DialContext() or Connect()
//
// if dial is nil, the default quic dialer is used
func NewClient(addr string, tlsConf *tls.Config, config *Config, dial QuicDialFn) *Client {
	return NewClientWithPinnedCert(addr, tlsConf, config, dial, nil)
}

// NewClientWithPinnedCert returns a new client configured
// as with NewClient, but accepting only a specific given
// certificate.  If the certificate presented by the connected
// server does match the given certificate, the connection is
// rejected. This check is performed regardless of tls.Config
// settings (ie even if InsecureSkipVerify is true)
//
// If a nil certificate is given, the check is not performed and
// any valid certificate according the tls.Config given is accepted
// (equivalent to NewClient behavior)
func NewClientWithPinnedCert(addr string, tlsConf *tls.Config, config *Config, dial QuicDialFn, cert *x509.Certificate) *Client {
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
	dial         QuicDialFn
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
	// on a goroutine.  To limit any extreme accumulation
	// of stuck goroutines, a global maximum number of pending
	// requests for streams is enforced using the
	// streamRequestCap semaphore.  If the context given
	// expires before the right to request can be acquired
	// from the semaphore, an error is returned and no additional
	// goroutines are started.
	var conn *Conn
	var err error

	rcap := getStreamRequestCap()

	err = rcap.Acquire(ctx, 1)
	if err != nil {
		return nil, fmt.Errorf("maximum pending stream requests reached: %v", err)
	}

	done := make(chan struct{})

	ops.Go(func() {
		defer rcap.Release(1)
		defer close(done)
		var err1 error
		if err1 = c.Connect(ctx); err1 != nil {
			err = fmt.Errorf("connecting session: %v", err1)
			return
		}

		stream, err1 := c.session.OpenStreamSync()
		if err1 != nil {
			err = fmt.Errorf("establishing stream: %v", err1)
			return
		}
		conn = newConn(stream, c.session, c.session, nil)
	})

	select {
	case <-done:
		return conn, err
	case <-ctx.Done():
		// context expired
		// cleanup when/if call returns
		ops.Go(func() {
			<-done
			if conn != nil {
				conn.Close()
			}
		})
		return nil, fmt.Errorf("establishing stream: %v", ctx.Err())
	}
}

// Dial creates a new multiplexed QUIC connection to the
// server configured for the client.
func (c *Client) Dial() (*Conn, error) {
	return c.DialContext(context.Background())
}

// Connect requests immediate handshaking regardless of
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
func (c *Client) Connect(ctx context.Context) error {
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
	if c.handshakeErr != nil {
		return fmt.Errorf("handshake error connecting to %s: %v", c.address, c.handshakeErr)
	}
	return nil
}

// closes the session established by this client
// (and all multiplexed connections)
func (c *Client) Close() error {
	if c.session != nil {
		log.Debugf("Closing client quic session.")
		return c.session.Close()
	}
	return nil
}

func (c *Client) verifyPinnedCert() error {
	certs := c.session.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("Server did not present any certificates!")
	}

	serverCert := certs[0]
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
