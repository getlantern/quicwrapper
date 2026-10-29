package webt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

const keepAliveInterval = 10 * time.Second

type ClientOptions struct {
	Addr       string
	Path       string
	TLSConfig  *tls.Config
	QUICConfig *quic.Config
	PinnedCert *x509.Certificate
}

type client struct {
	session    *webtransport.Session
	res        *http.Response
	muSession  sync.Mutex
	address    string
	path       string
	pinnedCert *x509.Certificate
	transport  *webtransport.Transport
	// quicConn is the connection under the current session, set by dialQUIC.
	quicConn *quic.Conn
}

// NewClient returns a client that creates multiplexed WebTransport based sessions
func NewClient(config *ClientOptions) *client {
	c := &client{
		address:    config.Addr,
		path:       config.Path,
		pinnedCert: config.PinnedCert,
	}
	c.transport = &webtransport.Transport{
		TLSClientConfig: config.TLSConfig,
		QUICConfig:      webTransportQUICConfig(config.QUICConfig),
		DialAddr:        c.dialQUIC,
	}
	return c
}

// dialQUIC is the transport's QUIC dialer. It keeps the connection it made so
// getOrCreateSession can read the TLS state: webtransport-go's CONNECT
// response carries none, and a Session no longer exposes it. Dial calls it
// synchronously under muSession, so the field needs no further locking.
func (c *client) dialQUIC(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	conn, err := quic.DialAddrEarly(ctx, addr, tlsCfg, cfg)
	if err != nil {
		return nil, err
	}
	c.quicConn = conn
	return conn, nil
}

// webTransportQUICConfig returns config with the QUIC features WebTransport
// requires switched on. webtransport-go refuses a config that lacks either,
// and callers that only ask for datagrams predate the second requirement.
// A nil config stays nil: webtransport-go then supplies its own defaults.
func webTransportQUICConfig(config *quic.Config) *quic.Config {
	if config == nil {
		return nil
	}
	c := config.Clone()
	c.EnableDatagrams = true
	c.EnableStreamResetPartialDelivery = true
	return c
}

// PacketConn creates a net.PacketConn from the current webtransport session.
// If no session exists, one will be created
func (c *client) PacketConn(ctx context.Context) (net.PacketConn, error) {
	session, _, err := c.getOrCreateSession(ctx)
	if err != nil {
		return nil, err
	}
	// enable client side keep-alive
	return getPacketConn(session, keepAliveInterval), nil
}

// DialContext creates a webtransport connection to the
// server configured in the client. The given Context governs
// cancellation / timeout.
func (c *client) DialContext(ctx context.Context) (net.Conn, error) {
	session, res, err := c.getOrCreateSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("connecting session: %w", err)
	}
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		if ne, ok := err.(net.Error); ok && !ne.Temporary() {
			// start over again when seeing unrecoverable error.
			c.clearSession(err.Error())
		}
		return nil, fmt.Errorf("establishing stream: %w", err)
	}
	return NewConn(stream, session, res, func() {}), nil
}

// Dial creates a new multiplexed WebTransport connection to the
// server configured for the client.
func (c *client) Dial() (net.Conn, error) {
	return c.DialContext(context.Background())
}

// Connect requests immediate handshaking regardless of
// whether any specific Dial has been initiated. It is
// called lazily on the first Dial if not otherwise
// called.
//
// This can serve to pre-establish a multiplexed
// session, but will also initiate idle timeout
// tracking, keepalives etc. Returns any error
// encountered during handshake.
//
// This may safely be called concurrently with Dial.
// The handshake is guaranteed to be completed when the
// call returns to any caller.
func (c *client) Connect(ctx context.Context) error {
	_, _, err := c.getOrCreateSession(ctx)
	return err
}

func validateURL(addr, path string) (*url.URL, error) {
	if !strings.Contains(addr, "://") {
		addr = "https://" + addr
	}

	// parse the address
	parsedAddr, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid addr: %w", err)
	}
	// ensure addr has "https" as scheme
	if parsedAddr.Scheme != "https" {
		return nil, fmt.Errorf("invalid scheme, got: %s", parsedAddr.Scheme)
	}

	// parse the path
	parsedPath, err := url.Parse(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}

	return parsedAddr.ResolveReference(parsedPath), nil
}

func (c *client) getOrCreateSession(ctx context.Context) (*webtransport.Session, *http.Response, error) {
	c.muSession.Lock()
	defer c.muSession.Unlock()
	if c.session == nil {
		u, err := validateURL(c.address, c.path)
		if err != nil {
			return nil, nil, err
		}
		res, session, err := c.transport.Dial(ctx, u.String(), nil)
		if err != nil {
			return nil, nil, err
		}
		if res.TLS == nil && c.quicConn != nil {
			// Expose the handshake on the response, where conn.PeerCertificates
			// and the pinned-cert check read it.
			state := c.quicConn.ConnectionState().TLS
			res.TLS = &state
		}
		if c.pinnedCert != nil {
			if err = c.verifyPinnedCert(res); err != nil {
				session.CloseWithError(webtransport.SessionErrorCode(0), "")
				return nil, nil, err
			}
		}
		c.session = session
		c.res = res
	}
	return c.session, c.res, nil
}

// verifyPinnedCert checks the leaf the server presented on the HTTP/3
// connection the session rides on, as recorded on the CONNECT response.
func (c *client) verifyPinnedCert(res *http.Response) error {
	var certs []*x509.Certificate
	if res != nil && res.TLS != nil {
		certs = res.TLS.PeerCertificates
	}
	if len(certs) == 0 {
		return errors.New("server did not present any certificates")
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

		return fmt.Errorf("server's certificate didn't match expected! Server had\n%v\nbut expected:\n%v", received, expected)
	}
	return nil
}

// closes the session established by this client
// (and all multiplexed connections)
func (c *client) Close() error {
	c.clearSession("client closed")
	return nil
}

func (c *client) clearSession(reason string) {
	c.muSession.Lock()
	s := c.session
	c.session = nil
	c.muSession.Unlock()
	if s != nil {
		log.Debugf("Closing webtransport session (%v)", reason)
		s.CloseWithError(webtransport.SessionErrorCode(0), "")
	}
}
