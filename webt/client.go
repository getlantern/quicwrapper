package webt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

type ClientOptions struct {
	Addr       string
	Path       string
	TLSConfig  *tls.Config
	QuicConfig *quic.Config
	PinnedCert *x509.Certificate
}

type client struct {
	session    *webtransport.Session
	res        *http.Response
	muSession  sync.Mutex
	address    string
	path       string
	pinnedCert *x509.Certificate
	dialer     *webtransport.Dialer
}

// NewClient returns a client that creates multiplexed WebTransport based sessions
func NewClient(config *ClientOptions) *client {
	dialer := &webtransport.Dialer{
		RoundTripper: &http3.RoundTripper{
			TLSClientConfig: config.TLSConfig,
			QuicConfig:      config.QuicConfig,
		},
	}

	return &client{
		address:    config.Addr,
		path:       config.Path,
		pinnedCert: config.PinnedCert,
		dialer:     dialer,
	}
}

// DialContext creates a webtransport connection to the
// server configured in the client. The given Context governs
// cancellation / timeout.
func (c *client) DialContext(ctx context.Context) (*conn, error) {
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
func (c *client) Dial() (*conn, error) {
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

func (c *client) getOrCreateSession(ctx context.Context) (*webtransport.Session, *http.Response, error) {
	c.muSession.Lock()
	defer c.muSession.Unlock()
	if c.session == nil {
		u := fmt.Sprintf("https://%s/%s/", c.address, c.path)
		res, session, err := c.dialer.Dial(ctx, u, nil)
		if err != nil {
			return nil, nil, err
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

func (c *client) verifyPinnedCert(res *http.Response) error {
	certs := res.TLS.PeerCertificates
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
