package webt

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/getlantern/golog"
	"github.com/getlantern/quicwrapper"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/webtransport-go"
)

var (
	log = golog.LoggerFor("quicwrapper")
)

var _ net.Conn = &conn{}

type streamClosedFn func()

// wraps webtransport.Stream and other info to implement net.Conn
type conn struct {
	webtransport.Stream
	session   *webtransport.Session
	res       *http.Response
	onClose   streamClosedFn
	closeOnce sync.Once
	closeErr  error
}

// NewConn creates a new net.Conn from a webtransport.Stream, session, and http.Response
func NewConn(stream webtransport.Stream, session *webtransport.Session, res *http.Response, onClose streamClosedFn) *conn {
	return &conn{
		Stream:  stream,
		session: session,
		res:     res,
		onClose: onClose,
	}
}

// implements net.Conn.Read
func (c *conn) Read(b []byte) (int, error) {
	n, err := c.Stream.Read(b)
	if err != nil && err != io.EOF {
		// remote end closed stream
		if _, ok := err.(*quic.StreamError); ok {
			err = io.EOF
		}
		// treat peer going away as EOF
		if quicwrapper.IsPeerGoingAway(err) {
			err = io.EOF
		}
		if _, ok := err.(*webtransport.StreamError); ok {
			err = io.EOF
		}
		if _, ok := err.(*webtransport.ConnectionError); ok {
			err = io.EOF
		}
	}
	return n, err
}

// implements net.Conn.Write
func (c *conn) Write(b []byte) (int, error) {
	n, err := c.Stream.Write(b)
	if err != nil && err != io.EOF {
		// treat "stop sending" as EOF
		if _, ok := err.(*quic.StreamError); ok {
			err = io.EOF
		}
		// treat peer going away as EOF
		if quicwrapper.IsPeerGoingAway(err) {
			err = io.EOF
		}
		if _, ok := err.(*webtransport.StreamError); ok {
			err = io.EOF
		}
		if _, ok := err.(*webtransport.ConnectionError); ok {
			err = io.EOF
		}
	}
	return n, err
}

// implements net.Conn.Close
func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		c.close()
	})
	return c.closeErr
}

func (c *conn) close() error {
	// this only closes the write side
	c.closeErr = c.Stream.Close()
	// to close both ends, this also forefully
	// cancels any pending reads / in flight data.
	c.Stream.CancelRead(0)
	c.onClose()
	return c.closeErr
}

// implements net.Conn.LocalAddr
func (c *conn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

// implements net.Conn.RemoteAddr
func (c *conn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

// Returns certificates presented by peer
func (c *conn) PeerCertificates() []*x509.Certificate {
	return c.res.TLS.PeerCertificates
}
