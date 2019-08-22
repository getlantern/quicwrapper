// Wraps quic structures in standard net interfaces and
// improves context awareness.
// Conn instances created by this package may be multiplexed
package quicwrapper

import (
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/getlantern/golog"
	quic "github.com/lucas-clemente/quic-go"
)

var (
	log               = golog.LoggerFor("quicwrapper")
	ErrListenerClosed = errors.New("listener closed")
)

const (
	peerGoingAway = "PeerGoingAway:"
)

type Config = quic.Config

var _ net.Conn = &Conn{}

// wraps quic.Stream and other info to implement net.Conn
type Conn struct {
	quic.Stream
	session   quic.Session
	bw        BandwidthEstimator
	onClose   func()
	closeOnce sync.Once
	closeErr  error
}

func newConn(stream quic.Stream, session quic.Session, bw BandwidthEstimator, onClose func()) *Conn {
	if onClose == nil {
		onClose = func() {}
	}

	return &Conn{
		Stream:  stream,
		session: session,
		bw:      bw,
		onClose: onClose,
	}
}

// implements net.Conn.Read
func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.Stream.Read(b)
	if err != nil && err != io.EOF {
		// remote end closed stream
		serr, ok := err.(quic.StreamError)
		if ok && serr.Canceled() {
			err = io.EOF
		}
		// treat peer going away as EOF
		if isPeerGoingAway(err) {
			err = io.EOF
		}
	}
	return n, err
}

// implements net.Conn.Write
func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.Stream.Write(b)
	if err != nil && err != io.EOF {
		// treat "stop sending" as EOF
		serr, ok := err.(quic.StreamError)
		if ok && serr.Canceled() {
			err = io.EOF
		}
		// treat peer going away as EOF
		if isPeerGoingAway(err) {
			err = io.EOF
		}
	}
	return n, err
}

// implements net.Conn.Close
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		c.close()
	})
	return c.closeErr
}

func (c *Conn) close() error {
	// this only closes the write side
	c.closeErr = c.Stream.Close()
	// to close both ends, this also forefully
	// cancels any pending reads / in flight data.
	c.Stream.CancelRead(0)
	c.onClose()
	return c.closeErr
}

// implements net.Conn.LocalAddr
func (c *Conn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

// implements net.Conn.RemoteAddr
func (c *Conn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

// Returns certificates presented by peer
func (c *Conn) PeerCertificates() []*x509.Certificate {
	// the ConnectionState interface the quic-go api is
	// considered unstable, so this is not exposed directly.
	return c.session.ConnectionState().PeerCertificates
}

func (c *Conn) BandwidthEstimate() Bandwidth {
	return c.bw.BandwidthEstimate()
}

func isPeerGoingAway(err error) bool {
	if err == nil {
		return false
	}
	return strings.HasPrefix(err.Error(), peerGoingAway)
}
