// Wraps quic structures in standard net interfaces and
// improves context awareness.
// Conn instances created by this package may be multiplexed
package quicwrapper

import (
	"crypto/tls"
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
	// this is a very non-informative error string that quic-go
	// gives back to indicate that something terminated with no explicit error
	// e.g. this is returned when a session terminates "normally"
	// (peer going away)
	applicationNoError = "Application error 0x0"
	closedConnError    = "use of closed network connection"
	noActivity         = "No recent network activity"

	// This the value represents HTTP/3 protocol (explicitly over quic draft-29).
	// chromium has stated they are sticking to h3-29/0xff00001d as the
	// alpn and quic wire version for H3 "until final RFCs are complete"
	AlpnH3 = "h3-29"
)

type Config = quic.Config

var _ net.Conn = &Conn{}

type streamClosedFn func(id quic.StreamID)

// wraps quic.Stream and other info to implement net.Conn
type Conn struct {
	quic.Stream
	session   quic.Session
	bw        BandwidthEstimator
	onClose   streamClosedFn
	closeOnce sync.Once
	closeErr  error
}

func newConn(stream quic.Stream, session quic.Session, bw BandwidthEstimator, onClose streamClosedFn) *Conn {
	if onClose == nil {
		onClose = func(id quic.StreamID) {}
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
	c.onClose(c.StreamID())
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
	str := err.Error()

	if strings.Contains(str, closedConnError) ||
		strings.Contains(str, applicationNoError) ||
		strings.Contains(str, noActivity) {
		return true
	} else {
		return false
	}
}

// returns a tls.Config with NextProtos set to AlpnH3
// if NextProtos is unset in the given tls.Config.
func defaultNextProtos(tlsConf *tls.Config) *tls.Config {
	if len(tlsConf.NextProtos) == 0 {
		c := tlsConf.Clone()
		c.NextProtos = []string{AlpnH3}
		return c
	} else {
		return tlsConf
	}
}
