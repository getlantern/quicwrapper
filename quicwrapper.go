// Wraps quic structures in standard net interfaces and
// improves context awareness.
// Conn instances created by this package may be multiplexed
package quicwrapper

import (
	"crypto/x509"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"github.com/getlantern/golog"
	quic "github.com/getlantern/quic-go"
	"github.com/getlantern/quic-go/qerr"
)

var (
	log               = golog.LoggerFor("quicwrapper")
	ErrListenerClosed = errors.New("listener closed")
)

type Config = quic.Config

const (
	Mib = 1024 * 1024
)

var _ net.Conn = &Conn{}

// wraps quic.Stream and other info to implement net.Conn
type Conn struct {
	stream    quic.Stream
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
		stream:  stream,
		session: session,
		bw:      bw,
		onClose: onClose,
	}
}

// implements net.Conn.Read
func (c *Conn) Read(b []byte) (int, error) {
	n, err := c.stream.Read(b)
	if err != nil {
		quicErr := qerr.ToQuicError(err)
		code := quicErr.ErrorCode
		// this is an "expected" way for a stream to close
		if code == qerr.PeerGoingAway {
			err = io.EOF
		}
	}
	return n, err
}

// implements net.Conn.Write
func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.stream.Write(b)
	if err != nil {
		quicErr := qerr.ToQuicError(err)
		code := quicErr.ErrorCode
		// This quic error shows up sort of arbitrarily
		// if the stream closes soon after completing a
		// write (by a race).  It's not consistent enough to
		// be useful.
		if n == len(b) && code == qerr.PeerGoingAway {
			err = nil
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
	// this only closes the write side, the connection will
	// not fully close until the read side is drained ...
	c.closeErr = c.stream.Close()

	// XXX ? this deadlocks with closing the session
	go func() {
		// attempt to drain any pending readable data from the connection
		// this is necessary for the stream to be considered fully closed.
		io.Copy(ioutil.Discard, c.stream)
	}()

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

// implements net.Conn.SetDeadline
func (c *Conn) SetDeadline(t time.Time) error {
	return c.stream.SetDeadline(t)
}

// implements net.Conn.SetReadDeadline
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

// implements net.Conn.SetWriteDeadline
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

// Returns unique identifier for the underlying stream
func (c *Conn) StreamID() quic.StreamID {
	return c.stream.StreamID()
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
