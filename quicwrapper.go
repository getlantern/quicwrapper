// Wraps quic structures in standard net interfaces and
// improves context awareness.
// Conn instances created by this package may be multiplexed
package quicwrapper

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/getlantern/golog"
	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/qerr"
)

var (
	log               = golog.LoggerFor("quicwrapper")
	ErrListenerClosed = errors.New("listener closed")
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
	if err != nil {
		quicErr := qerr.ToQuicError(err)
		code := quicErr.ErrorCode
		// this is an "expected" way for a stream to close
		if code == qerr.PeerGoingAway {
			err = io.EOF
		}
	}
	err = mapErr(err)
	return n, err
}

// implements net.Conn.Write
func (c *Conn) Write(b []byte) (int, error) {
	n, err := c.Stream.Write(b)
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
	err = mapErr(err)
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

var _ net.Error = &netErr{}

// an error type that fulfills the net.Error interface
type netErr struct {
	Err         error
	IsTimeout   bool
	IsTemporary bool
}

func (e *netErr) Error() string   { return e.Err.Error() }
func (e *netErr) Timeout() bool   { return e.IsTimeout }
func (e *netErr) Temporary() bool { return e.IsTemporary }

// wraps certain error types in a netErr
// for external packages expecting errors
// matching the net.Error interface.  There
// is some similar logic hiding in the
// net package itself :P
func mapErr(err error) error {
	if err == nil {
		return nil
	}

	if err == context.DeadlineExceeded {
		return &netErr{err, true, true}
	}
	quicErr := qerr.ToQuicError(err)
	code := quicErr.ErrorCode
	if code == qerr.NetworkIdleTimeout || code == qerr.HandshakeTimeout {
		return &netErr{err, true, true}
	}

	return err
}
