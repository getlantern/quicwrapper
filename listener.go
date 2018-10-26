package quicwrapper

import (
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/ops"
	quic "github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/qerr"
)

// ListenAddr creates a QUIC server listening on a given address.
// The net.Conn instances returned by the net.Listener may be multiplexed connections.
func ListenAddr(addr string, tlsConf *tls.Config, config *Config) (net.Listener, error) {

	ql, err := quic.ListenAddr(addr, tlsConf, config)
	if err != nil {
		return nil, err
	}

	l := &listener{
		quicListener: ql,
		config:       config,
		connections:  make(chan net.Conn, 1000),
		acceptError:  make(chan error, 1),
		closedSignal: make(chan struct{}),
	}
	ops.Go(l.listen)
	ops.Go(l.logStats)

	return l, nil
}

var _ net.Listener = &listener{}

// wraps quic.Listener to create a net.Listener
type listener struct {
	quicListener          quic.Listener
	config                *Config
	connections           chan net.Conn
	acceptError           chan error
	closedSignal          chan struct{}
	closed                bool
	numConnections        int64
	numVirtualConnections int64
	mx                    sync.Mutex
}

// implements net.Listener.Accept
func (l *listener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.connections:
		if !ok {
			return nil, ErrListenerClosed
		}
		return conn, nil
	case err, ok := <-l.acceptError:
		if !ok {
			return nil, ErrListenerClosed
		}
		return nil, err
	case <-l.closedSignal:
		return nil, ErrListenerClosed
	}
}

// implements net.Listener.Close
// Shut down the QUIC listener.
// this implicitly sends CONNECTION_CLOSE frames to peers
// note: it is still the responsibility of the caller
// to call Close() on any Conn returned from Accept()
func (l *listener) Close() error {
	l.mx.Lock()
	defer l.mx.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true

	close(l.closedSignal)
	err := l.quicListener.Close()

	return err
}

// implements net.Listener.Addr
func (l *listener) Addr() net.Addr {
	return l.quicListener.Addr()
}

func (l *listener) listen() {
	group := &sync.WaitGroup{}

	defer func() {
		l.Close()
		close(l.acceptError)
		// wait for writers to exit, drain connections
		group.Wait()
		close(l.connections)
		for c := range l.connections {
			c.Close()
		}
	}()

	for {
		session, err := l.quicListener.Accept()
		if err != nil {
			if !l.closed {
				l.acceptError <- err
			}
			return
		}
		if l.closed {
			session.Close()
			return
		} else {
			atomic.AddInt64(&l.numConnections, 1)
			ops.Go(func() { l.handleSession(session, group) })
			group.Add(1)
		}
	}
}

func (l *listener) handleSession(session quic.Session, group *sync.WaitGroup) {

	// keep a smoothed average of the bandwidth estimate
	// for the session
	bw := NewEMABandwidthSampler(session)
	bw.Start()

	defer func() {
		bw.Stop()
		session.Close()
		atomic.AddInt64(&l.numConnections, -1)
		group.Done()
	}()

	for {
		stream, err := session.AcceptStream()
		if err != nil {
			quicErr := qerr.ToQuicError(err)
			code := quicErr.ErrorCode
			switch code {
			case qerr.PeerGoingAway:
				log.Tracef("Session closed: %s", code)
				return
			case qerr.NetworkIdleTimeout:
				log.Tracef("Session closed: %s", code)
				return
			default:
				log.Errorf("Error accepting stream: %s", code)
				return
			}
		} else {
			atomic.AddInt64(&l.numVirtualConnections, 1)
			l.connections <- newConn(stream, session, bw, l.streamClosed)
		}
	}
}

func (l *listener) streamClosed() {
	atomic.AddInt64(&l.numVirtualConnections, -1)
}

func (l *listener) logStats() {
	for {
		select {
		case <-time.After(5 * time.Second):
			if !l.closed {
				log.Debugf("Connections: %d   Virtual: %d", atomic.LoadInt64(&l.numConnections), atomic.LoadInt64(&l.numVirtualConnections))
			}
		case <-l.closedSignal:
			log.Debug("Done logging stats")
			return
		}
	}
}
