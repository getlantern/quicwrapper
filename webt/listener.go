package webt

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/getlantern/ops"
	"github.com/getlantern/quicwrapper"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/webtransport-go"
)

var (
	connectionCounts = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "webt_connections",
			Help: "Connections that web transport is currently tracking",
		},
		[]string{"type"},
	)
)

type ListenOptions struct {
	Addr       string
	Path       string
	TLSConfig  *tls.Config
	QUICConfig *quic.Config
	Handler    *http.ServeMux
	// DatagramHandler is an optional datagram handler that will be called when a new WebTransport session is created
	// It will be called with a net.PacketConn that wraps the WebTransport session, and with the remote address
	DatagramHandler func(pconn net.PacketConn, remoteAddr net.Addr)
}

// ListenAddr creates an HTTP/3 server listening on a given address.
// The net.Conn instances returned by the net.Listener may be multiplexed connections.
func ListenAddr(options *ListenOptions) (net.Listener, error) {
	mux := options.Handler
	if mux == nil {
		mux = http.NewServeMux()
	}

	server := &webtransport.Server{
		H3: http3.Server{
			Handler:    mux,
			Addr:       options.Addr,
			TLSConfig:  options.TLSConfig,
			QUICConfig: options.QUICConfig,
		},
	}

	udpAddr, err := net.ResolveUDPAddr("udp", options.Addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	l := &listener{
		server:          server,
		conn:            conn,
		connections:     make(chan net.Conn, 1000),
		acceptError:     make(chan error, 1),
		closedSignal:    make(chan struct{}),
		datagramHandler: options.DatagramHandler,
	}

	path := fmt.Sprintf("/%s/", options.Path)
	mux.HandleFunc(path, l.handleUpgrade)
	ops.Go(l.listenAndServe)
	ops.Go(l.logStats)

	return l, nil
}

var _ net.Listener = &listener{}

// wraps quic.Listener to create a net.Listener
type listener struct {
	numConnections        int64
	numVirtualConnections int64

	server       *webtransport.Server
	conn         net.PacketConn
	connections  chan net.Conn
	acceptError  chan error
	closedSignal chan struct{}
	closeErr     error
	closeOnce    sync.Once

	datagramHandler func(net.PacketConn, net.Addr)
}

// implements net.Listener.Accept
func (l *listener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.connections:
		if !ok {
			return nil, quicwrapper.ErrListenerClosed
		}
		return conn, nil
	case err, ok := <-l.acceptError:
		if !ok {
			return nil, quicwrapper.ErrListenerClosed
		}
		return nil, err
	case <-l.closedSignal:
		return nil, quicwrapper.ErrListenerClosed
	}
}

// implements net.Listener.Close
// Shut down the WebTransport listener.
func (l *listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closedSignal)
		l.closeErr = l.server.Close()
	})
	return l.closeErr
}

func (l *listener) isClosed() bool {
	select {
	case <-l.closedSignal:
		return true
	default:
		return false
	}
}

// implements net.Listener.Addr
func (l *listener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

func (l *listener) listenAndServe() {
	err := l.server.Serve(l.conn)
	if err != nil {
		if !l.isClosed() {
			l.acceptError <- err
		}
	}
}

func (l *listener) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	session, err := l.server.Upgrade(w, r)
	if err != nil {
		fmt.Printf("upgrading failed: %s", err)
		w.WriteHeader(500)
		return
	}
	atomic.AddInt64(&l.numConnections, 1)
	go l.handleDatagramSession(session)
	l.handleStreamSession(session)
	// session closes if this handler returns.
	atomic.AddInt64(&l.numConnections, -1)
}

// handleStreamSession accepts new WebTransport streams from the session
func (l *listener) handleStreamSession(session *webtransport.Session) {
	for {
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			if quicwrapper.IsPeerGoingAway(err) {
				log.Tracef("Accepting stream: Peer going away (%v)", err)
				return
			} else if ce, ok := err.(*webtransport.SessionError); ok && ce.Remote {
				log.Tracef("Accepting stream: webtransport.SessionError remote=%v message=%v", ce.Remote, ce.Message)
				return
			} else {
				log.Errorf("Accepting stream: %v", err)
				return
			}
		}
		atomic.AddInt64(&l.numVirtualConnections, 1)
		conn := NewConn(stream, session, nil, func() {
			atomic.AddInt64(&l.numVirtualConnections, -1)
		})
		l.connections <- conn
	}
}

// handleDatagramSession wraps the WebTransport session to net.PacketConn and calls a custom datagramHandler if any
func (l *listener) handleDatagramSession(session *webtransport.Session) {
	if l.datagramHandler == nil {
		return
	}
	// l.numVirtualConnections isn't used in datagram mode so it remains 0
	// server doesn't need keep-alive
	l.datagramHandler(NewPacketConn(session, 0), session.RemoteAddr())
}

func (l *listener) logStats() {
	for {
		select {
		case <-time.After(5 * time.Second):
			if !l.isClosed() {
				log.Debugf("Connections: %d   Virtual: %d", atomic.LoadInt64(&l.numConnections), atomic.LoadInt64(&l.numVirtualConnections))
				connectionCounts.WithLabelValues("connections").Set(float64(atomic.LoadInt64(&l.numConnections)))
				connectionCounts.WithLabelValues("virtual").Set(float64(atomic.LoadInt64(&l.numVirtualConnections)))
			}
		case <-l.closedSignal:
			log.Debugf("Connections: %d   Virtual: %d", atomic.LoadInt64(&l.numConnections), atomic.LoadInt64(&l.numVirtualConnections))
			log.Debug("Done logging stats.")
			connectionCounts.WithLabelValues("connections").Set(0)
			connectionCounts.WithLabelValues("virtual").Set(0)
			return
		}
	}
}
