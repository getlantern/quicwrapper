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
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/marten-seemann/webtransport-go"
	"github.com/prometheus/client_golang/prometheus"
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
	QuicConfig *quic.Config
	Handler    *http.ServeMux
}

// ListenAddr creates an HTTP/3 server listening on a given address.
// The net.Conn instances returned by the net.Listener may be multiplexed connections.
func ListenAddr(options *ListenOptions) (net.Listener, error) {
	mux := options.Handler
	if mux == nil {
		mux = http.NewServeMux()
	}

	h3 := http3.Server{
		Handler:    mux,
		Addr:       options.Addr,
		TLSConfig:  options.TLSConfig,
		QuicConfig: options.QuicConfig,
	}

	server := &webtransport.Server{
		H3: h3,
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
		server:       server,
		conn:         conn,
		connections:  make(chan net.Conn, 1000),
		acceptError:  make(chan error, 1),
		closedSignal: make(chan struct{}),
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
	l.handleSession(session)
	// session closes if this handler returns.
	atomic.AddInt64(&l.numConnections, -1)
}

func (l *listener) handleSession(session *webtransport.Session) {
	for {
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			if quicwrapper.IsPeerGoingAway(err) {
				log.Tracef("Accepting stream: Peer going away (%v)", err)
				return
			} else if ce, ok := err.(*webtransport.ConnectionError); ok && ce.Remote == true {
				log.Tracef("Accepting stream: webtransport.ConnectionError remote=%v message=%v", ce.Remote, ce.Message)
				return
			} else {
				log.Errorf("Accepting stream: %v", err)
				return
			}
		} else {
			atomic.AddInt64(&l.numVirtualConnections, 1)
			conn := newConn(stream, session, nil, func() {
				atomic.AddInt64(&l.numVirtualConnections, -1)
			})
			l.connections <- conn
		}
	}
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
