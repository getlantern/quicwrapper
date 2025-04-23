package webt

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/quic-go/webtransport-go"
)

// map[*webtransport.Session]*refCountedConn that maps a WebTransport session to a reference counted packetConn
var connMap sync.Map

// refCountedConn is a reference counted wrapper for net.PacketConn
type refCountedConn struct {
	conn      net.PacketConn
	refLock   sync.Mutex
	refs      int
	closed    bool
	onCleanup func() // optional cleanup callback
}

// Acquire increments the reference count and returns the net.PacketConn
func (r *refCountedConn) Acquire() net.PacketConn {
	r.refLock.Lock()
	defer r.refLock.Unlock()
	if r.closed {
		return nil
	}
	r.refs++
	return &refCountedConnHandle{parent: r}
}

// Release decrements the reference count. When the reference count reaches 0, it closes the net.PacketConn and calls the cleanup callback
func (r *refCountedConn) Release() error {
	r.refLock.Lock()
	defer r.refLock.Unlock()

	if r.refs > 0 {
		r.refs--
	}
	if r.refs == 0 && !r.closed {
		r.closed = true
		err := r.conn.Close()
		if r.onCleanup != nil {
			r.onCleanup()
		}
		return err
	}
	return nil
}

// refCountedConnHandle implements net.PacketConn and calls refCountedConn.Release when closed
type refCountedConnHandle struct {
	parent *refCountedConn
}

func (h *refCountedConnHandle) ReadFrom(p []byte) (int, net.Addr, error) {
	return h.parent.conn.ReadFrom(p)
}
func (h *refCountedConnHandle) WriteTo(p []byte, addr net.Addr) (int, error) {
	return h.parent.conn.WriteTo(p, addr)
}
func (h *refCountedConnHandle) Close() error {
	return h.parent.Release()
}
func (h *refCountedConnHandle) LocalAddr() net.Addr {
	return h.parent.conn.LocalAddr()
}
func (h *refCountedConnHandle) SetDeadline(t time.Time) error {
	return h.parent.conn.SetDeadline(t)
}
func (h *refCountedConnHandle) SetReadDeadline(t time.Time) error {
	return h.parent.conn.SetReadDeadline(t)
}
func (h *refCountedConnHandle) SetWriteDeadline(t time.Time) error {
	return h.parent.conn.SetWriteDeadline(t)
}

// packetConn wraps a WebTransport session and implements net.PacketConn
type packetConn struct {
	session *webtransport.Session
	chunker *DatagramChunker
	excess  []byte

	// keep-alive interval that periodically sends "ping" messages to the peer to avoid QUIC idle timeout error
	keepAliveInterval time.Duration
	ctx               context.Context
	cancel            context.CancelFunc
}

// receiveDatagrams listens for incoming datagrams as chunks, reassembles them, and queues complete messages
func (c *packetConn) receiveDatagrams() {
	for {
		select {
		case <-c.ctx.Done():
			c.chunker.Close()
			log.Trace("receiveDatagrams context done")
			return
		default:
			//log.Debugf("receiveDatagrams waiting for datagram...")
			data, err := c.session.ReceiveDatagram(c.ctx)
			if err != nil {
				log.Tracef("receiveDatagrams error: %v", err)
				c.chunker.Close()
				return
			}

			// ignore keep-alive "ping" messages
			if len(data) == 4 && string(data) == "ping" {
				continue
			}
			c.chunker.Receive(data)
		}
	}
}

// ReadFrom waits for a complete message and returns it
func (c *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	if len(c.excess) > 0 {
		l := copy(p, c.excess)
		c.excess = c.excess[l:]
		return l, c.session.RemoteAddr(), nil
	}
	msg, err := c.chunker.Read()
	if err != nil {
		return 0, nil, err
	}
	l := copy(p, msg)
	if len(msg) > l {
		excess := msg[l:]
		c.excess = append(c.excess, excess...)
	}
	log.Tracef("packetConn.ReadFrom: Received %v bytes from %v", len(msg), c.session.RemoteAddr())
	return l, c.session.RemoteAddr(), nil
}

// WriteTo splits large messages and sends them as datagram chunks
func (c *packetConn) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	chunks := c.chunker.Chunk(p)
	for _, chunk := range chunks {
		if err := c.session.SendDatagram(chunk); err != nil {
			return 0, err
		}
	}
	log.Tracef("packetConn.WriteTo: Sent %v bytes of %v chunks", len(p), len(chunks))
	return len(p), nil
}

// keepAlive periodically sends a "ping" datagram
func (c *packetConn) keepAlive() {
	ticker := time.NewTicker(c.keepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := c.session.SendDatagram([]byte("ping"))
			if err != nil {
				log.Debugf("keepAlive error: %v", err)
				return
			}
		case <-c.ctx.Done():
			return
		}
	}
}

// Close does not close the underlying WebTransport session, instead it just stops
// the keepAlive() goroutine and receiveDatagrams() goroutine
func (c *packetConn) Close() error {
	c.cancel()
	return nil
}

// LocalAddr returns the local address
func (c *packetConn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

func (c *packetConn) SetDeadline(t time.Time) error      { return nil }
func (c *packetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *packetConn) SetWriteDeadline(t time.Time) error { return nil }

// newpacketConn creates a new packetConn by wrapping a WebTransport session.
// The keepAlive parameter, when > 0, is the duration between sending session keep-alive ping datagrams.
func newPacketConn(session *webtransport.Session, keepAlive time.Duration) net.PacketConn {
	ctx, cancel := context.WithCancel(context.Background())
	conn := &packetConn{
		session:           session,
		chunker:           NewDatagramChunker(),
		keepAliveInterval: keepAlive,
		ctx:               ctx,
		cancel:            cancel,
	}
	//listening for incoming datagrams
	go conn.receiveDatagrams()
	// keep-alive packets
	if keepAlive > 0 {
		go conn.keepAlive()
	}
	return conn
}

// getPacketConn returns a net.PacketConn for the given WebTransport session. For each session, the same net.PacketConn is returned
// and the reference count is incremented.
func getPacketConn(session *webtransport.Session, keepAlive time.Duration) net.PacketConn {
	v, _ := connMap.LoadOrStore(session, &refCountedConn{
		conn: newPacketConn(session, keepAlive),
		onCleanup: func() {
			connMap.Delete(session)
		},
	})
	refConn := v.(*refCountedConn)

	handle := refConn.Acquire()
	if handle == nil {
		// deleted after LoadOrStore
		connMap.Delete(session)
		return getPacketConn(session, keepAlive)
	}
	return handle
}
