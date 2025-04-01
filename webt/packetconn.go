package webt

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/quic-go/webtransport-go"
)

// WebTransport datagram uses QUIC datagram frames, with the minimum MTU (max transmission unit) being 1200 bytes which includes
// QUIC header and WebTransport header. Let's just use a smaller safe size to avoid hitting maximum packet size.
const maxDatagramSize = 1024

// packetConn wraps a WebTransport session to implement net.PacketConn with defined max datagram size
type packetConn struct {
	session *webtransport.Session

	mutex   sync.Mutex
	inbox   chan []byte               // the queue for reassembled messages
	buffers map[uint32]*messageBuffer // pending messages

	// keep-alive interval that periodically sends "ping" messages to avoid QUIC idle timeout error
	keepAliveInterval time.Duration
	keepAliveStop     chan struct{}
}

// messageBuffer stores chunks of a message until it's fully received
type messageBuffer struct {
	chunks    [][]byte
	total     int
	received  int
	timestamp time.Time
}

// receiveDatagrams listens for incoming chunks, reassembles them, and queues complete messages
func (c *packetConn) receiveDatagrams() {
	for {
		data, err := c.session.ReceiveDatagram(context.Background())
		if err != nil {
			log.Debugf("receiveDatagrams error:", err)
			close(c.inbox)
			return
		}

		// ignore keep-alive "ping" messages
		if len(data) == 4 && string(data) == "ping" {
			continue
		}

		if len(data) < 12 {
			log.Debugf("receiveDatagrams invalid datagram (too small)")
			continue
		}

		// header: msgID, chunkIndex, totalChunks
		msgID := binary.BigEndian.Uint32(data[0:4])
		chunkIndex := binary.BigEndian.Uint32(data[4:8])
		totalChunks := binary.BigEndian.Uint32(data[8:12])
		payload := data[12:]

		c.mutex.Lock()

		// initialize buffer (new message)
		if _, exists := c.buffers[msgID]; !exists {
			c.buffers[msgID] = &messageBuffer{
				chunks:    make([][]byte, totalChunks),
				total:     int(totalChunks),
				received:  0,
				timestamp: time.Now(),
			}
		}

		buffer := c.buffers[msgID]
		if buffer.chunks[chunkIndex] == nil {
			buffer.chunks[chunkIndex] = payload
			buffer.received++
		}

		// if all chunks have arrived, reassemble and queue the message
		if buffer.received == buffer.total {
			fullMessage := assembleMessage(buffer.chunks)
			delete(c.buffers, msgID)
			c.inbox <- fullMessage
		}

		c.mutex.Unlock()
	}
}

// assembleMessage merges chunks
func assembleMessage(chunks [][]byte) []byte {
	var fullMessage []byte
	for _, chunk := range chunks {
		fullMessage = append(fullMessage, chunk...)
	}
	return fullMessage
}

// ReadFrom waits for a complete message and returns it
func (c *packetConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	msg, ok := <-c.inbox
	if !ok {
		return 0, nil, errors.New("connection closed")
	}

	copy(p, msg)
	log.Tracef("packetConn.ReadFrom: Received %v bytes from %v", len(msg), c.session.RemoteAddr())
	return len(msg), c.session.RemoteAddr(), nil
}

// WriteTo splits large messages and sends them as datagram chunks
func (w *packetConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	totalChunks := (len(p) + maxDatagramSize - 1) / maxDatagramSize
	msgID := uint32(rand.Int31()) // unique message ID

	for i := 0; i < totalChunks; i++ {
		start := i * maxDatagramSize
		end := start + maxDatagramSize
		if end > len(p) {
			end = len(p)
		}

		// header: 4-byte msgID, 4-byte chunkIndex, 4-byte totalChunks
		header := make([]byte, 12)
		binary.BigEndian.PutUint32(header[0:4], msgID)
		binary.BigEndian.PutUint32(header[4:8], uint32(i))
		binary.BigEndian.PutUint32(header[8:12], uint32(totalChunks))

		packet := append(header, p[start:end]...)
		if err := w.session.SendDatagram(packet); err != nil {
			return 0, err
		}
	}
	log.Tracef("packetConn.WriteTo: Sent %v bytes of %v chunks", len(p), totalChunks)
	return len(p), nil
}

// keepAlive periodically sends a "ping" datagram
func (w *packetConn) keepAlive() {
	ticker := time.NewTicker(w.keepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := w.session.SendDatagram([]byte("ping"))
			if err != nil {
				log.Debugf("keepAlive error: %v", err)
				return
			}
		case <-w.keepAliveStop:
			return
		}
	}
}

// Close closes the WebTransport session
func (w *packetConn) Close() error {
	close(w.keepAliveStop)
	return w.session.CloseWithError(webtransport.SessionErrorCode(0), "session closed")
}

// LocalAddr returns the local address
func (w *packetConn) LocalAddr() net.Addr {
	return w.session.LocalAddr()
}

func (w *packetConn) SetDeadline(t time.Time) error {
	return nil
}

func (w *packetConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (w *packetConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// NewpacketConn creates a new packetConn by wrapping a WebTransport session.
// The keepAlive parameter, when > 0, is the duration between sending session keep-alive ping datagrams.
func NewPacketConn(session *webtransport.Session, keepAlive time.Duration) net.PacketConn {
	conn := &packetConn{
		session:           session,
		inbox:             make(chan []byte, 100),
		buffers:           make(map[uint32]*messageBuffer),
		keepAliveInterval: keepAlive,
		keepAliveStop:     make(chan struct{}),
	}
	//listening for incoming datagrams
	go conn.receiveDatagrams()
	// keep-alive packets
	if keepAlive > 0 {
		go conn.keepAlive()
	}
	return conn
}
