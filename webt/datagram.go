package webt

import (
	"encoding/binary"
	"io"
	"math/rand"
	"sync"
	"time"
)

// WebTransport datagram uses QUIC datagram frames, with the minimum MTU (max transmission unit) being 1200 bytes which includes
// QUIC header and WebTransport header. Let's just use a smaller safe size to avoid hitting maximum packet size.
const maxDatagramSize = 1024

// DatagramChunker handles chunking and reassemly of datagram payloads
type DatagramChunker struct {
	mutex   sync.Mutex
	buffers map[uint32]*messageBuffer // pending messages
	inbox   chan []byte               // queue for reassembled messages
}

// messageBuffer stores chunks of a message until it's fully received
type messageBuffer struct {
	chunks    [][]byte
	total     int
	received  int
	timestamp time.Time
}

// assembleChunks merges chunks
func assembleChunks(chunks [][]byte) []byte {
	var fullMessage []byte
	for _, chunk := range chunks {
		fullMessage = append(fullMessage, chunk...)
	}
	return fullMessage
}

// Receive processes a datagram chunk, assembles them, and queues complete messages that will be returned from Read()
func (dc *DatagramChunker) Receive(data []byte) {
	if len(data) < 12 {
		log.Debugf("invalid datagram (too small)")
		return
	}

	msgID := binary.BigEndian.Uint32(data[0:4])
	chunkIndex := binary.BigEndian.Uint32(data[4:8])
	totalChunks := binary.BigEndian.Uint32(data[8:12])
	payload := data[12:]

	dc.mutex.Lock()
	defer dc.mutex.Unlock()

	buf, exists := dc.buffers[msgID]
	if !exists {
		buf = &messageBuffer{
			chunks:    make([][]byte, totalChunks),
			total:     int(totalChunks),
			timestamp: time.Now(),
		}
		dc.buffers[msgID] = buf
	}
	if buf.chunks[chunkIndex] == nil {
		buf.chunks[chunkIndex] = payload
		buf.received++
	}

	if buf.received == buf.total {
		full := assembleChunks(buf.chunks)
		delete(dc.buffers, msgID)
		dc.inbox <- full
	}
}

// Read returns the complete/assembled message
func (dc *DatagramChunker) Read() ([]byte, error) {
	msg, ok := <-dc.inbox
	if !ok {
		return nil, io.EOF
	}
	return msg, nil
}

// Chunk splits a message into datagram chunks to be sent over the wire
func (dc *DatagramChunker) Chunk(p []byte) [][]byte {
	totalChunks := (len(p) + maxDatagramSize - 1) / maxDatagramSize
	msgID := uint32(rand.Int31())
	var chunks [][]byte

	for i := 0; i < totalChunks; i++ {
		start := i * maxDatagramSize
		end := min(start+maxDatagramSize, len(p))

		header := make([]byte, 12)
		binary.BigEndian.PutUint32(header[0:4], msgID)
		binary.BigEndian.PutUint32(header[4:8], uint32(i))
		binary.BigEndian.PutUint32(header[8:12], uint32(totalChunks))

		chunks = append(chunks, append(header, p[start:end]...))
	}
	return chunks
}

// Close disposes of the instance. After calling Close() the instance can not be used anymore
func (dc *DatagramChunker) Close() {
	close(dc.inbox)
}

// NewDatagramChunker creates a new ChunkedDatagramHandler that handles chunking and reassembly of datagram payloads
func NewDatagramChunker() *DatagramChunker {
	return &DatagramChunker{
		buffers: make(map[uint32]*messageBuffer),
		inbox:   make(chan []byte, 100),
	}
}
