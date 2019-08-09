package quicwrapper

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	quic "github.com/lucas-clemente/quic-go"
	"golang.org/x/crypto/salsa20"
)

const (
	maxRcvSize      = 1452       // what quic impl believes it could recieve
	maxPacketSize   = 1252       // max quic sends to achieve 1280 total (ipv6 min mtu)
	minInitialSize  = 1200       // spec minimum size for initial handshake packet
	fixedBitMask    = byte(0x40) // 2nd bit of packet
	minPaddedLen    = 128        // packets under this size are never padded
	aggressiveCount = 32         // this number of inital packets recieve aggressive padding
	salsaKeySize    = 32         // 32 bytes / 256 bits
)

var (
	packetBuffers sync.Pool
)

func init() {
	packetBuffers.New = func() interface{} {
		return make([]byte, 0, maxRcvSize)
	}
}

func getPacketBuffer() []byte {
	buf := packetBuffers.Get().([]byte)
	return buf[:maxRcvSize]
}

func releasePacketBuffer(buf []byte) {
	if cap(buf) != maxRcvSize {
		panic("releasePacketBuffer called with packet of wrong size!")
	}
	packetBuffers.Put(buf)
}

type OQuicConfig struct {
	Key       []byte   // Salsa 256 bit (32 byte) key 
	Padding   bool     // enable random padding 
	XSalsa20  bool     // enable XSalsa20 (use 24 byte nonce)
}

func (c *OQuicConfig) nonceSize() int {
	if c.XSalsa20 {
		return 24
	} else {
		return 8
	}
}

type Enveloper interface {
	net.PacketConn
	EnvelopeSize() uint64
}

// Creates a QuicDialFn dialer that obfuscates packets using the
// given 256 bit (32 byte) key.
// all outbound packets are obfuscated using the 256 bit (32 byte) key given,
// all inbound packets are expected to have been obfuscated using the same key.
func NewOQuicDialer(config *OQuicConfig) QuicDialFn {
	return NewOQuicDialerWithUDPDialer(DialUDPNetx, config)
}

// Creates a QuicDialFn dialer that obfuscates packets using the
// given 256 bit (32 byte) key.  The underlying net.PacketConn
// is obtained using the UDPDialFn given.
// all outbound packets are obfuscated using the 256 bit (32 byte) key given,
// all inbound packets are expected to have been obfuscated using the same key.
func NewOQuicDialerWithUDPDialer(dial UDPDialFn, config *OQuicConfig) QuicDialFn {
	dialSealed := func(addr string) (net.PacketConn, *net.UDPAddr, error) {
		pconn, udpAddr, err := dial(addr)
		if err != nil {
			return nil, nil, err
		}
		return NewSalsa20Enveloper(pconn, config), udpAddr, nil
	}
	return NewDialerWithUDPDialer(dialSealed)
}

// ListenAddrOQuic creates a QUIC server listening on a given address.
// all outbound packets are obfuscated using the 256 bit (32 byte) key given,
// all inbound packets are expected to have been obfuscated using the same key.
// The net.Conn instances returned by the net.Listener may be multiplexed connections.
func ListenAddrOQuic(addr string, tlsConf *tls.Config, config *quic.Config, oqConfig *OQuicConfig) (net.Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	pconn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}
	oconn := NewSalsa20Enveloper(pconn, oqConfig)
	return Listen(oconn, tlsConf, config)
}

type salsa20Enveloper struct {
	net.PacketConn
	key           [salsaKeySize]byte
	nonceSize     int 
	aggressive    uint64 // remaining packets with aggressive padding
	dataBytes     uint64
	overheadBytes uint64
	padding       bool   // apply random padding
}

// NewSalsa20Enveloper creates a new net.PacketConn that
// obfuscates an existing net.PacketConn according to the
// configuraton given.
func NewSalsa20Enveloper(conn net.PacketConn, config *OQuicConfig) *salsa20Enveloper {
	c := &salsa20Enveloper{
		PacketConn: conn,
		nonceSize: config.nonceSize(),
	}
	copy(c.key[:], config.Key)
	if config.Padding {
		c.padding = true
	}

	return c
}

// overrides net.PacketConn.ReadFrom
func (c *salsa20Enveloper) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := getPacketBuffer()
	defer releasePacketBuffer(buf)

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil || n == 0 {
			return 0, addr, err
		}
		if n > c.nonceSize {
			salsa20.XORKeyStream(p, buf[c.nonceSize:n], buf[:c.nonceSize], &c.key)
			if isDecoy(p) {
				atomic.AddUint64(&c.overheadBytes, uint64(n))
				continue
			}
			n -= c.nonceSize

			padBytes, err := readPaddingSize(p[:n])
			if err != nil {
				return 0, addr, err
			}
			n -= int(padBytes)
			atomic.AddUint64(&c.dataBytes, uint64(n))
			atomic.AddUint64(&c.overheadBytes, uint64(padBytes+c.nonceSize))
			return n, addr, err
		}
		log.Debugf("dropping short packet? (len=%d < %d)", n, c.nonceSize)
	}
}

// overrides net.PacketConn.WriteTo
func (c *salsa20Enveloper) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > (maxPacketSize - c.nonceSize) {
		return 0, fmt.Errorf("packet too long (%d)", len(p))
	}

	buf := getPacketBuffer()
	defer releasePacketBuffer(buf)

	nonce, err := salsaNonce(c.nonceSize)
	if err != nil {
		return 0, err
	}
	plen := 0

	copy(buf[:c.nonceSize], nonce[:c.nonceSize])
	plen += c.nonceSize

	copy(buf[plen:], p)
	plen += len(p)

	padding, err := c.addPadding(buf, plen)
	if err != nil {
		return 0, err
	}
	plen += padding

	ebuf := buf[c.nonceSize:plen]
	salsa20.XORKeyStream(ebuf, ebuf, nonce, &c.key)
	_, err = c.PacketConn.WriteTo(buf[:plen], addr)
	if err != nil {
		return 0, err
	}
	atomic.AddUint64(&c.dataBytes, uint64(len(p)))
	atomic.AddUint64(&c.overheadBytes, uint64(padding+c.nonceSize))
	return len(p), nil
}

// WriteDecoy writes an OQUIC 'decoy' packet to the 
// underlying PacketConn.
//
// A Decoy's bytes are included verbatim in the packet,
// but care must be taken to ensure that when decoded, the
// second bit of the result is a 0 (indicating that is not
// a valid quic packet).  This is tested before
// sending and an error is returned if it is not the case.
func (c *salsa20Enveloper) WriteDecoyTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > maxPacketSize {
		return 0, fmt.Errorf("decoy packet too long (%d)", len(p))
	}

	if !decodesAsDecoy(p, c.nonceSize, &c.key) {
		return 0, fmt.Errorf("invalid decoy: quic fixed bit is set after decoding.")
	}
	n, err := c.PacketConn.WriteTo(p, addr)
	atomic.AddUint64(&c.overheadBytes, uint64(n))
	return n, err
}

// overrides net.PacketConn.Close
func (c *salsa20Enveloper) Close() error {
	oh := atomic.LoadUint64(&c.overheadBytes)
	qb := atomic.LoadUint64(&c.dataBytes)
	log.Debugf("OQuic connection overhead %f%% (%d/%d)", 100*float64(oh)/float64(qb), oh, qb)
	return c.PacketConn.Close()
}

// EnvelopeSize indicates the minimum space that must be 
// reserved for use by the obfuscation layer.
func (c *salsa20Enveloper) EnvelopeSize() uint64 {
	return uint64(c.nonceSize + 1) // nonce + padding marker
}

func (c *salsa20Enveloper) addPadding(buf []byte, curLen int) (int, error) {
	var plen int
	maxPadding := maxPacketSize - curLen

	if (curLen - c.nonceSize) < minPaddedLen {
		plen = 0
	} else if c.padding == false {
		plen = 1
	} else if curLen >= minInitialSize {
		// always pad anything 1200+ up to the max
		// these include certain charateristic handshake packets
		// (eg 1200 + 25 padded handshake)
		// and many packets tranferred in an active stream
		// which are close to maximal within a few bytes.
		// quic-go often generates quirky off-by-one final
		// size of 1279 when aiming for the 1280 mtu mark.
		plen = maxPadding
	} else {
		var r [1]byte
		_, err := rand.Read(r[:])
		if err != nil {
			return 0, err
		}
		plen = int(r[0]) // up to 255 bytes

		if atomic.AddUint64(&c.aggressive, 1) > aggressiveCount {
			// after aggressiveCount packets, use a more modest
			// padding schedule.
			plen = plen >> 3 // up to 31 bytes
		}

		if plen == 0 {
			plen = 1
		}
	}

	if plen > maxPadding {
		plen = maxPadding
	}

	return applyPadding(buf[curLen:], plen)
}

func salsaNonce(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}

func decodesAsDecoy(p []byte, nonceSize int, key *[salsaKeySize]byte) bool {
	buf := getPacketBuffer()
	defer releasePacketBuffer(buf)

	salsa20.XORKeyStream(buf, p[nonceSize:], p[:nonceSize], key)
	return isDecoy(buf)
}

func isDecoy(p []byte) bool {
	// In the QUIC protocol, all packets have the second bit (0x40)
	// set to 1 (the 'fixed' bit) -- thus, any packet with the second bit
	// set to 0 is not a quic packet, and is considered
	// a decoy.
	return p[0]&fixedBitMask == byte(0)
}

func readPaddingSize(p []byte) (int, error) {
	// if the packet is smaller than minPaddedLen, there is no padding
	if len(p) < minPaddedLen {
		return 0, nil
	}
	// the final byte of the packet indicates the number of padding bytes
	// including the final byte (there is always at least one and at most
	// 255
	padding := int(p[len(p)-1])
	if padding >= len(p) || padding <= 0 {
		return 0, fmt.Errorf("invalid oquic padding marker: %d (len=%d)", padding, len(p))
	}
	return padding, nil
}

func applyPadding(buf []byte, paddingLen int) (int, error) {
	if paddingLen == 0 {
		return 0, nil
	}
	if paddingLen > 255 {
		return 0, fmt.Errorf("invalid oquic padding length: %d", paddingLen)
	}
	if paddingLen > len(buf) {
		return 0, fmt.Errorf("insufficient buffer for oquic padding: %d (len=%d)", paddingLen, len(buf))
	}
	marker := byte(paddingLen)
	for i := 0; i < paddingLen; i++ {
		buf[i] = marker
	}

	return paddingLen, nil
}

// MakeHighEntropyDecoy creates a decoy packet of the 
// indicated size.  The packet is run through
// the same obfuscation a normal packet and is thus
// 'high entropy' (appears encrypted or compressed)
func MakeHighEntropyDecoy(size int, config *OQuicConfig) []byte {
	var key [32]byte
	copy(key[:], config.Key)
	return makeHighEntropyDecoy(size, config.nonceSize(), &key)
}

func makeHighEntropyDecoy(size int, nonceSize int, key *[32]byte) []byte {
	p := make([]byte, size)
	rand.Read(p)
	p[nonceSize] &= ^fixedBitMask // mark as decoy
	salsa20.XORKeyStream(p[nonceSize:], p[nonceSize:], p[:nonceSize], key)
	return p
}
