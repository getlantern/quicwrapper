package quicwrapper

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/oxtoacart/bpool"
	"golang.org/x/crypto/salsa20"
)

const (
	CipherXSalsa20 = "XSALSA20"
	CipherSalsa20  = "SALSA20"

	maxRcvSize     = 1452       // what quic impl believes it could receive
	maxPacketSize  = 1252       // max quic sends to achieve 1280 total (ipv6 min mtu)
	minInitialSize = 1200       // spec minimum size for initial handshake packet
	fixedBitMask   = byte(0x40) // 2nd bit of packet
	salsaKeySize   = 32         // 32 bytes / 256 bits
	maxBuffers     = 64
)

var packetBuffers = bpool.NewBytePool(maxBuffers, maxRcvSize)

func DefaultOQuicConfig(key []byte) *OQuicConfig {
	return &OQuicConfig{
		Key:               key,
		AggressivePadding: 32,
		MaxPaddingHint:    32,
		MinPadded:         128,
		Cipher:            CipherSalsa20,
	}
}

type OQuicConfig struct {
	Key               []byte // Salsa 256 bit (32 byte) key
	AggressivePadding int64  // if non-zero, enable large padding for this number of initial packets
	MaxPaddingHint    uint8  // if non-zero, use padding, but limit to this maximum after agressive phase where appropriate
	MinPadded         int    // if non-zero, do not pad packets under this size
	Cipher            string // default: Salsa20
}

func (c *OQuicConfig) validate() error {
	if c.Cipher != "" && !strings.EqualFold(c.Cipher, CipherSalsa20) && !strings.EqualFold(c.Cipher, CipherXSalsa20) {
		return fmt.Errorf("Unsupported cipher: %s", c.Cipher)
	}
	if len(c.Key) != 32 {
		return fmt.Errorf("Incorrect key length: %d, expected 32", len(c.Key))
	}
	return nil
}

func (c *OQuicConfig) nonceSize() int {
	if c.Cipher == "" || strings.EqualFold(c.Cipher, CipherSalsa20) {
		return 8
	} else if strings.EqualFold(c.Cipher, CipherXSalsa20) {
		return 24
	} else {
		return 0
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
func NewOQuicDialer(config *OQuicConfig) (QuicDialFn, error) {
	return NewOQuicDialerWithUDPDialer(DialUDPNetx, config)
}

// Creates a QuicDialFn dialer that obfuscates packets using the
// given 256 bit (32 byte) key.  The underlying net.PacketConn
// is obtained using the UDPDialFn given.
// all outbound packets are obfuscated using the 256 bit (32 byte) key given,
// all inbound packets are expected to have been obfuscated using the same key.
func NewOQuicDialerWithUDPDialer(dial UDPDialFn, config *OQuicConfig) (QuicDialFn, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	dialSealed := func(addr string) (net.PacketConn, *net.UDPAddr, error) {
		pconn, udpAddr, err := dial(addr)
		if err != nil {
			return nil, nil, err
		}
		conn, err := NewSalsa20Enveloper(pconn, config)
		return conn, udpAddr, err
	}
	return newDialerWithUDPDialer(dialSealed), nil
}

type quicListenerCloser struct {
	net.Listener
	conn net.PacketConn
}

func (l *quicListenerCloser) Close() error {
	err := l.Listener.Close()
	err2 := l.conn.Close()
	if err == nil {
		err = err2
	}
	return err
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
	oconn, err := NewSalsa20Enveloper(pconn, oqConfig)
	if err != nil {
		return nil, err
	}
	l, err := Listen(oconn, tlsConf, config)
	if err != nil {
		return nil, err
	}
	return &quicListenerCloser{l, pconn}, nil
}

type salsa20Enveloper struct {
	net.PacketConn
	key           [salsaKeySize]byte
	nonceSize     int
	aggressive    int64 // remaining packets with aggressive padding
	minPadded     int
	maxPadding    uint64
	dataBytes     uint64
	overheadBytes uint64
}

// NewSalsa20Enveloper creates a new net.PacketConn that
// obfuscates an existing net.PacketConn according to the
// configuraton given.
func NewSalsa20Enveloper(conn net.PacketConn, config *OQuicConfig) (*salsa20Enveloper, error) {
	if err := config.validate(); err != nil {
		return nil, err
	}
	c := &salsa20Enveloper{
		PacketConn: conn,
		maxPadding: uint64(config.MaxPaddingHint),
		aggressive: config.AggressivePadding,
		minPadded:  config.MinPadded,
		nonceSize:  config.nonceSize(),
	}
	copy(c.key[:], config.Key)

	return c, nil
}

// overrides net.PacketConn.ReadFrom
func (c *salsa20Enveloper) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := packetBuffers.Get()
	defer packetBuffers.Put(buf)

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil || n == 0 {
			return 0, addr, err
		}
		if n <= c.nonceSize {
			return 0, addr, fmt.Errorf("short oquic packet (len=%d <= %d)", n, c.nonceSize)
		}

		salsa20.XORKeyStream(p, buf[c.nonceSize:n], buf[:c.nonceSize], &c.key)
		if isDecoy(p) {
			atomic.AddUint64(&c.overheadBytes, uint64(n))
			continue
		}
		n -= c.nonceSize

		padBytes := int(p[n-1])
		if padBytes >= n || padBytes <= 0 {
			return 0, addr, fmt.Errorf("invalid oquic padding marker: %d (len=%d)", padBytes, n)
		}
		n -= padBytes
		atomic.AddUint64(&c.dataBytes, uint64(n))
		atomic.AddUint64(&c.overheadBytes, uint64(padBytes+c.nonceSize))
		return n, addr, err
	}
}

// overrides net.PacketConn.WriteTo
func (c *salsa20Enveloper) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > (maxPacketSize - c.nonceSize) {
		return 0, fmt.Errorf("packet too long (%d)", len(p))
	}

	buf := packetBuffers.Get()
	defer packetBuffers.Put(buf)
	plen := 0

	_, err := rand.Read(buf[:c.nonceSize])
	if err != nil {
		return 0, err
	}
	plen += c.nonceSize

	copy(buf[plen:], p)
	plen += len(p)

	padding, err := c.addPadding(buf, plen)
	if err != nil {
		return 0, err
	}
	plen += padding

	ebuf := buf[c.nonceSize:plen]
	salsa20.XORKeyStream(ebuf, ebuf, buf[:c.nonceSize], &c.key)
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
	aggressive := (atomic.LoadInt64(&c.aggressive) > 0 && atomic.AddInt64(&c.aggressive, -1) > 0)

	if !aggressive && (curLen-c.nonceSize) < c.minPadded {
		plen = 1
	} else if curLen >= minInitialSize && (aggressive || c.maxPadding > 1) {
		// always pad anything 1200+ up to the max
		// these include certain charateristic handshake packets
		// (eg 1200 + 9 padded handshake)
		// and many packets tranferred in an active stream
		// which are close to maximal within a few bytes.
		// quic-go often generates quirky off-by-one final
		// size of 1279 when aiming for the 1280 mtu mark.
		// this can violate "max padding"
		plen = maxPadding
	} else {
		var r [1]byte
		_, err := rand.Read(r[:])
		if err != nil {
			return 0, err
		}
		plen = int(r[0]) // up to 255

		if !aggressive {
			// after aggressive count packets, use a more modest
			// padding schedule up to c.MaxPadding
			plen = int(c.maxPadding * uint64(plen) / 255.0)
		}
	}

	if plen == 0 {
		plen = 1
	}
	if plen > maxPadding {
		plen = maxPadding
	}

	// apply padding
	marker := byte(plen)
	for i := 0; i < plen; i++ {
		buf[curLen+i] = marker
	}

	return plen, nil
}

// DecodesAsDecoy tests whether a packet decodes as a decoy packet
// with the given configuration.
func DecodesAsDecoy(p []byte, config *OQuicConfig) bool {
	var key [32]byte
	copy(key[:], config.Key)
	return decodesAsDecoy(p, config.nonceSize(), &key)
}

func decodesAsDecoy(p []byte, nonceSize int, key *[salsaKeySize]byte) bool {
	buf := packetBuffers.Get()
	defer packetBuffers.Put(buf)

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

// MakeHighEntropyDecoy creates a decoy packet of the
// indicated size.  The packet is run through
// the same obfuscation as a normal packet and is thus
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
