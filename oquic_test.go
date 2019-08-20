package quicwrapper

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"math"
	mrand "math/rand"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func createOQuicKey() *[32]byte {
	var key [32]byte
	rand.Read(key[:])
	return &key
}

func TestEchoOQuic(t *testing.T) {
	config := DefaultOQuicConfig(createOQuicKey()[:])
	mcount := 512
	mean := 1024.0
	s := 384.0

	messages := make([][]byte, mcount)
	for i := 0; i < mcount; i++ {
		sz := mrand.NormFloat64()*s + mean
		if sz <= 0 {
			sz = 1
		} else if sz > 2048 {
			sz = 2048
		}
		messages[i] = make([]byte, uint64(sz))
		rand.Read(messages[i])
	}

	l, err := oquicEchoServer(nil, nil, config)
	assert.NoError(t, err)
	defer l.Close()

	odial, err := NewOQuicDialer(config)
	if !assert.NoError(t, err) {
		return
	}
	dialer := NewClient(l.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil, odial)
	defer dialer.Close()

	for i := 0; i < 100; i++ {
		for _, test := range messages {
			dialAndEcho(t, dialer, test)
		}
	}
}

func oquicEchoServer(config *Config, tlsConf *tls.Config, oqConfig *OQuicConfig) (net.Listener, error) {
	if tlsConf == nil {
		tc, err := generateTLSConfig()
		if err != nil {
			return nil, err
		}
		tlsConf = tc
	}
	l, err := ListenAddrOQuic("127.0.0.1:0", tlsConf, config, oqConfig)
	if err != nil {
		return nil, err
	}
	go runEchoServer(l)
	return l, nil
}

// shannon 'byte' entropy (max 8)
func sampleEntropy(buf []byte) float64 {
	counts := make(map[byte]int)
	for _, b := range buf {
		counts[b] += 1
	}

	var ent float64
	n := float64(len(buf))
	for _, c := range counts {
		freq := float64(c) / n
		ent += freq * math.Log2(freq)
	}
	return -ent
}

func TestHighEntropyDecoy(t *testing.T) {
	key := createOQuicKey()
	config := DefaultOQuicConfig(key[:])

	for i := 0; i < 250; i++ {
		m := MakeHighEntropyDecoy(1024, config)
		ent := sampleEntropy(m)
		assert.True(t, ent >= 7.5, "high entroy decoy had entropy %f < 7.5 (round %d)", ent, i)
		assert.True(t, DecodesAsDecoy(m, config), "MakeHighEntropyDecoy didn't decode as decoy...")
	}
}

func TestLowEntropyDecoy(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString("RSmN4eFvcYhys9JiTTtcj6Y9FzT3b/F48ecwmYe4Cp8=")
	config := DefaultOQuicConfig(key[:])

	assert.True(t, DecodesAsDecoy([]byte("I like cheese"), config))
}
