package webt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/quicwrapper"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
)

const (
	testPath = "webtransport"
)

var tests [][]byte

func init() {
	rb := make([]byte, 4096)
	rand.Read(rb)
	tests = [][]byte{
		[]byte("x"),
		[]byte("hello world"),
		rb,
		[]byte("ahoy"),
	}
}

func dialAndEcho(t *testing.T, dialer *client, data []byte) {
	conn, err := dialer.Dial()
	if !assert.NoError(t, err) {
		return
	}
	defer func() {
		err = conn.Close()
		assert.NoError(t, err)
	}()

	n, err := conn.Write(data)
	if !assert.NoError(t, err) {
		return
	}
	if !assert.Equal(t, len(data), n) {
		return
	}

	buf := make([]byte, len(data))
	_, err = io.ReadFull(conn, buf)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, data, buf)
}

func TestWebtEchoSeq(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()

	options := &ClientOptions{
		Addr:      l.Addr().String(),
		Path:      testPath,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}
	dialer := NewClient(options)
	defer dialer.Close()

	for i := 0; i < 5250; i++ {
		for _, test := range tests {
			dialAndEcho(t, dialer, test)
		}
	}
}

func TestWebtEchoPar1(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()

	options := &ClientOptions{
		Addr:      l.Addr().String(),
		Path:      testPath,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}
	dialer := NewClient(options)
	defer dialer.Close()

	var wg sync.WaitGroup
	for i := 0; i < 525; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, test := range tests {
				dialAndEcho(t, dialer, test)
			}
		}()
	}
	wg.Wait()
}

func TestWebtEchoPar2(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()
	var wg sync.WaitGroup

	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			options := &ClientOptions{
				Addr:      l.Addr().String(),
				Path:      testPath,
				TLSConfig: &tls.Config{InsecureSkipVerify: true},
			}
			dialer := NewClient(options)
			defer dialer.Close()

			for j := 0; j < 25; j++ {
				for _, test := range tests {
					dialAndEcho(t, dialer, test)
				}
			}
		}()
	}
	wg.Wait()
}

func TestWebtEchoPar3(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()
	var wg sync.WaitGroup

	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			options := &ClientOptions{
				Addr:      l.Addr().String(),
				Path:      testPath,
				TLSConfig: &tls.Config{InsecureSkipVerify: true},
			}
			dialer := NewClient(options)
			defer dialer.Close()

			var wg2 sync.WaitGroup
			for j := 0; j < 25; j++ {
				wg2.Add(1)
				go func() {
					defer wg2.Done()
					for _, test := range tests {
						dialAndEcho(t, dialer, test)
					}
				}()
			}
			wg2.Wait()
		}()
	}
	wg.Wait()
}

func TestWebtPinnedCert(t *testing.T) {
	keyPair, err := generateKeyPair()
	if !assert.NoError(t, err) {
		return
	}

	goodCert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if !assert.NoError(t, err) {
		return
	}
	goodBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   goodCert.Raw,
	})

	badPair, err := generateKeyPair()
	if !assert.NoError(t, err) {
		return
	}
	badCert, err := x509.ParseCertificate(badPair.Certificate[0])
	if !assert.NoError(t, err) {
		return
	}
	badBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   badCert.Raw,
	})

	l, err := echoServer(nil, &tls.Config{Certificates: []tls.Certificate{keyPair}})
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	server := l.Addr().String()

	// no pinning -> validation failure
	noPinDialer := NewClient(&ClientOptions{
		Addr:      server,
		Path:      testPath,
		TLSConfig: &tls.Config{InsecureSkipVerify: false, ServerName: "localhost"},
	})
	_, err = noPinDialer.Dial()
	assert.True(t, strings.Contains(err.Error(), "invalid leaf certificate"))

	// wrong cert
	badDialer := NewClient(&ClientOptions{
		Addr:       server,
		Path:       testPath,
		TLSConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
		PinnedCert: badCert,
	})
	_, err = badDialer.Dial()
	assert.EqualError(t, err, fmt.Sprintf("connecting session: Server's certificate didn't match expected! Server had\n%v\nbut expected:\n%v", goodBytes, badBytes))

	// correct cert
	pinDialer := NewClient(&ClientOptions{
		Addr:       server,
		Path:       testPath,
		TLSConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
		PinnedCert: goodCert,
	})
	_, err = pinDialer.Dial()
	assert.NoError(t, err)

}

func TestWebtWrongPath(t *testing.T) {
	keyPair, err := generateKeyPair()
	if !assert.NoError(t, err) {
		return
	}

	goodCert, err := x509.ParseCertificate(keyPair.Certificate[0])
	if !assert.NoError(t, err) {
		return
	}
	l, err := echoServer(nil, &tls.Config{Certificates: []tls.Certificate{keyPair}})
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	server := l.Addr().String()

	pinDialer := NewClient(&ClientOptions{
		Addr:       server,
		Path:       testPath,
		TLSConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
		PinnedCert: goodCert,
	})
	_, err = pinDialer.Dial()
	assert.NoError(t, err)

	wrongPath := NewClient(&ClientOptions{
		Addr:       server,
		Path:       "wrongpath",
		TLSConfig:  &tls.Config{InsecureSkipVerify: true, ServerName: "localhost"},
		PinnedCert: goodCert,
	})
	_, err = wrongPath.Dial()
	assert.True(t, strings.Contains(err.Error(), "status 404"))
}

func TestWebtNetErrDeadline(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()

	dialer := NewClient(&ClientOptions{
		Addr:      l.Addr().String(),
		Path:      testPath,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	})
	defer dialer.Close()

	conn, err := dialer.Dial()
	if !assert.NoError(t, err) {
		return
	}
	defer func() {
		err = conn.Close()
		assert.NoError(t, err)
	}()

	expired := time.Now().Add(-100 * time.Millisecond)

	conn.SetReadDeadline(expired)
	bs := make([]byte, 256, 256)
	n, err := conn.Read(bs)
	assert.Equalf(t, 0, n, "read succeeded unexpectedly (%d)", n)
	netErr, ok := err.(net.Error)
	assert.Truef(t, ok, "expected timeout error: %v", err)
	if ok {
		assert.Truef(t, netErr.Timeout(), "expected timeout error: %v", err)
	}

	conn.SetWriteDeadline(expired)
	n, err = conn.Write(bs)
	assert.Equalf(t, 0, n, "write succeeded unexpectedly (%d)", n)
	netErr, ok = err.(net.Error)
	assert.Truef(t, ok, "expected timeout error: %v", err)
	if ok {
		assert.Truef(t, netErr.Timeout(), "expected timeout error: %v", err)
	}
	// clear deadlines
	conn.SetWriteDeadline(time.Time{})
	conn.SetReadDeadline(time.Time{})

}

func echoServer(config *quic.Config, tlsConf *tls.Config) (net.Listener, error) {
	if tlsConf == nil {
		tc, err := generateTLSConfig()
		if err != nil {
			return nil, err
		}
		tlsConf = tc
	}
	options := &ListenOptions{
		Addr:       "127.0.0.1:0",
		Path:       testPath,
		TLSConfig:  tlsConf,
		QuicConfig: config,
	}
	l, err := ListenAddr(options)
	if err != nil {
		return nil, err
	}
	go runEchoServer(l)
	return l, nil
}

func runEchoServer(l net.Listener) {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept()
		if err != nil {
			if err != quicwrapper.ErrListenerClosed {
				log.Errorf("accepting connection: %v", err)
			}
			return
		}
		wg.Add(1)
		go func() {
			io.Copy(conn, conn)
			conn.Close()
			wg.Done()
		}()
	}
}

func generateTLSConfig() (*tls.Config, error) {
	tlsCert, err := generateKeyPair()
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}, nil
}

func generateKeyPair() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	return tlsCert, err
}
