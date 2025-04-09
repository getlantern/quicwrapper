package webt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/quicwrapper"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testPath      = "webtransport"
	maxByteLength = 4096
)

var (
	tests    [][]byte
	certPool *x509.CertPool
)

func init() {
	rb := make([]byte, maxByteLength)
	rand.Read(rb)
	tests = [][]byte{
		[]byte("x"),
		[]byte("hello world"),
		rb,
		[]byte("ahoy"),
	}
	certPool = x509.NewCertPool()
}

func newClientOptions(l net.Listener) *ClientOptions {
	return &ClientOptions{
		Addr:      l.Addr().String(),
		Path:      testPath,
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig: &quicwrapper.Config{
			EnableDatagrams: true,
		},
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

// echo server's datagram handler
func echoServerDatagramHandler(pconn net.PacketConn, remoteAddr net.Addr) {
	data := make([]byte, maxByteLength)
	for {
		rn, addr, err := pconn.ReadFrom(data)
		if err != nil {
			log.Debugf("Unable to read datagram: %v, remote address:%v", err, remoteAddr)
			return
		}
		_, err = pconn.WriteTo(data[:rn], addr)
		if err != nil {
			log.Debugf("Unable to write datagram: %v, remote address:%v", err, remoteAddr)
			return
		}
	}
}

func datagramEcho(t *testing.T, dialer *client, data []byte, addr net.Addr) {
	pconn, err := dialer.PacketConn(context.Background())
	require.NoError(t, err)
	defer pconn.Close()

	n, err := pconn.WriteTo(data, addr)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)

	buf := make([]byte, len(data))
	n, _, err = pconn.ReadFrom(buf)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, data, buf)
}

func TestWebtEchoSeq(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()

	dialer := NewClient(newClientOptions(l))
	defer dialer.Close()

	for range 5250 {
		for _, test := range tests {
			dialAndEcho(t, dialer, test)
			datagramEcho(t, dialer, test, l.Addr())
		}
	}
}

func TestWebtEchoPar1(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()

	dialer := NewClient(newClientOptions(l))
	defer dialer.Close()

	var wg sync.WaitGroup
	for range 525 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, test := range tests {
				dialAndEcho(t, dialer, test)
				// we don't test datagram echo (datagramEcho) in parallel here because it only makes sense
				// to have one receiver (the wrapped net.PacketConn.ReadFrom, or webtransport.Session.ReceiveDatagram)
				// per webtransport.Session
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
			dialer := NewClient(newClientOptions(l))
			defer dialer.Close()

			for j := 0; j < 25; j++ {
				for _, test := range tests {
					dialAndEcho(t, dialer, test)
					// since we will have different webtransport.Session per client in each goroutine here,
					// the datagram test should work in this case
					datagramEcho(t, dialer, test, l.Addr())
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
			dialer := NewClient(newClientOptions(l))
			defer dialer.Close()

			var wg2 sync.WaitGroup
			for j := 0; j < 25; j++ {
				wg2.Add(1)
				go func() {
					defer wg2.Done()
					for _, test := range tests {
						dialAndEcho(t, dialer, test)
						// same as TestWebtEchoPar1 we use concurrent goroutines here but the underlying
						// webtransport.Session is the same, so the datagram echo test will not work
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
	certPool.AddCert(goodCert)

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

	l, err := echoServer(nil, &tls.Config{Certificates: []tls.Certificate{keyPair}, RootCAs: certPool})
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
	if runtime.GOOS == "darwin" {
		assert.ErrorContains(t, err, "using a broken key size")
	} else {
		assert.ErrorContains(t, err, "x509: certificate signed by unknown authority")
	}

	// wrong cert
	badDialer := NewClient(&ClientOptions{
		Addr:       server,
		Path:       testPath,
		TLSConfig:  &tls.Config{InsecureSkipVerify: false, ServerName: "localhost", RootCAs: certPool},
		PinnedCert: badCert,
	})
	_, err = badDialer.Dial()
	assert.EqualError(t, err, fmt.Sprintf("connecting session: server's certificate didn't match expected! Server had\n%v\nbut expected:\n%v", goodBytes, badBytes))

	// correct cert
	pinDialer := NewClient(&ClientOptions{
		Addr:       server,
		Path:       testPath,
		TLSConfig:  &tls.Config{InsecureSkipVerify: false, ServerName: "localhost", RootCAs: certPool},
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
		Addr:            "127.0.0.1:0",
		Path:            testPath,
		TLSConfig:       tlsConf,
		QUICConfig:      config,
		DatagramHandler: echoServerDatagramHandler,
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
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}, RootCAs: certPool}, nil
}

func generateKeyPair() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	template.NotBefore = time.Now().Add(-1 * time.Hour)
	template.NotAfter = time.Now().Add(1 * time.Hour)
	template.PermittedDNSDomains = []string{"localhost"}
	template.DNSNames = []string{"localhost"}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}
