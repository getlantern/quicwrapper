package quicwrapper

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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getlantern/fdcount"
	"github.com/getlantern/netx"
	"github.com/stretchr/testify/assert"
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

func dialAndEcho(t *testing.T, dialer *Client, data []byte) {
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

func TestEchoSeq(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()

	dialer := NewClient(l.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil, nil)
	defer dialer.Close()

	for i := 0; i < 5250; i++ {
		for _, test := range tests {
			dialAndEcho(t, dialer, test)
		}
	}
}

func TestEchoPar1(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()

	dialer := NewClient(l.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil, nil)
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

func TestEchoPar2(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()
	var wg sync.WaitGroup

	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := NewClient(l.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil, nil)
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

func TestEchoPar3(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()
	var wg sync.WaitGroup

	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := NewClient(l.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil, nil)
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

func TestNetx(t *testing.T) {
	defer netx.Reset()
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()

	_, port, err := net.SplitHostPort(l.Addr().String())
	assert.NoError(t, err)

	fakehost := "kjhsdafhkjsa.getiantem.org"
	server := fmt.Sprintf("%s:%s", fakehost, port)

	_, fdc, _ := fdcount.Matching("UDP")
	defer func() {
		err = fdc.AssertDelta(0)
		if err != nil {
			t.Fatal(err)
		}
	}()

	normalDialer := NewClient(server, &tls.Config{InsecureSkipVerify: true}, nil, DialWithoutNetx)
	_, err = normalDialer.Dial()
	assert.EqualError(t, err, fmt.Sprintf("connecting session: lookup %s: no such host", fakehost))
	normalDialer.Close()

	dialer := NewClient(server, &tls.Config{InsecureSkipVerify: true}, nil, DialWithNetx)
	defer dialer.Close()
	/*
		netx.OverrideResolveUDP(func(network string, addr string) (*net.UDPAddr, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if host == fakehost {
				return net.ResolveUDPAddr(network, l.Addr().String())
			} else {
				return nil, fmt.Errorf("unexpected address %s", addr)
			}
		})
	*/

	calledListenOverride := false
	netx.OverrideListenUDP(func(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
		calledListenOverride = true
		return net.ListenUDP(network, laddr)
	})

	for i := 0; i < 525; i++ {
		for _, test := range tests {
			dialAndEcho(t, dialer, test)
		}
	}

	assert.True(t, calledListenOverride)
}

func TestPinnedCert(t *testing.T) {
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
	noPinDialer := NewClient(server, &tls.Config{InsecureSkipVerify: false, ServerName: "localhost"}, nil, nil)
	_, err = noPinDialer.Dial()
	assert.True(t, strings.Contains(err.Error(), "invalid leaf certificate"))
	// wrong cert
	badDialer := NewClientWithPinnedCert(server, &tls.Config{InsecureSkipVerify: true}, nil, nil, badCert)
	_, err = badDialer.Dial()
	assert.EqualError(t, err, fmt.Sprintf("connecting session: Server's certificate didn't match expected! Server had\n%v\nbut expected:\n%v", goodBytes, badBytes))

	// correct cert
	pinDialer := NewClientWithPinnedCert(server, &tls.Config{InsecureSkipVerify: true}, nil, nil, goodCert)
	_, err = pinDialer.Dial()
	assert.NoError(t, err)

}

func TestDialContextHandshakeStall(t *testing.T) {
	l, err := stallHandshakeServer(500 * time.Millisecond)
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	addr := l.LocalAddr().String()
	dialer := NewClient(addr, &tls.Config{InsecureSkipVerify: true}, nil, nil)
	timeout := 100 * time.Millisecond
	errchan := make(chan error, 1)
	var conn net.Conn

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c, err := dialer.DialContext(ctx)
		conn = c
		errchan <- err
	}()

	select {
	case err := <-errchan:
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "deadline exceeded")
	case <-time.After(2 * timeout):
		t.Errorf("Dial did not fail within twice timeout.")
	}

	time.Sleep(500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err = dialer.DialContext(ctx)
	assert.NotNil(t, conn, "should be able to dial again once network recovers")
	assert.NoError(t, err)
}

func TestNetErrDeadline(t *testing.T) {
	l, err := echoServer(nil, nil)
	assert.NoError(t, err)
	defer l.Close()

	dialer := NewClient(l.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil, nil)
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

}

type RandBW struct {
	min, max int64
	samples  int64
}

// starts a server that does not complete the quic handshake until after the
// given duration.
func stallHandshakeServer(d time.Duration) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	l, err := net.ListenUDP("udp", addr)
	if d > 0 {
		time.AfterFunc(d, func() {
			tlsConf, err := generateTLSConfig()
			if err != nil {
				return
			}
			_, _ = Listen(l, tlsConf, nil)
		})
	}
	return l, err
}

func echoServer(config *Config, tlsConf *tls.Config) (net.Listener, error) {
	if tlsConf == nil {
		tc, err := generateTLSConfig()
		if err != nil {
			return nil, err
		}
		tlsConf = tc
	}
	l, err := ListenAddr("127.0.0.1:0", tlsConf, config)
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
			if err != ErrListenerClosed {
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
