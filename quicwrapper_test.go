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
	"sync"
	"testing"
	"time"

	"github.com/getlantern/netx"
	"github.com/stretchr/testify/assert"
)

var tests [][]byte

func init() {
	rb := make([]byte, 1024)
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
	l, err := echoServer(nil)
	assert.NoError(t, err)
	defer l.Close()

	dialer := NewClient(l.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil, nil)
	defer dialer.Close()

	for i := 0; i < 525; i++ {
		for _, test := range tests {
			dialAndEcho(t, dialer, test)
		}
	}
}

func TestEchoPar1(t *testing.T) {
	l, err := echoServer(nil)
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
	l, err := echoServer(nil)
	assert.NoError(t, err)
	defer l.Close()
	var wg sync.WaitGroup

	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := NewClient(l.Addr().String(), &tls.Config{InsecureSkipVerify: true}, nil, nil)
			defer dialer.Close()

			for i := 0; i < 25; i++ {
				for _, test := range tests {
					dialAndEcho(t, dialer, test)
				}
			}
		}()
	}
	wg.Wait()
}

func TestEchoPar3(t *testing.T) {
	l, err := echoServer(nil)
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
	l, err := echoServer(nil)
	assert.NoError(t, err)
	defer l.Close()

	_, port, err := net.SplitHostPort(l.Addr().String())
	assert.NoError(t, err)

	fakehost := "kjhsdafhkjsa.getiantem.org"
	server := fmt.Sprintf("%s:%s", fakehost, port)

	normalDialer := NewClient(server, &tls.Config{InsecureSkipVerify: true}, nil, nil)
	defer normalDialer.Close()
	_, err = normalDialer.Dial()
	assert.EqualError(t, err, fmt.Sprintf("lookup %s: no such host", fakehost))
	normalDialer.Close()

	dialer := NewClient(server, &tls.Config{InsecureSkipVerify: true}, nil, DialWithNetx)
	defer dialer.Close()
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

	for i := 0; i < 525; i++ {
		for _, test := range tests {
			dialAndEcho(t, dialer, test)
		}
	}
}

func TestDialContextHandshakeStall(t *testing.T) {
	l, err := stallHandshakeServer()
	if !assert.NoError(t, err) {
		return
	}
	defer l.Close()

	addr := l.LocalAddr().String()
	dialer := NewClient(addr, &tls.Config{InsecureSkipVerify: true}, nil, nil)
	timeout := 100 * time.Millisecond
	errchan := make(chan error, 1)
	var conn *Conn

	go func() {
		ctx, _ := context.WithTimeout(context.Background(), timeout)
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
}

// starts a server that does not complete the quic handshake
func stallHandshakeServer() (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", addr)
}

func echoServer(config *Config) (net.Listener, error) {

	l, err := ListenAddr("127.0.0.1:0", generateTLSConfig(), config)
	if err != nil {
		return nil, err
	}

	go func() {
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
				defer wg.Done()
				_, err = io.Copy(conn, conn)
				if err != nil {
					log.Errorf("echoing data: %v", err)
				}
				conn.Close()
			}()
		}
	}()

	return l, nil
}

func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}}
}
