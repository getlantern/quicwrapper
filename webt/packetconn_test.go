package webt

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/webtransport-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dummyPacketConn struct {
	closed bool
	mutex  sync.Mutex
}

func (d *dummyPacketConn) ReadFrom(p []byte) (int, net.Addr, error)     { return 0, nil, nil }
func (d *dummyPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) { return len(p), nil }
func (d *dummyPacketConn) Close() error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.closed = true
	return nil
}
func (d *dummyPacketConn) LocalAddr() net.Addr                { return nil }
func (d *dummyPacketConn) SetDeadline(t time.Time) error      { return nil }
func (d *dummyPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (d *dummyPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestRefCountedConn(t *testing.T) {
	session := new(webtransport.Session)
	dummy := &dummyPacketConn{}
	rcc := &refCountedConn{conn: dummy, onCleanup: func() {
		connMap.Delete(session)
	}}
	connMap.Store(session, rcc)

	h1 := rcc.Acquire()
	h2 := rcc.Acquire()

	h1.Close()
	assert.False(t, dummy.closed, "closed too early")

	h2.Close()
	assert.True(t, dummy.closed, "not closed after final Close")

	_, exists := connMap.Load(session)
	assert.False(t, exists, "session should have been deleted from map")
}

func TestGetPacketConn(t *testing.T) {
	l, err := echoServer(nil, nil)
	require.NoError(t, err)
	defer l.Close()
	client := NewClient(newClientOptions(l))
	defer client.Close()

	pcon1, err := client.PacketConn(context.Background())
	require.NoError(t, err)
	pcon2, err := client.PacketConn(context.Background())
	require.NoError(t, err)
	defer pcon1.Close()
	defer pcon2.Close()

	p1 := pcon1.(*refCountedConnHandle).parent
	p2 := pcon2.(*refCountedConnHandle).parent
	assert.Equal(t, p1, p2, "expected same net.PacketConn")

	session2 := new(webtransport.Session)
	pcon3 := getPacketConn(session2, 0)
	defer pcon3.Close()
	p3 := pcon3.(*refCountedConnHandle).parent
	assert.NotEqual(t, p1, p3, "expected different net.PacketConn")
}
