package derpnet

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testKey = Key{
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
	24, 25, 26, 27, 28, 29, 30, 31,
}

func TestMultiPacketConnWriteToUsesFirstAvailableDERP(t *testing.T) {
	first := newFakePacketConn()
	second := newFakePacketConn()
	c := testMultiPacketConn(first, second)
	defer c.Close()

	n, err := c.WriteTo([]byte("hello"), Addr("peer"))
	if err != nil {
		t.Fatal(err)
	}
	if n != len("hello") {
		t.Fatalf("WriteTo wrote %d bytes, want %d", n, len("hello"))
	}
	if got := first.writeCount(); got != 1 {
		t.Fatalf("first DERP write count = %d, want 1", got)
	}
	if got := second.writeCount(); got != 0 {
		t.Fatalf("second DERP write count = %d, want 0", got)
	}
}

func TestMultiPacketConnWriteToUsesLastIngressDERP(t *testing.T) {
	first := newFakePacketConn()
	second := newFakePacketConn()
	c := testMultiPacketConn(first, second)
	defer c.Close()
	c.rememberIngressSlot(1, Addr("peer"))

	n, err := c.WriteTo([]byte("hello"), Addr("peer"))
	if err != nil {
		t.Fatal(err)
	}
	if n != len("hello") {
		t.Fatalf("WriteTo wrote %d bytes, want %d", n, len("hello"))
	}
	if got := first.writeCount(); got != 0 {
		t.Fatalf("first DERP write count = %d, want 0", got)
	}
	if got := second.writeCount(); got != 1 {
		t.Fatalf("second DERP write count = %d, want 1", got)
	}
}

func TestMultiPacketConnWriteToUpdatesLastIngressDERP(t *testing.T) {
	first := newFakePacketConn()
	second := newFakePacketConn()
	c := testMultiPacketConn(first, second)
	defer c.Close()
	c.rememberIngressSlot(1, Addr("peer"))
	c.rememberIngressSlot(0, Addr("peer"))

	n, err := c.WriteTo([]byte("hello"), Addr("peer"))
	if err != nil {
		t.Fatal(err)
	}
	if n != len("hello") {
		t.Fatalf("WriteTo wrote %d bytes, want %d", n, len("hello"))
	}
	if got := first.writeCount(); got != 1 {
		t.Fatalf("first DERP write count = %d, want 1", got)
	}
	if got := second.writeCount(); got != 0 {
		t.Fatalf("second DERP write count = %d, want 0", got)
	}
}

func TestMultiPacketConnWriteToFallsBackAfterLastIngressDERPFails(t *testing.T) {
	first := newFakePacketConn()
	second := newFakePacketConn()
	second.writeErr = errors.New("write failed")
	c := testMultiPacketConn(first, second)
	defer c.Close()
	c.rememberIngressSlot(1, Addr("peer"))

	n, err := c.WriteTo([]byte("hello"), Addr("peer"))
	if err != nil {
		t.Fatal(err)
	}
	if n != len("hello") {
		t.Fatalf("WriteTo wrote %d bytes, want %d", n, len("hello"))
	}
	if got := first.writeCount(); got != 1 {
		t.Fatalf("first DERP write count = %d, want 1", got)
	}
	if got := second.writeCount(); got != 1 {
		t.Fatalf("second DERP write count = %d, want 1", got)
	}
	if !second.isClosed() {
		t.Fatal("failed last-ingress DERP connection was not closed")
	}
	if conn := c.conn(1); conn != nil {
		t.Fatal("failed last-ingress DERP connection was not removed from availability")
	}
}

func TestMultiPacketConnWriteToFallsBackToNextAvailableDERP(t *testing.T) {
	writeErr := errors.New("write failed")
	first := newFakePacketConn()
	first.writeErr = writeErr
	second := newFakePacketConn()
	c := testMultiPacketConn(first, second)
	defer c.Close()

	n, err := c.WriteTo([]byte("hello"), Addr("peer"))
	if err != nil {
		t.Fatal(err)
	}
	if n != len("hello") {
		t.Fatalf("WriteTo wrote %d bytes, want %d", n, len("hello"))
	}
	if got := first.writeCount(); got != 1 {
		t.Fatalf("first DERP write count = %d, want 1", got)
	}
	if !first.isClosed() {
		t.Fatal("failed DERP connection was not closed")
	}
	if got := second.writeCount(); got != 1 {
		t.Fatalf("second DERP write count = %d, want 1", got)
	}
	if conn := c.conn(0); conn != nil {
		t.Fatal("failed DERP connection was not removed from availability")
	}
}

func TestMultiPacketConnWriteToFallsBackAfterDetectedClose(t *testing.T) {
	first := newFakePacketConn()
	second := newFakePacketConn()
	c := testMultiPacketConn(first, second)
	defer c.Close()

	first.Close()

	n, err := c.WriteTo([]byte("hello"), Addr("peer"))
	if err != nil {
		t.Fatal(err)
	}
	if n != len("hello") {
		t.Fatalf("WriteTo wrote %d bytes, want %d", n, len("hello"))
	}
	if got := first.writeCount(); got != 0 {
		t.Fatalf("first DERP write count = %d, want 0", got)
	}
	if got := second.writeCount(); got != 1 {
		t.Fatalf("second DERP write count = %d, want 1", got)
	}
	if conn := c.conn(0); conn != nil {
		t.Fatal("closed DERP connection was not removed from availability")
	}
}

func TestIsNoAvailableDERP(t *testing.T) {
	c := testMultiPacketConn()
	defer c.Close()

	_, err := c.WriteTo([]byte("hello"), Addr("peer"))
	if err == nil {
		t.Fatal("expected no available DERP error")
	}
	if !IsNoAvailableDERP(err) {
		t.Fatalf("IsNoAvailableDERP(%v) = false, want true", err)
	}
	if IsNoAvailableDERP(errors.New("other error")) {
		t.Fatal("IsNoAvailableDERP returned true for unrelated error")
	}
}

func TestMultiPacketConnReadFromAcceptsPacketsFromAnyDERP(t *testing.T) {
	c := testMultiPacketConn()
	defer c.Close()
	c.recvCh <- packetRead{b: []byte("from-any-derp"), addr: Addr("peer")}

	buf := make([]byte, 64)
	n, addr, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "from-any-derp" {
		t.Fatalf("ReadFrom payload = %q, want %q", got, "from-any-derp")
	}
	if addr.String() != "peer" {
		t.Fatalf("ReadFrom addr = %q, want %q", addr.String(), "peer")
	}
}

func TestListenPacketAllReturnsWhenAllDERPServersFailInitially(t *testing.T) {
	restoreReconnectInterval := setTestReconnectInterval(t)
	defer restoreReconnectInterval()

	var attempts atomic.Int32
	c, err := newMultiPacketConn(context.Background(), []string{"derp-a", "derp-b"}, testKey, func(context.Context, string, Key) (net.PacketConn, error) {
		attempts.Add(1)
		return nil, errors.New("unavailable")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	waitUntil(t, func() bool {
		return attempts.Load() >= 2
	})
}

func TestMultiPacketConnReconnectsAfterInitialFailure(t *testing.T) {
	restoreReconnectInterval := setTestReconnectInterval(t)
	defer restoreReconnectInterval()

	var attempts atomic.Int32
	recovered := newFakePacketConn()
	c, err := newMultiPacketConn(context.Background(), []string{"derp-a"}, testKey, func(context.Context, string, Key) (net.PacketConn, error) {
		if attempts.Add(1) == 1 {
			return nil, errors.New("unavailable")
		}
		return recovered, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	waitUntil(t, func() bool {
		return c.conn(0) == recovered
	})
}

func TestMultiPacketConnReconnectsAfterWriteFailure(t *testing.T) {
	restoreReconnectInterval := setTestReconnectInterval(t)
	defer restoreReconnectInterval()

	failed := newFakePacketConn()
	failed.writeErr = errors.New("write failed")
	recovered := newFakePacketConn()
	var attempts atomic.Int32
	c, err := newMultiPacketConn(context.Background(), []string{"derp-a"}, testKey, func(context.Context, string, Key) (net.PacketConn, error) {
		if attempts.Add(1) == 1 {
			return failed, nil
		}
		return recovered, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	waitUntil(t, func() bool {
		return c.conn(0) == failed
	})
	if _, err := c.WriteTo([]byte("hello"), Addr("peer")); err == nil {
		t.Fatal("expected write failure")
	}
	waitUntil(t, func() bool {
		return c.conn(0) == recovered
	})
}

func testMultiPacketConn(conns ...net.PacketConn) *multiPacketConn {
	slots := make([]derpSlot, len(conns))
	for i, conn := range conns {
		slots[i] = derpSlot{server: string(rune('a' + i)), conn: conn}
	}
	return &multiPacketConn{
		slots:   slots,
		peers:   make(map[string]int),
		recvCh:  make(chan packetRead, 10),
		recvT:   time.NewTimer(time.Hour),
		closeCh: make(chan struct{}),
		cancel:  func() {},
	}
}

type fakePacketConn struct {
	writeErr error

	mu        sync.Mutex
	closeOnce sync.Once
	closeCh   chan struct{}
	writes    [][]byte
	closed    bool
}

func newFakePacketConn() *fakePacketConn {
	return &fakePacketConn{closeCh: make(chan struct{})}
}

func (c *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	<-c.closeCh
	return 0, nil, net.ErrClosed
}

func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *fakePacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.closeCh)
	})
	return nil
}

func (*fakePacketConn) LocalAddr() net.Addr {
	return Addr("local")
}

func (*fakePacketConn) SetDeadline(time.Time) error {
	return nil
}

func (*fakePacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (*fakePacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

func (c *fakePacketConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.writes)
}

func (c *fakePacketConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func setTestReconnectInterval(t *testing.T) func() {
	t.Helper()
	old := derpReconnectInterval
	derpReconnectInterval = time.Millisecond
	return func() {
		derpReconnectInterval = old
	}
}

func waitUntil(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met before deadline")
}
