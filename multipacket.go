package derpnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
)

var derpReconnectInterval = 5 * time.Second

// ErrNoAvailableDERP means no monitored DERP server is currently connected.
// ListenPacketAll keeps reconnecting in the background after this error.
var ErrNoAvailableDERP = errors.New("no available DERP servers")

// IsNoAvailableDERP reports whether err means no monitored DERP server is
// currently connected. ListenPacketAll keeps reconnecting in the background.
func IsNoAvailableDERP(err error) bool {
	return errors.Is(err, ErrNoAvailableDERP)
}

type listenPacketFunc func(context.Context, string, Key) (net.PacketConn, error)

// ListenPacketAll connects to multiple DERP servers with the provided private key.
// Incoming packets are accepted from all available DERP servers, while outgoing
// packets are sent through the first available server in derpURLs order.
func (lc *ListenConfig) ListenPacketAll(ctx context.Context, derpURLs []string, key Key) (net.PacketConn, error) {
	cfg := ListenConfig{}
	if lc != nil {
		cfg = *lc
	}
	return newMultiPacketConn(ctx, derpURLs, key, cfg.ListenPacket)
}

type multiPacketConn struct {
	key    Key
	pub    [32]byte
	dial   listenPacketFunc
	slots  []derpSlot
	recvCh chan packetRead
	recvT  *time.Timer

	ctx    context.Context
	cancel context.CancelFunc

	closeCh   chan struct{}
	closeOnce sync.Once

	mu sync.RWMutex
}

type derpSlot struct {
	server string
	conn   net.PacketConn
}

type packetRead struct {
	b    []byte
	addr net.Addr
}

func newMultiPacketConn(ctx context.Context, derpURLs []string, key Key, dial listenPacketFunc) (*multiPacketConn, error) {
	if len(derpURLs) == 0 {
		return nil, errors.New("provide at least one DERP server")
	}
	pub, err := curve25519.X25519(key, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithCancel(ctx)
	c := &multiPacketConn{
		key:     Key(append([]byte(nil), key...)),
		pub:     [32]byte(pub),
		dial:    dial,
		slots:   make([]derpSlot, len(derpURLs)),
		recvCh:  make(chan packetRead, 10),
		recvT:   time.NewTimer(time.Duration(math.MaxInt64)),
		ctx:     ctx,
		cancel:  cancel,
		closeCh: make(chan struct{}),
	}
	for i, derpURL := range derpURLs {
		c.slots[i].server = derpURL
		go c.monitor(i)
	}
	return c, nil
}

func (c *multiPacketConn) monitor(i int) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.closeCh:
			return
		default:
		}

		server := c.slots[i].server
		conn, err := c.dial(c.ctx, server, c.key)
		if err != nil {
			if Debug {
				log.Printf("derpnet: DERP %s unavailable: %v", server, err)
			}
			if !c.waitBeforeReconnect() {
				return
			}
			continue
		}

		c.setConn(i, conn)
		if Debug {
			log.Printf("derpnet: DERP %s available", server)
		}

		if err := c.readLoop(conn); err != nil && !errors.Is(err, net.ErrClosed) && Debug {
			log.Printf("derpnet: DERP %s disconnected: %v", server, err)
		}
		c.clearConn(i, conn)
		conn.Close()
		if !c.waitBeforeReconnect() {
			return
		}
	}
}

func (c *multiPacketConn) waitBeforeReconnect() bool {
	timer := time.NewTimer(derpReconnectInterval)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-c.ctx.Done():
		return false
	case <-c.closeCh:
		return false
	}
}

func (c *multiPacketConn) setConn(i int, conn net.PacketConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.slots[i].conn; old != nil && old != conn {
		old.Close()
	}
	c.slots[i].conn = conn
}

func (c *multiPacketConn) clearConn(i int, conn net.PacketConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.slots[i].conn == conn {
		c.slots[i].conn = nil
	}
}

func (c *multiPacketConn) readLoop(conn net.PacketConn) error {
	buf := make([]byte, maxFrameSize)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		b := append([]byte(nil), buf[:n]...)
		select {
		case c.recvCh <- packetRead{b: b, addr: addr}:
		default:
			select {
			case <-c.recvCh:
			default:
			}
			select {
			case c.recvCh <- packetRead{b: b, addr: addr}:
			case <-c.closeCh:
				return net.ErrClosed
			default:
			}
		}
	}
}

func (c *multiPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt := <-c.recvCh:
		n = copy(p, pkt.b)
		if n < len(pkt.b) {
			return 0, nil, io.ErrShortBuffer
		}
		return n, pkt.addr, nil
	case <-c.recvT.C:
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.closeCh:
		return 0, nil, net.ErrClosed
	}
}

func (c *multiPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if addr.Network() != "derp" {
		return 0, fmt.Errorf("unsupported protocol: %v", addr.Network())
	}
	var errs []error
	for i := range c.slots {
		conn := c.conn(i)
		if conn == nil {
			continue
		}
		n, err := conn.WriteTo(p, addr)
		if err == nil {
			return n, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", c.slots[i].server, err))
		c.clearConn(i, conn)
		conn.Close()
	}
	if len(errs) > 0 {
		return 0, errors.Join(errs...)
	}
	return 0, ErrNoAvailableDERP
}

func (c *multiPacketConn) conn(i int) net.PacketConn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.slots[i].conn
}

func (c *multiPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closeCh)
		c.cancel()
		c.mu.Lock()
		defer c.mu.Unlock()
		for i := range c.slots {
			if c.slots[i].conn == nil {
				continue
			}
			if closeErr := c.slots[i].conn.Close(); closeErr != nil && err == nil {
				err = closeErr
			}
			c.slots[i].conn = nil
		}
	})
	return err
}

func (c *multiPacketConn) LocalAddr() net.Addr {
	return Addr(c.pub[:])
}

func (*multiPacketConn) SetDeadline(time.Time) error {
	return errors.New("unimplemented")
}

func (c *multiPacketConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.recvT.Stop()
	} else {
		c.recvT.Reset(time.Until(t))
	}
	return nil
}

func (*multiPacketConn) SetWriteDeadline(time.Time) error {
	return errors.New("unimplemented")
}

var _ net.PacketConn = (*multiPacketConn)(nil)
