package derpnet

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

var Debug = false

const maxFrameSize = 1 << 20

type ListenConfig struct {
	// InsecureDERP disables TLS certificate verification for the DERP server.
	// This does not affect derpquic's inner peer authentication.
	InsecureDERP bool
}

// ListenPacket connects to a DERP server URL with the provided private key.
// It returns net.PacketConn
// derpURL should be a valid server name compatible with the Tailscale's DERP protocol.
// key should have a length of 32 bytes
func ListenPacket(derpURL string, key Key) (net.PacketConn, error) {
	var lc ListenConfig
	return lc.ListenPacket(context.Background(), derpURL, key)
}

// ListenPacket connects to a DERP server URL with the provided private key.
func (lc *ListenConfig) ListenPacket(ctx context.Context, derpURL string, key Key) (net.PacketConn, error) {
	cfg := ListenConfig{}
	if lc != nil {
		cfg = *lc
	}
	pub, err := curve25519.X25519(key, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	conn := &PacketConn{
		key: [32]byte(key),
		pub: [32]byte(pub),
		// Keep 10 most received packets in client buffer.
		recvCh:  make(chan []byte, 10),
		recvT:   time.NewTimer(time.Duration(math.MaxInt64)),
		closeCh: make(chan struct{}, 1),
	}
	if err := handshake(ctx, derpURL, key, conn, cfg); err != nil {
		return nil, err
	}
	return conn, nil
}

func handshake(ctx context.Context, derpURL string, key Key, pc *PacketConn, cfg ListenConfig) (retErr error) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	dialAddr, serverName, err := derpServerAddr(derpURL)
	if err != nil {
		return err
	}
	// Connect to DERP
	var dialer net.Dialer
	tcpConn, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			tcpConn.Close()
		}
	}()
	conn := tls.Client(tcpConn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: cfg.InsecureDERP,
	})
	pc.c = conn

	// Upgrade to DERP protocol
	req, err := http.NewRequest("GET", "/derp", nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Upgrade", "DERP")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Derp-Fast-Start", "1")
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("error creating connection: %w", err)
	}

	// DERP protocol
	pc.brw = bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
	serverKey, err := recvServerKey(pc.brw.Reader)
	if err != nil {
		return err
	}
	if err := sendClientInfo(pc.brw.Writer, pc.key, pc.pub, serverKey); err != nil {
		return err
	}
	if err := recvServerInfo(pc.brw.Reader, pc.key, serverKey); err != nil {
		return err
	}

	go func() {
		for {
			typ, msg, err := readFrame(pc.brw.Reader)
			if err != nil {
				pc.Close()
				return
			}
			switch typ {
			case frameKeepAlive:
			case framePing:
				go func() {
					pc.mu.Lock()
					defer pc.mu.Unlock()
					if err := writeFrame(pc.brw.Writer, framePong, msg); err != nil {
						pc.Close()
					}
				}()
			case frameRecvPacket:
				select {
				case pc.recvCh <- msg:
				default:
					// Delete oldest element
					<-pc.recvCh
					pc.recvCh <- msg
				}
			}
		}
	}()

	return err
}

func derpServerAddr(derpURL string) (dialAddr string, serverName string, err error) {
	if derpURL == "" {
		return "", "", errors.New("empty DERP server")
	}
	host, port, err := net.SplitHostPort(derpURL)
	if err == nil {
		if host == "" || port == "" {
			return "", "", fmt.Errorf("invalid DERP server address: %q", derpURL)
		}
		return net.JoinHostPort(host, port), host, nil
	}
	if strings.Contains(derpURL, ":") && !strings.Contains(err.Error(), "missing port in address") && !strings.Contains(err.Error(), "too many colons in address") {
		return "", "", fmt.Errorf("invalid DERP server address %q: %w", derpURL, err)
	}
	return net.JoinHostPort(derpURL, "443"), derpURL, nil
}

// PacketConn implements net.PacketConn.
type PacketConn struct {
	c   net.Conn
	brw *bufio.ReadWriter

	key [32]byte
	pub [32]byte

	recvCh chan []byte
	recvT  *time.Timer

	closeCh   chan struct{}
	closeOnce sync.Once

	mu sync.Mutex
}

// ReadFrom implements net.PacketConn.
func (c *PacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case msg, ok := <-c.recvCh:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		if len(msg) <= 32 {
			return 0, nil, errors.New("unexpected data")
		}
		v := msg[32]
		if v != 0 {
			return 0, nil, errors.New("unexpected data")
		}
		n = copy(p, msg[33:])
		if n < len(msg)-33 {
			return 0, nil, io.ErrShortBuffer
		}
		return n, Addr(msg[:32]), nil
	case <-c.recvT.C:
		return 0, nil, os.ErrDeadlineExceeded
	case <-c.closeCh:
		return 0, nil, net.ErrClosed
	}
}

// WriteTo implements net.PacketConn.
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if addr.Network() != "derp" {
		return 0, fmt.Errorf("unsupported protocol: %v", addr.Network())
	}
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	default:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	default:
	}
	if err := writeFrame(c.brw.Writer, frameSendPacket, []byte(addr.String()), []byte{0}, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements net.PacketConn.
func (c *PacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closeCh)
		if c.c != nil {
			err = c.c.Close()
		}
	})
	return err
}

// LocalAddr implements net.PacketConn.
func (c *PacketConn) LocalAddr() net.Addr {
	return Addr(c.pub[:])
}

// SetDeadline implements net.PacketConn.
func (*PacketConn) SetDeadline(t time.Time) error {
	return errors.New("unimplemented")
}

// SetReadDeadline implements net.PacketConn.
func (c *PacketConn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.recvT.Stop()
	} else {
		c.recvT.Reset(time.Until(t))
	}
	return nil
}

// SetWriteDeadline implements net.PacketConn.
func (*PacketConn) SetWriteDeadline(t time.Time) error {
	return errors.New("unimplemented")
}

var _ net.PacketConn = (*PacketConn)(nil)

// Addr implements net.Addr, and represents the public addr of the connection.
type Addr []byte

// Network implements net.Addr.
func (Addr) Network() string {
	return "derp"
}

// String implements net.Addr.
func (a Addr) String() string {
	return string(a)
}

func (a Addr) EncodedString() string {
	return base64.RawURLEncoding.EncodeToString(a)
}

var _ net.Addr = (*Addr)(nil)

func readFrame(r *bufio.Reader) (frameType, []byte, error) {
	hdr := make([]byte, 5)
	_, err := io.ReadFull(r, hdr)
	if err != nil {
		return 0, nil, err
	}
	typ := frameType(hdr[0])
	siz := binary.BigEndian.Uint32(hdr[1:5])
	if siz > maxFrameSize {
		return 0, nil, fmt.Errorf("frame too large: %d > %d", siz, maxFrameSize)
	}
	msg := make([]byte, siz)
	_, err = io.ReadFull(r, msg)
	if Debug {
		log.Printf("derpnet: frame recv: %v %d %v", typ, siz, base64.RawURLEncoding.EncodeToString(msg[:min(siz, 32)]))
	}
	return typ, msg, err
}

func writeFrame(w *bufio.Writer, t frameType, msgs ...[]byte) error {
	hdr := make([]byte, 5)
	hdr[0] = byte(t)
	size := 0
	for _, msg := range msgs {
		size += len(msg)
		if size > maxFrameSize {
			return fmt.Errorf("frame too large: %d > %d", size, maxFrameSize)
		}
	}
	binary.BigEndian.PutUint32(hdr[1:5], uint32(size))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	for _, msg := range msgs {
		if _, err := w.Write(msg); err != nil {
			return err
		}
	}
	if Debug {
		logMsg := []byte{}
		if size > 0 {
			logMsg = msgs[0][:min(32, len(msgs[0]))]
		}
		log.Printf("derpnet: frame send: %v %d %v", t, size, base64.RawURLEncoding.EncodeToString(logMsg))
	}
	return w.Flush()
}

func recvServerKey(r *bufio.Reader) ([32]byte, error) {
	typ, msg, err := readFrame(r)
	if err != nil {
		return [32]byte{}, err
	}
	if typ != frameServerKey || len(msg) != 40 || string(msg[:8]) != magic {
		return [32]byte{}, fmt.Errorf("unexpected: %d %v", typ, string(msg))
	}
	if Debug {
		log.Printf("Server Key: %s", msg[8:])
	}
	return [32]byte(msg[8:]), nil
}

func sendClientInfo(w *bufio.Writer, privKey, pubKey, servKey [32]byte) error {
	msg, err := json.Marshal(map[string]interface{}{
		"version":     2,
		"CanAckPings": true,
	})
	if err != nil {
		return err
	}
	var b []byte
	b = append(b, pubKey[:]...)
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}
	b = append(b, nonce[:]...)
	boxed := box.Seal(b, msg, &nonce, &servKey, &privKey)
	if Debug {
		log.Printf("Msg: %s", msg)
	}
	return writeFrame(w, frameClientInfo, boxed)
}

func recvServerInfo(r *bufio.Reader, privKey, servKey [32]byte) error {
	typ, msg, err := readFrame(r)
	if err != nil {
		return err
	}
	if typ != frameServerInfo || len(msg) < 24 {
		return fmt.Errorf("unexpected: %d %v", typ, string(msg))
	}
	info, ok := box.Open(nil, msg[24:], (*[24]byte)(msg[:24]), &servKey, &privKey)
	if !ok {
		return fmt.Errorf("unable to unseal: %v", string(msg))
	}
	if Debug {
		log.Printf("Server info: %s", info)
	}
	return nil
}

// From tailscale repo
const magic = "DERP🔑" // 8 bytes: 0x44 45 52 50 f0 9f 94 91

type frameType byte

const (
	frameServerKey     = frameType(0x01) // 8B magic + 32B public key + (0+ bytes future use)
	frameClientInfo    = frameType(0x02) // 32B pub key + 24B nonce + naclbox(json)
	frameServerInfo    = frameType(0x03) // 24B nonce + naclbox(json)
	frameSendPacket    = frameType(0x04) // 32B dest pub key + packet bytes
	frameForwardPacket = frameType(0x0a) // 32B src pub key + 32B dst pub key + packet bytes
	frameRecvPacket    = frameType(0x05) // v0/1: packet bytes, v2: 32B src pub key + packet bytes
	frameKeepAlive     = frameType(0x06) // no payload, no-op (to be replaced with ping/pong)
	frameNotePreferred = frameType(0x07) // 1 byte payload: 0x01 or 0x00 for whether this is client's home node
	framePeerGone      = frameType(0x08) // 32B pub key of peer that's gone + 1 byte reason
	framePeerPresent   = frameType(0x09) // 32B pub key of peer that's connected + optional 18B ip:port (16 byte IP + 2 byte BE uint16 port)
	frameWatchConns    = frameType(0x10)
	frameClosePeer     = frameType(0x11) // 32B pub key of peer to close.
	framePing          = frameType(0x12) // 8 byte ping payload, to be echoed back in framePong
	framePong          = frameType(0x13) // 8 byte payload, the contents of the ping being replied to
	frameHealth        = frameType(0x14)
	frameRestarting    = frameType(0x15)
)
