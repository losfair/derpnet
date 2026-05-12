package derpquic

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/ntnj/derpnet"
	"github.com/quic-go/quic-go"
)

var Debug = false

const quicIdleTimeout = 300 * time.Second

type ListenConfig struct {
	// InsecureDERP disables TLS certificate verification for the DERP server.
	// This does not affect derpquic's inner peer authentication.
	InsecureDERP bool
}

// Listen connects to a DERP server URL with the provided private key.
// It returns net.Listener and implements a TCP-like stream.
// derpURL should be a valid server name compatible with the Tailscale's DERP protocol.
// key should have a length of 32 bytes
func Listen(derpURL string, key derpnet.Key) (net.Listener, error) {
	var lc ListenConfig
	return lc.Listen(derpURL, key)
}

// ListenAll connects to multiple DERP server URLs with the provided private key.
func ListenAll(derpURLs []string, key derpnet.Key) (net.Listener, error) {
	var lc ListenConfig
	return lc.ListenAll(derpURLs, key)
}

// Listen connects to a DERP server URL with the provided private key.
func (lc *ListenConfig) Listen(derpURL string, key derpnet.Key) (net.Listener, error) {
	derpConfig := lc.derpConfig()
	pkc, err := derpConfig.ListenPacket(context.Background(), derpURL, key)
	if err != nil {
		return nil, err
	}
	return NewListenerPacketConn(pkc, key)
}

// ListenAll connects to multiple DERP server URLs with the provided private key.
func (lc *ListenConfig) ListenAll(derpURLs []string, key derpnet.Key) (net.Listener, error) {
	derpConfig := lc.derpConfig()
	pkc, err := derpConfig.ListenPacketAll(context.Background(), derpURLs, key)
	if err != nil {
		return nil, err
	}
	return NewListenerPacketConn(pkc, key)
}

// NewListenerPacketConn creates a Listener over an existing DERP packet connection.
func NewListenerPacketConn(pkc net.PacketConn, key derpnet.Key) (*Listener, error) {
	pub, err := key.PublicKey()
	if err != nil {
		pkc.Close()
		return nil, err
	}
	tr := &quic.Transport{
		Conn: pkc,
	}
	cert, err := localhostCertificate()
	if err != nil {
		pkc.Close()
		return nil, err
	}
	l, err := tr.Listen(&tls.Config{
		ServerName:   "localhost",
		Certificates: []tls.Certificate{*cert},
	}, quicConfig())
	if err != nil {
		pkc.Close()
		return nil, err
	}
	ll := &Listener{
		l:   l,
		tr:  tr,
		pkc: pkc,
		key: cloneBytes(key),
		pub: cloneBytes(pub),
		s:   make(chan streamOrError),
	}
	go ll.start()
	return ll, nil
}

type Dialer struct {
	tr  *quic.Transport
	key derpnet.Key
	pub derpnet.PublicKey
}

// NewDialer connects to a DERP server URL with the provided private key.
// It returns Dialer which can be used to connect a TCP-like stream to derpquic.Listener.
// derpURL should be a valid server name compatible with the Tailscale's DERP protocol.
// key should have a length of 32 bytes
func NewDialer(derpURL string, key derpnet.Key) (*Dialer, error) {
	var lc ListenConfig
	return lc.NewDialer(derpURL, key)
}

// NewDialer connects to a DERP server URL with the provided private key.
func (lc *ListenConfig) NewDialer(derpURL string, key derpnet.Key) (*Dialer, error) {
	derpConfig := lc.derpConfig()
	pkc, err := derpConfig.ListenPacket(context.Background(), derpURL, key)
	if err != nil {
		return nil, err
	}
	return NewDialerPacketConn(pkc, key)
}

// NewDialerPacketConn creates a Dialer over an existing DERP packet connection.
func NewDialerPacketConn(pkc net.PacketConn, key derpnet.Key) (*Dialer, error) {
	pub, err := key.PublicKey()
	if err != nil {
		pkc.Close()
		return nil, err
	}
	tr := &quic.Transport{
		Conn: pkc,
	}
	return &Dialer{tr: tr, key: cloneBytes(key), pub: cloneBytes(pub)}, nil
}

func quicConfig() *quic.Config {
	return &quic.Config{
		InitialPacketSize: 32 << 10,
		MaxIdleTimeout:    quicIdleTimeout,
	}
}

func (lc *ListenConfig) derpConfig() derpnet.ListenConfig {
	if lc == nil {
		return derpnet.ListenConfig{}
	}
	return derpnet.ListenConfig{InsecureDERP: lc.InsecureDERP}
}

func (d *Dialer) Dial(addr derpnet.PublicKey) (net.Conn, error) {
	c, err := d.tr.Dial(context.TODO(), derpnet.Addr(addr), &tls.Config{
		// The peer uses an ephemeral self-signed certificate. authenticateClient
		// verifies the expected DERP key and binds that proof to this TLS session.
		InsecureSkipVerify: true,
	}, quicConfig())
	if err != nil {
		return nil, err
	}
	// TODO: reuse connection for the same target
	s, err := c.OpenStreamSync(context.TODO())
	if err != nil {
		c.CloseWithError(0, "open stream failed")
		return nil, err
	}
	if err := authenticateClient(c, s, d.key, d.pub, addr); err != nil {
		s.CancelRead(0)
		s.CancelWrite(0)
		c.CloseWithError(0, "authentication failed")
		return nil, err
	}
	return &Connection{c: c, s: s}, nil
}

// Listener implements net.Listener.
type Listener struct {
	l         *quic.Listener
	tr        *quic.Transport
	pkc       net.PacketConn
	key       derpnet.Key
	pub       derpnet.PublicKey
	s         chan streamOrError
	closeOnce sync.Once
	closeErr  error
}

// Accept implements net.Listener.
func (l *Listener) Accept() (net.Conn, error) {
	se := <-l.s
	if se.err != nil {
		return nil, se.err
	}
	return &Connection{c: se.c, s: se.s}, nil
}

// Addr implements net.Listener.
func (l *Listener) Addr() net.Addr {
	return l.l.Addr()
}

// Close implements net.Listener.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		if err := l.l.Close(); err != nil && l.closeErr == nil {
			l.closeErr = err
		}
		if err := l.pkc.Close(); err != nil && l.closeErr == nil {
			l.closeErr = err
		}
		if err := l.tr.Close(); err != nil && l.closeErr == nil {
			l.closeErr = err
		}
	})
	return l.closeErr
}

type streamOrError struct {
	c   *quic.Conn
	s   *quic.Stream
	err error
}

func (l *Listener) start() {
	for {
		conn, err := l.l.Accept(context.TODO())
		if Debug {
			if err == nil {
				log.Printf("accepted quic conn: %v", conn.RemoteAddr())
			} else {
				log.Printf("error accepting quic conn: %v", err)
			}
		}
		if err != nil {
			if err == quic.ErrServerClosed {
				l.s <- streamOrError{err: err}
				return
			}
			continue
		}
		go func(conn *quic.Conn) {
			for {
				stream, err := conn.AcceptStream(conn.Context())
				if Debug {
					if err == nil {
						log.Printf("accepted quic stream: %v", stream.StreamID())
					} else {
						log.Printf("error accepting quic stream: %v", err)
					}
				}
				if err != nil {
					if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
						return
					}
					l.s <- streamOrError{err: err}
					continue
				}
				if err := authenticateServer(conn, stream, l.key, l.pub); err != nil {
					stream.CancelRead(0)
					stream.CancelWrite(0)
					conn.CloseWithError(0, "authentication failed")
					l.s <- streamOrError{err: err}
					continue
				}
				l.s <- streamOrError{c: conn, s: stream}
			}
		}(conn)
	}
}

var _ net.Listener = (*Listener)(nil)

// Connection implements net.Conn.
type Connection struct {
	c *quic.Conn
	s *quic.Stream
}

// Close implements net.Conn.
func (s *Connection) Close() error {
	return s.s.Close()
}

func (*Connection) CloseRead() error {
	return nil
}
func (s *Connection) CloseWrite() error {
	return s.s.Close()
}

// LocalAddr implements net.Conn.
func (s *Connection) LocalAddr() net.Addr {
	return s.c.LocalAddr()
}

// Read implements net.Conn.
func (s *Connection) Read(b []byte) (n int, err error) {
	return s.s.Read(b)
}

// RemoteAddr implements net.Conn.
func (s *Connection) RemoteAddr() net.Addr {
	return s.c.RemoteAddr()
}

// SetDeadline implements net.Conn.
func (s *Connection) SetDeadline(t time.Time) error {
	s.s.SetReadDeadline(t)
	return s.s.SetWriteDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (s *Connection) SetReadDeadline(t time.Time) error {
	return s.s.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.
func (s *Connection) SetWriteDeadline(t time.Time) error {
	return s.s.SetWriteDeadline(t)
}

// Write implements net.Conn.
func (s *Connection) Write(b []byte) (n int, err error) {
	return s.s.Write(b)
}

var _ net.Conn = (*Connection)(nil)

func localhostCertificate() (*tls.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		Subject:      pkix.Name{CommonName: "localhost"},
		Issuer:       pkix.Name{CommonName: "localhost"},
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(1, 0, 0),
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	return &certificate, err
}
