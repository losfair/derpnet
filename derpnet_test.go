package derpnet

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadFrameRejectsOversizedFrame(t *testing.T) {
	var hdr [5]byte
	hdr[0] = byte(frameRecvPacket)
	binary.BigEndian.PutUint32(hdr[1:], maxFrameSize+1)

	_, _, err := readFrame(bufio.NewReader(bytes.NewReader(hdr[:])))
	if err == nil {
		t.Fatal("expected oversized frame error")
	}
	if !strings.Contains(err.Error(), "frame too large") {
		t.Fatalf("expected frame too large error, got %v", err)
	}
}

func TestDerpServerAddr(t *testing.T) {
	tests := []struct {
		name           string
		server         string
		wantDialAddr   string
		wantServerName string
	}{
		{
			name:           "default port",
			server:         "derp.example.com",
			wantDialAddr:   "derp.example.com:443",
			wantServerName: "derp.example.com",
		},
		{
			name:           "port override",
			server:         "derp.example.com:8443",
			wantDialAddr:   "derp.example.com:8443",
			wantServerName: "derp.example.com",
		},
		{
			name:           "ipv6 default port",
			server:         "2001:db8::1",
			wantDialAddr:   "[2001:db8::1]:443",
			wantServerName: "2001:db8::1",
		},
		{
			name:           "ipv6 port override",
			server:         "[2001:db8::1]:8443",
			wantDialAddr:   "[2001:db8::1]:8443",
			wantServerName: "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDialAddr, gotServerName, err := derpServerAddr(tt.server)
			if err != nil {
				t.Fatal(err)
			}
			if gotDialAddr != tt.wantDialAddr {
				t.Fatalf("dial address = %q, want %q", gotDialAddr, tt.wantDialAddr)
			}
			if gotServerName != tt.wantServerName {
				t.Fatalf("server name = %q, want %q", gotServerName, tt.wantServerName)
			}
		})
	}
}

func TestDerpServerAddrRejectsInvalidAddress(t *testing.T) {
	if _, _, err := derpServerAddr(""); err == nil {
		t.Fatal("expected empty DERP server error")
	}
	if _, _, err := derpServerAddr("derp.example.com:"); err == nil {
		t.Fatal("expected empty DERP port error")
	}
}

func TestPacketConnHeartbeatClosesWhenPongTimesOut(t *testing.T) {
	restoreHeartbeatTimings := setTestHeartbeatTimings(t, 5*time.Millisecond, 20*time.Millisecond)
	defer restoreHeartbeatTimings()

	pc, server, cleanup := testHeartbeatPacketConn(t)
	defer cleanup()

	go pc.readLoop()
	go pc.heartbeatLoop()

	typ, msg, err := readFrame(server.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if typ != framePing {
		t.Fatalf("heartbeat frame = %v, want %v", typ, framePing)
	}
	if len(msg) != 8 {
		t.Fatalf("heartbeat ping length = %d, want 8", len(msg))
	}
	go func() {
		for {
			if _, _, err := readFrame(server.Reader); err != nil {
				return
			}
		}
	}()

	waitUntil(t, func() bool {
		select {
		case <-pc.closeCh:
			return true
		default:
			return false
		}
	})
}

func TestPacketConnHeartbeatAcceptsMatchingPong(t *testing.T) {
	restoreHeartbeatTimings := setTestHeartbeatTimings(t, 5*time.Millisecond, 50*time.Millisecond)
	defer restoreHeartbeatTimings()

	pc, server, cleanup := testHeartbeatPacketConn(t)
	defer cleanup()

	go pc.readLoop()
	go pc.heartbeatLoop()

	typ, msg, err := readFrame(server.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if typ != framePing {
		t.Fatalf("heartbeat frame = %v, want %v", typ, framePing)
	}
	if err := writeFrame(server.Writer, framePong, msg); err != nil {
		t.Fatal(err)
	}

	typ, msg, err = readFrame(server.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if typ != framePing {
		t.Fatalf("second heartbeat frame = %v, want %v", typ, framePing)
	}
	if err := writeFrame(server.Writer, framePong, msg); err != nil {
		t.Fatal(err)
	}

	select {
	case <-pc.closeCh:
		t.Fatal("connection closed after receiving matching pong")
	case <-time.After(derpPingInterval):
	}
}

func testHeartbeatPacketConn(t *testing.T) (*PacketConn, *bufio.ReadWriter, func()) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	pc := &PacketConn{
		c:       clientConn,
		brw:     bufio.NewReadWriter(bufio.NewReader(clientConn), bufio.NewWriter(clientConn)),
		recvCh:  make(chan []byte, 10),
		recvT:   time.NewTimer(time.Hour),
		pongCh:  make(chan [8]byte, 10),
		closeCh: make(chan struct{}),
	}
	server := bufio.NewReadWriter(bufio.NewReader(serverConn), bufio.NewWriter(serverConn))
	cleanup := func() {
		pc.recvT.Stop()
		pc.Close()
		serverConn.Close()
	}
	return pc, server, cleanup
}

func setTestHeartbeatTimings(t *testing.T, interval, timeout time.Duration) func() {
	t.Helper()
	oldInterval := derpPingInterval
	oldTimeout := derpPongTimeout
	derpPingInterval = interval
	derpPongTimeout = timeout
	return func() {
		derpPingInterval = oldInterval
		derpPongTimeout = oldTimeout
	}
}
