package derpnet

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
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
