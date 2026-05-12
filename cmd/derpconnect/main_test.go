package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ntnj/derpnet"
)

func TestListenAddr(t *testing.T) {
	tests := []struct {
		name string
		arg  string
		want string
	}{
		{name: "empty defaults to loopback ephemeral", arg: "", want: "127.0.0.1:0"},
		{name: "bare port defaults to loopback", arg: "8080", want: "127.0.0.1:8080"},
		{name: "explicit loopback address", arg: "127.0.0.1:8080", want: "127.0.0.1:8080"},
		{name: "explicit all interfaces", arg: ":8080", want: ":8080"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := listenAddr(tt.arg)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("listenAddr(%q) = %q, want %q", tt.arg, got, tt.want)
			}
		})
	}
}

func TestListenAddrRejectsInvalidAddress(t *testing.T) {
	if _, err := listenAddr("localhost"); err == nil {
		t.Fatal("expected invalid listen address error")
	}
}

func TestFWMarkFromFlag(t *testing.T) {
	got, err := fwmarkFromFlag(123, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if got != 123 {
		t.Fatalf("fwmarkFromFlag = %d, want 123", got)
	}

	got, err = fwmarkFromFlag(0, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	if got != 0 {
		t.Fatalf("fwmarkFromFlag zero = %d, want 0", got)
	}

	if _, err := fwmarkFromFlag(123, "darwin"); err == nil {
		t.Fatal("expected non-Linux fwmark error")
	}
}

func TestStdioAddr(t *testing.T) {
	if !isStdioAddr("stdio") {
		t.Fatal("stdio should enable stdio mode")
	}
	if isStdioAddr("STDIO") {
		t.Fatal("stdio mode should require exact stdio address")
	}
}

func TestPipeConnCopiesStdioToStreamAndStreamToStdout(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	serverDone := make(chan string, 1)
	go func() {
		defer server.Close()

		request := make([]byte, len("request from stdin"))
		_, err := io.ReadFull(server, request)
		if err != nil {
			serverDone <- err.Error()
			return
		}
		if _, err := server.Write([]byte("response from stream")); err != nil {
			serverDone <- err.Error()
			return
		}
		serverDone <- string(request)
	}()

	var stdout bytes.Buffer
	if err := pipeConn(strings.NewReader("request from stdin"), &stdout, client); err != nil {
		t.Fatal(err)
	}
	if got, want := stdout.String(), "response from stream"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if got, want := <-serverDone, "request from stdin"; got != want {
		t.Fatalf("server read = %q, want %q", got, want)
	}
}

func TestDialWhenDERPAvailableRetriesUntilAvailable(t *testing.T) {
	restoreRetryInterval := setTestDialRetryInterval(t)
	defer restoreRetryInterval()

	var attempts int
	client, server := net.Pipe()
	defer server.Close()

	conn, err := dialWhenDERPAvailable(func() (net.Conn, error) {
		attempts++
		if attempts < 3 {
			return nil, derpnet.ErrNoAvailableDERP
		}
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if attempts != 3 {
		t.Fatalf("dial attempts = %d, want 3", attempts)
	}
}

func TestDialWhenDERPAvailableReturnsOtherErrors(t *testing.T) {
	restoreRetryInterval := setTestDialRetryInterval(t)
	defer restoreRetryInterval()

	want := io.ErrUnexpectedEOF
	_, err := dialWhenDERPAvailable(func() (net.Conn, error) {
		return nil, want
	})
	if err != want {
		t.Fatalf("dialWhenDERPAvailable error = %v, want %v", err, want)
	}
}

func TestParseDERPServers(t *testing.T) {
	got, err := parseDERPServers("derp1.example.com, derp2.example.com:8443,,derp3.example.com")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"derp1.example.com", "derp2.example.com:8443", "derp3.example.com"}
	if len(got) != len(want) {
		t.Fatalf("len(parseDERPServers) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("parseDERPServers[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseDERPServersRejectsEmptyList(t *testing.T) {
	if _, err := parseDERPServers(" , , "); err == nil {
		t.Fatal("expected empty DERP server list error")
	}
}

func TestFetchDERPServerList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("derp1.example.com, derp2.example.com:8443"))
	}))
	defer srv.Close()

	got, err := fetchDERPServerList(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	want := "derp1.example.com, derp2.example.com:8443"
	if got != want {
		t.Fatalf("fetchDERPServerList = %q, want %q", got, want)
	}
}

func TestFetchDERPServerListRejectsHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := fetchDERPServerList(srv.URL); err == nil {
		t.Fatal("expected HTTP status error")
	}
}

func TestGetKeyFromEnv(t *testing.T) {
	want := bytes.Repeat([]byte{7}, 32)
	t.Setenv(keyEnvVar, base64.StdEncoding.EncodeToString(want))

	got, err := getKey()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("getKey() = %x, want %x", got, want)
	}
}

func TestGetKeyGeneratesEphemeralWhenEnvMissing(t *testing.T) {
	t.Setenv(keyEnvVar, "")

	key, err := getKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

func TestGetKeyRejectsInvalidEnv(t *testing.T) {
	t.Setenv(keyEnvVar, base64.StdEncoding.EncodeToString([]byte("too short")))

	if _, err := getKey(); err == nil {
		t.Fatal("expected invalid key error")
	}
}

func setTestDialRetryInterval(t *testing.T) func() {
	t.Helper()
	old := derpDialRetryInterval
	derpDialRetryInterval = time.Millisecond
	return func() {
		derpDialRetryInterval = old
	}
}
