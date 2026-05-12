package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
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

func TestGetKeyFallsBackToEphemeralWithoutConfigDir(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	key, err := getKey("test-key")
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

func TestGetKeyFallsBackToEphemeralWhenPersistFails(t *testing.T) {
	configFile := filepath.Join(t.TempDir(), "config-file")
	if err := os.WriteFile(configFile, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", configFile)

	key, err := getKey("test-key")
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}
