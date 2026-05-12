package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ntnj/derpnet"
	"github.com/ntnj/derpnet/derpquic"
	"golang.org/x/crypto/curve25519"
)

var (
	derpServer   = flag.String("derp", "", "comma-separated list of derp servers to use, optionally host:port")
	derpListURL  = flag.String("derp-list", "", "url returning a comma-separated list of derp servers to use")
	keyName      = flag.String("key", "derpconnect", "key file to use")
	debug        = flag.Bool("debug", false, "enable debug logging")
	insecureDERP = flag.Bool("insecure-derp", false, "disable TLS certificate verification for the DERP server")
)

func main() {
	flag.Parse()
	if *debug {
		derpnet.Debug = true
		derpquic.Debug = true
	}
	derpServerArg := *derpServer
	if *derpListURL != "" {
		var err error
		derpServerArg, err = fetchDERPServerList(*derpListURL)
		if err != nil {
			log.Fatalf("unable to fetch DERP server list from %s: %v", *derpListURL, err)
		}
	} else if *derpServer == "" {
		log.Fatalln(`Provide a DERP server to use with --derp=<xxx>.tailscale.com flag.
You can find Tailscale hosted DERP server from https://login.tailscale.com/derpmap/default or use a self hosted DERP server.`)
	}
	derpServers, err := parseDERPServers(derpServerArg)
	if err != nil {
		log.Fatal(err)
	}
	derpConfig := derpquic.ListenConfig{InsecureDERP: *insecureDERP}
	key, err := getKey(*keyName)
	if err != nil {
		log.Fatalf("unable to generate key: %v", err)
	}

	switch flag.Arg(0) {
	case "serve":
		pubKey, err := curve25519.X25519(key, curve25519.Basepoint)
		if err != nil {
			log.Fatalf("unable to get public key: %v", err)
		}
		port, err := strconv.Atoi(flag.Arg(1))
		if err != nil {
			log.Fatalf(`provide a valid port with "derpconnect serve <port>"`)
		}
		listeners := make([]net.Listener, 0, len(derpServers))
		for _, derpServer := range derpServers {
			l, err := derpConfig.Listen(derpServer, key)
			if err != nil {
				log.Fatalf("unable to connect to DERP server %s: %v", derpServer, err)
			}
			listeners = append(listeners, l)
		}
		log.Printf(`Listening through DERP. Join with "derpconnect --derp=%s join %v"`, strings.Join(derpServers, ","), base64.RawURLEncoding.EncodeToString(pubKey))
		for _, l := range listeners {
			go proxyConn(l, func() (net.Conn, error) {
				return net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
			})
		}
		select {}
	case "join":
		pubkey, err := base64.RawURLEncoding.DecodeString(flag.Arg(1))
		if err != nil || len(pubkey) != 32 {
			log.Fatalf(`provide correct public key of server with "derpconnect join <pubkey>": %v`, err)
		}
		listenAddr, err := listenAddr(flag.Arg(2))
		if err != nil {
			log.Fatalf("unable to get address to listen on: %v", err)
		}
		l, err := net.Listen("tcp", listenAddr)
		if err != nil {
			log.Fatalf("unable to listen locally on %s: %v", listenAddr, err)
		}
		derpPacketConfig := derpnet.ListenConfig{InsecureDERP: *insecureDERP}
		pkc, err := derpPacketConfig.ListenPacketAll(context.Background(), derpServers, key)
		if err != nil {
			log.Fatalf("unable to connect to any DERP server: %v", err)
		}
		d, err := derpquic.NewDialerPacketConn(pkc, key)
		if err != nil {
			pkc.Close()
			log.Fatalf("unable to create DERP dialer: %v", err)
		}
		clientPubKey, err := key.PublicKey()
		if err != nil {
			log.Fatalf("unable to get client public key: %v", err)
		}
		log.Printf("Listening on %v", l.Addr())
		log.Printf("Monitoring DERP servers: %s", strings.Join(derpServers, ","))
		log.Printf("Client public key: %v", base64.RawURLEncoding.EncodeToString(clientPubKey))
		proxyConn(l, func() (net.Conn, error) {
			return d.Dial(pubkey)
		})
	case "internaltest":
		internalTesting(derpServers[0])
	default:
		log.Println(`Run "derpconnect --derp=... serve <port>" on server
Run "derpconnect --derp=... join <pubkey> <listen_addr>" to connect client to server`)
	}
}

func parseDERPServers(arg string) ([]string, error) {
	var servers []string
	for _, server := range strings.Split(arg, ",") {
		server = strings.TrimSpace(server)
		if server == "" {
			continue
		}
		servers = append(servers, server)
	}
	if len(servers) == 0 {
		return nil, errors.New("provide at least one DERP server")
	}
	return servers, nil
}

func fetchDERPServerList(url string) (string, error) {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func listenAddr(arg string) (string, error) {
	if arg == "" {
		return "127.0.0.1:0", nil
	}
	if _, err := strconv.Atoi(arg); err == nil {
		return net.JoinHostPort("127.0.0.1", arg), nil
	}
	if _, _, err := net.SplitHostPort(arg); err != nil {
		return "", fmt.Errorf("provide a valid listen address such as 127.0.0.1:8080 or :8080: %w", err)
	}
	return arg, nil
}

func proxyConn(l net.Listener, dial func() (net.Conn, error)) {
	for {
		inConn, err := l.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}
		if *debug {
			log.Printf("Accepted connection from %v", inConn.RemoteAddr())
		}
		go func(conn net.Conn) {
			outConn, err := dial()
			if err != nil {
				log.Printf("Error connecting to target: %v", err)
				inConn.Close()
				return
			}
			go func() {
				defer closeRead(conn)
				defer closeWrite(outConn)
				n, err := io.Copy(outConn, conn)
				if *debug {
					log.Printf("Copied out %d bytes %v", n, err)
				}
			}()
			go func() {
				defer closeRead(outConn)
				defer closeWrite(conn)
				n, err := io.Copy(conn, outConn)
				if *debug {
					log.Printf("Copied in %d bytes %v", n, err)
				}
			}()
		}(inConn)
	}
}

type closerReadWrite interface {
	CloseRead() error
	CloseWrite() error
}

func closeRead(conn net.Conn) {
	if c, ok := conn.(closerReadWrite); ok {
		c.CloseRead()
	}
}

func closeWrite(conn net.Conn) {
	if c, ok := conn.(closerReadWrite); ok {
		c.CloseWrite()
	}
}

func getKey(name string) (derpnet.Key, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ephemeralKey("unable to find config dir: %v", err)
	}
	keyPath := filepath.Join(configDir, "derpconnect", name)
	if bytes, err := os.ReadFile(keyPath); err == nil {
		if len(bytes) != 32 {
			return ephemeralKey("invalid key length found in %s: %d", keyPath, len(bytes))
		}
		return bytes, nil
	} else if !os.IsNotExist(err) {
		return ephemeralKey("unable to read existing key from %s: %v", keyPath, err)
	}

	key, err := derpnet.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		log.Printf("Unable to create key dir: %v; using ephemeral key", err)
		return key, nil
	}
	if err := os.WriteFile(keyPath, key, 0o400); err != nil {
		log.Printf("Unable to save key: %v; using ephemeral key", err)
		return key, nil
	}
	return key, nil
}

func ephemeralKey(format string, args ...any) (derpnet.Key, error) {
	log.Printf(format+"; using ephemeral key", args...)
	key, err := derpnet.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}
	return key, nil
}

func internalTesting(derpServer string) {
	derpConfig := derpnet.ListenConfig{InsecureDERP: *insecureDERP}
	key1 := [32]byte{'h', 'e'}
	key2 := [32]byte{'e', 'f'}
	var pkey1, pkey2 [32]byte
	curve25519.ScalarBaseMult(&pkey1, &key1)
	curve25519.ScalarBaseMult(&pkey2, &key2)
	go func() {
		conn, err := derpConfig.ListenPacket(context.Background(), derpServer, key1[:])
		if err != nil {
			panic(err)
		}
		go func() {
			for range time.Tick(13 * time.Second) {
				msg := fmt.Sprintf("key1: %v", time.Now())
				n, err := conn.WriteTo([]byte(msg), derpnet.Addr(pkey2[:]))
				log.Printf("W1 %d: %s : %v", n, msg, err)
			}
		}()
		go func() {
			b := make([]byte, 4096)
			for {
				n, _, err := conn.ReadFrom(b)
				log.Printf("R1 %d: %s : %v", n, b, err)
			}
		}()
	}()
	go func() {
		conn, err := derpConfig.ListenPacket(context.Background(), derpServer, key2[:])
		if err != nil {
			panic(err)
		}
		go func() {
			for range time.Tick(5 * time.Second) {
				msg := fmt.Sprintf("key2: %v", time.Now())
				n, err := conn.WriteTo([]byte(msg), derpnet.Addr(pkey1[:]))
				log.Printf("W2 %d: %s : %v", n, msg, err)
			}
		}()
		go func() {
			b := make([]byte, 4096)
			for {
				n, _, err := conn.ReadFrom(b)
				log.Printf("R2 %d: %s : %v", n, b, err)
			}
		}()
	}()
	time.Sleep(2 * time.Minute)
}
