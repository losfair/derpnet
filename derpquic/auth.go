package derpquic

import (
	"bytes"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ntnj/derpnet"
	"github.com/quic-go/quic-go"
	"golang.org/x/crypto/curve25519"
)

const (
	authVersion byte = 1

	authFrameClientHello byte = 1
	authFrameServerHello byte = 2
	authFrameClientProof byte = 3

	authNonceSize = 32
	authMACSize   = 32
	authKeySize   = 32
	authEKMSize   = 32

	authEKMLabel = "EXPORTER-derpquic-auth-v1"
	authTimeout  = 10 * time.Second
)

var errAuthFailed = errors.New("derpquic authentication failed")

func authenticateClient(conn *quic.Conn, stream *quic.Stream, key derpnet.Key, pub, serverPub derpnet.PublicKey) error {
	if len(pub) != 32 || len(serverPub) != 32 {
		return fmt.Errorf("%w: invalid public key length", errAuthFailed)
	}
	if err := stream.SetDeadline(time.Now().Add(authTimeout)); err != nil {
		return err
	}
	defer stream.SetDeadline(time.Time{})

	clientNonce, err := randomBytes(authNonceSize)
	if err != nil {
		return err
	}
	clientHello := makeClientHello(pub, clientNonce)
	if err := writeAuthFrame(stream, clientHello); err != nil {
		return err
	}

	serverHello, err := readAuthFrame(stream)
	if err != nil {
		return err
	}
	recvServerPub, serverNonce, serverMAC, err := parseServerHello(serverHello)
	if err != nil {
		return err
	}
	if !bytes.Equal(recvServerPub, serverPub) {
		return fmt.Errorf("%w: server DERP key mismatch", errAuthFailed)
	}

	ekm, err := exportKeyingMaterial(conn)
	if err != nil {
		return err
	}
	macKey, err := authMACKey(key, serverPub, ekm)
	if err != nil {
		return err
	}
	if !hmac.Equal(serverMAC, authMAC(macKey, "server", pub, serverPub, clientNonce, serverNonce, ekm)) {
		return fmt.Errorf("%w: bad server proof", errAuthFailed)
	}

	return writeAuthFrame(stream, makeClientProof(macKey, pub, serverPub, clientNonce, serverNonce, ekm))
}

func authenticateServer(conn *quic.Conn, stream *quic.Stream, key derpnet.Key, pub derpnet.PublicKey) error {
	if len(pub) != 32 {
		return fmt.Errorf("%w: invalid server public key length", errAuthFailed)
	}
	if err := stream.SetDeadline(time.Now().Add(authTimeout)); err != nil {
		return err
	}
	defer stream.SetDeadline(time.Time{})

	clientHello, err := readAuthFrame(stream)
	if err != nil {
		return err
	}
	clientPub, clientNonce, err := parseClientHello(clientHello)
	if err != nil {
		return err
	}

	serverNonce, err := randomBytes(authNonceSize)
	if err != nil {
		return err
	}
	ekm, err := exportKeyingMaterial(conn)
	if err != nil {
		return err
	}
	macKey, err := authMACKey(key, clientPub, ekm)
	if err != nil {
		return err
	}
	if err := writeAuthFrame(stream, makeServerHello(macKey, clientPub, pub, clientNonce, serverNonce, ekm)); err != nil {
		return err
	}

	clientProof, err := readAuthFrame(stream)
	if err != nil {
		return err
	}
	clientMAC, err := parseClientProof(clientProof)
	if err != nil {
		return err
	}
	if !hmac.Equal(clientMAC, authMAC(macKey, "client", clientPub, pub, clientNonce, serverNonce, ekm)) {
		return fmt.Errorf("%w: bad client proof", errAuthFailed)
	}
	return nil
}

func exportKeyingMaterial(conn *quic.Conn) ([]byte, error) {
	state := conn.ConnectionState().TLS
	return state.ExportKeyingMaterial(authEKMLabel, nil, authEKMSize)
}

func authMACKey(priv derpnet.Key, peerPub []byte, ekm []byte) ([]byte, error) {
	shared, err := curve25519.X25519(priv, peerPub)
	if err != nil {
		return nil, err
	}
	return hkdf.Key(sha256.New, shared, ekm, "derpquic auth mac key v1", authKeySize)
}

func authMAC(key []byte, role string, clientPub, serverPub, clientNonce, serverNonce, ekm []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("derpquic auth proof v1"))
	mac.Write([]byte{0})
	mac.Write([]byte(role))
	mac.Write([]byte{0})
	mac.Write(clientPub)
	mac.Write(serverPub)
	mac.Write(clientNonce)
	mac.Write(serverNonce)
	mac.Write(ekm)
	return mac.Sum(nil)
}

func makeClientHello(clientPub []byte, clientNonce []byte) []byte {
	msg := []byte{authVersion, authFrameClientHello}
	msg = append(msg, clientPub...)
	msg = append(msg, clientNonce...)
	return msg
}

func parseClientHello(msg []byte) ([]byte, []byte, error) {
	const wantLen = 2 + 32 + authNonceSize
	if len(msg) != wantLen || msg[0] != authVersion || msg[1] != authFrameClientHello {
		return nil, nil, fmt.Errorf("%w: invalid client hello", errAuthFailed)
	}
	return msg[2:34], msg[34:], nil
}

func makeServerHello(key []byte, clientPub, serverPub, clientNonce, serverNonce, ekm []byte) []byte {
	msg := []byte{authVersion, authFrameServerHello}
	msg = append(msg, serverPub...)
	msg = append(msg, serverNonce...)
	msg = append(msg, authMAC(key, "server", clientPub, serverPub, clientNonce, serverNonce, ekm)...)
	return msg
}

func parseServerHello(msg []byte) ([]byte, []byte, []byte, error) {
	const wantLen = 2 + 32 + authNonceSize + authMACSize
	if len(msg) != wantLen || msg[0] != authVersion || msg[1] != authFrameServerHello {
		return nil, nil, nil, fmt.Errorf("%w: invalid server hello", errAuthFailed)
	}
	return msg[2:34], msg[34:66], msg[66:], nil
}

func makeClientProof(key []byte, clientPub, serverPub, clientNonce, serverNonce, ekm []byte) []byte {
	msg := []byte{authVersion, authFrameClientProof}
	msg = append(msg, authMAC(key, "client", clientPub, serverPub, clientNonce, serverNonce, ekm)...)
	return msg
}

func parseClientProof(msg []byte) ([]byte, error) {
	const wantLen = 2 + authMACSize
	if len(msg) != wantLen || msg[0] != authVersion || msg[1] != authFrameClientProof {
		return nil, fmt.Errorf("%w: invalid client proof", errAuthFailed)
	}
	return msg[2:], nil
}

func readAuthFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(hdr[:])
	if size == 0 || size > 512 {
		return nil, fmt.Errorf("%w: invalid auth frame size", errAuthFailed)
	}
	msg := make([]byte, size)
	_, err := io.ReadFull(r, msg)
	return msg, err
}

func writeAuthFrame(w io.Writer, msg []byte) error {
	if len(msg) == 0 || len(msg) > 512 {
		return fmt.Errorf("%w: invalid auth frame size", errAuthFailed)
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(msg)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}

func cloneBytes[T ~[]byte](b T) T {
	return append(T(nil), b...)
}
