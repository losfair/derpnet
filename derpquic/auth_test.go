package derpquic

import (
	"bytes"
	"testing"

	"github.com/ntnj/derpnet"
)

func TestAuthMACKeyIsSymmetricAndChannelBound(t *testing.T) {
	clientKey, err := derpnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := derpnet.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	clientPub, err := clientKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	serverPub, err := serverKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	ekm := bytes.Repeat([]byte{1}, authEKMSize)
	clientMACKey, err := authMACKey(clientKey, serverPub, ekm)
	if err != nil {
		t.Fatal(err)
	}
	serverMACKey, err := authMACKey(serverKey, clientPub, ekm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(clientMACKey, serverMACKey) {
		t.Fatal("client and server derived different auth MAC keys")
	}

	otherEKM := bytes.Repeat([]byte{2}, authEKMSize)
	otherMACKey, err := authMACKey(clientKey, serverPub, otherEKM)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(clientMACKey, otherMACKey) {
		t.Fatal("auth MAC key did not change when TLS exporter changed")
	}
}

func TestAuthMACSeparatesRoles(t *testing.T) {
	key := bytes.Repeat([]byte{3}, authKeySize)
	clientPub := bytes.Repeat([]byte{4}, 32)
	serverPub := bytes.Repeat([]byte{5}, 32)
	clientNonce := bytes.Repeat([]byte{6}, authNonceSize)
	serverNonce := bytes.Repeat([]byte{7}, authNonceSize)
	ekm := bytes.Repeat([]byte{8}, authEKMSize)

	serverProof := authMAC(key, "server", clientPub, serverPub, clientNonce, serverNonce, ekm)
	clientProof := authMAC(key, "client", clientPub, serverPub, clientNonce, serverNonce, ekm)
	if bytes.Equal(serverProof, clientProof) {
		t.Fatal("server and client proofs should be distinct")
	}
}
