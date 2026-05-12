//go:build !linux

package derpnet

import (
	"net"
	"testing"
)

func TestSetDialerFWMarkUnsupported(t *testing.T) {
	var dialer net.Dialer
	if err := setDialerFWMark(&dialer, 123); err == nil {
		t.Fatal("expected unsupported fwmark error")
	}
}

func TestSetDialerFWMarkZeroUnsupported(t *testing.T) {
	var dialer net.Dialer
	if err := setDialerFWMark(&dialer, 0); err != nil {
		t.Fatal(err)
	}
}

func TestValidateFWMarkUnsupported(t *testing.T) {
	if err := ValidateFWMark(123); err == nil {
		t.Fatal("expected unsupported fwmark error")
	}
}

func TestValidateFWMarkZeroUnsupported(t *testing.T) {
	if err := ValidateFWMark(0); err != nil {
		t.Fatal(err)
	}
}
