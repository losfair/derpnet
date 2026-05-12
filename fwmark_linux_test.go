//go:build linux

package derpnet

import (
	"net"
	"testing"
)

func TestSetDialerFWMarkLinux(t *testing.T) {
	var dialer net.Dialer
	if err := setDialerFWMark(&dialer, 123); err != nil {
		t.Fatal(err)
	}
	if dialer.Control == nil {
		t.Fatal("expected dialer Control to be set")
	}
}

func TestSetDialerFWMarkZeroLinux(t *testing.T) {
	var dialer net.Dialer
	if err := setDialerFWMark(&dialer, 0); err != nil {
		t.Fatal(err)
	}
	if dialer.Control != nil {
		t.Fatal("expected zero fwmark to leave dialer Control unset")
	}
}

func TestValidateFWMarkZeroLinux(t *testing.T) {
	if err := ValidateFWMark(0); err != nil {
		t.Fatal(err)
	}
}
