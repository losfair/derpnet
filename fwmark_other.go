//go:build !linux

package derpnet

import (
	"errors"
	"net"
)

// ValidateFWMark checks that the process can set SO_MARK to mark.
func ValidateFWMark(mark uint32) error {
	if mark == 0 {
		return nil
	}
	return errors.New("fwmark is only supported on Linux")
}

func setDialerFWMark(_ *net.Dialer, mark uint32) error {
	if mark == 0 {
		return nil
	}
	return errors.New("fwmark is only supported on Linux")
}
