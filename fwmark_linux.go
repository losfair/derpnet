//go:build linux

package derpnet

import (
	"fmt"
	"net"
	"syscall"
)

// ValidateFWMark checks that the process can set SO_MARK to mark.
func ValidateFWMark(mark uint32) error {
	if mark == 0 {
		return nil
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("create socket for fwmark validation: %w", err)
	}
	defer syscall.Close(fd)
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, int(mark)); err != nil {
		return fmt.Errorf("set SO_MARK %d: %w", mark, err)
	}
	return nil
}

func setDialerFWMark(dialer *net.Dialer, mark uint32) error {
	if mark == 0 {
		return nil
	}
	dialer.Control = func(_, _ string, conn syscall.RawConn) error {
		var sockOptErr error
		if err := conn.Control(func(fd uintptr) {
			if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark)); err != nil {
				sockOptErr = fmt.Errorf("set SO_MARK %d: %w", mark, err)
			}
		}); err != nil {
			return err
		}
		return sockOptErr
	}
	return nil
}
