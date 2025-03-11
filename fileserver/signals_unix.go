// +build !windows

package main

import (
	"os/signal"
	"syscall"
)

func init() {
	// On Unix, ignore SIGURG to prevent repeated interruptions.
	signal.Ignore(syscall.SIGURG)
}
