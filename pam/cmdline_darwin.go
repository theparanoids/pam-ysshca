// Copyright 2023 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"encoding/binary"
	"errors"
	"github.com/theparanoids/pam-ysshca/msg"
	"golang.org/x/sys/unix"
	"os"
	"strings"
	"syscall"
)

var unknownCommand = []byte("unknown command")

func getCmdLine() []byte {
	data, err := unix.SysctlRaw("kern.procargs2", os.Getpid())
	if err != nil {
		if errors.Is(err, syscall.EINVAL) {
			// sysctl returns "invalid argument" for both "no such process"
			// and "operation not permitted" errors.
			msg.Printlf(msg.WARN, "No such process or operation not permitted: %w", err)
		}
		return unknownCommand
	}
	return parseKernProcargs2(data)
}

func parseKernProcargs2(data []byte) []byte {
	// argc
	if len(data) < 4 {
		msg.Printlf(msg.WARN, "Invalid kern.procargs2 data")
		return unknownCommand
	}
	argc := binary.LittleEndian.Uint32(data)
	data = data[4:]

	// exe
	lines := strings.Split(string(data), "\x00")
	exe := lines[0]
	lines = lines[1:]

	// Skip nulls that may be appended after the exe.
	for len(lines) > 0 {
		if lines[0] != "" {
			break
		}
		lines = lines[1:]
	}

	// argv
	if c := min(argc, uint32(len(lines))); c > 0 {
		exe += " "
		exe += strings.Join(lines[:c], " ")
	}

	return []byte(exe)
}

func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}
