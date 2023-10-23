// Copyright 2023 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"bytes"
	"encoding/binary"
	"errors"
	"syscall"

	"github.com/theparanoids/pam-ysshca/msg"
	"golang.org/x/sys/unix"
)

func getCmdLine(pid int) []byte {
	data, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		msg.Printlf(msg.WARN, "unable to do sysctlraw, error: %w", err)
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
		msg.Printlf(msg.WARN, "invalid kern.procargs2 data")
		return unknownCommand
	}
	argc := binary.LittleEndian.Uint32(data[:4])

	// The program name starts after first 4 bytes
	data = data[4:]

	lines := bytes.Split(data, []byte{0})
	result := bytes.Buffer{}
	count := uint32(0)

	for _, line := range lines {
		// data is expected to contain series of nulls, which could be skipped
		if len(line) != 0 {
			// we need program name + argc number of tokens
			if count < argc {
				result.Write(line)
				result.WriteByte(' ')
				count++
			} else {
				result.Write(line)
				break
			}
		}
	}

	if result.Len() == 0 {
		return unknownCommand
	}

	return result.Bytes()
}
