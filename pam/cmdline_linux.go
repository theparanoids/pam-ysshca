// Copyright 2023 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"bytes"
	"fmt"
	"os"

	"github.com/theparanoids/pam-ysshca/msg"
)

func getCmdLine(pid int) []byte {
	return getProcCmdLine(fmt.Sprintf("/proc/%d/cmdline", pid))
}

func getProcCmdLine(fname string) []byte {
	cmd, err := os.ReadFile(fname)
	if err != nil {
		msg.Printlf(msg.WARN, "failed to read file: %q, err: %w", fname, err)
		return unknownCommand
	}

	if len(cmd) == 0 {
		msg.Printlf(msg.WARN, "file: %q is empty", fname)
		return unknownCommand
	}

	// Remove '\0' at the end.
	cmd = bytes.TrimSuffix(cmd, []byte{0})

	// Replace '\0' with ' '.
	cmd = bytes.Replace(cmd, []byte{0}, []byte{' '}, -1)

	return cmd
}
