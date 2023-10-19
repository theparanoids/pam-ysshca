// Copyright 2023 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/theparanoids/pam-ysshca/msg"
)

func getCmdLine() []byte {
	cmd, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/cmdline", os.Getpid()))
	if err != nil {
		cmd = []byte("unknown command")
		msg.Printlf(msg.WARN, "Failed to read /proc/%d/cmdline: %v", os.Getpid(), err)
	} else if len(cmd) == 0 {
		cmd = []byte("empty command")
		msg.Printlf(msg.WARN, "/proc/%d/cmdline is empty", os.Getpid())
	}

	// Remove '\0' at the end.
	cmd = cmd[:len(cmd)-1]
	// Replace '\0' with ' '.
	cmd = bytes.Replace(cmd, []byte{0}, []byte{' '}, -1)

	return cmd
}
