// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package filter

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/theparanoids/pam-ysshca/msg"
)

// CommandFilter encapsulates the path and the logic to invoke the program that offers additional
// restrictions on public keys.
type CommandFilter struct {
	path string
	cmd  *exec.Cmd
}

// NewCommandFilter returns a command filter.
func NewCommandFilter(filterPath string) (*CommandFilter, error) {
	if _, err := os.Stat(filterPath); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s does not exist, err:%v", filterPath, err)
	}
	return &CommandFilter{
		path: filterPath,
		cmd:  exec.Command(filterPath),
	}, nil
}

// Filter invokes the filter program and returns the qualified keys.
func (f *CommandFilter) Filter(input []byte) []byte {
	f.cmd.Stdin = bytes.NewReader(input)

	var out bytes.Buffer
	f.cmd.Stdout = &out

	err := f.cmd.Run()

	if err != nil {
		msg.Printlf(msg.WARN, "Cannot execute filter %s: %v", f.path, err)
		return nil
	}
	return out.Bytes()
}
