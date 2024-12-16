// Copyright 2022 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package filter

import (
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestCommandFilter_Filter(t *testing.T) {
	if os.Getenv("RUN_CMD") == "1" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			os.Exit(1)
		}
		os.Stdout.Write(b)
		return
	}
	tests := []struct {
		name   string
		getCMD func(t *testing.T) *exec.Cmd
		input  []byte
		want   []byte
	}{
		{
			name: "happy path",
			getCMD: func(t *testing.T) *exec.Cmd {
				cmd := exec.Command(os.Args[0], "-test.run=TestCommandFilter_Filter")
				cmd.Env = append(os.Environ(), "RUN_CMD=1")
				return cmd
			},
			input: []byte("input data"),
			want:  []byte("input data"),
		},
		{
			name: "wrong command",
			getCMD: func(t *testing.T) *exec.Cmd {
				cmd := exec.Command("wrong-command")
				return cmd
			},
			input: []byte("input data"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmdFilter := &CommandFilter{
				cmd: tt.getCMD(t),
			}
			got := cmdFilter.Filter(tt.input)
			if !strings.Contains(string(got), string(tt.want)) {
				t.Errorf("filter() = %q, want %q", string(got), string(tt.want))
			}
			if len(tt.want) == 0 && len(got) != 0 {
				t.Errorf("filter() = %q, want empty", string(got))
			}
		})
	}
}
