// Copyright 2023 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pam

import (
	"reflect"
	"testing"
)

func Test_parseKernProcargs2(t *testing.T) {
	t.Parallel()

	type args struct {
		data []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "happy path, expect program name with arguments",
			args: args{
				data: []byte("\x05\x00\x00\x00/usr/bin/progname\x00\x00\x00\x00\x00\x00arg1\x00arg2\x00arg3\x00arg4\x00arg5\x00PATH=/x/y/z:/p/q/r\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00ptr_munge=\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00main_stack=\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00executable_file=0x1a0100000d,0x895c698\x00dyld_file=0x1a0100000d,0xfffffff0008818a\x00executable_cdhash=1afc1f6b19d2b3cb02a62770921572e26fb9fda0\x00executable_boothash=ef08db055c513271d2e440eb5c1e1a0c7cbd1a40\x00arm64e_abi=os\x00th_port=\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
			},
			want: []byte("/usr/bin/progname arg1 arg2 arg3 arg4 arg5"),
		},
		{
			name: "not enough bytes",
			args: args{
				data: []byte("\x05\x00\x00"),
			},
			want: unknownCommand,
		},
		{
			name: "four bytes",
			args: args{
				data: []byte("\x05\x00\x00\x00"),
			},
			want: unknownCommand,
		},
		{
			name: "five bytes",
			args: args{
				data: []byte("\x05\x00\x00\x00\x00"),
			},
			want: unknownCommand,
		},
		{
			name: "truncated result",
			args: args{
				data: []byte("\x05\x00\x00\x00/progname"),
			},
			want: []byte("/progname "),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseKernProcargs2(tt.args.data); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseKernProcargs2() = %v, want %v", got, tt.want)
			}
		})
	}
}
