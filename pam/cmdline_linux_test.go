package pam

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func Test_getCmdLine(t *testing.T) {
	t.Parallel()
	type args struct {
		pid int
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "invalid pid",
			args: args{
				pid: -1,
			},
			want: unknownCommand,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getCmdLine(tt.args.pid); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getCmdLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getProcCmdLine(t *testing.T) {
	t.Parallel()

	testDir, err := os.MkdirTemp("", "proc")
	if err != nil {
		t.Errorf("unable to create testDir, err: %v", err)
	}
	defer os.RemoveAll(testDir)

	makeFile := func(basename string, data []byte) string {
		f := filepath.Join(testDir, basename)
		err := os.WriteFile(f, data, 0444)
		if err != nil {
			t.Errorf("unable to create testDir, err: %v", err)
		}
		return f
	}

	type args struct {
		fname string
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "happy path, regular command with args",
			args: args{
				fname: makeFile("regularCmd", []byte("/usr/bin/program\x00arg1\x00arg2\x00arg3\x00")),
			},
			want: []byte("/usr/bin/program arg1 arg2 arg3"),
		},
		{
			name: "happy path, regular command with no args",
			args: args{
				fname: makeFile("noArgs", []byte("/program\x00")),
			},
			want: []byte("/program"),
		},
		{
			name: "just name",
			args: args{
				fname: makeFile("justName", []byte("/program")),
			},
			want: []byte("/program"),
		},
		{
			name: "non existing proc file",
			args: args{
				fname: "/xyz/nonExisting",
			},
			want: unknownCommand,
		},
		{
			name: "zero bytes",
			args: args{
				fname: makeFile("zeroBytes", []byte{}),
			},
			want: unknownCommand,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getProcCmdLine(tt.args.fname); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getProcCmdLine() = %v, want %v", got, tt.want)
			}
		})
	}
}
